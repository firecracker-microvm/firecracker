// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::read_to_string;
use std::sync::{Arc, Mutex};

use vmm::Vmm;

use crate::fingerprint::Fingerprint;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum FingerprintDumpError {
    /// Failed to dump CPU config: {0}
    DumpCpuConfig(#[from] crate::template::dump::DumpError),
    /// Failed to read {0}: {1}
    ReadSysfsFile(String, std::io::Error),
    /// Failed to get kernel version: {0}
    GetKernelVersion(std::io::Error),
}

pub fn dump(vmm: Arc<Mutex<Vmm>>) -> Result<Fingerprint, FingerprintDumpError> {
    Ok(Fingerprint {
        firecracker_version: crate::utils::CPU_TEMPLATE_HELPER_VERSION.to_string(),
        kernel_version: get_kernel_version()?,
        #[cfg(target_arch = "x86_64")]
        microcode_version: read_sysfs_file("/sys/devices/system/cpu/cpu0/microcode/version")?,
        #[cfg(target_arch = "aarch64")]
        microcode_version: read_sysfs_file(
            "/sys/devices/system/cpu/cpu0/regs/identification/revidr_el1",
        )?,
        bios_version: read_sysfs_file("/sys/devices/virtual/dmi/id/bios_version")?,
        bios_revision: read_sysfs_file("/sys/devices/virtual/dmi/id/bios_release")?,
        guest_cpu_config: crate::template::dump::dump(vmm)?,
    })
}

fn get_kernel_version() -> Result<String, FingerprintDumpError> {
    // SAFETY: An all-zeroed value for `libc::utsname` is valid.
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: The passed arg is a valid mutable reference of `libc::utsname`.
    let ret = unsafe { libc::uname(&mut name) };
    if ret < 0 {
        return Err(FingerprintDumpError::GetKernelVersion(
            std::io::Error::last_os_error(),
        ));
    }

    // SAFETY: The fields of `libc::utsname` are terminated by a null byte ('\0').
    // https://man7.org/linux/man-pages/man2/uname.2.html
    let c_str = unsafe { std::ffi::CStr::from_ptr(name.release.as_ptr()) };
    // SAFETY: The `release` field is an array of `char` in C, in other words, ASCII.
    let version = c_str.to_str().unwrap();
    Ok(version.to_string())
}

fn read_sysfs_file(path: &str) -> Result<String, FingerprintDumpError> {
    let s = read_to_string(path)
        .map_err(|err| FingerprintDumpError::ReadSysfsFile(path.to_string(), err))?;
    Ok(s.trim_end_matches('\n').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_kernel_version() {
        // `get_kernel_version()` should always succeed.
        get_kernel_version().unwrap();
    }

    #[test]
    fn test_read_valid_sysfs_file() {
        // The sysfs file for microcode version should exist and be read.
        let valid_sysfs_path = "/sys/devices/virtual/dmi/id/bios_version";
        read_sysfs_file(valid_sysfs_path).unwrap();
    }

    #[test]
    fn test_read_invalid_sysfs_file() {
        let invalid_sysfs_path = "/sys/invalid/path";
        if read_sysfs_file(invalid_sysfs_path).is_ok() {
            panic!("Should fail with `No such file or directory`");
        }
    }
}
