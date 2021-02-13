// Copyright 2021 Geoff Johnstone. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Contains support for detecting macvtap interfaces.
use std::ffi::CString;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::{ffi::OsStrExt, fs::FileTypeExt};
use std::path::{Path, PathBuf};

use crate::syscall::SyscallReturnCode;

/// Represents a macvtap interface.
pub struct MacVTap {
    /// Interface name, as seen in 'ip addr' output.
    pub if_name: String,
    /// Host tap device node name in /dev.
    pub tap_name: String,
    /// Device major number.
    pub major: u32,
    /// Device minor number.
    pub minor: u32,
}

impl MacVTap {
    /// Returns the device node for the given macvtap interface.
    pub fn get_device_node(if_name: &str) -> Result<PathBuf> {
        // If this is run with jailer, we expect /dev/net/<if_name> to be a valid char device;
        // If run without jailer, try /dev/tapXX.
        is_char_device(Path::new("/dev/net").join(if_name))
            .or_else(|_| is_char_device(Path::new("/dev").join(Self::by_name(if_name)?.tap_name)))
    }

    /// Returns a MacVTap instance for the given network interface name.
    /// This function looks into /sys/devices/virtual/net/{if_name}/macvtap/ and expects to find
    /// the name of the /dev/tapXX associated with it.
    /// It will look further to find out the major and minor numbers in the
    /// /sys/devices/virtual/net/{if_name}/macvtap/tapXX/dev
    pub fn by_name(if_name: &str) -> Result<Self> {
        // Need to convert if_name into a device node. There should be one
        // directory under /sys/.../<if_name>/macvtap, which is the name of
        // the device node in /dev. Within that, dev gives major:minor\n
        if !is_normal_path_component(if_name) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("Invalid macvtap interface name: {}", if_name),
            ));
        }

        let macvtap_dir = Path::new("/sys/devices/virtual/net")
            .join(if_name)
            .join("macvtap");
        let dirents = macvtap_dir.read_dir()?.collect::<Vec<_>>();
        if dirents.len() != 1 {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Found {} dirents in {}",
                    dirents.len(),
                    macvtap_dir.display()
                ),
            ));
        }

        // unwrap() is safe because there is one element in dirents and we already checked for that.
        let dirent = dirents.into_iter().next().unwrap();
        let dev_name = dirent?.file_name(); // e.g. tap42

        // Read /sys/.../<if_name>/macvtap/<dev_name>/dev
        let dev_file_path = macvtap_dir.join(&dev_name).join("dev");
        let dev_str = std::fs::read_to_string(&dev_file_path)?;

        // Trim trailing newline, split on ':', parse major and minor numbers
        let mut cpts = dev_str.trim_end().splitn(2, ':');
        let major = parse_dev(&mut cpts);
        let minor = parse_dev(&mut cpts);

        if major.is_none() || minor.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid {} contents: {}", dev_file_path.display(), dev_str),
            ));
        }

        Ok(Self {
            if_name: if_name.to_string(),
            tap_name: dev_name.into_string().unwrap(),
            major: major.unwrap(),
            minor: minor.unwrap(),
        })
    }

    /// Creates a device node for the given network MacVTap instance at the given path with
    /// the given owner and group.
    pub fn mknod<P: AsRef<Path>>(&self, path: P, uid: u32, gid: u32) -> Result<()> {
        let osstr = path.as_ref().as_os_str();
        let cstr =
            CString::new(osstr.as_bytes()).map_err(|x| Error::new(ErrorKind::InvalidInput, x))?;

        // Safety: path is a C-compatible pointer to memory that is in scope
        SyscallReturnCode(unsafe {
            libc::mknod(
                cstr.as_ptr(),
                libc::S_IFCHR | libc::S_IRUSR | libc::S_IWUSR,
                libc::makedev(self.major, self.minor),
            )
        })
        .into_empty_result()?;

        // Safety: path is a C-compatible pointer to memory that is in scope
        SyscallReturnCode(unsafe { libc::chown(cstr.as_ptr(), uid, gid) }).into_empty_result()
    }
}

fn parse_dev<'a, It: Iterator<Item = &'a str>>(it: &mut It) -> Option<u32> {
    it.next().and_then(|s| s.parse().ok())
}

fn is_normal_path_component(if_name: &str) -> bool {
    // Mustn't be empty, "." or ".."; mustn't contain / or \.
    if_name != ""
        && if_name != "."
        && if_name != ".."
        && if_name.as_bytes().iter().all(|b| *b != b'/' && *b != b'\\')
}

fn is_char_device(dev_path: PathBuf) -> Result<PathBuf> {
    dev_path.metadata().and_then(|md| {
        if !md.file_type().is_char_device() {
            Err(Error::new(
                ErrorKind::InvalidInput,
                format!("{} is not a character device", dev_path.display()),
            ))
        } else {
            Ok(dev_path)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_normal_path_component() {
        assert!(!is_normal_path_component(""));
        assert!(!is_normal_path_component("."));
        assert!(!is_normal_path_component(".."));
        assert!(!is_normal_path_component("/"));
        assert!(!is_normal_path_component("./x"));
        assert!(!is_normal_path_component("../x"));
        assert!(!is_normal_path_component("x/./x"));
        assert!(!is_normal_path_component("x/"));
        assert!(!is_normal_path_component("x/y"));
        assert!(!is_normal_path_component("/.."));
        assert!(!is_normal_path_component("../"));
        assert!(is_normal_path_component("x"));
        assert!(is_normal_path_component(".x"));
        assert!(is_normal_path_component("..x"));
    }
}
