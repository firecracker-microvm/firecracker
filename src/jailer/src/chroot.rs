// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::ffi::CStr;
use std::path::Path;
use std::ptr::null;

use libc;

use super::{to_cstring, Error, Result};
use utils::syscall::SyscallReturnCode;

const OLD_ROOT_DIR_NAME_NUL_TERMINATED: &[u8] = b"old_root\0";
const ROOT_DIR_NUL_TERMINATED: &[u8] = b"/\0";
const CURRENT_DIR_NUL_TERMINATED: &[u8] = b".\0";

// This uses switching to a new mount namespace + pivot_root(), together with the regular chroot,
// to provide a hardened jail (at least compared to only relying on chroot).
pub fn chroot(path: &Path) -> Result<()> {
    // We unshare into a new mount namespace. The call is safe because we're invoking a C library
    // function with valid parameters.
    SyscallReturnCode(unsafe { libc::unshare(libc::CLONE_NEWNS) })
        .into_empty_result()
        .map_err(Error::UnshareNewNs)?;

    let root_dir = CStr::from_bytes_with_nul(ROOT_DIR_NUL_TERMINATED)
        .map_err(|_| Error::FromBytesWithNul(ROOT_DIR_NUL_TERMINATED))?;

    // Recursively change the propagation type of all the mounts in this namespace to SLAVE, so
    // we can call pivot_root. Safe because we provide valid parameters.
    SyscallReturnCode(unsafe {
        libc::mount(
            null(),
            root_dir.as_ptr(),
            null(),
            libc::MS_SLAVE | libc::MS_REC,
            null(),
        )
    })
    .into_empty_result()
    .map_err(Error::MountPropagationSlave)?;

    // We need a CString for the following mount call.
    let chroot_dir = to_cstring(path)?;

    // Bind mount the jail root directory over itself, so we can go around a restriction
    // imposed by pivot_root, which states that the new root and the old root should not
    // be on the same filesystem. Safe because we provide valid parameters.
    SyscallReturnCode(unsafe {
        libc::mount(
            chroot_dir.as_ptr(),
            chroot_dir.as_ptr(),
            null(),
            libc::MS_BIND | libc::MS_REC,
            null(),
        )
    })
    .into_empty_result()
    .map_err(Error::MountBind)?;

    // Change current dir to the chroot dir, so we only need to handle relative paths from now on.
    env::set_current_dir(path).map_err(Error::SetCurrentDir)?;

    // We use the CStr conversion to make sure the contents of the byte slice would be a
    // valid C string (and for the as_ptr() method).
    let old_root_dir = CStr::from_bytes_with_nul(OLD_ROOT_DIR_NAME_NUL_TERMINATED)
        .map_err(|_| Error::FromBytesWithNul(OLD_ROOT_DIR_NAME_NUL_TERMINATED))?;

    // Create the old_root folder we're going to use for pivot_root, using a relative path. The call
    // is safe because we provide valid arguments.
    SyscallReturnCode(unsafe { libc::mkdir(old_root_dir.as_ptr(), libc::S_IRUSR | libc::S_IWUSR) })
        .into_empty_result()
        .map_err(Error::MkdirOldRoot)?;

    let cwd = CStr::from_bytes_with_nul(CURRENT_DIR_NUL_TERMINATED)
        .map_err(|_| Error::FromBytesWithNul(CURRENT_DIR_NUL_TERMINATED))?;

    // We are now ready to call pivot_root. We have to use sys_call because there is no libc
    // wrapper for pivot_root. Safe because we provide valid parameters.
    SyscallReturnCode(unsafe {
        libc::syscall(libc::SYS_pivot_root, cwd.as_ptr(), old_root_dir.as_ptr())
    } as libc::c_int)
    .into_empty_result()
    .map_err(Error::PivotRoot)?;

    // pivot_root doesn't guarantee that we will be in "/" at this point, so switch to "/"
    // explicitly. Safe because we provide valid parameters.
    SyscallReturnCode(unsafe { libc::chdir(root_dir.as_ptr()) })
        .into_empty_result()
        .map_err(Error::ChdirNewRoot)?;

    // Umount the old_root, thus isolating the process from everything outside the jail root folder.
    // Safe because we provide valid parameters.
    SyscallReturnCode(unsafe { libc::umount2(old_root_dir.as_ptr(), libc::MNT_DETACH) })
        .into_empty_result()
        .map_err(Error::UmountOldRoot)?;

    // Remove the no longer necessary old_root directory.
    SyscallReturnCode(unsafe { libc::rmdir(old_root_dir.as_ptr()) })
        .into_empty_result()
        .map_err(Error::RmOldRootDir)
}
