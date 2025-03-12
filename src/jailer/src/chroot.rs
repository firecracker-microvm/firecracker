// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::ffi::CStr;
use std::path::Path;
use std::ptr::null;

use vmm_sys_util::syscall::SyscallReturnCode;

use super::{JailerError, to_cstring};

const OLD_ROOT_DIR: &CStr = c"old_root";
const ROOT_DIR: &CStr = c"/";
const CURRENT_DIR: &CStr = c".";

// This uses switching to a new mount namespace + pivot_root(), together with the regular chroot,
// to provide a hardened jail (at least compared to only relying on chroot).
pub fn chroot(path: &Path) -> Result<(), JailerError> {
    // We unshare into a new mount namespace.
    // SAFETY: The call is safe because we're invoking a C library
    // function with valid parameters.
    SyscallReturnCode(unsafe { libc::unshare(libc::CLONE_NEWNS) })
        .into_empty_result()
        .map_err(JailerError::UnshareNewNs)?;

    // Recursively change the propagation type of all the mounts in this namespace to SLAVE, so
    // we can call pivot_root.
    // SAFETY: Safe because we provide valid parameters.
    SyscallReturnCode(unsafe {
        libc::mount(
            null(),
            ROOT_DIR.as_ptr(),
            null(),
            libc::MS_SLAVE | libc::MS_REC,
            null(),
        )
    })
    .into_empty_result()
    .map_err(JailerError::MountPropagationSlave)?;

    // We need a CString for the following mount call.
    let chroot_dir = to_cstring(path)?;

    // Bind mount the jail root directory over itself, so we can go around a restriction
    // imposed by pivot_root, which states that the new root and the old root should not
    // be on the same filesystem.
    // SAFETY: Safe because we provide valid parameters.
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
    .map_err(JailerError::MountBind)?;

    // Change current dir to the chroot dir, so we only need to handle relative paths from now on.
    env::set_current_dir(path).map_err(JailerError::SetCurrentDir)?;

    // Create the old_root folder we're going to use for pivot_root, using a relative path.
    // SAFETY: The call is safe because we provide valid arguments.
    SyscallReturnCode(unsafe { libc::mkdir(OLD_ROOT_DIR.as_ptr(), libc::S_IRUSR | libc::S_IWUSR) })
        .into_empty_result()
        .map_err(JailerError::MkdirOldRoot)?;

    // We are now ready to call pivot_root. We have to use sys_call because there is no libc
    // wrapper for pivot_root.
    // SAFETY: Safe because we provide valid parameters.
    SyscallReturnCode(unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            CURRENT_DIR.as_ptr(),
            OLD_ROOT_DIR.as_ptr(),
        )
    })
    .into_empty_result()
    .map_err(JailerError::PivotRoot)?;

    // pivot_root doesn't guarantee that we will be in "/" at this point, so switch to "/"
    // explicitly.
    // SAFETY: Safe because we provide valid parameters.
    SyscallReturnCode(unsafe { libc::chdir(ROOT_DIR.as_ptr()) })
        .into_empty_result()
        .map_err(JailerError::ChdirNewRoot)?;

    // Umount the old_root, thus isolating the process from everything outside the jail root folder.
    // SAFETY: Safe because we provide valid parameters.
    SyscallReturnCode(unsafe { libc::umount2(OLD_ROOT_DIR.as_ptr(), libc::MNT_DETACH) })
        .into_empty_result()
        .map_err(JailerError::UmountOldRoot)?;

    // Remove the no longer necessary old_root directory.
    // SAFETY: Safe because we provide valid parameters.
    SyscallReturnCode(unsafe { libc::rmdir(OLD_ROOT_DIR.as_ptr()) })
        .into_empty_result()
        .map_err(JailerError::RmOldRootDir)
}
