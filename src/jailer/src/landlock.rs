// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Landlock LSM integration for the Firecracker jailer.
//!
//! Landlock is a Linux security module (available since kernel 5.13) that allows a process to
//! restrict its own file system access. The jailer uses it as a defense-in-depth mechanism: even
//! if a guest VM escapes the pivot_root chroot, the Landlock rules—applied before the exec—
//! prevent Firecracker from accessing files outside the jail directory.
//!
//! Usage:
//! 1. Call [`prepare_ruleset`] **before** `chroot()` to open a file descriptor referencing the
//!    jail directory by inode. The inode reference survives `pivot_root`.
//! 2. After all post-chroot setup is done, call [`enforce`] on the returned ruleset right before
//!    `exec`. The restrictions are inherited by the exec'd process.

use std::path::Path;

use landlock::{
    ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr,
};

use crate::JailerError;

/// Create a Landlock ruleset that grants all file-system access rights within `jail_dir` and
/// denies everything outside.
///
/// Must be called **before** `chroot()`/`pivot_root()` so that the `PathFd` captures the inode
/// of the jail directory while it is still reachable by its host path.  The returned
/// [`RulesetCreated`] holds the open `PathFd` and can safely be passed across the `pivot_root`
/// boundary.
///
/// # Errors
///
/// Returns [`JailerError::Landlock`] if the kernel does not support Landlock (kernel < 5.13),
/// if `jail_dir` cannot be opened, or if any ruleset syscall fails.
pub fn prepare_ruleset(jail_dir: &Path) -> Result<RulesetCreated, JailerError> {
    let abi = ABI::V1;

    let path_fd = PathFd::new(jail_dir).map_err(|err| {
        JailerError::Landlock(format!(
            "Failed to open Landlock path fd for {:?}: {}",
            jail_dir, err
        ))
    })?;

    Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|err| JailerError::Landlock(format!("Failed to create Landlock ruleset: {err}")))?
        .create()
        .map_err(|err| JailerError::Landlock(format!("Failed to create Landlock ruleset: {err}")))?
        .add_rule(PathBeneath::new(path_fd, AccessFs::from_all(abi)))
        .map_err(|err| JailerError::Landlock(format!("Failed to add Landlock rule: {err}")))
}

/// Enforce a prepared Landlock ruleset on the current thread.
///
/// The restrictions are inherited across `exec`, so calling this right before `execve` will
/// confine the jailed Firecracker process to only the paths allowed by the ruleset.
///
/// # Errors
///
/// Returns [`JailerError::Landlock`] if `restrict_self` fails.
pub fn enforce(ruleset: RulesetCreated) -> Result<(), JailerError> {
    ruleset
        .restrict_self()
        .map_err(|err| JailerError::Landlock(format!("Failed to enforce Landlock ruleset: {err}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::ffi::CStr;

    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    fn is_landlock_supported() -> bool {
        // SAFETY: zeroed() is always safe for plain-old-data types.
        let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };
        // SAFETY: utsname is a valid pointer to a libc::utsname struct.
        if unsafe { libc::uname(&mut utsname) } != 0 {
            return false;
        }
        // SAFETY: release is a null-terminated C string written by uname().
        let release = unsafe { CStr::from_ptr(utsname.release.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let mut parts = release.split('.');
        let major: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        major > 5 || (major == 5 && minor >= 13)
    }

    #[test]
    fn test_prepare_ruleset_valid_dir() {
        if !is_landlock_supported() {
            // Skip on kernels that don't support Landlock.
            return;
        }
        let tmp = TempDir::new_with_prefix("landlock_test_").unwrap();
        assert!(prepare_ruleset(tmp.as_path()).is_ok());
    }

    #[test]
    fn test_prepare_ruleset_nonexistent_dir() {
        let result = prepare_ruleset(Path::new("/nonexistent/path/for/landlock/test"));
        assert!(result.is_err());
    }
}
