// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Landlock LSM integration for the Firecracker jailer.
//!
//! [Landlock](https://docs.kernel.org/userspace-api/landlock.html) is a Linux security module
//! (available since kernel 5.13) that
//! allows a process to restrict its own file system access. The jailer uses it as a
//! defense-in-depth mechanism: even if a guest VM escapes the pivot_root chroot, the Landlock
//! rules—applied before the exec—prevent Firecracker from accessing files outside the jail
//! directory.
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
/// Returns [`JailerError::Landlock`] if `jail_dir` cannot be opened or if any
/// ruleset syscall fails. On kernels with partial or no Landlock support the
/// ruleset is silently downgraded to the highest ABI the kernel supports
/// (best-effort, per [`Ruleset::default`] semantics).
pub fn prepare_ruleset(jail_dir: &Path) -> Result<RulesetCreated, JailerError> {
    // V7 is the highest tested ABI. The crate's default SoftRequirement mode
    // automatically downgrades to whatever the running kernel supports.
    let abi = ABI::V7;

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
    ruleset.restrict_self().map_err(|err| {
        JailerError::Landlock(format!("Failed to enforce Landlock ruleset: {err}"))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use landlock::{CompatLevel, Compatible};
    use vmm_sys_util::tempdir::TempDir;

    use super::*;

    /// Returns true if the running kernel supports Landlock (any ABI version).
    ///
    /// Uses the Landlock crate's own compatibility check (via `HardRequirement`) rather than
    /// parsing the kernel version string, since Landlock may be backported to older kernels.
    fn is_landlock_supported() -> bool {
        Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(ABI::V1))
            .and_then(|r: Ruleset| r.create())
            .is_ok()
    }

    #[test]
    fn test_prepare_ruleset_valid_dir() {
        if !is_landlock_supported() {
            // Skip on kernels that don't support Landlock.
            return;
        }
        let tmp = TempDir::new_with_prefix("landlock_test_").unwrap();
        prepare_ruleset(tmp.as_path()).unwrap();
    }

    #[test]
    fn test_prepare_ruleset_nonexistent_dir() {
        let result = prepare_ruleset(Path::new("/nonexistent/path/for/landlock/test"));
        result.unwrap_err();
    }

    /// Env var that signals this process is the re-exec'd child for
    /// `test_enforce`. Set only by the parent invocation below.
    const ENFORCE_CHILD_ENV: &str = "LANDLOCK_TEST_ENFORCE_CHILD";

    #[test]
    #[allow(
        clippy::exit,
        reason = "deliberate exit from a re-exec'd child process"
    )]
    fn test_enforce() {
        if !is_landlock_supported() {
            return;
        }

        // enforce() restricts the calling process irreversibly, and cargo
        // test runs many tests as threads within one process, so we can't
        // call it directly here without breaking file access for other
        // tests. Instead, re-exec this test binary as a real child process,
        // filtered to just this test, and let the child perform the actual
        // (irreversible) enforce() call.
        if std::env::var_os(ENFORCE_CHILD_ENV).is_some() {
            let tmp = TempDir::new_with_prefix("landlock_test_").unwrap();
            let ruleset = prepare_ruleset(tmp.as_path()).unwrap();
            std::process::exit(i32::from(enforce(ruleset).is_err()));
        }

        let exe = std::env::current_exe().unwrap();
        let status = std::process::Command::new(exe)
            .args(["landlock::tests::test_enforce", "--exact"])
            .env(ENFORCE_CHILD_ENV, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}
