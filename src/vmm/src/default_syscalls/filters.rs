// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryInto;

use seccomp::{
    allow_syscall, allow_syscall_if, BpfProgram, Error, SeccompAction, SeccompCmpArgLen as ArgLen,
    SeccompCmpOp::Eq, SeccompCondition as Cond, SeccompError, SeccompFilter, SeccompLevel,
    SeccompRule,
};
use utils::signal::sigrtmin;

/// The default filter containing the white listed syscall rules required by `Firecracker` to
/// function.
/// Any non-trivial modification to this allow list needs a proper comment to specify its source
/// or why the sycall/condition is needed.
pub fn default_filter() -> Result<SeccompFilter, Error> {
    Ok(SeccompFilter::new(
        vec![
            // Called by the api thread to receive data on socket
            allow_syscall_if(
                libc::SYS_accept4,
                or![and![Cond::new(
                    3,
                    ArgLen::DWORD,
                    Eq,
                    libc::SOCK_CLOEXEC as u64
                )?],],
            ),
            // Called for expanding the heap
            allow_syscall(libc::SYS_brk),
            // Used for metrics, via the helpers in utils/src/time.rs
            allow_syscall_if(
                libc::SYS_clock_gettime,
                or![and![Cond::new(
                    0,
                    ArgLen::DWORD,
                    Eq,
                    libc::CLOCK_PROCESS_CPUTIME_ID as u64
                )?],],
            ),
            allow_syscall(libc::SYS_close),
            // Needed for vsock
            allow_syscall(libc::SYS_connect),
            allow_syscall(libc::SYS_epoll_ctl),
            allow_syscall(libc::SYS_epoll_pwait),
            #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
            allow_syscall(libc::SYS_epoll_wait),
            allow_syscall(libc::SYS_exit),
            allow_syscall(libc::SYS_exit_group),
            // Used by snapshotting, drive patching and rescanning
            allow_syscall_if(
                libc::SYS_fcntl,
                or![and![
                    Cond::new(1, ArgLen::DWORD, Eq, super::FCNTL_F_SETFD)?,
                    Cond::new(2, ArgLen::DWORD, Eq, super::FCNTL_FD_CLOEXEC)?,
                ],],
            ),
            // Used for drive patching & rescanning, for reading the local timezone
            allow_syscall(libc::SYS_fstat),
            // Used for snapshotting
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_ftruncate),
            // Used for synchronization
            allow_syscall_if(
                libc::SYS_futex,
                or![
                    and![Cond::new(1, ArgLen::DWORD, Eq, super::FUTEX_WAIT_PRIVATE)?],
                    and![Cond::new(1, ArgLen::DWORD, Eq, super::FUTEX_WAKE_PRIVATE)?],
                    #[cfg(target_env = "gnu")]
                    and![Cond::new(
                        1,
                        ArgLen::DWORD,
                        Eq,
                        super::FUTEX_CMP_REQUEUE_PRIVATE
                    )?],
                ],
            ),
            // Used by glibc's tgkill
            #[cfg(target_env = "gnu")]
            allow_syscall(libc::SYS_getpid),
            allow_syscall_if(libc::SYS_ioctl, super::create_ioctl_seccomp_rule()?),
            // Used by the block device
            allow_syscall(libc::SYS_lseek),
            // Triggered by musl for some customer workloads
            #[cfg(target_env = "musl")]
            allow_syscall_if(
                libc::SYS_madvise,
                or![and![Cond::new(
                    2,
                    ArgLen::DWORD,
                    Eq,
                    libc::MADV_DONTNEED as u64
                )?],],
            ),
            // Used for re-allocating large memory regions, for example vectors
            allow_syscall(libc::SYS_mremap),
            // Used for freeing memory
            allow_syscall(libc::SYS_munmap),
            // Used for reading the timezone in LocalTime::now()
            allow_syscall_if(
                libc::SYS_mmap,
                or![and![Cond::new(
                    3,
                    ArgLen::DWORD,
                    Eq,
                    libc::MAP_SHARED as u64
                )?],],
            ),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_open),
            #[cfg(target_arch = "aarch64")]
            allow_syscall(libc::SYS_openat),
            allow_syscall(libc::SYS_read),
            // Used by the API thread and vsock
            allow_syscall(libc::SYS_recvfrom),
            // SYS_rt_sigreturn is needed in case a fault does occur, so that the signal handler
            // can return. Otherwise we get stuck in a fault loop.
            allow_syscall(libc::SYS_rt_sigreturn),
            // Used by the API thread and vsock
            allow_syscall_if(
                libc::SYS_socket,
                or![and![
                    Cond::new(0, ArgLen::DWORD, Eq, libc::AF_UNIX as u64)?,
                    Cond::new(
                        1,
                        ArgLen::DWORD,
                        Eq,
                        (libc::SOCK_STREAM as u64) | (libc::SOCK_CLOEXEC as u64)
                    )?,
                    Cond::new(2, ArgLen::DWORD, Eq, 0u64)?
                ],],
            ),
            // Used to kick vcpus
            allow_syscall_if(
                libc::SYS_tkill,
                or![and![Cond::new(
                    1,
                    ArgLen::DWORD,
                    Eq,
                    (sigrtmin() + super::super::vstate::vcpu::VCPU_RTSIG_OFFSET) as u64
                )?]],
            ),
            // Used to kick vcpus, on gnu
            #[cfg(target_env = "gnu")]
            allow_syscall(libc::SYS_tgkill),
            // Needed for rate limiting
            allow_syscall_if(
                libc::SYS_timerfd_create,
                or![and![
                    Cond::new(0, ArgLen::DWORD, Eq, libc::CLOCK_MONOTONIC as u64)?,
                    Cond::new(
                        1,
                        ArgLen::DWORD,
                        Eq,
                        (libc::TFD_CLOEXEC as u64) | (libc::TFD_NONBLOCK as u64)
                    )?,
                ],],
            ),
            // Needed for rate limiting
            allow_syscall_if(
                libc::SYS_timerfd_settime,
                or![and![Cond::new(1, ArgLen::DWORD, Eq, 0u64)?],],
            ),
            allow_syscall(libc::SYS_write),
        ]
        .into_iter()
        .collect(),
        SeccompAction::Trap,
    )?)
}

/// Generate a BPF program based on a seccomp level value.
pub fn get_seccomp_filter(seccomp_level: SeccompLevel) -> Result<BpfProgram, SeccompError> {
    match seccomp_level {
        SeccompLevel::None => Ok(vec![]),
        SeccompLevel::Basic => default_filter()
            .and_then(|filter| Ok(filter.allow_all()))
            .and_then(|filter| filter.try_into())
            .map_err(SeccompError::SeccompFilter),
        SeccompLevel::Advanced => default_filter()
            .and_then(|filter| filter.try_into())
            .map_err(SeccompError::SeccompFilter),
    }
}

#[cfg(test)]
mod tests {
    use super::get_seccomp_filter;
    use seccomp::SeccompLevel;

    #[test]
    fn test_get_seccomp_filter() {
        assert!(get_seccomp_filter(SeccompLevel::None).is_ok());
        assert!(get_seccomp_filter(SeccompLevel::Basic).is_ok());
        assert!(get_seccomp_filter(SeccompLevel::Advanced).is_ok());
    }
}
