// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate libc;
extern crate utils;

use std::convert::TryInto;

use seccomp::{
    allow_syscall, allow_syscall_if, BpfProgram, Error, SeccompAction, SeccompCmpArgLen as ArgLen,
    SeccompCmpOp::Eq, SeccompCondition as Cond, SeccompError, SeccompFilter, SeccompLevel,
    SeccompRule,
};
use utils::signal::sigrtmin;

/// The default filter containing the white listed syscall rules required by `Firecracker` to
/// function.
pub fn default_filter() -> Result<SeccompFilter, Error> {
    Ok(SeccompFilter::new(
        vec![
            allow_syscall(libc::SYS_accept4),
            allow_syscall(libc::SYS_brk),
            allow_syscall(libc::SYS_clock_gettime),
            allow_syscall(libc::SYS_close),
            allow_syscall(libc::SYS_connect),
            allow_syscall(libc::SYS_dup),
            allow_syscall(libc::SYS_epoll_ctl),
            allow_syscall(libc::SYS_epoll_pwait),
            #[cfg(all(target_env = "gnu", target_arch = "x86_64"))]
            allow_syscall(libc::SYS_epoll_wait),
            allow_syscall(libc::SYS_exit),
            allow_syscall(libc::SYS_exit_group),
            allow_syscall_if(
                libc::SYS_fcntl,
                or![and![
                    Cond::new(1, ArgLen::DWORD, Eq, super::FCNTL_F_SETFD)?,
                    Cond::new(2, ArgLen::QWORD, Eq, super::FCNTL_FD_CLOEXEC)?,
                ]],
            ),
            allow_syscall(libc::SYS_fstat),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_ftruncate),
            allow_syscall_if(
                libc::SYS_futex,
                or![
                    and![Cond::new(1, ArgLen::DWORD, Eq, super::FUTEX_WAIT_PRIVATE)?],
                    and![Cond::new(1, ArgLen::DWORD, Eq, super::FUTEX_WAKE_PRIVATE)?],
                    and![Cond::new(
                        1,
                        ArgLen::DWORD,
                        Eq,
                        super::FUTEX_REQUEUE_PRIVATE
                    )?],
                    #[cfg(target_env = "gnu")]
                    and![Cond::new(
                        1,
                        ArgLen::DWORD,
                        Eq,
                        super::FUTEX_CMP_REQUEUE_PRIVATE
                    )?],
                ],
            ),
            #[cfg(target_env = "gnu")]
            allow_syscall(libc::SYS_getpid),
            allow_syscall(libc::SYS_getrandom),
            allow_syscall_if(libc::SYS_ioctl, super::create_ioctl_seccomp_rule()?),
            allow_syscall(libc::SYS_lseek),
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
            allow_syscall(libc::SYS_mmap),
            allow_syscall(libc::SYS_mremap),
            allow_syscall(libc::SYS_munmap),
            #[cfg(target_arch = "aarch64")]
            allow_syscall(libc::SYS_newfstatat),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_open),
            allow_syscall(libc::SYS_openat),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_pipe),
            allow_syscall(libc::SYS_read),
            allow_syscall(libc::SYS_readv),
            allow_syscall(libc::SYS_recvfrom),
            // SYS_rt_sigreturn is needed in case a fault does occur, so that the signal handler
            // can return. Otherwise we get stuck in a fault loop.
            allow_syscall(libc::SYS_rt_sigreturn),
            allow_syscall(libc::SYS_sigaltstack),
            allow_syscall_if(
                libc::SYS_socket,
                or![and![Cond::new(0, ArgLen::DWORD, Eq, libc::AF_UNIX as u64)?],],
            ),
            #[cfg(target_arch = "x86_64")]
            allow_syscall(libc::SYS_stat),
            allow_syscall_if(
                libc::SYS_tkill,
                or![and![Cond::new(
                    1,
                    ArgLen::DWORD,
                    Eq,
                    (sigrtmin() + super::super::vstate::VCPU_RTSIG_OFFSET) as u64
                )?]],
            ),
            #[cfg(target_env = "gnu")]
            allow_syscall(libc::SYS_tgkill),
            allow_syscall(libc::SYS_timerfd_create),
            allow_syscall(libc::SYS_timerfd_settime),
            allow_syscall(libc::SYS_write),
            allow_syscall(libc::SYS_writev),
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
