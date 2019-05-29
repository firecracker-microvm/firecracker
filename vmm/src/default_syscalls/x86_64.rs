// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use seccomp::{
    allow_syscall, allow_syscall_if, Error, SeccompAction, SeccompCmpOp::Eq,
    SeccompCondition as Cond, SeccompFilter, SeccompRule,
};

/// The default filter containing the white listed syscall rules required by `Firecracker` to
/// function.
///
pub fn default_filter() -> Result<SeccompFilter, Error> {
    Ok(SeccompFilter::new(
        vec![
            #[cfg(target_env = "musl")]
            allow_syscall(libc::SYS_accept),
            #[cfg(target_env = "gnu")]
            allow_syscall(libc::SYS_accept4),
            allow_syscall(libc::SYS_brk),
            allow_syscall(libc::SYS_clock_gettime),
            allow_syscall(libc::SYS_close),
            allow_syscall(libc::SYS_dup),
            allow_syscall_if(
                libc::SYS_epoll_ctl,
                or![
                    and![Cond::new(1, Eq, super::EPOLL_CTL_ADD)?],
                    and![Cond::new(1, Eq, super::EPOLL_CTL_DEL)?],
                ],
            ),
            #[cfg(target_env = "musl")]
            allow_syscall(libc::SYS_epoll_pwait),
            #[cfg(target_env = "gnu")]
            allow_syscall(libc::SYS_epoll_wait),
            allow_syscall(libc::SYS_exit),
            allow_syscall(libc::SYS_exit_group),
            allow_syscall_if(
                libc::SYS_fcntl,
                or![and![
                    Cond::new(1, Eq, super::FCNTL_F_SETFD)?,
                    Cond::new(2, Eq, super::FCNTL_FD_CLOEXEC)?,
                ]],
            ),
            allow_syscall(libc::SYS_fstat),
            allow_syscall_if(
                libc::SYS_futex,
                or![
                    and![Cond::new(1, Eq, super::FUTEX_WAIT_PRIVATE)?],
                    and![Cond::new(1, Eq, super::FUTEX_WAKE_PRIVATE)?],
                    and![Cond::new(1, Eq, super::FUTEX_REQUEUE_PRIVATE)?],
                ],
            ),
            allow_syscall(libc::SYS_getrandom),
            allow_syscall_if(libc::SYS_ioctl, super::create_ioctl_seccomp_rule()?),
            allow_syscall(libc::SYS_lseek),
            #[cfg(target_env = "musl")]
            allow_syscall_if(
                libc::SYS_madvise,
                or![and![Cond::new(2, Eq, libc::MADV_DONTNEED as u64)?],],
            ),
            allow_syscall(libc::SYS_mmap),
            allow_syscall(libc::SYS_munmap),
            #[cfg(target_env = "musl")]
            allow_syscall(libc::SYS_open),
            #[cfg(target_env = "gnu")]
            allow_syscall(libc::SYS_openat),
            allow_syscall(libc::SYS_pipe),
            allow_syscall(libc::SYS_read),
            allow_syscall(libc::SYS_readv),
            // SYS_rt_sigreturn is needed in case a fault does occur, so that the signal handler
            // can return. Otherwise we get stuck in a fault loop.
            allow_syscall(libc::SYS_rt_sigreturn),
            allow_syscall(libc::SYS_stat),
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
