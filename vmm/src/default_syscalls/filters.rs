// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use seccomp::{
    allow_syscall, allow_syscall_if, Error, SeccompAction, SeccompCmpArgLen as ArgLen,
    SeccompCmpOp::Eq, SeccompCondition as Cond, SeccompFilter, SeccompRule,
};

// Currently these variables are missing from rust libc:
// https://github.com/rust-lang/libc/blob/master/src/unix/notbsd/linux/musl/b64/aarch64.rs
// even though they are defined in musl libc:
// https://git.musl-libc.org/cgit/musl/tree/arch/aarch64/bits/syscall.h.in.
// Submitted issue in rust-lang: https://github.com/rust-lang/libc/issues/1348.
#[allow(non_upper_case_globals)]
#[cfg(target_arch = "aarch64")]
mod libc_patch {
    pub const SYS_fcntl: ::std::os::raw::c_long = 25;
    pub const SYS_lseek: ::std::os::raw::c_long = 62;
    pub const SYS_newfstatat: ::std::os::raw::c_long = 79;
    pub const SYS_fstat: ::std::os::raw::c_long = 80;
    pub const SYS_mmap: ::std::os::raw::c_long = 222;
}

#[cfg(target_arch = "aarch64")]
use self::libc_patch::{SYS_fcntl, SYS_fstat, SYS_lseek, SYS_mmap, SYS_newfstatat};
#[cfg(target_arch = "x86_64")]
use libc::{SYS_fcntl, SYS_fstat, SYS_lseek, SYS_mmap};

/// The default filter containing the white listed syscall rules required by `Firecracker` to
/// function.
///
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
                SYS_fcntl,
                or![and![
                    Cond::new(1, ArgLen::DWORD, Eq, super::FCNTL_F_SETFD)?,
                    Cond::new(2, ArgLen::QWORD, Eq, super::FCNTL_FD_CLOEXEC)?,
                ]],
            ),
            allow_syscall(SYS_fstat),
            #[cfg(target_arch = "aarch64")]
            allow_syscall(SYS_newfstatat),
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
            allow_syscall(libc::SYS_getrandom),
            allow_syscall_if(libc::SYS_ioctl, super::create_ioctl_seccomp_rule()?),
            allow_syscall(SYS_lseek),
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
            allow_syscall(SYS_mmap),
            allow_syscall(libc::SYS_munmap),
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
