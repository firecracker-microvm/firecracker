// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate seccomp;

use std::env::args;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

fn main() {
    let args: Vec<String> = args().collect();
    let exec_file = &args[1];

    seccomp::setup_seccomp(seccomp::SeccompLevel::Basic(&[
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_open,
        libc::SYS_close,
        libc::SYS_stat,
        libc::SYS_fstat,
        libc::SYS_lseek,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_ioctl,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pipe,
        libc::SYS_dup,
        libc::SYS_socket,
        libc::SYS_accept,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_clone,
        libc::SYS_execve,
        libc::SYS_exit,
        libc::SYS_fcntl,
        libc::SYS_readlink,
        libc::SYS_sigaltstack,
        libc::SYS_prctl,
        libc::SYS_arch_prctl,
        libc::SYS_futex,
        libc::SYS_sched_getaffinity,
        libc::SYS_set_tid_address,
        libc::SYS_exit_group,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_timerfd_create,
        libc::SYS_eventfd2,
        libc::SYS_epoll_create1,
        libc::SYS_getrandom,
    ])).unwrap();

    Command::new(exec_file)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .exec();
}
