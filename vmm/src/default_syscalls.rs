// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate libc;
extern crate sys_util;

use seccomp::{
    setup_seccomp, Error, SeccompAction, SeccompCmpOp, SeccompCondition, SeccompFilterContext,
    SeccompLevel, SeccompRule, SECCOMP_LEVEL_ADVANCED, SECCOMP_LEVEL_BASIC, SECCOMP_LEVEL_NONE,
};

/// List of allowed syscalls, necessary for Firecracker to function correctly.
pub const ALLOWED_SYSCALLS: &[i64] = &[
    libc::SYS_accept,
    libc::SYS_clock_gettime,
    libc::SYS_close,
    libc::SYS_dup,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_fstat,
    libc::SYS_futex,
    libc::SYS_ioctl,
    libc::SYS_lseek,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_open,
    libc::SYS_pipe,
    libc::SYS_read,
    libc::SYS_readv,
    libc::SYS_rt_sigreturn,
    libc::SYS_stat,
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_settime,
    libc::SYS_tkill,
    libc::SYS_write,
    libc::SYS_writev,
];

// See /usr/include/x86_64-linux-gnu/sys/epoll.h
const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;

// See /usr/include/x86_64-linux-gnu/bits/fcntl-linux.h
const O_RDONLY: u64 = 0x00000000;
const O_RDWR: u64 = 0x00000002;
const O_NONBLOCK: u64 = 0x00004000;
const O_CLOEXEC: u64 = 0x02000000;

// See /usr/include/linux/futex.h
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_REQUEUE: u64 = 3;
const FUTEX_PRIVATE_FLAG: u64 = 128;
const FUTEX_WAIT_PRIVATE: u64 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_PRIVATE: u64 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;
const FUTEX_REQUEUE_PRIVATE: u64 = FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG;

// See /usr/include/asm-generic/ioctls.h
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TIOCGWINSZ: u64 = 0x5413;
const FIOCLEX: u64 = 0x5451;
const FIONBIO: u64 = 0x5421;

// See /usr/include/linux/kvm.h
const KVM_GET_API_VERSION: u64 = 0xae00;
const KVM_CREATE_VM: u64 = 0xae01;
const KVM_CHECK_EXTENSION: u64 = 0xae03;
const KVM_GET_VCPU_MMAP_SIZE: u64 = 0xae04;
const KVM_CREATE_VCPU: u64 = 0xae41;
const KVM_SET_TSS_ADDR: u64 = 0xae47;
const KVM_CREATE_IRQCHIP: u64 = 0xae60;
const KVM_RUN: u64 = 0xae80;
const KVM_SET_MSRS: u64 = 0x4008ae89;
const KVM_SET_CPUID2: u64 = 0x4008ae90;
const KVM_SET_USER_MEMORY_REGION: u64 = 0x4020ae46;
const KVM_IRQFD: u64 = 0x4020ae76;
const KVM_CREATE_PIT2: u64 = 0x4040ae77;
const KVM_IOEVENTFD: u64 = 0x4040ae79;
const KVM_SET_REGS: u64 = 0x4090ae82;
const KVM_SET_SREGS: u64 = 0x4138ae84;
const KVM_SET_FPU: u64 = 0x41a0ae8d;
const KVM_SET_LAPIC: u64 = 0x4400ae8f;
const KVM_GET_SREGS: u64 = 0x8138ae83;
const KVM_GET_LAPIC: u64 = 0x8400ae8e;
const KVM_GET_SUPPORTED_CPUID: u64 = 0xc008ae05;

// See /usr/include/linux/if_tun.h
const TUNSETIFF: u64 = 0x400454ca;
const TUNSETOFFLOAD: u64 = 0x400454d0;
const TUNSETVNETHDRSZ: u64 = 0x400454d8;

// See /usr/include/asm-generic/mman-common.h and /usr/include/asm-generic/mman.h
const PROT_NONE: u64 = 0x0;
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_NORESERVE: u64 = 0x4000;

/// Applies the configured level of seccomp filtering to the current thread.
pub fn set_seccomp_level(seccomp_level: u32) -> Result<(), Error> {
    // Load seccomp filters before executing guest code.
    // Execution panics if filters cannot be loaded, use --seccomp-level=0 if skipping filters
    // altogether is the desired behaviour.
    match seccomp_level {
        SECCOMP_LEVEL_ADVANCED => setup_seccomp(SeccompLevel::Advanced(default_context()?)),
        SECCOMP_LEVEL_BASIC => setup_seccomp(seccomp::SeccompLevel::Basic(ALLOWED_SYSCALLS)),
        SECCOMP_LEVEL_NONE | _ => Ok(()),
    }
}

/// The default context containing the white listed syscall rules required by `Firecracker` to
/// function.
pub fn default_context() -> Result<SeccompFilterContext, Error> {
    Ok(SeccompFilterContext::new(
        vec![
            (
                libc::SYS_accept,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_clock_gettime,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_close,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_dup,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_epoll_ctl,
                (
                    0,
                    vec![
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, EPOLL_CTL_ADD)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, EPOLL_CTL_DEL)?],
                            SeccompAction::Allow,
                        ),
                    ],
                ),
            ),
            (
                libc::SYS_epoll_pwait,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_exit,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_exit_group,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_fstat,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_futex,
                (
                    0,
                    vec![
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                FUTEX_WAIT_PRIVATE,
                            )?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                FUTEX_WAKE_PRIVATE,
                            )?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                FUTEX_REQUEUE_PRIVATE,
                            )?],
                            SeccompAction::Allow,
                        ),
                    ],
                ),
            ),
            (
                libc::SYS_ioctl,
                (
                    0,
                    vec![
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, TCSETS)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, TCGETS)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, TIOCGWINSZ)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                KVM_CHECK_EXTENSION,
                            )?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_CREATE_VM)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                KVM_GET_API_VERSION,
                            )?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                KVM_GET_SUPPORTED_CPUID,
                            )?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                KVM_GET_VCPU_MMAP_SIZE,
                            )?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                KVM_CREATE_IRQCHIP,
                            )?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_CREATE_PIT2)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_CREATE_VCPU)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_IOEVENTFD)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_IRQFD)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                KVM_SET_TSS_ADDR,
                            )?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                KVM_SET_USER_MEMORY_REGION,
                            )?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, FIOCLEX)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, FIONBIO)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, TUNSETIFF)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, TUNSETOFFLOAD)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, TUNSETVNETHDRSZ)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_GET_LAPIC)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_GET_SREGS)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_RUN)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_SET_CPUID2)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_SET_FPU)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_SET_LAPIC)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_SET_MSRS)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_SET_REGS)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, KVM_SET_SREGS)?],
                            SeccompAction::Allow,
                        ),
                    ],
                ),
            ),
            (
                libc::SYS_lseek,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_mmap,
                (
                    0,
                    vec![
                        SeccompRule::new(vec![], SeccompAction::Allow),
                        SeccompRule::new(
                            vec![
                                SeccompCondition::new(0, SeccompCmpOp::Eq, 0)?,
                                SeccompCondition::new(2, SeccompCmpOp::Eq, PROT_NONE)?,
                                SeccompCondition::new(
                                    3,
                                    SeccompCmpOp::Eq,
                                    MAP_PRIVATE | MAP_ANONYMOUS,
                                )?,
                                SeccompCondition::new(4, SeccompCmpOp::Eq, -1i64 as u64)?,
                                SeccompCondition::new(5, SeccompCmpOp::Eq, 0)?,
                            ],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![
                                SeccompCondition::new(0, SeccompCmpOp::Eq, 0)?,
                                SeccompCondition::new(2, SeccompCmpOp::Eq, PROT_READ)?,
                                SeccompCondition::new(3, SeccompCmpOp::Eq, MAP_SHARED)?,
                                SeccompCondition::new(5, SeccompCmpOp::Eq, 0)?,
                            ],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![
                                SeccompCondition::new(0, SeccompCmpOp::Eq, 0)?,
                                SeccompCondition::new(2, SeccompCmpOp::Eq, PROT_READ | PROT_WRITE)?,
                                SeccompCondition::new(3, SeccompCmpOp::Eq, MAP_SHARED)?,
                                SeccompCondition::new(5, SeccompCmpOp::Eq, 0)?,
                            ],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![
                                SeccompCondition::new(0, SeccompCmpOp::Eq, 0)?,
                                SeccompCondition::new(2, SeccompCmpOp::Eq, PROT_READ | PROT_WRITE)?,
                                SeccompCondition::new(
                                    3,
                                    SeccompCmpOp::Eq,
                                    MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE,
                                )?,
                                SeccompCondition::new(4, SeccompCmpOp::Eq, -1i64 as u64)?,
                                SeccompCondition::new(5, SeccompCmpOp::Eq, 0)?,
                            ],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![
                                SeccompCondition::new(0, SeccompCmpOp::Eq, 0)?,
                                SeccompCondition::new(2, SeccompCmpOp::Eq, PROT_READ | PROT_WRITE)?,
                                SeccompCondition::new(
                                    3,
                                    SeccompCmpOp::Eq,
                                    MAP_PRIVATE | MAP_ANONYMOUS,
                                )?,
                                SeccompCondition::new(4, SeccompCmpOp::Eq, -1i64 as u64)?,
                                SeccompCondition::new(5, SeccompCmpOp::Eq, 0)?,
                            ],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![
                                SeccompCondition::new(0, SeccompCmpOp::Eq, 0)?,
                                SeccompCondition::new(2, SeccompCmpOp::Eq, PROT_READ | PROT_WRITE)?,
                                SeccompCondition::new(
                                    3,
                                    SeccompCmpOp::Eq,
                                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                                )?,
                                SeccompCondition::new(4, SeccompCmpOp::Eq, -1i64 as u64)?,
                                SeccompCondition::new(5, SeccompCmpOp::Eq, 0)?,
                            ],
                            SeccompAction::Allow,
                        ),
                    ],
                ),
            ),
            (
                libc::SYS_munmap,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_open,
                (
                    0,
                    vec![
                        SeccompRule::new(vec![], SeccompAction::Allow),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, O_RDWR)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                O_RDWR | O_CLOEXEC,
                            )?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                O_RDWR | O_NONBLOCK | O_CLOEXEC,
                            )?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(1, SeccompCmpOp::Eq, O_RDONLY)?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                O_RDONLY | O_CLOEXEC,
                            )?],
                            SeccompAction::Allow,
                        ),
                        SeccompRule::new(
                            vec![SeccompCondition::new(
                                1,
                                SeccompCmpOp::Eq,
                                O_RDONLY | O_NONBLOCK | O_CLOEXEC,
                            )?],
                            SeccompAction::Allow,
                        ),
                    ],
                ),
            ),
            (
                libc::SYS_pipe,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_read,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_readv,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            // SYS_rt_sigreturn is needed in case a fault does occur, so that the signal handler
            // can return. Otherwise we get stuck in a fault loop.
            (
                libc::SYS_rt_sigreturn,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_stat,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_tkill,
                (
                    0,
                    vec![SeccompRule::new(
                        vec![SeccompCondition::new(
                            1,
                            SeccompCmpOp::Eq,
                            sys_util::validate_signal_num(super::VCPU_RTSIG_OFFSET, true)
                                .map_err(|_| Error::InvalidArgumentNumber)?
                                as u64,
                        )?],
                        SeccompAction::Allow,
                    )],
                ),
            ),
            (
                libc::SYS_timerfd_create,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_timerfd_settime,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_write,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
            (
                libc::SYS_writev,
                (0, vec![SeccompRule::new(vec![], SeccompAction::Allow)]),
            ),
        ]
        .into_iter()
        .collect(),
        SeccompAction::Trap,
    )?)
}

#[cfg(test)]
#[cfg(target_env = "musl")]
mod tests {
    extern crate libc;
    extern crate seccomp;

    use super::*;

    #[test]
    fn test_basic_seccomp() {
        let mut rules = ALLOWED_SYSCALLS.to_vec();
        rules.extend(vec![
            libc::SYS_clone,
            libc::SYS_mprotect,
            libc::SYS_rt_sigprocmask,
            libc::SYS_set_tid_address,
            libc::SYS_sigaltstack,
        ]);
        assert!(seccomp::setup_seccomp(seccomp::SeccompLevel::Basic(&rules)).is_ok());
    }

    #[test]
    fn test_advanced_seccomp() {
        // Sets up context with additional rules required by the test.
        let mut context = default_context().unwrap();
        for rule in vec![
            libc::SYS_clone,
            libc::SYS_mprotect,
            libc::SYS_rt_sigprocmask,
            libc::SYS_set_tid_address,
            libc::SYS_sigaltstack,
        ] {
            assert!(context
                .add_rules(
                    rule,
                    None,
                    vec![seccomp::SeccompRule::new(
                        vec![],
                        seccomp::SeccompAction::Allow,
                    )],
                )
                .is_ok());
        }
        assert!(seccomp::setup_seccomp(seccomp::SeccompLevel::Advanced(context)).is_ok());
    }
}
