// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::convert::TryInto;

use libc;

use seccomp::{
    allow_syscall, allow_syscall_if, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp::*,
    SeccompCondition, SeccompFilter, SeccompRule, SyscallRuleSet,
};
use utils::signal::sigrtmin;

// Constant values copied from Firecracker.

const FCNTL_FD_CLOEXEC: u64 = 1;
const FCNTL_F_SETFD: u64 = 2;

// See include/uapi/linux/futex.h in the kernel code.
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_REQUEUE: u64 = 3;
#[cfg(target_env = "gnu")]
const FUTEX_CMP_REQUEUE: u64 = 4;
const FUTEX_PRIVATE_FLAG: u64 = 128;
const FUTEX_WAIT_PRIVATE: u64 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_PRIVATE: u64 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;
const FUTEX_REQUEUE_PRIVATE: u64 = FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG;
#[cfg(target_env = "gnu")]
const FUTEX_CMP_REQUEUE_PRIVATE: u64 = FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG;

// See include/uapi/asm-generic/ioctls.h in the kernel code.
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TIOCGWINSZ: u64 = 0x5413;
const FIOCLEX: u64 = 0x5451;
const FIONBIO: u64 = 0x5421;

// See include/uapi/linux/if_tun.h in the kernel code.
const KVM_GET_API_VERSION: u64 = 0xae00;
const KVM_CREATE_VM: u64 = 0xae01;
const KVM_CHECK_EXTENSION: u64 = 0xae03;
const KVM_GET_VCPU_MMAP_SIZE: u64 = 0xae04;
const KVM_CREATE_VCPU: u64 = 0xae41;
const KVM_SET_TSS_ADDR: u64 = 0xae47;
const KVM_CREATE_IRQCHIP: u64 = 0xae60;
const KVM_RUN: u64 = 0xae80;
const KVM_SET_MSRS: u64 = 0x4008_ae89;
const KVM_SET_CPUID2: u64 = 0x4008_ae90;
const KVM_SET_USER_MEMORY_REGION: u64 = 0x4020_ae46;
const KVM_IRQFD: u64 = 0x4020_ae76;
const KVM_CREATE_PIT2: u64 = 0x4040_ae77;
const KVM_IOEVENTFD: u64 = 0x4040_ae79;
const KVM_SET_REGS: u64 = 0x4090_ae82;
const KVM_SET_SREGS: u64 = 0x4138_ae84;
const KVM_SET_FPU: u64 = 0x41a0_ae8d;
const KVM_SET_LAPIC: u64 = 0x4400_ae8f;
const KVM_GET_SREGS: u64 = 0x8138_ae83;
const KVM_GET_LAPIC: u64 = 0x8400_ae8e;
const KVM_GET_SUPPORTED_CPUID: u64 = 0xc008_ae05;

// See include/uapi/linux/if_tun.h in the kernel code.
const TUNSETIFF: u64 = 0x4004_54ca;
const TUNSETOFFLOAD: u64 = 0x4004_54d0;
const TUNSETVNETHDRSZ: u64 = 0x4004_54d8;

// This gets incremented in the signal handler.
pub static mut SIGSYS_RECEIVED: bool = false;

pub struct MockSeccomp {
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    default_action: SeccompAction,
}

// Seccomp rule building macros copied from Firecracker.

macro_rules! and {
    ($($x:expr,)*) => (SeccompRule::new(vec![$($x),*], SeccompAction::Allow));
    ($($x:expr),*) => (SeccompRule::new(vec![$($x),*], SeccompAction::Allow))
}

macro_rules! or {
    ($($x:expr,)*) => (vec![$($x),*]);
    ($($x:expr),*) => (vec![$($x),*])
}

impl MockSeccomp {
    pub fn new() -> Self {
        MockSeccomp {
            // Rules copied from Firecracker.
            rules: vec![
                // Inherited from Firecracker
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
                        SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, FCNTL_F_SETFD)
                            .unwrap(),
                        SeccompCondition::new(2, SeccompCmpArgLen::QWORD, Eq, FCNTL_FD_CLOEXEC)
                            .unwrap(),
                    ]],
                ),
                allow_syscall(libc::SYS_fstat),
                allow_syscall_if(
                    libc::SYS_futex,
                    or![
                        and![SeccompCondition::new(
                            1,
                            SeccompCmpArgLen::DWORD,
                            Eq,
                            FUTEX_WAIT_PRIVATE
                        )
                        .unwrap()],
                        and![SeccompCondition::new(
                            1,
                            SeccompCmpArgLen::DWORD,
                            Eq,
                            FUTEX_WAKE_PRIVATE
                        )
                        .unwrap()],
                        and![SeccompCondition::new(
                            1,
                            SeccompCmpArgLen::DWORD,
                            Eq,
                            FUTEX_REQUEUE_PRIVATE
                        )
                        .unwrap()],
                        #[cfg(target_env = "gnu")]
                        and![SeccompCondition::new(
                            1,
                            SeccompCmpArgLen::DWORD,
                            Eq,
                            FUTEX_CMP_REQUEUE_PRIVATE
                        )
                        .unwrap()],
                    ],
                ),
                allow_syscall(libc::SYS_getrandom),
                Self::ioctl_rule(),
                allow_syscall(libc::SYS_lseek),
                #[cfg(target_env = "musl")]
                allow_syscall_if(
                    libc::SYS_madvise,
                    or![and![SeccompCondition::new(
                        2,
                        SeccompCmpArgLen::DWORD,
                        Eq,
                        libc::MADV_DONTNEED as u64
                    )
                    .unwrap()],],
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
                    or![and![SeccompCondition::new(
                        0,
                        SeccompCmpArgLen::DWORD,
                        Eq,
                        libc::AF_UNIX as u64
                    )
                    .unwrap()],],
                ),
                #[cfg(target_arch = "x86_64")]
                allow_syscall(libc::SYS_stat),
                allow_syscall_if(
                    libc::SYS_tkill,
                    or![and![SeccompCondition::new(
                        1,
                        SeccompCmpArgLen::DWORD,
                        Eq,
                        sigrtmin() as u64
                    )
                    .unwrap()]],
                ),
                allow_syscall(libc::SYS_timerfd_create),
                allow_syscall(libc::SYS_timerfd_settime),
                allow_syscall(libc::SYS_write),
                allow_syscall(libc::SYS_writev),
            ]
            .into_iter()
            .collect(),
            default_action: SeccompAction::Trap,
        }
    }

    // Full set of ioctls allowed by Firecracker.
    fn ioctl_rule() -> SyscallRuleSet {
        let mut rules = Self::ioctl_rule_without_kvm_run();
        rules.1.append(&mut or![and![SeccompCondition::new(
            1,
            SeccompCmpArgLen::DWORD,
            Eq,
            KVM_RUN
        )
        .unwrap()]]);
        rules
    }

    // Ioctls allowed by Firecracker, except KVM_RUN.
    fn ioctl_rule_without_kvm_run() -> SyscallRuleSet {
        allow_syscall_if(
            libc::SYS_ioctl,
            or![
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, TCSETS).unwrap()],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, TCGETS).unwrap()],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, TIOCGWINSZ).unwrap()],
                and![
                    SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_CHECK_EXTENSION,)
                        .unwrap()
                ],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_CREATE_VM).unwrap()],
                and![
                    SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_GET_API_VERSION,)
                        .unwrap()
                ],
                and![SeccompCondition::new(
                    1,
                    SeccompCmpArgLen::DWORD,
                    Eq,
                    KVM_GET_SUPPORTED_CPUID,
                )
                .unwrap()],
                and![
                    SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_GET_VCPU_MMAP_SIZE,)
                        .unwrap()
                ],
                and![
                    SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_CREATE_IRQCHIP,)
                        .unwrap()
                ],
                and![
                    SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_CREATE_PIT2).unwrap()
                ],
                and![
                    SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_CREATE_VCPU).unwrap()
                ],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_IOEVENTFD).unwrap()],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_IRQFD).unwrap()],
                and![
                    SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_SET_TSS_ADDR,)
                        .unwrap()
                ],
                and![SeccompCondition::new(
                    1,
                    SeccompCmpArgLen::DWORD,
                    Eq,
                    KVM_SET_USER_MEMORY_REGION,
                )
                .unwrap()],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, FIOCLEX).unwrap()],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, FIONBIO).unwrap()],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, TUNSETIFF).unwrap()],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, TUNSETOFFLOAD).unwrap()],
                and![
                    SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, TUNSETVNETHDRSZ).unwrap()
                ],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_GET_LAPIC).unwrap()],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_GET_SREGS).unwrap()],
                and![
                    SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_SET_CPUID2).unwrap()
                ],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_SET_FPU).unwrap()],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_SET_LAPIC).unwrap()],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_SET_MSRS).unwrap()],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_SET_REGS).unwrap()],
                and![SeccompCondition::new(1, SeccompCmpArgLen::DWORD, Eq, KVM_SET_SREGS).unwrap()],
            ],
        )
    }

    // Blacklist KVM_RUN.
    pub fn without_kvm_run(mut self) -> Self {
        self.rules
            .insert(libc::SYS_ioctl, Self::ioctl_rule_without_kvm_run().1);
        self
    }
}

impl Into<BpfProgram> for MockSeccomp {
    fn into(self) -> BpfProgram {
        let flt = SeccompFilter::new(self.rules, self.default_action).unwrap();
        let bpf_prog: BpfProgram = flt.try_into().unwrap();
        bpf_prog
    }
}

pub extern "C" fn mock_sigsys_handler(
    _num: libc::c_int,
    info: *mut libc::siginfo_t,
    _unused: *mut libc::c_void,
) {
    // Safe because we're just reading some fields from a supposedly valid argument.
    let si_signo = unsafe { (*info).si_signo };
    let si_code = unsafe { (*info).si_code };
    if si_signo == libc::SIGSYS && si_code == 1 {
        unsafe {
            SIGSYS_RECEIVED = true;
        }
    }
}
