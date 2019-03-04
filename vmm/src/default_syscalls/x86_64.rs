// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use seccomp::{
    allow_syscall, allow_syscall_if, setup_seccomp, Error, SeccompAction, SeccompCmpOp::*,
    SeccompCondition as Cond, SeccompFilterContext, SeccompRule, SECCOMP_LEVEL_ADVANCED,
    SECCOMP_LEVEL_BASIC, SECCOMP_LEVEL_NONE,
};

// See include/uapi/linux/eventpoll.h in the kernel code.
const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;

// See include/uapi/asm-generic/fcntl.h in the kernel code.
const FCNTL_FD_CLOEXEC: u64 = 1;
const FCNTL_F_SETFD: u64 = 2;

// See include/uapi/linux/futex.h in the kernel code.
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_REQUEUE: u64 = 3;
const FUTEX_PRIVATE_FLAG: u64 = 128;
const FUTEX_WAIT_PRIVATE: u64 = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
const FUTEX_WAKE_PRIVATE: u64 = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;
const FUTEX_REQUEUE_PRIVATE: u64 = FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG;

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
const KVM_GET_DIRTY_LOG: u64 = 0x4010_ae42;
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

#[cfg(feature = "vsock")]
mod vsock_ioctls {
    pub const VHOST_GET_FEATURES: u64 = 0x8008_af00;
    pub const VHOST_SET_FEATURES: u64 = 0x4008_af00;
    pub const VHOST_SET_OWNER: u64 = 0x0000_af01;
    pub const VHOST_SET_MEM_TABLE: u64 = 0x4008_af03;
    pub const VHOST_SET_VRING_NUM: u64 = 0x4008_af10;
    pub const VHOST_SET_VRING_ADDR: u64 = 0x4028_af11;
    pub const VHOST_SET_VRING_BASE: u64 = 0x4008_af12;
    pub const VHOST_GET_VRING_BASE: u64 = 0xc008_af12;
    pub const VHOST_SET_VRING_KICK: u64 = 0x4008_af20;
    pub const VHOST_SET_VRING_CALL: u64 = 0x4008_af21;
    pub const VHOST_VSOCK_SET_GUEST_CID: u64 = 0x4008_af60;
    pub const VHOST_VSOCK_SET_RUNNING: u64 = 0x4004_af61;
}

/// Shorthand for chaining `SeccompCondition`s with the `and` operator  in a `SeccompRule`.
/// The rule will take the `Allow` action if _all_ the conditions are true.
///
/// [`Allow`]: enum.SeccompAction.html
/// [`SeccompCondition`]: struct.SeccompCondition.html
/// [`SeccompRule`]: struct.SeccompRule.html
///
macro_rules! and {
    ($($x:expr,)*) => (SeccompRule::new(vec![$($x),*], SeccompAction::Allow));
    ($($x:expr),*) => (SeccompRule::new(vec![$($x),*], SeccompAction::Allow))
}

/// Shorthand for chaining `SeccompRule`s with the `or` operator in a `SeccompFilterContext`.
///
/// [`SeccompFilterContext`]: struct.SeccompFilterContext.html
/// [`SeccompRule`]: struct.SeccompRule.html
///
macro_rules! or {
    ($($x:expr,)*) => (vec![$($x),*]);
    ($($x:expr),*) => (vec![$($x),*])
}

/// Applies the configured level of seccomp filtering to the current thread.
pub fn set_seccomp_level(seccomp_level: u32) -> Result<(), Error> {
    // Load seccomp filters before executing guest code.
    // Execution panics if filters cannot be loaded, use --seccomp-level=0 if skipping filters
    // altogether is the desired behaviour.
    match seccomp_level {
        SECCOMP_LEVEL_ADVANCED => setup_seccomp(default_context()?),
        SECCOMP_LEVEL_BASIC => setup_seccomp(default_context()?.allow_all()),
        SECCOMP_LEVEL_NONE | _ => Ok(()),
    }
}

// The position of the flags parameter for open/openat.
#[cfg(target_env = "musl")]
const OPEN_FLAGS_POS: u8 = 1;
#[cfg(target_env = "gnu")]
const OPEN_FLAGS_POS: u8 = 2;

/// The default context containing the white listed syscall rules required by `Firecracker` to
/// function.
pub fn default_context() -> Result<SeccompFilterContext, Error> {
    Ok(SeccompFilterContext::new(
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
                    and![Cond::new(1, Eq, EPOLL_CTL_ADD)?],
                    and![Cond::new(1, Eq, EPOLL_CTL_DEL)?],
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
                    Cond::new(1, Eq, FCNTL_F_SETFD)?,
                    Cond::new(2, Eq, FCNTL_FD_CLOEXEC)?,
                ]],
            ),
            allow_syscall(libc::SYS_fstat),
            allow_syscall_if(
                libc::SYS_futex,
                or![
                    and![Cond::new(1, Eq, FUTEX_WAIT_PRIVATE)?],
                    and![Cond::new(1, Eq, FUTEX_WAKE_PRIVATE)?],
                    and![Cond::new(1, Eq, FUTEX_REQUEUE_PRIVATE)?],
                ],
            ),
            allow_syscall_if(libc::SYS_ioctl, create_ioctl_seccomp_rule()?),
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
            allow_syscall_if(
                libc::SYS_tkill,
                or![and![Cond::new(
                    1,
                    Eq,
                    sys_util::validate_signal_num(super::super::VCPU_RTSIG_OFFSET, true)
                        .map_err(|_| Error::InvalidArgumentNumber)? as u64,
                )?]],
            ),
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

fn create_common_ioctl_seccomp_rule() -> Result<Vec<SeccompRule>, Error> {
    Ok(or![
        and![Cond::new(1, Eq, TCSETS)?],
        and![Cond::new(1, Eq, TCGETS)?],
        and![Cond::new(1, Eq, TIOCGWINSZ)?],
        and![Cond::new(1, Eq, KVM_CHECK_EXTENSION,)?],
        and![Cond::new(1, Eq, KVM_CREATE_VM)?],
        and![Cond::new(1, Eq, KVM_GET_API_VERSION,)?],
        and![Cond::new(1, Eq, KVM_GET_SUPPORTED_CPUID,)?],
        and![Cond::new(1, Eq, KVM_GET_VCPU_MMAP_SIZE,)?],
        and![Cond::new(1, Eq, KVM_CREATE_IRQCHIP,)?],
        and![Cond::new(1, Eq, KVM_CREATE_PIT2)?],
        and![Cond::new(1, Eq, KVM_CREATE_VCPU)?],
        and![Cond::new(1, Eq, KVM_GET_DIRTY_LOG,)?],
        and![Cond::new(1, Eq, KVM_IOEVENTFD)?],
        and![Cond::new(1, Eq, KVM_IRQFD)?],
        and![Cond::new(1, Eq, KVM_SET_TSS_ADDR,)?],
        and![Cond::new(1, Eq, KVM_SET_USER_MEMORY_REGION,)?],
        and![Cond::new(1, Eq, FIOCLEX)?],
        and![Cond::new(1, Eq, FIONBIO)?],
        and![Cond::new(1, Eq, TUNSETIFF)?],
        and![Cond::new(1, Eq, TUNSETOFFLOAD)?],
        and![Cond::new(1, Eq, TUNSETVNETHDRSZ)?],
        and![Cond::new(1, Eq, KVM_GET_LAPIC)?],
        and![Cond::new(1, Eq, KVM_GET_SREGS)?],
        and![Cond::new(1, Eq, KVM_RUN)?],
        and![Cond::new(1, Eq, KVM_SET_CPUID2)?],
        and![Cond::new(1, Eq, KVM_SET_FPU)?],
        and![Cond::new(1, Eq, KVM_SET_LAPIC)?],
        and![Cond::new(1, Eq, KVM_SET_MSRS)?],
        and![Cond::new(1, Eq, KVM_SET_REGS)?],
        and![Cond::new(1, Eq, KVM_SET_SREGS)?],
    ])
}

#[cfg(feature = "vsock")]
fn create_vsock_ioctl_seccomp_rule() -> Result<Vec<SeccompRule>, Error> {
    Ok(or![
        and![Cond::new(1, Eq, vsock_ioctls::VHOST_GET_FEATURES,)?],
        and![Cond::new(1, Eq, vsock_ioctls::VHOST_SET_FEATURES,)?],
        and![Cond::new(1, Eq, vsock_ioctls::VHOST_SET_OWNER,)?],
        and![Cond::new(1, Eq, vsock_ioctls::VHOST_SET_MEM_TABLE,)?],
        and![Cond::new(1, Eq, vsock_ioctls::VHOST_SET_VRING_NUM,)?],
        and![Cond::new(1, Eq, vsock_ioctls::VHOST_SET_VRING_ADDR,)?],
        and![Cond::new(1, Eq, vsock_ioctls::VHOST_SET_VRING_BASE,)?],
        and![Cond::new(1, Eq, vsock_ioctls::VHOST_GET_VRING_BASE,)?],
        and![Cond::new(1, Eq, vsock_ioctls::VHOST_SET_VRING_KICK,)?],
        and![Cond::new(1, Eq, vsock_ioctls::VHOST_SET_VRING_CALL,)?],
        and![Cond::new(1, Eq, vsock_ioctls::VHOST_VSOCK_SET_GUEST_CID,)?],
        and![Cond::new(1, Eq, vsock_ioctls::VHOST_VSOCK_SET_RUNNING,)?],
    ])
}

fn create_ioctl_seccomp_rule() -> Result<Vec<SeccompRule>, Error> {
    #[cfg(feature = "vsock")]
    {
        let mut rule = create_common_ioctl_seccomp_rule()?;
        rule.append(&mut create_vsock_ioctl_seccomp_rule()?);
        Ok(rule)
    }
    #[cfg(not(feature = "vsock"))]
    Ok(create_common_ioctl_seccomp_rule()?)
}

#[cfg(test)]
#[cfg(target_env = "musl")]
mod tests {
    extern crate libc;
    extern crate seccomp;

    use super::*;

    const EXTRA_SYSCALLS: [i64; 5] = [
        libc::SYS_clone,
        libc::SYS_mprotect,
        libc::SYS_rt_sigprocmask,
        libc::SYS_set_tid_address,
        libc::SYS_sigaltstack,
    ];

    fn add_syscalls_install_context(mut context: SeccompFilterContext) {
        // Test error case: add empty rule array.
        assert!(context.add_rules(0, vec![],).is_err());
        // Add "Allow" rule for each syscall.
        for syscall in EXTRA_SYSCALLS.iter() {
            assert!(context
                .add_rules(
                    *syscall,
                    vec![SeccompRule::new(vec![], SeccompAction::Allow)],
                )
                .is_ok());
        }
        assert!(seccomp::setup_seccomp(context).is_ok());
    }

    #[test]
    fn test_basic_seccomp() {
        let context = default_context().unwrap().allow_all();
        add_syscalls_install_context(context);
    }

    #[test]
    fn test_advanced_seccomp() {
        let context = default_context().unwrap();
        add_syscalls_install_context(context);
    }
}
