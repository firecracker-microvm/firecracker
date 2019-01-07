// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use kvm_gen::*;

// Declares necessary ioctls specific to their platform.

ioctl_io_nr!(KVM_GET_API_VERSION, KVMIO, 0x00);
ioctl_io_nr!(KVM_CREATE_VM, KVMIO, 0x01);
ioctl_io_nr!(KVM_CHECK_EXTENSION, KVMIO, 0x03);
ioctl_io_nr!(KVM_GET_VCPU_MMAP_SIZE, KVMIO, 0x04);
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
ioctl_iowr_nr!(KVM_GET_SUPPORTED_CPUID, KVMIO, 0x05, kvm_cpuid2);
ioctl_io_nr!(KVM_CREATE_VCPU, KVMIO, 0x41);
ioctl_iow_nr!(KVM_GET_DIRTY_LOG, KVMIO, 0x42, kvm_dirty_log);
ioctl_iow_nr!(
    KVM_SET_USER_MEMORY_REGION,
    KVMIO,
    0x46,
    kvm_userspace_memory_region
);
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
ioctl_io_nr!(KVM_SET_TSS_ADDR, KVMIO, 0x47);
#[cfg(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "s390"
))]
ioctl_io_nr!(KVM_CREATE_IRQCHIP, KVMIO, 0x60);
#[cfg(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "s390"
))]
ioctl_iow_nr!(KVM_IRQFD, KVMIO, 0x76, kvm_irqfd);
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
ioctl_iow_nr!(KVM_CREATE_PIT2, KVMIO, 0x77, kvm_pit_config);
ioctl_iow_nr!(KVM_IOEVENTFD, KVMIO, 0x79, kvm_ioeventfd);
ioctl_io_nr!(KVM_RUN, KVMIO, 0x80);
#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
ioctl_ior_nr!(KVM_GET_REGS, KVMIO, 0x81, kvm_regs);
#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
ioctl_iow_nr!(KVM_SET_REGS, KVMIO, 0x82, kvm_regs);
#[cfg(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "powerpc",
    target_arch = "powerpc64"
))]
ioctl_ior_nr!(KVM_GET_SREGS, KVMIO, 0x83, kvm_sregs);
#[cfg(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "powerpc",
    target_arch = "powerpc64"
))]
ioctl_iow_nr!(KVM_SET_SREGS, KVMIO, 0x84, kvm_sregs);
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
ioctl_iowr_nr!(KVM_GET_MSRS, KVMIO, 0x88, kvm_msrs);
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
ioctl_iow_nr!(KVM_SET_MSRS, KVMIO, 0x89, kvm_msrs);
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
ioctl_iow_nr!(KVM_SET_CPUID2, KVMIO, 0x90, kvm_cpuid2);
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
ioctl_ior_nr!(KVM_GET_FPU, KVMIO, 0x8c, kvm_fpu);
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
ioctl_iow_nr!(KVM_SET_FPU, KVMIO, 0x8d, kvm_fpu);
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
ioctl_ior_nr!(KVM_GET_LAPIC, KVMIO, 0x8e, kvm_lapic_state);
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
ioctl_iow_nr!(KVM_SET_LAPIC, KVMIO, 0x8f, kvm_lapic_state);

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::io::FromRawFd;

    use libc::{c_char, open, O_RDWR};

    use super::*;
    use sys_util::{ioctl, ioctl_with_val};

    const KVM_PATH: &'static str = "/dev/kvm\0";

    #[test]
    fn get_version() {
        let sys_fd = unsafe { open(KVM_PATH.as_ptr() as *const c_char, O_RDWR) };
        assert!(sys_fd >= 0);

        let ret = unsafe { ioctl(&File::from_raw_fd(sys_fd), KVM_GET_API_VERSION()) };
        assert_eq!(ret as u32, KVM_API_VERSION);
    }

    #[test]
    fn create_vm_fd() {
        let sys_fd = unsafe { open(KVM_PATH.as_ptr() as *const c_char, O_RDWR) };
        assert!(sys_fd >= 0);

        let vm_fd = unsafe { ioctl(&File::from_raw_fd(sys_fd), KVM_CREATE_VM()) };
        assert!(vm_fd >= 0);
    }

    #[test]
    fn check_vm_extension() {
        let sys_fd = unsafe { open(KVM_PATH.as_ptr() as *const c_char, O_RDWR) };
        assert!(sys_fd >= 0);

        let has_user_memory = unsafe {
            ioctl_with_val(
                &File::from_raw_fd(sys_fd),
                KVM_CHECK_EXTENSION(),
                KVM_CAP_USER_MEMORY.into(),
            )
        };
        assert_eq!(has_user_memory, 1);
    }
}
