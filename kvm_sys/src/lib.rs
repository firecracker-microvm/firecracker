// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[macro_use]
extern crate sys_util;

// Somehow this one gets missed by bindgen
pub const KVM_EXIT_IO_OUT: ::std::os::raw::c_uint = 1;

// Each of the below modules defines ioctls specific to their platform.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86 {
    // generated with bindgen /usr/include/linux/kvm.h --no-unstable-rust --constified-enum '*' --with-derive-default
    pub mod bindings;
    pub use bindings::*;

    ioctl_iowr_nr!(KVM_GET_MSR_INDEX_LIST, KVMIO, 0x02, kvm_msr_list);
    ioctl_iowr_nr!(KVM_GET_SUPPORTED_CPUID, KVMIO, 0x05, kvm_cpuid2);
    ioctl_iowr_nr!(KVM_GET_EMULATED_CPUID, KVMIO, 0x09, kvm_cpuid2);
    ioctl_iow_nr!(KVM_SET_MEMORY_ALIAS, KVMIO, 0x43, kvm_memory_alias);
    ioctl_iow_nr!(KVM_XEN_HVM_CONFIG, KVMIO, 0x7a, kvm_xen_hvm_config);
    ioctl_ior_nr!(KVM_GET_PIT2, KVMIO, 0x9f, kvm_pit_state2);
    ioctl_iow_nr!(KVM_SET_PIT2, KVMIO, 0xa0, kvm_pit_state2);
    ioctl_iowr_nr!(KVM_GET_MSRS, KVMIO, 0x88, kvm_msrs);
    ioctl_iow_nr!(KVM_SET_MSRS, KVMIO, 0x89, kvm_msrs);
    ioctl_iow_nr!(KVM_SET_CPUID, KVMIO, 0x8a, kvm_cpuid);
    ioctl_ior_nr!(KVM_GET_LAPIC, KVMIO, 0x8e, kvm_lapic_state);
    ioctl_iow_nr!(KVM_SET_LAPIC, KVMIO, 0x8f, kvm_lapic_state);
    ioctl_iow_nr!(KVM_SET_CPUID2, KVMIO, 0x90, kvm_cpuid2);
    ioctl_iowr_nr!(KVM_GET_CPUID2, KVMIO, 0x91, kvm_cpuid2);
    ioctl_iow_nr!(KVM_X86_SETUP_MCE, KVMIO, 0x9c, __u64);
    ioctl_ior_nr!(KVM_X86_GET_MCE_CAP_SUPPORTED, KVMIO, 0x9d, __u64);
    ioctl_iow_nr!(KVM_X86_SET_MCE, KVMIO, 0x9e, kvm_x86_mce);
    ioctl_ior_nr!(KVM_GET_VCPU_EVENTS, KVMIO, 0x9f, kvm_vcpu_events);
    ioctl_iow_nr!(KVM_SET_VCPU_EVENTS, KVMIO, 0xa0, kvm_vcpu_events);
    ioctl_ior_nr!(KVM_GET_DEBUGREGS, KVMIO, 0xa1, kvm_debugregs);
    ioctl_iow_nr!(KVM_SET_DEBUGREGS, KVMIO, 0xa2, kvm_debugregs);
    ioctl_ior_nr!(KVM_GET_XSAVE, KVMIO, 0xa4, kvm_xsave);
    ioctl_iow_nr!(KVM_SET_XSAVE, KVMIO, 0xa5, kvm_xsave);
    ioctl_ior_nr!(KVM_GET_XCRS, KVMIO, 0xa6, kvm_xcrs);
    ioctl_iowr_nr!(KVM_SET_XCRS, KVMIO, 0xa7, kvm_xcrs);
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub mod arm {
    // generated with bindgen <arm sysroot>/usr/include/linux/kvm.h --no-unstable-rust --constified-enum '*' --with-derive-default -- -I<arm sysroot>/usr/include
    pub mod bindings;
    pub use bindings::*;

    ioctl_iow_nr!(KVM_ARM_SET_DEVICE_ADDR, KVMIO, 0xab, kvm_arm_device_addr);
    ioctl_iow_nr!(KVM_ARM_VCPU_INIT, KVMIO, 0xae, kvm_vcpu_init);
    ioctl_ior_nr!(KVM_ARM_PREFERRED_TARGET, KVMIO, 0xaf, kvm_vcpu_init);
}

// These ioctls are commonly defined on all/multiple platforms.
ioctl_io_nr!(KVM_GET_API_VERSION, KVMIO, 0x00);
ioctl_io_nr!(KVM_CREATE_VM, KVMIO, 0x01);
ioctl_io_nr!(KVM_CHECK_EXTENSION, KVMIO, 0x03);
ioctl_io_nr!(KVM_GET_VCPU_MMAP_SIZE, KVMIO, 0x04) /* in bytes */;
ioctl_iow_nr!(KVM_SET_MEMORY_REGION, KVMIO, 0x40, kvm_memory_region);
ioctl_io_nr!(KVM_CREATE_VCPU, KVMIO, 0x41);
ioctl_iow_nr!(KVM_GET_DIRTY_LOG, KVMIO, 0x42, kvm_dirty_log);
ioctl_io_nr!(KVM_SET_NR_MMU_PAGES, KVMIO, 0x44);
ioctl_io_nr!(KVM_GET_NR_MMU_PAGES, KVMIO, 0x45);
ioctl_iow_nr!(KVM_SET_USER_MEMORY_REGION,KVMIO, 0x46, kvm_userspace_memory_region);
ioctl_io_nr!(KVM_SET_TSS_ADDR, KVMIO, 0x47);
ioctl_iow_nr!(KVM_SET_IDENTITY_MAP_ADDR, KVMIO, 0x48, __u64);
ioctl_io_nr!(KVM_CREATE_IRQCHIP, KVMIO, 0x60);
ioctl_iow_nr!(KVM_IRQ_LINE, KVMIO, 0x61, kvm_irq_level);
ioctl_iowr_nr!(KVM_GET_IRQCHIP, KVMIO, 0x62, kvm_irqchip);
ioctl_ior_nr!(KVM_SET_IRQCHIP, KVMIO, 0x63, kvm_irqchip);
ioctl_io_nr!(KVM_CREATE_PIT, KVMIO, 0x64);
ioctl_iowr_nr!(KVM_IRQ_LINE_STATUS, KVMIO, 0x67, kvm_irq_level);
ioctl_iow_nr!(KVM_REGISTER_COALESCED_MMIO, KVMIO, 0x67, kvm_coalesced_mmio_zone);
ioctl_iow_nr!(KVM_UNREGISTER_COALESCED_MMIO, KVMIO, 0x68, kvm_coalesced_mmio_zone);
ioctl_ior_nr!(KVM_ASSIGN_PCI_DEVICE, KVMIO, 0x69,  kvm_assigned_pci_dev);
ioctl_iow_nr!(KVM_ASSIGN_DEV_IRQ, KVMIO, 0x70, kvm_assigned_irq);
ioctl_io_nr!(KVM_REINJECT_CONTROL, KVMIO, 0x71);
ioctl_iow_nr!(KVM_DEASSIGN_PCI_DEVICE, KVMIO, 0x72,  kvm_assigned_pci_dev);
ioctl_iow_nr!(KVM_ASSIGN_SET_MSIX_NR, KVMIO, 0x73,  kvm_assigned_msix_nr);
ioctl_iow_nr!(KVM_ASSIGN_SET_MSIX_ENTRY, KVMIO, 0x74,  kvm_assigned_msix_entry);
ioctl_iow_nr!(KVM_DEASSIGN_DEV_IRQ, KVMIO, 0x75, kvm_assigned_irq);
ioctl_iow_nr!(KVM_IRQFD, KVMIO, 0x76, kvm_irqfd);
ioctl_iow_nr!(KVM_CREATE_PIT2, KVMIO, 0x77, kvm_pit_config);
ioctl_io_nr!(KVM_SET_BOOT_CPU_ID, KVMIO, 0x78);
ioctl_iow_nr!(KVM_IOEVENTFD, KVMIO, 0x79, kvm_ioeventfd);
ioctl_iow_nr!(KVM_SET_CLOCK, KVMIO, 0x7b, kvm_clock_data);
ioctl_ior_nr!(KVM_GET_CLOCK, KVMIO, 0x7c, kvm_clock_data);
ioctl_io_nr!(KVM_SET_TSC_KHZ, KVMIO, 0xa2);
ioctl_io_nr!(KVM_GET_TSC_KHZ, KVMIO, 0xa3);
ioctl_iow_nr!(KVM_ASSIGN_SET_INTX_MASK, KVMIO, 0xa4,  kvm_assigned_pci_dev);
ioctl_iow_nr!(KVM_SIGNAL_MSI, KVMIO, 0xa5, kvm_msi);
ioctl_iowr_nr!(KVM_CREATE_DEVICE, KVMIO, 0xe0, kvm_create_device);
ioctl_iow_nr!(KVM_SET_DEVICE_ATTR, KVMIO, 0xe1, kvm_device_attr);
ioctl_iow_nr!(KVM_GET_DEVICE_ATTR, KVMIO, 0xe2, kvm_device_attr);
ioctl_iow_nr!(KVM_HAS_DEVICE_ATTR, KVMIO, 0xe3, kvm_device_attr);
ioctl_io_nr!(KVM_RUN, KVMIO, 0x80);
// The following two ioctls are commonly defined but specifically excluded
// from arm platforms.
#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
ioctl_ior_nr!(KVM_GET_REGS, KVMIO, 0x81, kvm_regs);
#[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
ioctl_iow_nr!(KVM_SET_REGS, KVMIO, 0x82, kvm_regs);
ioctl_ior_nr!(KVM_GET_SREGS, KVMIO, 0x83, kvm_sregs);
ioctl_iow_nr!(KVM_SET_SREGS, KVMIO, 0x84, kvm_sregs);
ioctl_iowr_nr!(KVM_TRANSLATE, KVMIO, 0x85, kvm_translation);
ioctl_iow_nr!(KVM_INTERRUPT, KVMIO, 0x86, kvm_interrupt);
ioctl_iow_nr!(KVM_SET_SIGNAL_MASK, KVMIO, 0x8b, kvm_signal_mask);
ioctl_ior_nr!(KVM_GET_FPU, KVMIO, 0x8c, kvm_fpu);
ioctl_iow_nr!(KVM_SET_FPU, KVMIO, 0x8d, kvm_fpu);
ioctl_iowr_nr!(KVM_TPR_ACCESS_REPORTING, KVMIO, 0x92, kvm_tpr_access_ctl);
ioctl_iow_nr!(KVM_SET_VAPIC_ADDR, KVMIO, 0x93, kvm_vapic_addr);
ioctl_ior_nr!(KVM_GET_MP_STATE, KVMIO, 0x98, kvm_mp_state);
ioctl_iow_nr!(KVM_SET_MP_STATE, KVMIO, 0x99, kvm_mp_state);
ioctl_io_nr!(KVM_NMI, KVMIO, 0x9a);
ioctl_iow_nr!(KVM_SET_GUEST_DEBUG, KVMIO, 0x9b, kvm_guest_debug);
ioctl_iow_nr!(KVM_ENABLE_CAP, KVMIO, 0xa3, kvm_enable_cap);
ioctl_iow_nr!(KVM_DIRTY_TLB, KVMIO, 0xaa, kvm_dirty_tlb);
ioctl_iow_nr!(KVM_GET_ONE_REG, KVMIO, 0xab, kvm_one_reg);
ioctl_iow_nr!(KVM_SET_ONE_REG, KVMIO, 0xac, kvm_one_reg);
ioctl_io_nr!(KVM_KVMCLOCK_CTRL, KVMIO, 0xad);
ioctl_iowr_nr!(KVM_GET_REG_LIST, KVMIO, 0xb0, kvm_reg_list);
ioctl_io_nr!(KVM_SMI, KVMIO, 0xb7);

// Along with the common ioctls, we reexport the ioctls of the current
// platform.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use x86::*;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use arm::*;
