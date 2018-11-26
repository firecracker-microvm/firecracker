// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[macro_use]
extern crate sys_util;

// Each of the below modules defines ioctls specific to their platform (currently, x86 and x86_64).

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86 {
    // generated with:
    // bindgen include/uapi/linux/kvm.h -o bindings.rs
    //        --no-rustfmt-bindings
    //        --with-derive-default
    //        -- -Iinclude -Iarch/x86/include/
    pub mod bindings;
    pub use bindings::*;

    ioctl_iowr_nr!(KVM_GET_SUPPORTED_CPUID, KVMIO, 0x05, kvm_cpuid2);
    ioctl_iowr_nr!(KVM_GET_MSRS, KVMIO, 0x88, kvm_msrs);
    ioctl_iow_nr!(KVM_SET_MSRS, KVMIO, 0x89, kvm_msrs);
    ioctl_ior_nr!(KVM_GET_LAPIC, KVMIO, 0x8e, kvm_lapic_state);
    ioctl_iow_nr!(KVM_SET_LAPIC, KVMIO, 0x8f, kvm_lapic_state);
    ioctl_iow_nr!(KVM_SET_CPUID2, KVMIO, 0x90, kvm_cpuid2);
    // we do use KVM_SET_CPUID2, however KVM_GET_CPUID2 is never used
    // should be used to unit test the SET!!!
    ioctl_iowr_nr!(KVM_GET_CPUID2, KVMIO, 0x91, kvm_cpuid2);
}

// These ioctls are commonly defined on all/multiple platforms.
ioctl_io_nr!(KVM_GET_API_VERSION, KVMIO, 0x00);
ioctl_io_nr!(KVM_CREATE_VM, KVMIO, 0x01);
ioctl_io_nr!(KVM_CHECK_EXTENSION, KVMIO, 0x03);
ioctl_io_nr!(KVM_GET_VCPU_MMAP_SIZE, KVMIO, 0x04);
ioctl_io_nr!(KVM_CREATE_VCPU, KVMIO, 0x41);
ioctl_iow_nr!(KVM_GET_DIRTY_LOG, KVMIO, 0x42, kvm_dirty_log);
ioctl_iow_nr!(
    KVM_SET_USER_MEMORY_REGION,
    KVMIO,
    0x46,
    kvm_userspace_memory_region
);
ioctl_io_nr!(KVM_SET_TSS_ADDR, KVMIO, 0x47);
ioctl_io_nr!(KVM_CREATE_IRQCHIP, KVMIO, 0x60);
ioctl_iow_nr!(KVM_IRQFD, KVMIO, 0x76, kvm_irqfd);
ioctl_iow_nr!(KVM_CREATE_PIT2, KVMIO, 0x77, kvm_pit_config);
ioctl_iow_nr!(KVM_IOEVENTFD, KVMIO, 0x79, kvm_ioeventfd);
ioctl_io_nr!(KVM_RUN, KVMIO, 0x80);
ioctl_ior_nr!(KVM_GET_REGS, KVMIO, 0x81, kvm_regs);
ioctl_iow_nr!(KVM_SET_REGS, KVMIO, 0x82, kvm_regs);
ioctl_ior_nr!(KVM_GET_SREGS, KVMIO, 0x83, kvm_sregs);
ioctl_iow_nr!(KVM_SET_SREGS, KVMIO, 0x84, kvm_sregs);
ioctl_ior_nr!(KVM_GET_FPU, KVMIO, 0x8c, kvm_fpu);
ioctl_iow_nr!(KVM_SET_FPU, KVMIO, 0x8d, kvm_fpu);

// Along with the common ioctls, we reexport the ioctls of the current
// platform.
pub use x86::*;
