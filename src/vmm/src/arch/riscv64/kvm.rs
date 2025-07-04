// Copyright © 2025 Computing Systems Laboratory (CSLab), ECE, NTUA. All rights reserved.
//
// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;

use kvm_ioctls::Kvm as KvmFd;

use crate::cpu_config::templates::KvmCapability;

/// ['Kvm'] initialization can't fail for Riscv64
pub type KvmArchError = Infallible;

/// Struct with kvm fd and kvm associated parameters.
#[derive(Debug)]
pub struct Kvm {
    /// KVM fd.
    pub fd: KvmFd,
    /// Additional capabilities that were specified in cpu template.
    pub kvm_cap_modifiers: Vec<KvmCapability>,
}

impl Kvm {
    pub(crate) const DEFAULT_CAPABILITIES: [u32; 5] = [
        kvm_bindings::KVM_CAP_IOEVENTFD,
        kvm_bindings::KVM_CAP_USER_MEMORY,
        kvm_bindings::KVM_CAP_DEVICE_CTRL,
        kvm_bindings::KVM_CAP_MP_STATE,
        kvm_bindings::KVM_CAP_ONE_REG,
    ];

    /// Initialize [`Kvm`] type for riscv64 architecture.
    pub fn init_arch(
        fd: KvmFd,
        kvm_cap_modifiers: Vec<KvmCapability>,
    ) -> Result<Self, KvmArchError> {
        Ok(Self {
            fd,
            kvm_cap_modifiers,
        })
    }
}
