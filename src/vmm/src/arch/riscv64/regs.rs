// Copyright © 2025 Computing Systems Laboratory (CSLab), ECE, NTUA. All rights reserved.
//
// Copyright © 2024 Institute of Software, CAS. All rights reserved.
//
// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Storage for riscv64 registers with different sizes.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Riscv64RegisterVec {
    ids: Vec<u64>,
    data: Vec<u8>,
}

impl Serialize for Riscv64RegisterVec {
    fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        unimplemented!();
    }
}

impl<'de> Deserialize<'de> for Riscv64RegisterVec {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        unimplemented!();
    }
}

// #[repr(C)]
// #[derive(Debug, Default, Copy, Clone, PartialEq)]
// pub struct kvm_riscv_config {
//     pub isa: u64,
//     pub zicbom_block_size: u64,
//     pub mvendorid: u64,
//     pub marchid: u64,
//     pub mimpid: u64,
//     pub zicboz_block_size: u64,
//     pub satp_mode: u64,
// }

// Helper macro from Cloud Hypervisor.
/// Get the ID of a register.
#[macro_export]
macro_rules! riscv64_reg_id {
    ($reg_type: tt, $offset: tt) => {
        // The core registers of an riscv64 machine are represented
        // in kernel by the `kvm_riscv_core` structure:
        //
        // struct kvm_riscv_core {
        //     struct user_regs_struct regs;
        //     unsigned long mode;
        // };
        //
        // struct user_regs_struct {
        //     unsigned long pc;
        //     unsigned long ra;
        //     unsigned long sp;
        //     unsigned long gp;
        //     unsigned long tp;
        //     unsigned long t0;
        //     unsigned long t1;
        //     unsigned long t2;
        //     unsigned long s0;
        //     unsigned long s1;
        //     unsigned long a0;
        //     unsigned long a1;
        //     unsigned long a2;
        //     unsigned long a3;
        //     unsigned long a4;
        //     unsigned long a5;
        //     unsigned long a6;
        //     unsigned long a7;
        //     unsigned long s2;
        //     unsigned long s3;
        //     unsigned long s4;
        //     unsigned long s5;
        //     unsigned long s6;
        //     unsigned long s7;
        //     unsigned long s8;
        //     unsigned long s9;
        //     unsigned long s10;
        //     unsigned long s11;
        //     unsigned long t3;
        //     unsigned long t4;
        //     unsigned long t5;
        //     unsigned long t6;
        // };
        // The id of a core register can be obtained like this: offset = id &
        // ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_RISCV_CORE). Thus,
        // id = KVM_REG_RISCV | KVM_REG_SIZE_U64 | KVM_REG_RISCV_CORE | offset
        //
        // To generalize, the id of a register can be obtained by:
        // id = KVM_REG_RISCV | KVM_REG_SIZE_U64 |
        //      KVM_REG_RISCV_CORE/KVM_REG_RISCV_CONFIG/KVM_REG_RISCV_TIMER |
        //      offset
        KVM_REG_RISCV as u64
            | u64::from($reg_type)
            | u64::from(KVM_REG_SIZE_U64)
            | ($offset as u64 / std::mem::size_of::<u64>() as u64)
    };
}
pub(crate) use riscv64_reg_id;

/// Return the ID of an ISA register.
#[macro_export]
macro_rules! riscv64_isa_id {
    ($reg_type: tt, $id: tt) => {
        KVM_REG_RISCV as u64 | u64::from($reg_type) | KVM_REG_SIZE_U64 as u64 | u64::from($id)
    };
}
pub(crate) use riscv64_isa_id;

/// Return the ID of a core register.
#[macro_export]
macro_rules! riscv64_reg_core_id {
    ($offset: tt) => {
        riscv64_reg_id!(KVM_REG_RISCV_CORE, $offset)
    };
}
pub(crate) use riscv64_reg_core_id;

/// Return the ID of a config register.
#[macro_export]
macro_rules! riscv64_reg_config_id {
    ($offset: tt) => {
        riscv64_reg_id!(KVM_REG_RISCV_CONFIG, $offset)
    };
}
pub(crate) use riscv64_reg_config_id;

/// Return the ID of timer register.
#[macro_export]
macro_rules! riscv64_reg_timer_id {
    ($offset: tt) => {
        riscv64_reg_id!(KVM_REG_RISCV_TIMER, $offset)
    };
}

/// Return the ID of an ISA extension.
#[macro_export]
macro_rules! riscv64_reg_isa_ext {
    ($ext_id: tt) => {
        riscv64_isa_id!(KVM_REG_RISCV_ISA_EXT, $ext_id)
    };
}
pub(crate) use riscv64_reg_isa_ext;
