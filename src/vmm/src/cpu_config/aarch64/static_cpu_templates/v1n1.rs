// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::arch::aarch64::regs::{
    ID_AA64ISAR0_EL1, ID_AA64ISAR1_EL1, ID_AA64MMFR2_EL1, ID_AA64PFR0_EL1,
};
use crate::cpu_config::aarch64::custom_cpu_template::{CustomCpuTemplate, RegisterModifier};
use crate::cpu_config::templates::RegisterValueFilter;

// Arm Armv8-A Architecture Registers documentation
// https://developer.arm.com/documentation/ddi0595/2021-12/AArch64-Registers?lang=en

/// Template to mask Neoverse-V1 as Neoverse-N1
/// Masks: dgh, asimdfhm, bf16, dcpodp, flagm, i8mm, sha3, sha512, sm3, sm4
/// sve, svebf16, svei8mm, uscat, fcma, jscvt, dit, ilrcpc, rng
pub fn v1n1() -> CustomCpuTemplate {
    CustomCpuTemplate {
        reg_modifiers: vec![
            RegisterModifier {
                // Disabling sve CPU feature. Setting to 0b0000.
                // This disables sve, svebf16, svei8mm
                // sve occupies bits [35:32] in ID_AA64PFR0_EL1.
                //
                // Disabling dit CPU feature. Setting to 0b0000.
                // dit occupies bits [51:48] in ID_AA64PFR0_EL1.
                addr: ID_AA64PFR0_EL1,
                bitmap: RegisterValueFilter {
                    filter: 0x000F000F00000000,
                    value: 0x0000000000000000,
                },
            },
            RegisterModifier {
                // Disabling sha3 CPU feature. Setting sha3 to 0b0000.
                // Disabling sha512 CPU feature. Setting sha2 to 0b0001.
                // sha3 occupies bits [35:32] in ID_AA64ISAR0_EL1.
                // sha2 occupies bits [15:12] in ID_AA64ISAR0_EL1.
                //
                // Note from the documentation:
                //  If the value of SHA2 field is 0b0010,
                //  ID_AA64ISAR0_EL1. SHA3 must have the value 0b0001
                //
                // Disabling sm3 and sm4 CPU features. Setting to 0b0000.
                // sm3 occupies bits [39:36] in ID_AA64ISAR0_EL1.
                // sm4 occupies bits [43:40] in ID_AA64ISAR0_EL1.
                //
                // Note from the documentation:
                //  "This field (sm3) must have the same value as ID_AA64ISAR0_EL1.SM4."
                //
                // Disabling asimdfhm (fhm) CPU feature. Setting to 0b0000.
                // fhm occupies bits [51:48] in ID_AA64ISAR0_EL1.
                //
                // Disabling flagm (ts) CPU feature. Setting to 0b0000.
                // ts occupies bits [55:52] in ID_AA64ISAR0_EL1.
                //
                // Disabling rnd (rndr) CPU feature. Setting to 0b0000.
                // rndr occupies bits [63:60] in ID_AA64ISAR0_EL1.
                addr: ID_AA64ISAR0_EL1,
                bitmap: RegisterValueFilter {
                    filter: 0xF0FF0FFF0000F000,
                    value: 0x0000000000001000,
                },
            },
            RegisterModifier {
                // Disabling dcpodp (dpb) CPU feature. Setting to 0b0001.
                // dpb occupies bits [3:0] in ID_AA64ISAR1_EL1.
                //
                // Disabling jscvt CPU feature. Setting to 0b0000.
                // jscvt occupies bits [15:12] in ID_AA64ISAR1_EL1.
                //
                // Disabling fcma CPU feature. Setting to 0b0000.
                // fcma occupies bits [19:16] in ID_AA64ISAR1_EL1.
                //
                // Disabling ilrcpc CPU feature. Setting to 0b0001.
                // lrcpc occupies bits [23:20] in ID_AA64ISAR1_EL1.
                //
                // Disabling bf16 CPU feature. Setting to 0b0000.
                // bf16 occupies bits [47:44] in ID_AA64ISAR1_EL1.
                //
                // Disabling dgh CPU feature. Setting to 0b0000.
                // dgh occupies bits [51:48] in ID_AA64ISAR1_EL1.
                //
                // Disabling i8mm CPU feature. Setting to 0b0000.
                // i8mm occupies bits [55:52] in ID_AA64ISAR1_EL1.
                addr: ID_AA64ISAR1_EL1,
                bitmap: RegisterValueFilter {
                    filter: 0x00FFF00000FFF00F,
                    value: 0x0000000000100001,
                },
            },
            RegisterModifier {
                // Disable uscat (at) CPU feature. Setting to 0b0000.
                // at occupies bits [35:28] in ID_AA64MMFR2_EL1.
                addr: ID_AA64MMFR2_EL1,
                bitmap: RegisterValueFilter {
                    filter: 0x0000000F00000000,
                    value: 0x0000000000000000,
                },
            },
        ],
        ..Default::default()
    }
}
