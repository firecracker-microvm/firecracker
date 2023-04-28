// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

macro_rules! cpuid_reg_modifier {
    ($register:expr, $value:expr) => {
        CpuidRegisterModifier {
            register: $register,
            bitmap: RegisterValueFilter {
                filter: u32::MAX.into(),
                value: $value,
            },
        }
    };
    ($register:expr, $value:expr, $filter:expr) => {
        CpuidRegisterModifier {
            register: $register,
            bitmap: RegisterValueFilter {
                filter: $filter,
                value: $value,
            },
        }
    };
}

macro_rules! cpuid_leaf_modifier {
    ($leaf:expr, $subleaf:expr, $flags:expr, $reg_modifiers:expr) => {
        CpuidLeafModifier {
            leaf: $leaf,
            subleaf: $subleaf,
            flags: $flags,
            modifiers: $reg_modifiers,
        }
    };
}

macro_rules! msr_modifier {
    ($addr:expr, $value:expr) => {
        RegisterModifier {
            addr: $addr,
            bitmap: RegisterValueFilter {
                filter: u64::MAX,
                value: $value,
            },
        }
    };
    ($addr:expr, $value:expr, $filter:expr) => {
        RegisterModifier {
            addr: $addr,
            bitmap: RegisterValueFilter {
                filter: $filter,
                value: $value,
            },
        }
    };
}

pub(crate) use {cpuid_leaf_modifier, cpuid_reg_modifier, msr_modifier};
