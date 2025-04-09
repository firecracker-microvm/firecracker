// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::arch::x86_64::__cpuid as host_cpuid;
use std::cmp::{Eq, PartialEq};

/// Structure representing x86_64 CPU model.
#[derive(Debug, Eq, PartialEq)]
pub struct CpuModel {
    /// Extended family.
    pub extended_family: u8,
    /// Extended model.
    pub extended_model: u8,
    /// Family.
    pub family: u8,
    /// Model.
    pub model: u8,
    /// Stepping.
    pub stepping: u8,
}

/// Family / Model / Stepping for Intel Skylake
pub const SKYLAKE_FMS: CpuModel = CpuModel {
    extended_family: 0x0,
    extended_model: 0x5,
    family: 0x6,
    model: 0x5,
    stepping: 0x4,
};

/// Family / Model / Stepping for Intel Cascade Lake
pub const CASCADE_LAKE_FMS: CpuModel = CpuModel {
    extended_family: 0x0,
    extended_model: 0x5,
    family: 0x6,
    model: 0x5,
    stepping: 0x7,
};

/// Family / Model / Stepping for Intel Ice Lake
pub const ICE_LAKE_FMS: CpuModel = CpuModel {
    extended_family: 0x0,
    extended_model: 0x6,
    family: 0x6,
    model: 0xa,
    stepping: 0x6,
};

/// Family / Model / Stepping for AMD Milan
pub const MILAN_FMS: CpuModel = CpuModel {
    extended_family: 0xa,
    extended_model: 0x0,
    family: 0xf,
    model: 0x1,
    stepping: 0x1,
};

impl CpuModel {
    /// Get CPU model from current machine.
    pub fn get_cpu_model() -> Self {
        // SAFETY: This operation is safe as long as the processor implements this CPUID function.
        // 0x1 is the defined code for getting the processor version information.
        let eax = unsafe { host_cpuid(0x1) }.eax;
        CpuModel::from(&eax)
    }
}

impl From<&u32> for CpuModel {
    fn from(eax: &u32) -> Self {
        CpuModel {
            extended_family: ((eax >> 20) & 0xff) as u8,
            extended_model: ((eax >> 16) & 0xf) as u8,
            family: ((eax >> 8) & 0xf) as u8,
            model: ((eax >> 4) & 0xf) as u8,
            stepping: (eax & 0xf) as u8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_model_from() {
        let skylake_eax = 0x00050654;
        assert_eq!(CpuModel::from(&skylake_eax), SKYLAKE_FMS);

        let cascade_lake_eax = 0x00050657;
        assert_eq!(CpuModel::from(&cascade_lake_eax), CASCADE_LAKE_FMS);

        let ice_lake_eax = 0x000606a6;
        assert_eq!(CpuModel::from(&ice_lake_eax), ICE_LAKE_FMS);

        let milan_eax = 0x00a00f11;
        assert_eq!(CpuModel::from(&milan_eax), MILAN_FMS);
    }
}
