// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::arch::x86_64::__cpuid as host_cpuid;
use std::cmp::{Eq, Ordering, PartialEq, PartialOrd};

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

impl CpuModel {
    /// Get CPU model from current machine.
    pub fn get_cpu_model() -> Self {
        // SAFETY: This operation is safe as long as the processor implements this CPUID function.
        // 0x1 is the defined code for getting the processor version information.
        let eax = unsafe { host_cpuid(0x1) }.eax;
        CpuModel::from(&eax)
    }

    /// Check if the current CPU model is Intel Cascade Lake or later.
    pub fn is_at_least_cascade_lake(&self) -> bool {
        let cascade_lake = CpuModel {
            extended_family: 0,
            extended_model: 5,
            family: 6,
            model: 5,
            stepping: 7,
        };

        self >= &cascade_lake
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

impl From<&CpuModel> for u32 {
    fn from(cpu_model: &CpuModel) -> Self {
        u32::from(cpu_model.extended_family) << 20
            | u32::from(cpu_model.extended_model) << 16
            | u32::from(cpu_model.family) << 8
            | u32::from(cpu_model.model) << 4
            | u32::from(cpu_model.stepping)
    }
}

impl PartialOrd for CpuModel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(u32::from(self).cmp(&u32::from(other)))
    }
}

impl Ord for CpuModel {
    fn cmp(&self, other: &Self) -> Ordering {
        u32::from(self).cmp(&u32::from(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SKYLAKE: CpuModel = CpuModel {
        extended_family: 0,
        extended_model: 5,
        family: 6,
        model: 5,
        stepping: 4,
    };

    const CASCADE_LAKE: CpuModel = CpuModel {
        extended_family: 0,
        extended_model: 5,
        family: 6,
        model: 5,
        stepping: 7,
    };

    #[test]
    fn cpu_model_from() {
        let skylake_eax = 0x00050654;
        assert_eq!(u32::from(&SKYLAKE), skylake_eax);
        assert_eq!(CpuModel::from(&skylake_eax), SKYLAKE);
    }

    #[test]
    fn cpu_model_ord() {
        assert_eq!(SKYLAKE, SKYLAKE);
        assert!(SKYLAKE < CASCADE_LAKE);
        assert!(CASCADE_LAKE > SKYLAKE);
    }
}
