// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Model Specific Registers (MSRs) related functionality.
use std::result;

use arch_gen::x86::msr_index::*;
use kvm_bindings::{kvm_msr_entry, Msrs};
use kvm_ioctls::VcpuFd;

#[derive(Debug)]
/// MSR related errors.
pub enum Error {
    /// Setting up MSRs failed.
    SetModelSpecificRegisters(kvm_ioctls::Error),
    /// Failed to set all MSRs.
    SetModelSpecificRegistersCount,
}

type Result<T> = result::Result<T, Error>;

/// MSR range
struct MsrRange {
    /// Base MSR address
    base: u32,
    /// Number of MSRs
    nmsrs: u32,
}

impl MsrRange {
    /// Returns whether `msr` is contained in this MSR range.
    fn contains(&self, msr: u32) -> bool {
        self.base <= msr && msr < self.base + self.nmsrs
    }
}

/// Base MSR for APIC
const APIC_BASE_MSR: u32 = 0x800;

/// Number of APIC MSR indexes
const APIC_MSR_INDEXES: u32 = 0x400;

/// Custom MSRs fall in the range 0x4b564d00-0x4b564dff
const MSR_KVM_WALL_CLOCK_NEW: u32 = 0x4b56_4d00;
const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b56_4d01;
const MSR_KVM_ASYNC_PF_EN: u32 = 0x4b56_4d02;
const MSR_KVM_STEAL_TIME: u32 = 0x4b56_4d03;
const MSR_KVM_PV_EOI_EN: u32 = 0x4b56_4d04;

/// Taken from arch/x86/include/asm/msr-index.h
const MSR_IA32_SPEC_CTRL: u32 = 0x0000_0048;
const MSR_IA32_PRED_CMD: u32 = 0x0000_0049;

// Creates a MsrRange of one msr given as argument.
macro_rules! SINGLE_MSR {
    ($msr:expr) => {
        MsrRange {
            base: $msr,
            nmsrs: 1,
        }
    };
}

// Creates a MsrRange of with msr base and count given as arguments.
macro_rules! MSR_RANGE {
    ($first:expr, $count:expr) => {
        MsrRange {
            base: $first,
            nmsrs: $count,
        }
    };
}

// List of MSRs that can be serialized. List is sorted in ascending order of MSRs addresses.
static WHITELISTED_MSR_RANGES: &[MsrRange] = &[
    SINGLE_MSR!(MSR_IA32_P5_MC_ADDR),
    SINGLE_MSR!(MSR_IA32_P5_MC_TYPE),
    SINGLE_MSR!(MSR_IA32_TSC),
    SINGLE_MSR!(MSR_IA32_PLATFORM_ID),
    SINGLE_MSR!(MSR_IA32_APICBASE),
    SINGLE_MSR!(MSR_IA32_EBL_CR_POWERON),
    SINGLE_MSR!(MSR_EBC_FREQUENCY_ID),
    SINGLE_MSR!(MSR_SMI_COUNT),
    SINGLE_MSR!(MSR_IA32_FEATURE_CONTROL),
    SINGLE_MSR!(MSR_IA32_TSC_ADJUST),
    SINGLE_MSR!(MSR_IA32_SPEC_CTRL),
    SINGLE_MSR!(MSR_IA32_PRED_CMD),
    SINGLE_MSR!(MSR_IA32_UCODE_WRITE),
    SINGLE_MSR!(MSR_IA32_UCODE_REV),
    SINGLE_MSR!(MSR_IA32_SMBASE),
    SINGLE_MSR!(MSR_FSB_FREQ),
    SINGLE_MSR!(MSR_PLATFORM_INFO),
    SINGLE_MSR!(MSR_PKG_CST_CONFIG_CONTROL),
    SINGLE_MSR!(MSR_IA32_MPERF),
    SINGLE_MSR!(MSR_IA32_APERF),
    SINGLE_MSR!(MSR_MTRRcap),
    SINGLE_MSR!(MSR_IA32_BBL_CR_CTL3),
    SINGLE_MSR!(MSR_IA32_SYSENTER_CS),
    SINGLE_MSR!(MSR_IA32_SYSENTER_ESP),
    SINGLE_MSR!(MSR_IA32_SYSENTER_EIP),
    SINGLE_MSR!(MSR_IA32_MCG_CAP),
    SINGLE_MSR!(MSR_IA32_MCG_STATUS),
    SINGLE_MSR!(MSR_IA32_MCG_CTL),
    SINGLE_MSR!(MSR_IA32_PERF_STATUS),
    SINGLE_MSR!(MSR_IA32_MISC_ENABLE),
    SINGLE_MSR!(MSR_MISC_FEATURE_CONTROL),
    SINGLE_MSR!(MSR_MISC_PWR_MGMT),
    SINGLE_MSR!(MSR_TURBO_RATIO_LIMIT),
    SINGLE_MSR!(MSR_TURBO_RATIO_LIMIT1),
    SINGLE_MSR!(MSR_IA32_DEBUGCTLMSR),
    SINGLE_MSR!(MSR_IA32_LASTBRANCHFROMIP),
    SINGLE_MSR!(MSR_IA32_LASTBRANCHTOIP),
    SINGLE_MSR!(MSR_IA32_LASTINTFROMIP),
    SINGLE_MSR!(MSR_IA32_LASTINTTOIP),
    SINGLE_MSR!(MSR_IA32_POWER_CTL),
    MSR_RANGE!(
        // IA32_MTRR_PHYSBASE0
        0x200, 0x100
    ),
    MSR_RANGE!(
        // MSR_CORE_C3_RESIDENCY
        // MSR_CORE_C6_RESIDENCY
        // MSR_CORE_C7_RESIDENCY
        MSR_CORE_C3_RESIDENCY,
        3
    ),
    MSR_RANGE!(MSR_IA32_MC0_CTL, 0x80),
    SINGLE_MSR!(MSR_RAPL_POWER_UNIT),
    MSR_RANGE!(
        // MSR_PKGC3_IRTL
        // MSR_PKGC6_IRTL
        // MSR_PKGC7_IRTL
        MSR_PKGC3_IRTL,
        3
    ),
    SINGLE_MSR!(MSR_PKG_POWER_LIMIT),
    SINGLE_MSR!(MSR_PKG_ENERGY_STATUS),
    SINGLE_MSR!(MSR_PKG_PERF_STATUS),
    SINGLE_MSR!(MSR_PKG_POWER_INFO),
    SINGLE_MSR!(MSR_DRAM_POWER_LIMIT),
    SINGLE_MSR!(MSR_DRAM_ENERGY_STATUS),
    SINGLE_MSR!(MSR_DRAM_PERF_STATUS),
    SINGLE_MSR!(MSR_DRAM_POWER_INFO),
    SINGLE_MSR!(MSR_CONFIG_TDP_NOMINAL),
    SINGLE_MSR!(MSR_CONFIG_TDP_LEVEL_1),
    SINGLE_MSR!(MSR_CONFIG_TDP_LEVEL_2),
    SINGLE_MSR!(MSR_CONFIG_TDP_CONTROL),
    SINGLE_MSR!(MSR_TURBO_ACTIVATION_RATIO),
    SINGLE_MSR!(MSR_IA32_TSCDEADLINE),
    MSR_RANGE!(APIC_BASE_MSR, APIC_MSR_INDEXES),
    SINGLE_MSR!(MSR_IA32_BNDCFGS),
    SINGLE_MSR!(MSR_KVM_WALL_CLOCK_NEW),
    SINGLE_MSR!(MSR_KVM_SYSTEM_TIME_NEW),
    SINGLE_MSR!(MSR_KVM_ASYNC_PF_EN),
    SINGLE_MSR!(MSR_KVM_STEAL_TIME),
    SINGLE_MSR!(MSR_KVM_PV_EOI_EN),
    SINGLE_MSR!(MSR_EFER),
    SINGLE_MSR!(MSR_STAR),
    SINGLE_MSR!(MSR_LSTAR),
    SINGLE_MSR!(MSR_CSTAR),
    SINGLE_MSR!(MSR_SYSCALL_MASK),
    SINGLE_MSR!(MSR_FS_BASE),
    SINGLE_MSR!(MSR_GS_BASE),
    SINGLE_MSR!(MSR_KERNEL_GS_BASE),
    SINGLE_MSR!(MSR_TSC_AUX),
];

/// Specifies whether a particular MSR should be included in vcpu serialization.
///
/// # Arguments
///
/// * `index` - The index of the MSR that is checked whether it's needed for serialization.
pub fn msr_should_serialize(index: u32) -> bool {
    // Blacklisted MSRs not exported by Linux: IA32_FEATURE_CONTROL and IA32_MCG_CTL
    if index == MSR_IA32_FEATURE_CONTROL || index == MSR_IA32_MCG_CTL {
        return false;
    };
    WHITELISTED_MSR_RANGES
        .iter()
        .any(|range| range.contains(index))
}

// Creates and populates required MSR entries for booting Linux on X86_64.
fn create_boot_msr_entries() -> Vec<kvm_msr_entry> {
    let msr_entry_default = |msr| kvm_msr_entry {
        index: msr,
        data: 0x0,
        ..Default::default()
    };

    vec![
        msr_entry_default(MSR_IA32_SYSENTER_CS),
        msr_entry_default(MSR_IA32_SYSENTER_ESP),
        msr_entry_default(MSR_IA32_SYSENTER_EIP),
        // x86_64 specific msrs, we only run on x86_64 not x86.
        msr_entry_default(MSR_STAR),
        msr_entry_default(MSR_CSTAR),
        msr_entry_default(MSR_KERNEL_GS_BASE),
        msr_entry_default(MSR_SYSCALL_MASK),
        msr_entry_default(MSR_LSTAR),
        // end of x86_64 specific code
        msr_entry_default(MSR_IA32_TSC),
        kvm_msr_entry {
            index: MSR_IA32_MISC_ENABLE,
            data: u64::from(MSR_IA32_MISC_ENABLE_FAST_STRING),
            ..Default::default()
        },
    ]
}

/// Configure Model Specific Registers (MSRs) required to boot Linux for a given x86_64 vCPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_msrs(vcpu: &VcpuFd) -> Result<()> {
    let entry_vec = create_boot_msr_entries();
    let msrs = Msrs::from_entries(&entry_vec);
    vcpu.set_msrs(&msrs)
        .map_err(Error::SetModelSpecificRegisters)
        .and_then(|msrs_written| {
            if msrs_written as u32 != msrs.as_fam_struct_ref().nmsrs {
                Err(Error::SetModelSpecificRegistersCount)
            } else {
                Ok(())
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm_ioctls::Kvm;

    #[test]
    fn test_msr_whitelist() {
        for range in WHITELISTED_MSR_RANGES.iter() {
            for msr in range.base..(range.base + range.nmsrs) {
                let should = match msr {
                    MSR_IA32_FEATURE_CONTROL | MSR_IA32_MCG_CTL => false,
                    _ => true,
                };
                assert_eq!(msr_should_serialize(msr), should);
            }
        }
    }

    #[test]
    #[allow(clippy::cast_ptr_alignment)]
    fn test_setup_msrs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        setup_msrs(&vcpu).unwrap();

        // This test will check against the last MSR entry configured (the tenth one).
        // See create_msr_entries() for details.
        let test_kvm_msrs_entry = [kvm_msr_entry {
            index: MSR_IA32_MISC_ENABLE,
            ..Default::default()
        }];
        let mut kvm_msrs_wrapper = Msrs::from_entries(&test_kvm_msrs_entry);

        // Get_msrs() returns the number of msrs that it succeed in reading.
        // We only want to read one in this test case scenario.
        let read_nmsrs = vcpu.get_msrs(&mut kvm_msrs_wrapper).unwrap();
        // Validate it only read one.
        assert_eq!(read_nmsrs, 1);

        // Official entries that were setup when we did setup_msrs. We need to assert that the
        // tenth one (i.e the one with index MSR_IA32_MISC_ENABLE has the data we
        // expect.
        let entry_vec = create_boot_msr_entries();
        assert_eq!(entry_vec[9], kvm_msrs_wrapper.as_slice()[0]);
    }
}
