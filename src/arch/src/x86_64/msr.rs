// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Model Specific Registers (MSRs) related functionality.
use std::result;

use arch_gen::x86::msr_index::*;
use arch_gen::x86::perf_event::*;
use bitflags::bitflags;
use kvm_bindings::{kvm_msr_entry, MsrList, Msrs};
use kvm_ioctls::{Kvm, VcpuFd};

#[derive(Debug)]
/// MSR related errors.
pub enum Error {
    /// A FamStructWrapper operation has failed.
    Fam(utils::fam::Error),
    /// Getting supported MSRs failed.
    GetSupportedModelSpecificRegisters(kvm_ioctls::Error),
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
const MSR_KVM_POLL_CONTROL: u32 = 0x4b56_4d05;
const MSR_KVM_ASYNC_PF_INT: u32 = 0x4b56_4d06;

/// Taken from arch/x86/include/asm/msr-index.h
/// Spectre mitigations control MSR
pub const MSR_IA32_SPEC_CTRL: u32 = 0x0000_0048;
/// Architecture capabilities MSR
pub const MSR_IA32_ARCH_CAPABILITIES: u32 = 0x0000_010a;

const MSR_IA32_PRED_CMD: u32 = 0x0000_0049;

bitflags! {
    /// Feature flags enumerated in the IA32_ARCH_CAPABILITIES MSR.
    /// See https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/cpuid-enumeration-and-architectural-msrs.html
    #[derive(Default)]
    #[repr(C)]
    pub struct ArchCapaMSRFlags: u64 {
        /// The processor is not susceptible to Rogue Data Cache Load (RDCL).
        const RDCL_NO               = 1 << 0;
        /// The processor supports enhanced Indirect Branch Restriction Speculation (IBRS)
        const IBRS_ALL              = 1 << 1;
        /// The processor supports RSB Alternate. Alternative branch predictors may be used by RET instructions
        /// when the RSB is empty. Software using retpoline may be affected by this behavior.
        const RSBA                  = 1 << 2;
        /// A value of 1 indicates the hypervisor need not flush the L1D on VM entry.
        const SKIP_L1DFL_VMENTRY    = 1 << 3;
        /// Processor is not susceptible to Speculative Store Bypass (SSB).
        const SSB_NO                = 1 << 4;
        /// Processor is not susceptible to Microarchitectural Data Sampling (MDS).
        const MDS_NO                = 1 << 5;
        /// The processor is not susceptible to a machine check error due to modifying the size of a code page
        /// without TLB invalidation.
        const IF_PSCHANGE_MC_NO     = 1 << 6;
        /// The processor supports RTM_DISABLE and TSX_CPUID_CLEAR.
        const TSX_CTRL              = 1 << 7;
        /// Processor is not susceptible to Intel® Transactional Synchronization Extensions
        /// (Intel® TSX) Asynchronous Abort (TAA).
        const TAA_NO                = 1 << 8;
        // Bit 9 is reserved
        /// Processor supports IA32_MISC_PACKAGE_CTRLS MSR.
        const MISC_PACKAGE_CTRLS    = 1 << 10;
        /// Processor supports setting and reading IA32_MISC_PACKAGE_CTLS[0] (ENERGY_FILTERING_ENABLE) bit.
        const ENERGY_FILTERING_CTL  = 1 << 11;
        /// The processor supports data operand independent timing mode.
        const DOITM                 = 1 << 12;
        /// The processor is not affected by either the Shared Buffers Data Read (SBDR) vulnerability or the
        /// Sideband Stale Data Propagator (SSDP).
        const SBDR_SSDP_NO          = 1 << 13;
        /// The processor is not affected by the Fill Buffer Stale Data Propagator (FBSDP).
        const FBSDP_NO              = 1 << 14;
        /// The processor is not affected by vulnerabilities involving the Primary Stale Data Propagator (PSDP).
        const PSDP_NO               = 1 << 15;
        // Bit 16 is reserved
        /// The processor will overwrite fill buffer values as part of MD_CLEAR operations with the VERW instruction.
        /// On these processors, L1D_FLUSH does not overwrite fill buffer values.
        const FB_CLEAR              = 1 << 17;
        /// The processor supports read and write to the IA32_MCU_OPT_CTRL MSR (MSR 123H) and to the FB_CLEAR_DIS bit
        /// in that MSR (bit position 3).
        const FB_CLEAR_CTRL         = 1 << 18;
        /// A value of 1 indicates processor may have the RRSBA alternate prediction behavior,
        /// if not disabled by RRSBA_DIS_U or RRSBA_DIS_S.
        const RRSBA                 = 1 << 19;
        /// A value of 1 indicates BHI_NO branch prediction behavior,
        /// regardless of the value of IA32_SPEC_CTRL[BHI_DIS_S] MSR bit.
        const BHI_NO                = 1 << 20;
        // Bits 21:22 are reserved
        /// If set, the IA32_OVERCLOCKING STATUS MSR exists.
        const OVERCLOCKING_STATUS   = 1 << 23;
        // Bits 24:63 are reserved
    }
}

// Macro for generating a MsrRange.
macro_rules! MSR_RANGE {
    ($base:expr, $nmsrs:expr) => {
        MsrRange {
            base: $base,
            nmsrs: $nmsrs,
        }
    };
    ($base:expr) => {
        MSR_RANGE!($base, 1)
    };
}

// List of MSRs that should be serialized. List is sorted in ascending order of MSRs addresses.
static SERIALIZE_MSR_RANGES: &[MsrRange] = &[
    MSR_RANGE!(MSR_IA32_P5_MC_ADDR),
    MSR_RANGE!(MSR_IA32_P5_MC_TYPE),
    MSR_RANGE!(MSR_IA32_TSC),
    MSR_RANGE!(MSR_IA32_PLATFORM_ID),
    MSR_RANGE!(MSR_IA32_APICBASE),
    MSR_RANGE!(MSR_IA32_EBL_CR_POWERON),
    MSR_RANGE!(MSR_EBC_FREQUENCY_ID),
    MSR_RANGE!(MSR_SMI_COUNT),
    MSR_RANGE!(MSR_IA32_FEAT_CTL),
    MSR_RANGE!(MSR_IA32_TSC_ADJUST),
    MSR_RANGE!(MSR_IA32_SPEC_CTRL),
    MSR_RANGE!(MSR_IA32_PRED_CMD),
    MSR_RANGE!(MSR_IA32_UCODE_WRITE),
    MSR_RANGE!(MSR_IA32_UCODE_REV),
    MSR_RANGE!(MSR_IA32_SMBASE),
    MSR_RANGE!(MSR_FSB_FREQ),
    MSR_RANGE!(MSR_PLATFORM_INFO),
    MSR_RANGE!(MSR_PKG_CST_CONFIG_CONTROL),
    MSR_RANGE!(MSR_IA32_MPERF),
    MSR_RANGE!(MSR_IA32_APERF),
    MSR_RANGE!(MSR_MTRRcap),
    MSR_RANGE!(MSR_IA32_BBL_CR_CTL3),
    MSR_RANGE!(MSR_IA32_SYSENTER_CS),
    MSR_RANGE!(MSR_IA32_SYSENTER_ESP),
    MSR_RANGE!(MSR_IA32_SYSENTER_EIP),
    MSR_RANGE!(MSR_IA32_MCG_CAP),
    MSR_RANGE!(MSR_IA32_MCG_STATUS),
    MSR_RANGE!(MSR_IA32_MCG_CTL),
    MSR_RANGE!(MSR_IA32_PERF_STATUS),
    MSR_RANGE!(MSR_IA32_MISC_ENABLE),
    MSR_RANGE!(MSR_MISC_FEATURE_CONTROL),
    MSR_RANGE!(MSR_MISC_PWR_MGMT),
    MSR_RANGE!(MSR_TURBO_RATIO_LIMIT),
    MSR_RANGE!(MSR_TURBO_RATIO_LIMIT1),
    MSR_RANGE!(MSR_IA32_DEBUGCTLMSR),
    MSR_RANGE!(MSR_IA32_LASTBRANCHFROMIP),
    MSR_RANGE!(MSR_IA32_LASTBRANCHTOIP),
    MSR_RANGE!(MSR_IA32_LASTINTFROMIP),
    MSR_RANGE!(MSR_IA32_LASTINTTOIP),
    MSR_RANGE!(MSR_IA32_POWER_CTL),
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
    MSR_RANGE!(MSR_RAPL_POWER_UNIT),
    MSR_RANGE!(
        // MSR_PKGC3_IRTL
        // MSR_PKGC6_IRTL
        // MSR_PKGC7_IRTL
        MSR_PKGC3_IRTL,
        3
    ),
    MSR_RANGE!(MSR_PKG_POWER_LIMIT),
    MSR_RANGE!(MSR_PKG_ENERGY_STATUS),
    MSR_RANGE!(MSR_PKG_PERF_STATUS),
    MSR_RANGE!(MSR_PKG_POWER_INFO),
    MSR_RANGE!(MSR_DRAM_POWER_LIMIT),
    MSR_RANGE!(MSR_DRAM_ENERGY_STATUS),
    MSR_RANGE!(MSR_DRAM_PERF_STATUS),
    MSR_RANGE!(MSR_DRAM_POWER_INFO),
    MSR_RANGE!(MSR_CONFIG_TDP_NOMINAL),
    MSR_RANGE!(MSR_CONFIG_TDP_LEVEL_1),
    MSR_RANGE!(MSR_CONFIG_TDP_LEVEL_2),
    MSR_RANGE!(MSR_CONFIG_TDP_CONTROL),
    MSR_RANGE!(MSR_TURBO_ACTIVATION_RATIO),
    MSR_RANGE!(MSR_IA32_TSC_DEADLINE),
    MSR_RANGE!(APIC_BASE_MSR, APIC_MSR_INDEXES),
    MSR_RANGE!(MSR_KVM_WALL_CLOCK_NEW),
    MSR_RANGE!(MSR_KVM_SYSTEM_TIME_NEW),
    MSR_RANGE!(MSR_KVM_ASYNC_PF_EN),
    MSR_RANGE!(MSR_KVM_STEAL_TIME),
    MSR_RANGE!(MSR_KVM_PV_EOI_EN),
    MSR_RANGE!(MSR_EFER),
    MSR_RANGE!(MSR_STAR),
    MSR_RANGE!(MSR_LSTAR),
    MSR_RANGE!(MSR_CSTAR),
    MSR_RANGE!(MSR_SYSCALL_MASK),
    MSR_RANGE!(MSR_FS_BASE),
    MSR_RANGE!(MSR_GS_BASE),
    MSR_RANGE!(MSR_KERNEL_GS_BASE),
    MSR_RANGE!(MSR_TSC_AUX),
    MSR_RANGE!(MSR_MISC_FEATURES_ENABLES),
    MSR_RANGE!(MSR_K7_HWCR),
    MSR_RANGE!(MSR_KVM_POLL_CONTROL),
    MSR_RANGE!(MSR_KVM_ASYNC_PF_INT),
];

/// Specifies whether a particular MSR should be included in vcpu serialization.
///
/// # Arguments
///
/// * `index` - The index of the MSR that is checked whether it's needed for serialization.
pub fn msr_should_serialize(index: u32) -> bool {
    // Denied MSR not exported by Linux: IA32_MCG_CTL
    if index == MSR_IA32_MCG_CTL {
        return false;
    };
    SERIALIZE_MSR_RANGES
        .iter()
        .any(|range| range.contains(index))
}

// List of MSRs that should not be included.
//
// MSR index list gotten via KVM_GET_MSR_INDEX_LIST can include invalid PMU-related MSRs, because
// the availability of PMU-related MSRs are based on CPUID leaf 0xa and can change after calling
// KVM_GET_MSR_INDEX_LIST. Since firecracker disables PMU by default, it is safe to remove
// PMU-related MSRs from the supported MSR list. Otherwise, KVM_GET_MSRS fails. The PMU-related
// availability update based on CPUID leaf 0xa can be found in the following link.
// https://elixir.bootlin.com/linux/v5.10.176/source/arch/x86/kvm/vmx/pmu_intel.c#L325
//
// For VMX-related MSRs, the above situation can happen. As we don't test firecarcker in nested
// virtualization environment, we exclude these MSRs. You can see that VMX-related MSRs depend on
// whether nested virtualization is allowed in the following link.
// https://elixir.bootlin.com/linux/v6.1.8/source/arch/x86/kvm/vmx/vmx.c#L1936
//
// The list of MSRs that is potentially supported by KVM can be found here:
// https://elixir.bootlin.com/linux/v5.10.176/source/arch/x86/kvm/x86.c#L1211
static DENY_MSR_RANGES: &[MsrRange] = &[
    // MSR_ARCH_PERFMON_PERFCTRn
    MSR_RANGE!(MSR_ARCH_PERFMON_PERFCTR0, 18),
    // MSR_ARCH_PERFMON_EVENTSELn
    MSR_RANGE!(MSR_ARCH_PERFMON_EVENTSEL0, 18),
    // MSR_ARCH_PERFMON_FIXED_CTRn
    MSR_RANGE!(MSR_ARCH_PERFMON_FIXED_CTR0, 3),
    // MSR_CORE_PERF_FIXED_CTR_CTRL
    // MSR_CORE_PERF_GLOBAL_STATUS
    // MSR_CORE_PERF_GLOBAL_CTRL
    // MSR_CORE_PERF_GLOBAL_OVF_CTRL
    MSR_RANGE!(MSR_CORE_PERF_FIXED_CTR_CTRL, 4),
    // MSR_K7_EVNTSELn
    MSR_RANGE!(MSR_K7_EVNTSEL0, 4),
    // MSR_K7_PERFCTRn
    MSR_RANGE!(MSR_K7_PERFCTR0, 4),
    // MSR_F15H_PERF_CTLn
    MSR_RANGE!(MSR_F15H_PERF_CTL0, 6),
    // MSR_F15H_PERF_CTRn
    MSR_RANGE!(MSR_F15H_PERF_CTR0, 6),
    // MSR_IA32_VMX_BASIC
    // MSR_IA32_VMX_PINBASED_CTLS
    // MSR_IA32_VMX_PROCBASED_CTLS
    // MSR_IA32_VMX_EXIT_CTLS
    // MSR_IA32_VMX_ENTRY_CTLS
    // MSR_IA32_VMX_MISC
    // MSR_IA32_VMX_CR0_FIXED0
    // MSR_IA32_VMX_CR0_FIXED1
    // MSR_IA32_VMX_CR4_FIXED0
    // MSR_IA32_VMX_CR4_FIXED1
    // MSR_IA32_VMX_VMCS_ENUM
    // MSR_IA32_VMX_PROCBASED_CTLS2
    // MSR_IA32_VMX_EPT_VPID_CAP
    // MSR_IA32_VMX_TRUE_PINBASED_CTLS
    // MSR_IA32_VMX_TRUE_PROCBASED_CTLS
    // MSR_IA32_VMX_TRUE_EXIT_CTLS
    // MSR_IA32_VMX_TRUE_ENTRY_CTLS
    // MSR_IA32_VMX_VMFUNC
    MSR_RANGE!(MSR_IA32_VMX_BASIC, 18),
];

/// Specifies whether a particular MSR should be removed from supported MSRs.
///
/// # Arguments
///
/// * `index` - The index of the MSR that is checked whether it's needed for serialization.
pub fn msr_should_deny(index: u32) -> bool {
    DENY_MSR_RANGES.iter().any(|range| range.contains(index))
}

/// Creates and populates required MSR entries for booting Linux on X86_64.
pub fn create_boot_msr_entries() -> Vec<kvm_msr_entry> {
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

/// Error type for [`set_msrs`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum SetMsrsError {
    /// Failed to create [`vmm_sys_util::fam::FamStructWrapper`] for MSRs.
    #[error("Could not create `vmm_sys_util::fam::FamStructWrapper` for MSRs")]
    Create(utils::fam::Error),
    /// Settings MSRs resulted in an error.
    #[error("Setting MSRs resulted in an error: {0}")]
    Set(#[from] kvm_ioctls::Error),
    /// Not all given MSRs were set.
    #[error("Not all given MSRs were set.")]
    Incomplete,
}

/// Configure Model Specific Registers (MSRs) required to boot Linux for a given x86_64 vCPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
///
/// # Errors
///
/// When:
/// - Failed to create [`vmm_sys_util::fam::FamStructWrapper`] for MSRs.
/// - [`kvm_ioctls::ioctls::vcpu::VcpuFd::set_msrs`] errors.
/// - [`kvm_ioctls::ioctls::vcpu::VcpuFd::set_msrs`] fails to write all given MSRs entries.
pub fn set_msrs(
    vcpu: &VcpuFd,
    msr_entries: &[kvm_msr_entry],
) -> std::result::Result<(), SetMsrsError> {
    let msrs = Msrs::from_entries(msr_entries).map_err(SetMsrsError::Create)?;
    vcpu.set_msrs(&msrs)
        .map_err(SetMsrsError::Set)
        .and_then(|msrs_written| {
            if msrs_written as u32 == msrs.as_fam_struct_ref().nmsrs {
                Ok(())
            } else {
                Err(SetMsrsError::Incomplete)
            }
        })
}

/// Returns the list of supported MSR indices.
///
/// # Arguments
///
/// * `kvm_fd` - Structure that holds the KVM's fd.
///
/// # Errors
///
/// When:
/// - [`kvm_ioctls::ioctls::system::Kvm::get_msr_index_list()`] errors.
pub fn get_supported_msrs(kvm_fd: &Kvm) -> Result<MsrList> {
    let mut supported_msrs = kvm_fd
        .get_msr_index_list()
        .map_err(Error::GetSupportedModelSpecificRegisters)?;

    supported_msrs.retain(|msr_index| !msr_should_deny(*msr_index));
    Ok(supported_msrs)
}

/// Returns the list of serializable MSR indices.
///
/// # Arguments
///
/// * `supported_msrs` - List of supported MSR indices.
pub fn get_msrs_to_save(supported_msrs: &MsrList) -> MsrList {
    let mut msrs_to_save = supported_msrs.clone();
    msrs_to_save.retain(|msr_index| msr_should_serialize(*msr_index));
    msrs_to_save
}

#[cfg(test)]
mod tests {
    use kvm_ioctls::Kvm;

    use super::*;

    #[test]
    fn test_msr_list_to_serialize() {
        for range in SERIALIZE_MSR_RANGES.iter() {
            for msr in range.base..(range.base + range.nmsrs) {
                let should = !matches!(msr, MSR_IA32_MCG_CTL);
                assert_eq!(msr_should_serialize(msr), should);
            }
        }
    }

    #[test]
    fn test_msr_list_to_deny() {
        for range in DENY_MSR_RANGES.iter() {
            for msr in range.base..(range.base + range.nmsrs) {
                assert!(msr_should_deny(msr));
            }
        }
    }

    #[test]
    #[allow(clippy::cast_ptr_alignment)]
    fn test_setup_msrs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let msr_boot_entries = create_boot_msr_entries();
        set_msrs(&vcpu, &msr_boot_entries).unwrap();

        // This test will check against the last MSR entry configured (the tenth one).
        // See create_msr_entries() for details.
        let test_kvm_msrs_entry = [kvm_msr_entry {
            index: MSR_IA32_MISC_ENABLE,
            ..Default::default()
        }];
        let mut kvm_msrs_wrapper = Msrs::from_entries(&test_kvm_msrs_entry).unwrap();

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
