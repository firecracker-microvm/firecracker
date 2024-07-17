// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Model Specific Registers (MSRs) related functionality.
use bitflags::bitflags;
use kvm_bindings::{kvm_msr_entry, MsrList, Msrs};
use kvm_ioctls::{Kvm, VcpuFd};

use crate::arch_gen::x86::hyperv::*;
use crate::arch_gen::x86::hyperv_tlfs::*;
use crate::arch_gen::x86::msr_index::*;
use crate::arch_gen::x86::perf_event::*;
use crate::cpu_config::x86_64::cpuid::common::GetCpuidError;

#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
/// MSR related errors.
pub enum MsrError {
    /// Failed to create `vmm_sys_util::fam::FamStructWrapper` for MSRs
    Fam(#[from] utils::fam::Error),
    /// Failed to get MSR index list: {0}
    GetMsrIndexList(kvm_ioctls::Error),
    /// Invalid CPU vendor: {0}
    InvalidVendor(#[from] GetCpuidError),
    /// Failed to set MSRs: {0}
    SetMsrs(kvm_ioctls::Error),
    /// Not all given MSRs were set.
    SetMsrsIncomplete,
}

/// MSR range
#[derive(Debug)]
pub struct MsrRange {
    /// Base MSR address
    pub base: u32,
    /// Number of MSRs
    pub nmsrs: u32,
}

impl MsrRange {
    /// Returns whether `msr` is contained in this MSR range.
    pub fn contains(&self, msr: u32) -> bool {
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

/// Macro for generating a MsrRange.
#[macro_export]
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

// List of MSRs that can be serialized. List is sorted in ascending order of MSRs addresses.
static SERIALIZABLE_MSR_RANGES: &[MsrRange] = &[
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
    MSR_RANGE!(MSR_IA32_TSX_CTRL),
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
    SERIALIZABLE_MSR_RANGES
        .iter()
        .any(|range| range.contains(index))
}

/// Returns the list of serializable MSR indices.
///
/// # Arguments
///
/// * `kvm_fd` - Ref to `kvm_ioctls::Kvm`.
///
/// # Errors
///
/// When:
/// - [`kvm_ioctls::Kvm::get_msr_index_list()`] errors.
pub fn get_msrs_to_save(kvm_fd: &Kvm) -> Result<MsrList, MsrError> {
    let mut msr_index_list = kvm_fd
        .get_msr_index_list()
        .map_err(MsrError::GetMsrIndexList)?;
    msr_index_list.retain(|msr_index| msr_should_serialize(*msr_index));
    Ok(msr_index_list)
}

// List of MSRs that cannot be dumped.
//
// KVM_GET_MSR_INDEX_LIST returns some MSR indices that KVM_GET_MSRS fails to get depending on
// configuration. For example, Firecracker disables PMU by default in CPUID normalization for CPUID
// leaf 0xA. Due to this, some PMU-related MSRs cannot be retrieved via KVM_GET_MSRS. The dependency
// on CPUID leaf 0xA can be found in the following link.
// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/x86/kvm/vmx/pmu_intel.c?h=v5.10.176#n325
//
// The list of MSR indices returned by KVM_GET_MSR_INDEX_LIST can be found in the following link
// (`msrs_to_save_all` + `num_emulated_msrs`).
// https://elixir.bootlin.com/linux/v5.10.176/source/arch/x86/kvm/x86.c#L1211
const UNDUMPABLE_MSR_RANGES: [MsrRange; 17] = [
    // - MSR_ARCH_PERFMON_FIXED_CTRn (0x309..=0x30C): CPUID.0Ah:EDX[0:4] > 0
    MSR_RANGE!(MSR_ARCH_PERFMON_FIXED_CTR0, 4),
    // - MSR_CORE_PERF_FIXED_CTR_CTRL (0x38D): CPUID:0Ah:EAX[7:0] > 1
    // - MSR_CORE_PERF_GLOBAL_STATUS (0x38E): CPUID:0Ah:EAX[7:0] > 0 ||
    //   (CPUID.(EAX=07H,ECX=0):EBX[25] = 1 && CPUID.(EAX=014H,ECX=0):ECX[0] = 1)
    // - MSR_CORE_PERF_GLOBAL_CTRL (0x39F): CPUID.0AH: EAX[7:0] > 0
    // - MSR_CORE_PERF_GLOBAL_OVF_CTRL (0x390): CPUID.0AH: EAX[7:0] > 0 && CPUID.0AH: EAX[7:0] <= 3
    MSR_RANGE!(MSR_CORE_PERF_FIXED_CTR_CTRL, 4),
    // - MSR_ARCH_PERFMON_PERFCTRn (0xC1..=0xC8): CPUID.0AH:EAX[15:8] > 0
    MSR_RANGE!(MSR_ARCH_PERFMON_PERFCTR0, 8),
    // - MSR_ARCH_PERFMON_EVENTSELn (0x186..=0x18D): CPUID.0AH:EAX[15:8] > 0
    MSR_RANGE!(MSR_ARCH_PERFMON_EVENTSEL0, 8),
    // On kernel 4.14, IA32_MCG_CTL (0x17B) can be retrieved only if IA32_MCG_CAP.CTL_P[8] = 1 for
    // vCPU. IA32_MCG_CAP can be set up via KVM_X86_SETUP_MCE API, but Firecracker doesn't use it.
    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/x86/kvm/x86.c?h=v4.14.311#n2553
    MSR_RANGE!(MSR_IA32_MCG_CTL),
    // Firecracker is not tested with nested virtualization. Some CPU templates intentionally
    // disable nested virtualization. If nested virtualization is disabled, VMX-related MSRs cannot
    // be dumped. It can be seen in the following link that VMX-related MSRs depend on whether
    // nested virtualization is allowed.
    // https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/x86/kvm/vmx/vmx.c?h=v5.10.176#n1950
    // - MSR_IA32_VMX_BASIC (0x480)
    // - MSR_IA32_VMX_PINBASED_CTLS (0x481)
    // - MSR_IA32_VMX_PROCBASED_CTLS (0x482)
    // - MSR_IA32_VMX_EXIT_CTLS (0x483)
    // - MSR_IA32_VMX_ENTRY_CTLS (0x484)
    // - MSR_IA32_VMX_MISC (0x485)
    // - MSR_IA32_VMX_CR0_FIXED0 (0x486)
    // - MSR_IA32_VMX_CR0_FIXED1 (0x487)
    // - MSR_IA32_VMX_CR4_FIXED0 (0x488)
    // - MSR_IA32_VMX_CR4_FIXED1 (0x489)
    // - MSR_IA32_VMX_VMCS_ENUM (0x48A)
    // - MSR_IA32_VMX_PROCBASED_CTLS2 (0x48B)
    // - MSR_IA32_VMX_EPT_VPID_CAP (0x48C)
    // - MSR_IA32_VMX_TRUE_PINBASED_CTLS (0x48D)
    // - MSR_IA32_VMX_TRUE_PROCBASED_CTLS (0x48E)
    // - MSR_IA32_VMX_TRUE_EXIT_CTLS (0x48F)
    // - MSR_IA32_VMX_TRUE_ENTRY_CTLS (0x490)
    // - MSR_IA32_VMX_VMFUNC (0x491)
    MSR_RANGE!(MSR_IA32_VMX_BASIC, 18),
    // Firecracker doesn't work with Hyper-V. KVM_GET_MSRS fails on kernel 4.14 because it doesn't
    // have the following patch.
    // https://github.com/torvalds/linux/commit/44883f01fe6ae436a8604c47d8435276fef369b0
    // - HV_X64_MSR_GUEST_OS_ID (0x40000000)
    // - HV_X64_MSR_HYPERCALL (0x40000001)
    // - HV_X64_MSR_VP_INDEX (0x40000002)
    // - HV_X64_MSR_RESET (0x40000003)
    // - HV_X64_MSR_VP_RUNTIME (0x40000010)
    // - HV_X64_MSR_TIME_REF_COUNT (0x40000020)
    // - HV_X64_MSR_REFERENCE_TSC (0x40000021)
    // - HV_X64_MSR_TSC_FREQUENCY (0x40000022)
    // - HV_X64_MSR_APIC_FREQUENCY (0x40000023)
    // - HV_X64_MSR_VP_ASSIST_PAGE (0x40000073)
    // - HV_X64_MSR_SCONTROL (0x40000080)
    // - HV_X64_MSR_STIMER0_CONFIG (0x400000b0)
    // - HV_X64_MSR_SYNDBG_CONTROL (0x400000f1)
    // - HV_X64_MSR_SYNDBG_STATUS (0x400000f2)
    // - HV_X64_MSR_SYNDBG_SEND_BUFFER (0x400000f3)
    // - HV_X64_MSR_SYNDBG_RECV_BUFFER (0x400000f4)
    // - HV_X64_MSR_SYNDBG_PENDING_BUFFER (0x400000f5)
    // - HV_X64_MSR_SYNDBG_OPTIONS (0x400000ff)
    // - HV_X64_MSR_CRASH_Pn (0x40000100..=0x40000104)
    // - HV_X64_MSR_CRASH_CTL (0x40000105)
    // - HV_X64_MSR_REENLIGHTENMENT_CONTROL (0x40000106)
    // - HV_X64_MSR_TSC_EMULATION_CONTROL (0x40000107)
    // - HV_X64_MSR_TSC_EMULATION_STATUS (0x40000108)
    // - HV_X64_MSR_TSC_INVARIANT_CONTROL (0x40000118)
    MSR_RANGE!(HV_X64_MSR_GUEST_OS_ID, 4),
    MSR_RANGE!(HV_X64_MSR_VP_RUNTIME),
    MSR_RANGE!(HV_X64_MSR_TIME_REF_COUNT, 4),
    MSR_RANGE!(HV_X64_MSR_SCONTROL),
    MSR_RANGE!(HV_X64_MSR_VP_ASSIST_PAGE),
    MSR_RANGE!(HV_X64_MSR_STIMER0_CONFIG),
    MSR_RANGE!(HV_X64_MSR_SYNDBG_CONTROL, 5),
    MSR_RANGE!(HV_X64_MSR_SYNDBG_OPTIONS),
    MSR_RANGE!(HV_X64_MSR_CRASH_P0, 6),
    MSR_RANGE!(HV_X64_MSR_REENLIGHTENMENT_CONTROL, 3),
    MSR_RANGE!(HV_X64_MSR_TSC_INVARIANT_CONTROL),
];

/// Checks whether a particular MSR can be dumped.
///
/// # Arguments
///
/// * `index` - The index of the MSR that is checked whether it's needed for serialization.
pub fn msr_is_dumpable(index: u32) -> bool {
    !UNDUMPABLE_MSR_RANGES
        .iter()
        .any(|range| range.contains(index))
}

/// Returns the list of dumpable MSR indices.
///
/// # Arguments
///
/// * `kvm_fd` - Ref to `Kvm`
///
/// # Errors
///
/// When:
/// - [`kvm_ioctls::Kvm::get_msr_index_list()`] errors.
pub fn get_msrs_to_dump(kvm_fd: &Kvm) -> Result<MsrList, MsrError> {
    let mut msr_index_list = kvm_fd
        .get_msr_index_list()
        .map_err(MsrError::GetMsrIndexList)?;

    msr_index_list.retain(|msr_index| msr_is_dumpable(*msr_index));
    Ok(msr_index_list)
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
pub fn set_msrs(vcpu: &VcpuFd, msr_entries: &[kvm_msr_entry]) -> Result<(), MsrError> {
    let msrs = Msrs::from_entries(msr_entries)?;
    vcpu.set_msrs(&msrs)
        .map_err(MsrError::SetMsrs)
        .and_then(|msrs_written| {
            if msrs_written == msrs.as_fam_struct_ref().nmsrs as usize {
                Ok(())
            } else {
                Err(MsrError::SetMsrsIncomplete)
            }
        })
}

#[cfg(test)]
mod tests {
    use kvm_ioctls::Kvm;

    use super::*;

    fn create_vcpu() -> VcpuFd {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        vm.create_vcpu(0).unwrap()
    }

    #[test]
    fn test_msr_list_to_serialize() {
        for range in SERIALIZABLE_MSR_RANGES.iter() {
            for msr in range.base..(range.base + range.nmsrs) {
                let should = !matches!(msr, MSR_IA32_MCG_CTL);
                assert_eq!(msr_should_serialize(msr), should);
            }
        }
    }

    #[test]
    fn test_msr_list_to_dump() {
        for range in UNDUMPABLE_MSR_RANGES.iter() {
            for msr in range.base..(range.base + range.nmsrs) {
                assert!(!msr_is_dumpable(msr));
            }
        }
    }

    #[test]
    #[allow(clippy::cast_ptr_alignment)]
    fn test_setup_msrs() {
        let vcpu = create_vcpu();
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

    #[test]
    fn test_set_valid_msrs() {
        // Test `set_msrs()` with a valid MSR entry. It should succeed, as IA32_TSC MSR is listed
        // in supported MSRs as of now.
        let vcpu = create_vcpu();
        let msr_entries = vec![kvm_msr_entry {
            index: MSR_IA32_TSC,
            data: 0,
            ..Default::default()
        }];
        set_msrs(&vcpu, &msr_entries).unwrap();
    }

    #[test]
    fn test_set_invalid_msrs() {
        // Test `set_msrs()` with an invalid MSR entry. It should fail, as MSR index 2 is not
        // listed in supported MSRs as of now. If hardware vendor adds this MSR index and KVM
        // supports this MSR, we need to change the index as needed.
        let vcpu = create_vcpu();
        let msr_entries = vec![kvm_msr_entry {
            index: 2,
            ..Default::default()
        }];
        assert_eq!(
            set_msrs(&vcpu, &msr_entries).unwrap_err(),
            MsrError::SetMsrsIncomplete
        );
    }
}
