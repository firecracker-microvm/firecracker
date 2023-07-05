// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use arch::x86_64::cpu_model::CpuModel;
use arch::x86_64::msr::{ArchCapaMSRFlags, MSR_IA32_ARCH_CAPABILITIES};
use kvm_bindings::{kvm_cpuid_entry2, kvm_msr_entry, CpuId};

use crate::bit_helper::BitHelper;
use crate::cpu_leaf::*;
use crate::template::intel::validate_vendor_id;
use crate::transformer::*;

fn update_extended_feature_info_entry(
    entry: &mut kvm_cpuid_entry2,
    _vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpu_leaf::leaf_0x80000001::*;

    entry
        .ecx
        .write_bit(ecx::SSE4A_BITINDEX, false)
        .write_bit(ecx::MISALIGN_SSE_BITINDEX, false)
        .write_bit(ecx::PREFETCH_BITINDEX, false)
        .write_bit(ecx::MWAIT_EXTENDED_BITINDEX, false);

    entry
        .edx
        .write_bit(edx::MMX_EXT_BITINDEX, false)
        .write_bit(edx::MMX_BITINDEX, false)
        .write_bit(edx::FXSR_BITINDEX, false)
        .write_bit(edx::FFXSR_BITINDEX, false)
        .write_bit(edx::PDPE1GB_BITINDEX, false);

    Ok(())
}

/// Sets up the CPUID entries for a given VCPU following the T2CL template.
struct T2CLCpuidTransformer;

impl CpuidTransformer for T2CLCpuidTransformer {
    fn entry_transformer_fn(&self, entry: &mut kvm_cpuid_entry2) -> Option<EntryTransformerFn> {
        match entry.function {
            leaf_0x1::LEAF_NUM => Some(crate::t2::update_feature_info_entry),
            leaf_0x7::LEAF_NUM => Some(crate::t2::update_structured_extended_entry),
            leaf_0xd::LEAF_NUM => Some(crate::t2::update_xsave_features_entry),
            leaf_0x80000001::LEAF_NUM => Some(update_extended_feature_info_entry),
            leaf_0x80000008::LEAF_NUM => Some(crate::t2::update_extended_feature_extensions_entry),
            _ => None,
        }
    }
}

fn validate_at_least_cascade_lake() -> Result<(), Error> {
    let cascade_lake = CpuModel {
        extended_family: 0,
        extended_model: 5,
        family: 6,
        model: 5,
        stepping: 7,
    };

    if CpuModel::get_cpu_model() < cascade_lake {
        return Err(Error::InvalidModel);
    }
    Ok(())
}

/// Sets up the CPUID entries for a given VCPU following the T2CL template.
pub fn set_cpuid_entries(kvm_cpuid: &mut CpuId, vm_spec: &VmSpec) -> Result<(), Error> {
    validate_vendor_id()?;
    validate_at_least_cascade_lake()?;
    T2CLCpuidTransformer.process_cpuid(kvm_cpuid, vm_spec)
}

/// Add the MSR entries speciffic to this T2CL template.
pub fn update_msr_entries(msr_entries: &mut Vec<kvm_msr_entry>, default_arch_cap: u64) {
    let arch_cap = ArchCapaMSRFlags::RDCL_NO
        | ArchCapaMSRFlags::IBRS_ALL
        | ArchCapaMSRFlags::SKIP_L1DFL_VMENTRY
        | ArchCapaMSRFlags::MDS_NO
        | ArchCapaMSRFlags::IF_PSCHANGE_MC_NO
        | ArchCapaMSRFlags::TSX_CTRL;

    // Pass through RSBA and RRSBA bits if they are set.
    let rsba_rrbsa = default_arch_cap & (ArchCapaMSRFlags::RSBA | ArchCapaMSRFlags::RRSBA).bits();

    msr_entries.push(kvm_msr_entry {
        index: MSR_IA32_ARCH_CAPABILITIES,
        data: arch_cap.bits() | rsba_rrbsa,
        ..Default::default()
    });
}

static EXTRA_MSR_ENTRIES: &[u32] = &[MSR_IA32_ARCH_CAPABILITIES];

/// Return a list of MSRs specific to this T2CL template.
pub fn msr_entries_to_save() -> &'static [u32] {
    EXTRA_MSR_ENTRIES
}

#[cfg(test)]
mod tests {
    use std::arch::x86_64::__cpuid as host_cpuid;

    use super::*;

    fn is_on_amd() -> bool {
        #[allow(clippy::undocumented_unsafe_blocks)]
        let ebx = unsafe { host_cpuid(0x0) }.ebx;
        // Checking for first 4 brand string letters is enough
        // for test purposes.
        ebx == 0x68747541
    }

    const CASCADE_LAKE: CpuModel = CpuModel {
        extended_family: 0,
        extended_model: 5,
        family: 6,
        model: 5,
        stepping: 7,
    };

    #[test]
    fn test_update_extended_feature_info_entry() {
        use crate::cpu_leaf::leaf_0x80000001::*;

        let mut entry = kvm_cpuid_entry2 {
            ..Default::default()
        };
        let vmspec = VmSpec::new(0, 1, false).unwrap();
        let res = update_extended_feature_info_entry(&mut entry, &vmspec);

        assert!(matches!(res, Ok(())));

        assert_eq!(entry.ecx & (1 << ecx::SSE4A_BITINDEX), 0);
        assert_eq!(entry.ecx & (1 << ecx::MISALIGN_SSE_BITINDEX), 0);
        assert_eq!(entry.ecx & (1 << ecx::PREFETCH_BITINDEX), 0);
        assert_eq!(entry.ecx & (1 << ecx::MWAIT_EXTENDED_BITINDEX), 0);

        assert_eq!(entry.edx & (1 << edx::MMX_EXT_BITINDEX), 0);
        assert_eq!(entry.edx & (1 << edx::MMX_BITINDEX), 0);
        assert_eq!(entry.edx & (1 << edx::FXSR_BITINDEX), 0);
        assert_eq!(entry.edx & (1 << edx::FFXSR_BITINDEX), 0);
        assert_eq!(entry.edx & (1 << edx::PDPE1GB_BITINDEX), 0);
    }

    #[test]
    fn test_entry_transformer_fn() {
        let transformer = T2CLCpuidTransformer;
        let mut entry = kvm_cpuid_entry2 {
            ..Default::default()
        };

        entry.function = leaf_0x1::LEAF_NUM;
        let res = transformer.entry_transformer_fn(&mut entry);
        assert!(matches!(res, Some(_)));

        entry.function = leaf_0x7::LEAF_NUM;
        let res = transformer.entry_transformer_fn(&mut entry);
        assert!(matches!(res, Some(_)));

        entry.function = leaf_0xd::LEAF_NUM;
        let res = transformer.entry_transformer_fn(&mut entry);
        assert!(matches!(res, Some(_)));

        entry.function = leaf_0x80000001::LEAF_NUM;
        let res = transformer.entry_transformer_fn(&mut entry);
        assert!(matches!(res, Some(_)));

        entry.function = leaf_0x80000008::LEAF_NUM;
        let res = transformer.entry_transformer_fn(&mut entry);
        assert!(matches!(res, Some(_)));

        entry.function = leaf_0x8000001d::LEAF_NUM;
        let res = transformer.entry_transformer_fn(&mut entry);
        assert!(matches!(res, None));
    }

    #[test]
    fn test_validate_at_least_cascade_lake() {
        let cpu_model = CpuModel::get_cpu_model();

        // t2cl::validate_at_least_cascade_lake() does not make sense on AMD CPUs.
        if is_on_amd() {
            return;
        }

        let res = validate_at_least_cascade_lake();

        if cpu_model < CASCADE_LAKE {
            assert!(matches!(res, Err(Error::InvalidModel)));
        } else {
            assert!(matches!(res, Ok(())));
        }
    }

    #[test]
    fn test_set_cpuid_entries() {
        let mut cpuid = CpuId::new(0).unwrap();
        let vmspec = VmSpec::new(0, 1, false).unwrap();
        let cpu_model = CpuModel::get_cpu_model();

        // t2cl::set_cpuid_entries() does not make sense on AMD CPUs.
        if is_on_amd() {
            return;
        }

        let res = set_cpuid_entries(&mut cpuid, &vmspec);

        if cpu_model < CASCADE_LAKE {
            assert!(matches!(res, Err(Error::InvalidModel)));
        } else {
            assert!(matches!(res, Ok(())));
        }
    }

    #[test]
    fn test_msr_entries_to_save() {
        let res = msr_entries_to_save();

        assert_eq!(res.len(), 1);
        assert_eq!(res[0], MSR_IA32_ARCH_CAPABILITIES);
    }

    #[test]
    fn test_update_msr_entries() {
        // Case 1: The default IA32_ARCH_CAPABILITIES MSR does not enumerate RSBA and RRSBA.
        let mut msrs = Vec::<kvm_msr_entry>::new();
        let default_arch_cap = 0;
        update_msr_entries(&mut msrs, default_arch_cap);
        let arch_cap = msrs[0];

        assert_eq!(arch_cap.index, MSR_IA32_ARCH_CAPABILITIES);
        assert_eq!(
            arch_cap.data,
            (ArchCapaMSRFlags::RDCL_NO
                | ArchCapaMSRFlags::IBRS_ALL
                | ArchCapaMSRFlags::SKIP_L1DFL_VMENTRY
                | ArchCapaMSRFlags::MDS_NO
                | ArchCapaMSRFlags::IF_PSCHANGE_MC_NO
                | ArchCapaMSRFlags::TSX_CTRL)
                .bits()
        );

        // Case 2: The default IA32_ARCH_CAPABILITIES MSR enumerates both RSBA and RRSBA.
        let mut msrs = Vec::<kvm_msr_entry>::new();
        let default_arch_cap = (ArchCapaMSRFlags::RSBA | ArchCapaMSRFlags::RRSBA).bits();
        update_msr_entries(&mut msrs, default_arch_cap);
        let arch_cap = msrs[0];

        assert_eq!(arch_cap.index, MSR_IA32_ARCH_CAPABILITIES);
        assert_eq!(
            arch_cap.data,
            (ArchCapaMSRFlags::RDCL_NO
                | ArchCapaMSRFlags::IBRS_ALL
                | ArchCapaMSRFlags::RSBA
                | ArchCapaMSRFlags::SKIP_L1DFL_VMENTRY
                | ArchCapaMSRFlags::MDS_NO
                | ArchCapaMSRFlags::IF_PSCHANGE_MC_NO
                | ArchCapaMSRFlags::TSX_CTRL
                | ArchCapaMSRFlags::RRSBA)
                .bits()
        );
    }
}
