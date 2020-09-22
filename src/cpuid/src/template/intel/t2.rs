// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::bit_helper::BitHelper;
use crate::cpu_leaf::*;
use crate::template::intel::validate_vendor_id;
use crate::transformer::*;
use kvm_bindings::{kvm_cpuid_entry2, CpuId};

fn update_feature_info_entry(entry: &mut kvm_cpuid_entry2, _vm_spec: &VmSpec) -> Result<(), Error> {
    use crate::cpu_leaf::leaf_0x1::*;

    entry
        .eax
        // Extended Family ID = 0
        .write_bits_in_range(&eax::EXTENDED_FAMILY_ID_BITRANGE, 0)
        // Extended Processor Model ID = 3 (Haswell)
        .write_bits_in_range(&eax::EXTENDED_PROCESSOR_MODEL_BITRANGE, 3)
        // Processor Type = 0 (Primary processor)
        .write_bits_in_range(&eax::PROCESSOR_TYPE_BITRANGE, 0)
        // Processor Family = 6
        .write_bits_in_range(&eax::PROCESSOR_FAMILY_BITRANGE, 6)
        // Processor Model = 15
        .write_bits_in_range(&eax::PROCESSOR_MODEL_BITRANGE, 15)
        // Stepping = 2
        .write_bits_in_range(&eax::STEPPING_BITRANGE, 2);

    // Disable Features
    entry
        .ecx
        .write_bit(ecx::DTES64_BITINDEX, false)
        .write_bit(ecx::MONITOR_BITINDEX, false)
        .write_bit(ecx::DS_CPL_SHIFT, false)
        .write_bit(ecx::TM2_BITINDEX, false)
        .write_bit(ecx::CNXT_ID_BITINDEX, false)
        .write_bit(ecx::SDBG_BITINDEX, false)
        .write_bit(ecx::XTPR_UPDATE_BITINDEX, false)
        .write_bit(ecx::PDCM_BITINDEX, false)
        .write_bit(ecx::OSXSAVE_BITINDEX, false);

    entry
        .edx
        .write_bit(edx::PSN_BITINDEX, false)
        .write_bit(edx::DS_BITINDEX, false)
        .write_bit(edx::ACPI_BITINDEX, false)
        .write_bit(edx::SS_BITINDEX, false)
        .write_bit(edx::TM_BITINDEX, false)
        .write_bit(edx::PBE_BITINDEX, false);

    Ok(())
}

fn update_structured_extended_entry(
    entry: &mut kvm_cpuid_entry2,
    _vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpu_leaf::leaf_0x7::index0::*;

    if entry.index == 0 {
        entry
            .ebx
            .write_bit(ebx::SGX_BITINDEX, false)
            .write_bit(ebx::HLE_BITINDEX, false)
            .write_bit(ebx::FPDP_BITINDEX, false)
            .write_bit(ebx::RTM_BITINDEX, false)
            .write_bit(ebx::RDT_M_BITINDEX, false)
            .write_bit(ebx::RDT_A_BITINDEX, false)
            .write_bit(ebx::MPX_BITINDEX, false)
            .write_bit(ebx::AVX512F_BITINDEX, false)
            .write_bit(ebx::AVX512DQ_BITINDEX, false)
            .write_bit(ebx::RDSEED_BITINDEX, false)
            .write_bit(ebx::ADX_BITINDEX, false)
            .write_bit(ebx::AVX512IFMA_BITINDEX, false)
            .write_bit(ebx::CLFLUSHOPT_BITINDEX, false)
            .write_bit(ebx::CLWB_BITINDEX, false)
            .write_bit(ebx::PT_BITINDEX, false)
            .write_bit(ebx::AVX512PF_BITINDEX, false)
            .write_bit(ebx::AVX512ER_BITINDEX, false)
            .write_bit(ebx::AVX512CD_BITINDEX, false)
            .write_bit(ebx::SHA_BITINDEX, false)
            .write_bit(ebx::AVX512BW_BITINDEX, false)
            .write_bit(ebx::AVX512VL_BITINDEX, false);

        entry
            .ecx
            .write_bit(ecx::AVX512_VBMI_BITINDEX, false)
            .write_bit(ecx::PKU_BITINDEX, false)
            .write_bit(ecx::OSPKE_BITINDEX, false)
            .write_bit(ecx::AVX512_VPOPCNTDQ_BITINDEX, false)
            .write_bit(ecx::RDPID_BITINDEX, false)
            .write_bit(ecx::SGX_LC_BITINDEX, false);

        entry
            .edx
            .write_bit(edx::AVX512_4VNNIW_BITINDEX, false)
            .write_bit(edx::AVX512_4FMAPS_BITINDEX, false);
    }

    Ok(())
}

fn update_xsave_features_entry(
    entry: &mut kvm_cpuid_entry2,
    _vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpu_leaf::leaf_0xd::*;

    if entry.index == 0 {
        // MPX is masked out with the current template so the size in bytes of the save
        // area should be 0 (or invalid).
        entry
            .eax
            .write_bits_in_range(&index0::eax::MPX_STATE_BITRANGE, 0);

        // AVX-512 instructions are masked out with the current template so the size in bytes
        // of the save area should be 0 (or invalid).
        entry
            .eax
            .write_bits_in_range(&index0::eax::AVX512_STATE_BITRANGE, 0);
    }

    if entry.index == 1 {
        entry
            .eax
            .write_bit(index1::eax::XSAVEC_SHIFT, false)
            .write_bit(index1::eax::XGETBV_SHIFT, false)
            .write_bit(index1::eax::XSAVES_SHIFT, false);
    }

    Ok(())
}

fn update_extended_feature_info_entry(
    entry: &mut kvm_cpuid_entry2,
    _vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpu_leaf::leaf_0x80000001::*;

    entry.ecx.write_bit(ecx::PREFETCH_BITINDEX, false);

    entry.edx.write_bit(edx::PDPE1GB_BITINDEX, false);

    Ok(())
}

/// Sets up the cpuid entries for a given VCPU following a T2 template.
struct T2CpuidTransformer {}

impl CpuidTransformer for T2CpuidTransformer {
    fn entry_transformer_fn(&self, entry: &mut kvm_cpuid_entry2) -> Option<EntryTransformerFn> {
        match entry.function {
            leaf_0x1::LEAF_NUM => Some(update_feature_info_entry),
            leaf_0x7::LEAF_NUM => Some(update_structured_extended_entry),
            leaf_0xd::LEAF_NUM => Some(update_xsave_features_entry),
            leaf_0x80000001::LEAF_NUM => Some(update_extended_feature_info_entry),
            _ => None,
        }
    }
}

/// Sets up the cpuid entries for a given VCPU following a T2 template.
pub fn set_cpuid_entries(kvm_cpuid: &mut CpuId, vm_spec: &VmSpec) -> Result<(), Error> {
    validate_vendor_id()?;
    T2CpuidTransformer {}.process_cpuid(kvm_cpuid, vm_spec)
}
