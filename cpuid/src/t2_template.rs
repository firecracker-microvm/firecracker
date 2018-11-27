// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use cpu_leaf::*;
use kvm_gen::kvm_cpuid_entry2;

/// Sets up the cpuid entries for a given VCPU following a T2 template.
pub fn set_cpuid_entries(entries: &mut [kvm_cpuid_entry2]) {
    for entry in entries.iter_mut() {
        match entry.function {
            0x1 => {
                // Set CPU Basic Information
                // EAX[20:27] Extended Family ID = 0
                entry.eax &= !(0b11111111 << leaf_0x1::eax::EXTENDED_FAMILY_ID_SHIFT);

                // EAX[19:16] Extended Processor Model ID = 3 (Haswell)
                entry.eax &= !(0b1111 << leaf_0x1::eax::EXTENDED_PROCESSOR_MODEL_SHIFT);
                entry.eax |= 3 << leaf_0x1::eax::EXTENDED_PROCESSOR_MODEL_SHIFT;

                // EAX[13:12] Processor Type = 0 (Primary processor)
                entry.eax &= !(0b11 << leaf_0x1::eax::PROCESSOR_TYPE_SHIFT);

                // EAX[11:8] Processor Family = 6
                entry.eax &= !(0b1111 << leaf_0x1::eax::PROCESSOR_FAMILY_SHIFT);
                entry.eax |= 6 << leaf_0x1::eax::PROCESSOR_FAMILY_SHIFT;

                // EAX[7:4] Processor Model = 15
                entry.eax &= !(0b1111 << leaf_0x1::eax::PROCESSOR_MODEL_SHIFT);
                entry.eax |= 15 << leaf_0x1::eax::PROCESSOR_MODEL_SHIFT;

                // EAX[0:3] Stepping = 2
                entry.eax &= !(0b1111 as u32);
                entry.eax |= 2 as u32;

                // Disable Features
                entry.ecx &= !(1 << leaf_0x1::ecx::DTES64_SHIFT);
                entry.ecx &= !(1 << leaf_0x1::ecx::MONITOR_SHIFT);
                entry.ecx &= !(1 << leaf_0x1::ecx::DS_CPL_SHIFT);
                entry.ecx &= !(1 << leaf_0x1::ecx::TM2_SHIFT);
                entry.ecx &= !(1 << leaf_0x1::ecx::CNXT_ID);
                entry.ecx &= !(1 << leaf_0x1::ecx::SDBG_SHIFT);
                entry.ecx &= !(1 << leaf_0x1::ecx::XTPR_UPDATE_SHIFT);
                entry.ecx &= !(1 << leaf_0x1::ecx::PDCM_SHIFT);
                entry.ecx &= !(1 << leaf_0x1::ecx::OSXSAVE_SHIFT);

                entry.edx &= !(1 << leaf_0x1::edx::PSN_SHIFT);
                entry.edx &= !(1 << leaf_0x1::edx::DS_SHIFT);
                entry.edx &= !(1 << leaf_0x1::edx::ACPI_SHIFT);
                entry.edx &= !(1 << leaf_0x1::edx::SS_SHIFT);
                entry.edx &= !(1 << leaf_0x1::edx::TM_SHIFT);
                entry.edx &= !(1 << leaf_0x1::edx::PBE_SHIFT);
            }
            0x7 => {
                if entry.index == 0 {
                    entry.ebx &= !(1 << leaf_0x7::index0::ebx::SGX_SHIFT);
                    entry.ebx &= !(1 << leaf_0x7::index0::ebx::HLE_SHIFT);
                    entry.ebx &= !(1 << leaf_0x7::index0::ebx::FPDP_SHIFT);
                    entry.ebx &= !(1 << leaf_0x7::index0::ebx::RTM_SHIFT);
                    entry.ebx &= !(1 << leaf_0x7::index0::ebx::RDT_M_SHIFT);
                    entry.ebx &= !(1 << leaf_0x7::index0::ebx::RDT_A_SHIFT);
                    entry.ebx &= !(1 << leaf_0x7::index0::ebx::AVX512F_SHIFT);
                    entry.ebx &= !(1 << leaf_0x7::index0::ebx::RDSEED_SHIFT);
                    entry.ebx &= !(1 << leaf_0x7::index0::ebx::ADX_SHIFT);
                    entry.ebx &= !(1 << leaf_0x7::index0::ebx::PT_SHIFT);
                    entry.ebx &= !(1 << leaf_0x7::index0::ebx::AVX512CD_SHIFT);
                    entry.ebx &= !(1 << leaf_0x7::index0::ebx::SHA_SHIFT);

                    entry.ecx &= !(1 << leaf_0x7::index0::ecx::RDPID_SHIFT);
                    entry.ecx &= !(1 << leaf_0x7::index0::ecx::SGX_LC_SHIFT);
                }
            }
            0x80000001 => {
                entry.ecx &= !(1 << leaf_0x80000001::ecx::PREFETCH_SHIFT);
                entry.edx &= !(1 << leaf_0x80000001::edx::PDPE1GB_SHIFT);
            }

            _ => (),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm::CpuId;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_t2_cpuid_template() {
        let mut kvm_cpuid = CpuId::new(5);
        {
            let entries = kvm_cpuid.mut_entries_slice();
            entries[0].function = 0x1;
            entries[0].ecx = 0b11;
            entries[0].edx = 0b111;
        }
        {
            let entries = kvm_cpuid.mut_entries_slice();
            entries[1].function = 0x7;
            entries[1].index = 0;
            entries[1].ebx = 0b11;
            entries[1].ecx = 0b111;
        }
        {
            let entries = kvm_cpuid.mut_entries_slice();
            entries[2].function = 0x7;
            // Something other than 0.
            entries[2].index = 2;
        }
        {
            let entries = kvm_cpuid.mut_entries_slice();
            entries[3].function = 0x80000001;
            entries[3].ecx = 0b11;
            entries[3].edx = 0b111;
        }
        {
            let entries = kvm_cpuid.mut_entries_slice();
            // Something other than 0x1, 0x7, 0x80000001.
            entries[4].function = 0x0;
        }

        set_cpuid_entries(&mut kvm_cpuid.mut_entries_slice());

        let cpuid_f1 = kvm_cpuid_entry2 {
            function: 1,
            index: 0,
            flags: 0,
            eax: 0
                & !(0b11111111 << leaf_0x1::eax::EXTENDED_FAMILY_ID_SHIFT)
                & !(0b1111 << leaf_0x1::eax::EXTENDED_PROCESSOR_MODEL_SHIFT)
                | 3 << leaf_0x1::eax::EXTENDED_PROCESSOR_MODEL_SHIFT
                    & !(0b11 << leaf_0x1::eax::PROCESSOR_TYPE_SHIFT)
                    & !(0b1111 << leaf_0x1::eax::PROCESSOR_FAMILY_SHIFT)
                | 6 << leaf_0x1::eax::PROCESSOR_FAMILY_SHIFT
                    & !(0b1111 << leaf_0x1::eax::PROCESSOR_MODEL_SHIFT)
                | 15 << leaf_0x1::eax::PROCESSOR_MODEL_SHIFT & !(0b1111 as u32)
                | 2 as u32,
            ebx: 0,
            ecx: 0b11
                & !(1 << leaf_0x1::ecx::DTES64_SHIFT)
                & !(1 << leaf_0x1::ecx::MONITOR_SHIFT)
                & !(1 << leaf_0x1::ecx::DS_CPL_SHIFT)
                & !(1 << leaf_0x1::ecx::TM2_SHIFT)
                & !(1 << leaf_0x1::ecx::CNXT_ID)
                & !(1 << leaf_0x1::ecx::SDBG_SHIFT)
                & !(1 << leaf_0x1::ecx::XTPR_UPDATE_SHIFT)
                & !(1 << leaf_0x1::ecx::PDCM_SHIFT)
                & !(1 << leaf_0x1::ecx::OSXSAVE_SHIFT),
            edx: 0b111
                & !(1 << leaf_0x1::edx::PSN_SHIFT)
                & !(1 << leaf_0x1::edx::DS_SHIFT)
                & !(1 << leaf_0x1::edx::ACPI_SHIFT)
                & !(1 << leaf_0x1::edx::SS_SHIFT)
                & !(1 << leaf_0x1::edx::TM_SHIFT)
                & !(1 << leaf_0x1::edx::PBE_SHIFT),
            padding: [0, 0, 0],
        };
        {
            let entries = kvm_cpuid.mut_entries_slice();
            assert_eq!(entries[0], cpuid_f1);
        }
        let cpuid_f7_index0 = kvm_cpuid_entry2 {
            function: 0x7,
            index: 0,
            flags: 0,
            eax: 0,
            ebx: 0b11
                & !(1 << leaf_0x7::index0::ebx::SGX_SHIFT)
                & !(1 << leaf_0x7::index0::ebx::HLE_SHIFT)
                & !(1 << leaf_0x7::index0::ebx::FPDP_SHIFT)
                & !(1 << leaf_0x7::index0::ebx::RTM_SHIFT)
                & !(1 << leaf_0x7::index0::ebx::RDT_M_SHIFT)
                & !(1 << leaf_0x7::index0::ebx::RDT_A_SHIFT)
                & !(1 << leaf_0x7::index0::ebx::AVX512F_SHIFT)
                & !(1 << leaf_0x7::index0::ebx::RDSEED_SHIFT)
                & !(1 << leaf_0x7::index0::ebx::ADX_SHIFT)
                & !(1 << leaf_0x7::index0::ebx::PT_SHIFT)
                & !(1 << leaf_0x7::index0::ebx::AVX512CD_SHIFT)
                & !(1 << leaf_0x7::index0::ebx::SHA_SHIFT),
            ecx: 0b111
                & !(1 << leaf_0x7::index0::ecx::RDPID_SHIFT)
                & !(1 << leaf_0x7::index0::ecx::SGX_LC_SHIFT),
            edx: 0,
            padding: [0, 0, 0],
        };
        {
            let entries = kvm_cpuid.mut_entries_slice();
            assert_eq!(entries[1], cpuid_f7_index0);
        }
        let cpuid_f7_index_non0 = kvm_cpuid_entry2 {
            function: 0x7,
            index: 2,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };
        {
            let entries = kvm_cpuid.mut_entries_slice();
            assert_eq!(entries[2], cpuid_f7_index_non0);
        }
        let cpuid_f801 = kvm_cpuid_entry2 {
            function: 0x80000001,
            index: 0,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0b11 & !(1 << leaf_0x80000001::ecx::PREFETCH_SHIFT),
            edx: 0b111 & !(1 << leaf_0x80000001::edx::PDPE1GB_SHIFT),
            padding: [0, 0, 0],
        };
        {
            let entries = kvm_cpuid.mut_entries_slice();
            assert_eq!(entries[3], cpuid_f801);
        }
        let cpuid_nof = kvm_cpuid_entry2 {
            function: 0,
            index: 0,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };
        {
            let entries = kvm_cpuid.mut_entries_slice();
            assert_eq!(entries[4], cpuid_nof);
        }
    }
}
