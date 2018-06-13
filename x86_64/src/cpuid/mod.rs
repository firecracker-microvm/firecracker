use std::result;

use cpuid::cpu_leaf::*;
use data_model::vm::CpuFeaturesTemplate;
use kvm::CpuId;

mod cpu_leaf;

mod c3_template;
mod t2_template;

// constants for setting the fields of kvm_cpuid2 structures
// CPUID bits in ebx, ecx, and edx.
const EBX_CLFLUSH_CACHELINE: u32 = 8; // Flush a cache line size.

// The APIC ID shift in leaf 0xBh specifies the number of bits to shit the x2APIC ID to get a
// unique topology of the next level. This allows 64 logical processors/package.
const LEAFBH_INDEX1_APICID_SHIFT: u32 = 6;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    VcpuCountOverflow,
}

/// This function is used for setting leaf 01H EBX[23-16]
/// The maximum number of addressable logical CPUs is computed as the closest power of 2
/// higher or equal to the CPU count configured by the user
fn get_max_addressable_lprocessors(cpu_count: u8) -> result::Result<u8, Error> {
    let mut max_addressable_lcpu = (cpu_count as f64).log2().ceil();
    max_addressable_lcpu = (2 as f64).powf(max_addressable_lcpu);
    // check that this number is still an u8
    if max_addressable_lcpu > u8::max_value().into() {
        return Err(Error::VcpuCountOverflow);
    }
    Ok(max_addressable_lcpu as u8)
}

// Converts a 4 letters string to u32; if the string has more than 4 letters, only the first 4 are returned
fn str_to_u32(string: &str) -> u32 {
    let str_bytes = string.as_bytes();
    return (str_bytes[0] as u32) << 24 | (str_bytes[1] as u32) << 16 | (str_bytes[2] as u32) << 8
        | (str_bytes[3] as u32);
}

pub fn set_cpuid_template(template: CpuFeaturesTemplate, kvm_cpuid: &mut CpuId) {
    let entries = kvm_cpuid.mut_entries_slice();
    match template {
        CpuFeaturesTemplate::T2 => t2_template::set_cpuid_entries(entries),
        CpuFeaturesTemplate::C3 => c3_template::set_cpuid_entries(entries),
    }
}

/// Sets up the cpuid entries for the given vcpu
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn filter_cpuid(
    cpu_id: u8,
    cpu_count: u8,
    ht_enabled: bool,
    kvm_cpuid: &mut CpuId,
) -> Result<()> {
    let entries = kvm_cpuid.mut_entries_slice();
    let max_addr_cpu = get_max_addressable_lprocessors(cpu_count).unwrap() as u32;
    for entry in entries.iter_mut() {
        match entry.function {
            0x1 => {
                // X86 hypervisor feature
                entry.ecx |= 1 << leaf_0x1::ecx::TSC_DEADLINE_TIMER_SHIFT;
                entry.ecx |= 1 << leaf_0x1::ecx::HYPERVISOR_SHIFT;
                entry.ebx = ((cpu_id as u32) << leaf_0x1::ebx::APICID_SHIFT) as u32
                    | (EBX_CLFLUSH_CACHELINE << leaf_0x1::ebx::CLFLUSH_SIZE_SHIFT);
                entry.ebx |= max_addr_cpu << leaf_0x1::ebx::CPU_COUNT_SHIFT;
                // Make sure that HTT is disabled
                entry.edx &= !(1 << leaf_0x1::edx::HTT_SHIFT);
                // Max APIC IDs reserved field is Valid
                // A value of 1 for HTT indicates the value in CPUID.1.EBX[23:16]
                // (the Maximum number of addressable IDs for logical processors in this package) is
                // valid for the package
                if cpu_count > 1 {
                    entry.edx |= 1 << leaf_0x1::edx::HTT_SHIFT;
                }
            }
            0x4 => {
                // Deterministic Cache Parameters Leaf
                // Only use the last 3 bits of EAX[5:32] because the level is encoded in EAX[5:7]
                let cache_level = (entry.eax >> leaf_0x4::eax::CACHE_LEVEL) & (0b111 as u32);
                match cache_level {
                    // L1 & L2 Cache
                    1 | 2 => {
                        // Set the maximum addressable IDS sharing the data cache to zero
                        // when you only have 1 vcpu because there are no other threads on
                        // the machine to share the data/instruction cache
                        // This sets EAX[25:14]
                        entry.eax &= !(0b111111111111 << leaf_0x4::eax::MAX_ADDR_IDS_SHARING_CACHE);
                        if cpu_count > 1 && ht_enabled {
                            // There are 2 hyperthreads sharing L1 & L2 caches
                            entry.eax |= 1 << leaf_0x4::eax::MAX_ADDR_IDS_SHARING_CACHE;
                        }
                    }
                    // L3 Cache
                    3 => {
                        // Set the maximum addressable IDS sharing the data cache to zero
                        // when you only have 1 vcpu because there are no other logical cores on
                        // the machine to share the data/instruction cache
                        // This sets EAX[25:14]
                        entry.eax &= !(0b111111111111 << leaf_0x4::eax::MAX_ADDR_IDS_SHARING_CACHE);
                        if cpu_count > 1 {
                            entry.eax |= ((cpu_count - 1) as u32)
                                << leaf_0x4::eax::MAX_ADDR_IDS_SHARING_CACHE;
                        }
                    }
                    _ => (),
                }

                // Maximum number of addressable IDs for processor cores in the physical package
                // should be the same on all cache levels
                // This sets EAX[31:26]
                entry.eax &= !(0b111111 << leaf_0x4::eax::MAX_ADDR_IDS_IN_PACKAGE);
                if cpu_count >= 2 {
                    // We don't handle properly the case where we have more than one socket
                    // Put all cores in the same socket
                    entry.eax |= ((cpu_count - 1) as u32) << leaf_0x4::eax::MAX_ADDR_IDS_IN_PACKAGE;
                }
            }
            0x6 => {
                // Disable Turbo Boost
                entry.eax &= !(1 << leaf_0x6::eax::TURBO_BOOST_SHIFT);
                // Clear X86 EPB feature.  No frequency selection in the hypervisor.
                entry.ecx &= !(1 << leaf_0x6::ecx::EPB_SHIFT);
            }
            0xA => {
                // Architectural Performance Monitor Leaf
                // Disable PMU
                entry.eax = 0;
                entry.ebx = 0;
                entry.ecx = 0;
                entry.edx = 0;
            }
            0xB => {
                // Hide the actual topology of the underlying host
                match entry.index {
                    0 => {
                        // Thread Level Topology; index = 0
                        if cpu_count == 1 {
                            // No APIC ID at the next level, set EAX to 0
                            entry.eax = 0;
                            // Set the numbers of logical processors to 1
                            entry.ebx = 1;
                            // There are no hyperthreads for 1 VCPU, set the level type = 2 (Core)
                            entry.ecx =
                                leaf_0xb::LEVEL_TYPE_CORE << leaf_0xb::ecx::LEVEL_TYPE_SHIFT;
                        } else {
                            if ht_enabled {
                                // When HT is enabled, there are 2 logical cores at this level
                                // To get the next level APIC ID, shift right with 1 because we have
                                // maximum 2 hyperthreads per core that can be represented with 1 bit
                                entry.eax = 1;
                                entry.ebx = 2;
                            } else {
                                // When HT is disabled, there is 1 logical core at this level
                                // No bits used from the APIC id at the thread level
                                entry.eax = 0;
                                entry.ebx = 1;
                            }

                            // enforce this level to be of type thread
                            entry.ecx =
                                leaf_0xb::LEVEL_TYPE_THREAD << leaf_0xb::ecx::LEVEL_TYPE_SHIFT;
                        }
                    }
                    1 => {
                        // Core Level Processor Topology; index = 1
                        entry.eax = LEAFBH_INDEX1_APICID_SHIFT;
                        if cpu_count == 1 {
                            // For 1 vCPU, this level is invalid
                            entry.ebx = 0;
                            // ECX[7:0] = entry.index; ECX[15:8] = 0 (Invalid Level)
                            entry.ecx = (entry.index as u32)
                                | (leaf_0xb::LEVEL_TYPE_INVALID << leaf_0xb::ecx::LEVEL_TYPE_SHIFT);
                        } else {
                            entry.ebx = cpu_count as u32;
                            entry.ecx = (entry.index as u32)
                                | (leaf_0xb::LEVEL_TYPE_CORE << leaf_0xb::ecx::LEVEL_TYPE_SHIFT);
                        }
                    }
                    level => {
                        // Core Level Processor Topology; index >=2
                        // No other levels available; This should already be set to correctly,
                        // and it is added here as a "re-enforcement" in case we run on
                        // different hardware
                        entry.eax = 0;
                        entry.ebx = 0;
                        entry.ecx = level;
                    }
                }
                // EDX bits 31..0 contain x2APIC ID of current logical processor
                // x2APIC increases the size of the APIC ID from 8 bits to 32 bits
                entry.edx = cpu_id as u32;
            }
            _ => (),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvm::{Kvm, MAX_KVM_CPUID_ENTRIES};
    use kvm_sys::kvm_cpuid_entry2;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_get_max_addressable_lprocessors() {
        assert_eq!(get_max_addressable_lprocessors(1).unwrap(), 1);
        assert_eq!(get_max_addressable_lprocessors(2).unwrap(), 2);
        assert_eq!(get_max_addressable_lprocessors(4).unwrap(), 4);
        assert_eq!(get_max_addressable_lprocessors(6).unwrap(), 8);
        assert!(get_max_addressable_lprocessors(u8::max_value()).is_err());
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn test_cpuid() {
        let kvm = Kvm::new().unwrap();
        let mut kvm_cpuid: CpuId = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
        match filter_cpuid(0, 1, true, &mut kvm_cpuid) {
            Ok(_) => (),
            _ => assert!(false),
        };

        set_cpuid_template(CpuFeaturesTemplate::T2, &mut kvm_cpuid);

        let entries = kvm_cpuid.mut_entries_slice();
        // TODO: This should be tested as part of the CI; only check that the function result is ok
        // after moving this to the CI
        // Test the extended topology
        // See https://www.scss.tcd.ie/~jones/CS4021/processor-identification-cpuid-instruction-note.pdf
        let leaf11_index0 = kvm_cpuid_entry2 {
            function: 11,
            index: 0,
            flags: 1,
            eax: 0,
            ebx: 1, // nr of hyperthreads/core
            ecx: leaf_0xb::LEVEL_TYPE_CORE << leaf_0xb::ecx::LEVEL_TYPE_SHIFT, // ECX[15:8] = 2 (Core Level)
            edx: 0,                                                            // EDX = APIC ID = 0
            padding: [0, 0, 0],
        };
        assert!(entries.contains(&leaf11_index0));
        let leaf11_index1 = kvm_cpuid_entry2 {
            function: 11,
            index: 1,
            flags: 1,
            eax: LEAFBH_INDEX1_APICID_SHIFT,
            ebx: 0,
            ecx: 1, // ECX[15:8] = 0 (Invalid Level) & ECX[7:0] = 1 (Level Number)
            edx: 0, // EDX = APIC ID = 0
            padding: [0, 0, 0],
        };
        assert!(entries.contains(&leaf11_index1));
        let leaf11_index2 = kvm_cpuid_entry2 {
            function: 11,
            index: 2,
            flags: 1,
            eax: 0,
            ebx: 0, // nr of hyperthreads/core
            ecx: 2, // ECX[15:8] = 0 (Invalid Level) & ECX[7:0] = 2 (Level Number)
            edx: 0, // EDX = APIC ID = 0
            padding: [0, 0, 0],
        };
        assert!(entries.contains(&leaf11_index2));
    }
}
