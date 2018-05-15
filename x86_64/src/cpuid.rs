use kvm::CpuId;

use std::result;

// Basic CPUID Information
mod leaf_0x1 {
    pub mod eax {
        pub const EXTENDED_FAMILY_ID_SHIFT: u32 = 20;
        pub const EXTENDED_PROCESSOR_MODEL_SHIFT: u32 = 16;
        pub const PROCESSOR_TYPE_SHIFT: u32 = 12;
        pub const PROCESSOR_FAMILY_SHIFT: u32 = 8;
        pub const PROCESSOR_MODEL_SHIFT: u32 = 4;
    }

    pub mod ebx {
        // The (fixed) default APIC ID.
        pub const APICID_SHIFT: u32 = 24;
        // Bytes flushed when executing CLFLUSH.
        pub const CLFLUSH_SIZE_SHIFT: u32 = 8;
        // The logical processor count.
        pub const CPU_COUNT_SHIFT: u32 = 16;
    }

    pub mod ecx {
        // DTES64 = 64-bit debug store
        pub const DTES64_SHIFT: u32 = 2;
        // MONITOR = Monitor/MWAIT
        pub const MONITOR_SHIFT: u32 = 3;
        // CPL Qualified Debug Store
        pub const DS_CPL_SHIFT: u32 = 4;
        // 5 = VMX (Virtual Machine Extensions)
        // 6 = SMX (Safer Mode Extensions)
        // 7 = EIST (Enhanced Intel SpeedStep® technology)
        // TM2 = Thermal Monitor 2
        pub const TM2_SHIFT: u32 = 8;
        // CNXT_ID = L1 Context ID (L1 data cache can be set to adaptive/shared mode)
        pub const CNXT_ID: u32 = 10;
        // 11 = SDBG (cpu supports IA32_DEBUG_INTERFACE MSR for silicon debug)
        // XTPR_UPDATE = xTPR Update Control
        pub const XTPR_UPDATE_SHIFT: u32 = 14;
        // PDCM = Perfmon and Debug Capability
        pub const PDCM_SHIFT: u32 = 15;
        // 18 = DCA Direct Cache Access (prefetch data from a memory mapped device)
        pub const TSC_DEADLINE_TIMER_SHIFT: u32 = 24;
        pub const OSXSAVE_SHIFT: u32 = 27;
        // Cpu is running on a hypervisor.
        pub const HYPERVISOR_SHIFT: u32 = 31;
    }

    pub mod edx {
        pub const PSN_SHIFT: u32 = 18; // Processor Serial Number
        pub const DS_SHIFT: u32 = 21; // Debug Store.
        pub const ACPI_SHIFT: u32 = 22; // Thermal Monitor and Software Controlled Clock Facilities.
        pub const SS_SHIFT: u32 = 27; // Self Snoop
        pub const HTT_SHIFT: u32 = 28; // Hyper Threading Enabled.
        pub const TM_SHIFT: u32 = 29; // Thermal Monitor.
        pub const PBE_SHIFT: u32 = 31; // Pending Break Enable.
    }
}

// Deterministic Cache Parameters Leaf
mod leaf_0x4 {
    pub mod eax {
        pub const CACHE_LEVEL: u32 = 5;
        pub const MAX_ADDR_IDS_SHARING_CACHE: u32 = 14;
        pub const MAX_ADDR_IDS_IN_PACKAGE: u32 = 26;
    }
}

// Thermal and Power Management Leaf
mod leaf_0x6 {
    pub mod eax {
        pub const TURBO_BOOST_SHIFT: u32 = 1;
    }

    pub mod ecx {
        // "Energy Performance Bias" bit.
        pub const EPB_SHIFT: u32 = 3;
    }
}

// Structured Extended Feature Flags Enumeration Leaf
mod leaf_0x7 {
    pub mod index0 {
        pub mod ebx {
            // 1 = TSC_ADJUST
            pub const SGX_SHIFT: u32 = 2;
            // 3 = BMI
            pub const HLE_SHIFT: u32 = 4;
            // 5 = AVX2
            // FPU Data Pointer updated only on x87 exceptions if 1.
            pub const FPDP_SHIFT: u32 = 6;
            // 7 = SMEP (Supervisor-Mode Execution Prevention if 1)
            // 8 = BMI2
            // 9 = Enhanced REP MOVSB/STOSB if 1
            // 10 = INVPCID
            pub const RTM_SHIFT: u32 = 11;
            // Intel® Resource Director Technology (Intel® RDT) Monitoring
            pub const RDT_M_SHIFT: u32 = 12;
            // 13 = Deprecates FPU CS and FPU DS values if 1
            // 14 = MPX (Intel® Memory Protection Extensions)
            // RDT = Intel® Resource Director Technology
            pub const RDT_A_SHIFT: u32 = 15;
            // AVX-512 Foundation instructions
            pub const AVX512F_SHIFT: u32 = 16;
            pub const RDSEED_SHIFT: u32 = 18;
            pub const ADX_SHIFT: u32 = 19;
            // 20 = SMAP (Supervisor-Mode Access Prevention)
            // 21 & 22 reserved
            // 23 = CLFLUSH_OPT (flushing multiple cache lines in parallel within a single logical processor)
            // 24 = CLWB (Cache Line Write Back)
            // PT = Intel Processor Trace
            pub const PT_SHIFT: u32 = 25;
            // AVX512CD = AVX512 Conflict Detection
            pub const AVX512CD_SHIFT: u32 = 28;
            // Intel Secure Hash Algorithm Extensions
            pub const SHA_SHIFT: u32 = 29;
            // 30 - 32 reserved
        }

        pub mod ecx {
            // 0 = PREFETCHWT1 (move data closer to the processor in anticipation of future use)
            // 1 = reserved
            // 2 = UMIP (User Mode Instruction Prevention)
            // 3 = PKU (Protection Keys for user-mode pages)
            // 4 = OSPKE (If 1, OS has set CR4.PKE to enable protection keys)
            // 5- 16 reserved
            // 21 - 17 = The value of MAWAU used by the BNDLDX and BNDSTX instructions in 64-bit mode.
            pub const RDPID_SHIFT: u32 = 22; // Read Processor ID
                                             // 23 - 29 reserved
                                             // SGX_LC = SGX Launch Configuration
            pub const SGX_LC_SHIFT: u32 = 30;
            // 31 reserved
        }
    }
}

mod leaf_0x80000001 {
    pub mod ecx {
        pub const PREFETCH_SHIFT: u32 = 8; // 3DNow! PREFETCH/PREFETCHW instructions
    }

    pub mod edx {
        pub const PDPE1GB_SHIFT: u32 = 26; // 1-GByte pages are available if 1.
    }
}

// Extended Topology Leaf
mod leaf_0xb {
    pub const LEVEL_TYPE_INVALID: u32 = 0;
    pub const LEVEL_TYPE_THREAD: u32 = 1;
    pub const LEVEL_TYPE_CORE: u32 = 2;
    pub mod ecx {
        pub const LEVEL_TYPE_SHIFT: u32 = 8; // Shift for setting level type for leaf 11
    }
}

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

pub enum CPUFeaturesTemplate {
    T2,
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

pub fn set_cpuid_template(template: CPUFeaturesTemplate, kvm_cpuid: &mut CpuId) -> Result<()> {
    let entries = kvm_cpuid.mut_entries_slice();
    match template {
        CPUFeaturesTemplate::T2 => {
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
                        entry.ebx &= !(1 << leaf_0x1::ecx::DTES64_SHIFT);
                        entry.ebx &= !(1 << leaf_0x1::ecx::MONITOR_SHIFT);
                        entry.ebx &= !(1 << leaf_0x1::ecx::DS_CPL_SHIFT);
                        entry.ebx &= !(1 << leaf_0x1::ecx::TM2_SHIFT);
                        entry.ebx &= !(1 << leaf_0x1::ecx::CNXT_ID);
                        entry.ebx &= !(1 << leaf_0x1::ecx::XTPR_UPDATE_SHIFT);
                        entry.ebx &= !(1 << leaf_0x1::ecx::PDCM_SHIFT);
                        entry.ebx &= !(1 << leaf_0x1::ecx::OSXSAVE_SHIFT);

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
                    0x80000002 => {
                        // set this leaf to "Intel(R) Xeon(R)"
                        entry.eax = str_to_u32("etnI");
                        entry.ebx = str_to_u32(")R(l");
                        entry.ecx = str_to_u32("oeX ");
                        entry.edx = str_to_u32(")R(n");
                    }
                    0x80000003 => {
                        // set this leaf to " Processor"
                        entry.eax = str_to_u32("orP ");
                        entry.ebx = str_to_u32("ssec");
                        entry.ecx = str_to_u32("  ro");
                        entry.edx = 0;
                    }
                    0x80000004 => {
                        entry.eax = 0;
                        entry.ebx = 0;
                        entry.ecx = 0;
                        entry.edx = 0;
                    }

                    _ => (),
                }
            }

            Ok(())
        }
    }
}

/// Sets up the cpuid entries for the given vcpu
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn filter_cpuid(cpu_id: u8, cpu_count: u8, kvm_cpuid: &mut CpuId) -> Result<()> {
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
                // Make sure that Hyperthreading is disabled
                entry.edx &= !(1 << leaf_0x1::edx::HTT_SHIFT);
                // Enable Hyperthreading for even vCPU count so you don't end up with
                // an even and > 1 number of siblings
                if cpu_count > 1 && cpu_count % 2 == 0 {
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
                        if cpu_count > 1 {
                            // Hyperthreading is enabled by default for vcpu_count > 2
                            entry.eax |= 1 << leaf_0x4::eax::MAX_ADDR_IDS_SHARING_CACHE;
                        }
                    }
                    // L3 Cache
                    3 => {
                        // Set the maximum addressable IDS sharing the data cache to zero
                        // when you only have 1 vcpu because there are no other threads on
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
                // set this to 0 because there is only 1 core available for vcpu_count <= 2
                // This sets EAX[31:26]
                entry.eax &= !(0b111111 << leaf_0x4::eax::MAX_ADDR_IDS_IN_PACKAGE);
                if cpu_count > 2 {
                    // we have HT enabled by default, so we will have cpu_count/2 cores in package
                    entry.eax |=
                        (((cpu_count >> 1) - 1) as u32) << leaf_0x4::eax::MAX_ADDR_IDS_IN_PACKAGE;
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
                            // To get the next level APIC ID, shift right with 1 because we have
                            // maximum 2 hyperthreads per core that can be represented with 1 bit
                            entry.eax = 1;
                            // 2 logical cores at this level
                            entry.ebx = 2;
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
        match filter_cpuid(0, 1, &mut kvm_cpuid) {
            Ok(_) => (),
            _ => assert!(false),
        };

        assert!(set_cpuid_template(CPUFeaturesTemplate::T2, &mut kvm_cpuid).is_ok());

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
