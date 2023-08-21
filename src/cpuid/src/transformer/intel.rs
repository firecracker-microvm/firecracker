// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::bit_helper::BitHelper;
use crate::cpu_leaf::*;
use crate::transformer::common::use_host_cpuid_function;

// The APIC ID shift in leaf 0xBh specifies the number of bits to shit the x2APIC ID to get a
// unique topology of the next level. This allows 128 logical processors/package.
const LEAFBH_INDEX1_APICID: u32 = 7;

fn update_deterministic_cache_entry(
    entry: &mut kvm_cpuid_entry2,
    vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpu_leaf::leaf_0x4::*;

    common::update_cache_parameters_entry(entry, vm_spec)?;

    // Put all the cores in the same socket
    entry.eax.write_bits_in_range(
        &eax::MAX_CORES_PER_PACKAGE_BITRANGE,
        u32::from(vm_spec.cpu_count / vm_spec.cpus_per_core()) - 1,
    );

    Ok(())
}

fn update_power_management_entry(
    entry: &mut kvm_cpuid_entry2,
    _vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpu_leaf::leaf_0x6::*;

    entry.eax.write_bit(eax::TURBO_BOOST_BITINDEX, false);
    // Clear X86 EPB feature. No frequency selection in the hypervisor.
    entry.ecx.write_bit(ecx::EPB_BITINDEX, false);

    Ok(())
}

fn update_perf_mon_entry(entry: &mut kvm_cpuid_entry2, _vm_spec: &VmSpec) -> Result<(), Error> {
    // Architectural Performance Monitor Leaf
    // Disable PMU
    entry.eax = 0;
    entry.ebx = 0;
    entry.ecx = 0;
    entry.edx = 0;

    Ok(())
}

fn update_extended_topology_entry(
    entry: &mut kvm_cpuid_entry2,
    vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpu_leaf::leaf_0xb::*;

    // reset eax, ebx, ecx
    entry.eax = 0_u32;
    entry.ebx = 0_u32;
    entry.ecx = 0_u32;
    // EDX bits 31..0 contain x2APIC ID of current logical processor
    // x2APIC increases the size of the APIC ID from 8 bits to 32 bits
    entry.edx = u32::from(vm_spec.cpu_index);

    // "If SMT is not present in a processor implementation but CPUID leaf 0BH is supported,
    // CPUID.EAX=0BH, ECX=0 will return EAX = 0, EBX = 1 and level type = 1.
    // Number of logical processors at the core level is reported at level type = 2."
    // (Intel® 64 Architecture x2APIC Specification, Ch. 2.8)
    match entry.index {
        // Thread Level Topology; index = 0
        0 => {
            // To get the next level APIC ID, shift right with at most 1 because we have
            // maximum 2 hyperthreads per core that can be represented by 1 bit.
            entry
                .eax
                .write_bits_in_range(&eax::APICID_BITRANGE, u32::from(vm_spec.cpu_bits));
            // When cpu_count == 1 or HT is disabled, there is 1 logical core at this level
            // Otherwise there are 2
            entry.ebx.write_bits_in_range(
                &ebx::NUM_LOGICAL_PROCESSORS_BITRANGE,
                u32::from(vm_spec.cpus_per_core()),
            );

            entry
                .ecx
                .write_bits_in_range(&ecx::LEVEL_TYPE_BITRANGE, LEVEL_TYPE_THREAD);
        }
        // Core Level Processor Topology; index = 1
        1 => {
            entry
                .eax
                .write_bits_in_range(&eax::APICID_BITRANGE, LEAFBH_INDEX1_APICID);
            entry.ebx.write_bits_in_range(
                &ebx::NUM_LOGICAL_PROCESSORS_BITRANGE,
                u32::from(vm_spec.cpu_count),
            );
            entry
                .ecx
                .write_bits_in_range(&ecx::LEVEL_NUMBER_BITRANGE, entry.index);
            entry
                .ecx
                .write_bits_in_range(&ecx::LEVEL_TYPE_BITRANGE, LEVEL_TYPE_CORE);
        }
        // Core Level Processor Topology; index >=2
        // No other levels available; This should already be set correctly,
        // and it is added here as a "re-enforcement" in case we run on
        // different hardware
        level => {
            entry.ecx = level;
        }
    }

    Ok(())
}

pub struct IntelCpuidTransformer {}

impl CpuidTransformer for IntelCpuidTransformer {
    fn process_cpuid(&self, cpuid: &mut CpuId, vm_spec: &VmSpec) -> Result<(), Error> {
        // The following commit changed the behavior of KVM_GET_SUPPORTED_CPUID to no longer
        // include leaf 0xb / sub-leaf 1.
        // https://lore.kernel.org/all/20221027092036.2698180-1-pbonzini@redhat.com/
        // The registers within sub-leaves of 0xB are zeroed by update_extended_topology_entry()
        // and then modified. So the value they are set to at this point doesn't matter.
        if !cpuid
            .as_slice()
            .iter()
            .any(|entry| entry.function == 0xb && entry.index == 1)
        {
            cpuid
                .push(kvm_cpuid_entry2 {
                    function: leaf_0xb::LEAF_NUM,
                    index: 1,
                    flags: kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
                    ..kvm_cpuid_entry2::default()
                })
                .map_err(Error::Fam)?;
        }

        use_host_cpuid_function(cpuid, leaf_0x80000006::LEAF_NUM, false)?;

        self.process_entries(cpuid, vm_spec)
    }

    fn entry_transformer_fn(&self, entry: &mut kvm_cpuid_entry2) -> Option<EntryTransformerFn> {
        match entry.function {
            leaf_0x1::LEAF_NUM => Some(common::update_feature_info_entry),
            leaf_0x4::LEAF_NUM => Some(intel::update_deterministic_cache_entry),
            leaf_0x6::LEAF_NUM => Some(intel::update_power_management_entry),
            leaf_0xa::LEAF_NUM => Some(intel::update_perf_mon_entry),
            leaf_0xb::LEAF_NUM => Some(intel::update_extended_topology_entry),
            0x8000_0002..=0x8000_0004 => Some(common::update_brand_string_entry),
            leaf_0x80000006::LEAF_NUM => Some(common::update_cache_parameters_entry),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use kvm_bindings::kvm_cpuid_entry2;

    use super::*;
    use crate::cpu_leaf::leaf_0xb::{LEVEL_TYPE_CORE, LEVEL_TYPE_THREAD};
    use crate::transformer::VmSpec;

    #[test]
    fn test_process_cpuid() {
        let vm_spec = VmSpec::new(0, 1, false).expect("Error creating vm_spec");
        let mut cpuid = CpuId::new(0).unwrap();

        assert!(IntelCpuidTransformer {}
            .process_cpuid(&mut cpuid, &vm_spec)
            .is_ok());

        // Assert that leaf 0xb / subleaf 1 is generated correctly if not exist in the given cpuid.
        assert!(cpuid
            .as_slice()
            .iter()
            .any(|entry| entry.function == leaf_0xb::LEAF_NUM && entry.index == 1));
    }

    #[test]
    fn test_update_perf_mon_entry() {
        let vm_spec = VmSpec::new(0, 1, false).expect("Error creating vm_spec");
        let entry = &mut kvm_cpuid_entry2 {
            function: leaf_0xa::LEAF_NUM,
            index: 0,
            flags: 0,
            eax: 1,
            ebx: 1,
            ecx: 1,
            edx: 1,
            padding: [0, 0, 0],
        };

        assert!(update_perf_mon_entry(entry, &vm_spec).is_ok());

        assert_eq!(entry.eax, 0);
        assert_eq!(entry.ebx, 0);
        assert_eq!(entry.ecx, 0);
        assert_eq!(entry.edx, 0);
    }

    fn check_update_deterministic_cache_entry(
        cpu_count: u8,
        smt: bool,
        cache_level: u32,
        expected_max_cores_per_package: u32,
    ) {
        use crate::cpu_leaf::leaf_0x4::*;

        let vm_spec = VmSpec::new(0, cpu_count, smt).expect("Error creating vm_spec");
        let entry = &mut kvm_cpuid_entry2 {
            function: 0x0,
            index: 0,
            flags: 0,
            eax: *(0_u32).write_bits_in_range(&eax::CACHE_LEVEL_BITRANGE, cache_level),
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };

        assert!(update_deterministic_cache_entry(entry, &vm_spec).is_ok());

        assert!(
            entry
                .eax
                .read_bits_in_range(&eax::MAX_CORES_PER_PACKAGE_BITRANGE)
                == expected_max_cores_per_package
        );
    }

    fn check_update_extended_topology_entry(
        cpu_count: u8,
        smt: bool,
        index: u32,
        expected_apicid: u32,
        expected_num_logical_processors: u32,
        expected_level_type: u32,
    ) {
        use crate::cpu_leaf::leaf_0xb::*;

        let vm_spec = VmSpec::new(0, cpu_count, smt).expect("Error creating vm_spec");
        let entry = &mut kvm_cpuid_entry2 {
            function: 0x0,
            index,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };

        assert!(update_extended_topology_entry(entry, &vm_spec).is_ok());

        assert!(entry.eax.read_bits_in_range(&eax::APICID_BITRANGE) == expected_apicid);
        assert!(
            entry
                .ebx
                .read_bits_in_range(&ebx::NUM_LOGICAL_PROCESSORS_BITRANGE)
                == expected_num_logical_processors
        );
        assert!(entry.ecx.read_bits_in_range(&ecx::LEVEL_TYPE_BITRANGE) == expected_level_type);
        assert!(entry.ecx.read_bits_in_range(&ecx::LEVEL_NUMBER_BITRANGE) == index);
    }

    #[test]
    fn test_1vcpu_ht_off() {
        // test update_deterministic_cache_entry
        // test L1
        check_update_deterministic_cache_entry(1, false, 1, 0);
        // test L2
        check_update_deterministic_cache_entry(1, false, 2, 0);
        // test L3
        check_update_deterministic_cache_entry(1, false, 3, 0);

        // test update_extended_topology_entry
        // index 0
        check_update_extended_topology_entry(1, false, 0, 0, 1, LEVEL_TYPE_THREAD);
        // index 1
        check_update_extended_topology_entry(1, false, 1, LEAFBH_INDEX1_APICID, 1, LEVEL_TYPE_CORE);
    }

    #[test]
    fn test_1vcpu_ht_on() {
        // test update_deterministic_cache_entry
        // test L1
        check_update_deterministic_cache_entry(1, true, 1, 0);
        // test L2
        check_update_deterministic_cache_entry(1, true, 2, 0);
        // test L3
        check_update_deterministic_cache_entry(1, true, 3, 0);

        // test update_extended_topology_entry
        // index 0
        check_update_extended_topology_entry(1, true, 0, 0, 1, LEVEL_TYPE_THREAD);
        // index 1
        check_update_extended_topology_entry(1, true, 1, LEAFBH_INDEX1_APICID, 1, LEVEL_TYPE_CORE);
    }

    #[test]
    fn test_2vcpu_ht_off() {
        // test update_deterministic_cache_entry
        // test L1
        check_update_deterministic_cache_entry(2, false, 1, 1);
        // test L2
        check_update_deterministic_cache_entry(2, false, 2, 1);
        // test L3
        check_update_deterministic_cache_entry(2, false, 3, 1);

        // test update_extended_topology_entry
        // index 0
        check_update_extended_topology_entry(2, false, 0, 0, 1, LEVEL_TYPE_THREAD);
        // index 1
        check_update_extended_topology_entry(2, false, 1, LEAFBH_INDEX1_APICID, 2, LEVEL_TYPE_CORE);
    }

    #[test]
    fn test_2vcpu_ht_on() {
        // test update_deterministic_cache_entry
        // test L1
        check_update_deterministic_cache_entry(2, true, 1, 0);
        // test L2
        check_update_deterministic_cache_entry(2, true, 2, 0);
        // test L3
        check_update_deterministic_cache_entry(2, true, 3, 0);

        // test update_extended_topology_entry
        // index 0
        check_update_extended_topology_entry(2, true, 0, 1, 2, LEVEL_TYPE_THREAD);
        // index 1
        check_update_extended_topology_entry(2, true, 1, LEAFBH_INDEX1_APICID, 2, LEVEL_TYPE_CORE);
    }
}