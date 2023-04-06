// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::cpuid::bit_helper::BitHelper;
use crate::cpuid::cpu_leaf::*;
use crate::cpuid::transformer::common::use_host_cpuid_function;

fn update_deterministic_cache_entry(
    entry: &mut kvm_cpuid_entry2,
    vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpuid::cpu_leaf::leaf_0x4::*;

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
    use crate::cpuid::cpu_leaf::leaf_0x6::*;

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

pub struct IntelCpuidTransformer {}

impl CpuidTransformer for IntelCpuidTransformer {
    fn process_cpuid(&self, cpuid: &mut CpuId, vm_spec: &VmSpec) -> Result<(), Error> {
        // The following commit changed the behavior of KVM_GET_SUPPORTED_CPUID to no longer
        // include leaf 0xb / subleaf 1.
        // https://lore.kernel.org/all/20221027092036.2698180-1-pbonzini@redhat.com/
        // We call `use_host_cpuid_function()` to add the leaf 0xb / subleaf 1. As the registers
        // within subleaves are filled by `update_extended_topology_entry()`, these values set here
        // don't matter at this point.
        use_host_cpuid_function(cpuid, leaf_0xb::LEAF_NUM, true)?;
        self.process_entries(cpuid, vm_spec)
    }

    fn entry_transformer_fn(&self, entry: &mut kvm_cpuid_entry2) -> Option<EntryTransformerFn> {
        match entry.function {
            leaf_0x1::LEAF_NUM => Some(common::update_feature_info_entry),
            leaf_0x4::LEAF_NUM => Some(intel::update_deterministic_cache_entry),
            leaf_0x6::LEAF_NUM => Some(intel::update_power_management_entry),
            leaf_0xa::LEAF_NUM => Some(intel::update_perf_mon_entry),
            leaf_0xb::LEAF_NUM => Some(common::update_extended_topology_entry),
            0x8000_0002..=0x8000_0004 => Some(common::update_brand_string_entry),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use kvm_bindings::kvm_cpuid_entry2;

    use super::*;
    use crate::cpuid::transformer::VmSpec;

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
        use crate::cpuid::cpu_leaf::leaf_0x4::*;

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

    #[test]
    fn test_1vcpu_ht_off() {
        // test update_deterministic_cache_entry
        // test L1
        check_update_deterministic_cache_entry(1, false, 1, 0);
        // test L2
        check_update_deterministic_cache_entry(1, false, 2, 0);
        // test L3
        check_update_deterministic_cache_entry(1, false, 3, 0);
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
    }
}
