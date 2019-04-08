// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

use kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
use kvm_ioctls::CpuId;

use bit_helper::BitHelper;
use cpu_leaf::*;
use transformer::common::use_host_cpuid_function;

// Largest extended function. It has to be larger then 0x8000001d (Extended Cache Topology).
const LARGEST_EXTENDED_FN: u32 = 0x8000_001f;
// This value allows at most 64 logical threads within a package.
// See also the documentation for leaf_0x80000008::ecx::THREAD_ID_SIZE_BITRANGE
const THREAD_ID_MAX_SIZE: u32 = 6;

pub fn update_structured_extended_entry(
    entry: &mut kvm_cpuid_entry2,
    _vm_spec: &VmSpec,
) -> Result<(), Error> {
    use cpu_leaf::leaf_0x7::index0::*;

    // according to the EPYC PPR, only the leaf 0x7 with index 0 contains the
    // structured extended feature identifiers
    if entry.index == 0 {
        // KVM sets this bit no matter what but this feature is not supported by hardware
        entry.edx.write_bit(edx::ARCH_CAPABILITIES_BITINDEX, false);
    }

    Ok(())
}

pub fn update_largest_extended_fn_entry(
    entry: &mut kvm_cpuid_entry2,
    _vm_spec: &VmSpec,
) -> Result<(), Error> {
    use cpu_leaf::leaf_0x80000000::*;

    // KVM sets the largest extended function to 0x80000000. Change it to 0x8000001f
    // Since we also use the leaf 0x8000001d (Extended Cache Topology).
    entry
        .eax
        .write_bits_in_range(&eax::LARGEST_EXTENDED_FN_BITRANGE, LARGEST_EXTENDED_FN);

    Ok(())
}

pub fn update_extended_feature_info_entry(
    entry: &mut kvm_cpuid_entry2,
    _vm_spec: &VmSpec,
) -> Result<(), Error> {
    use cpu_leaf::leaf_0x80000001::*;

    // set the Topology Extension bit since we use the Extended Cache Topology leaf
    entry.ecx.write_bit(ecx::TOPOEXT_INDEX, true);

    Ok(())
}

pub fn update_amd_features_entry(
    entry: &mut kvm_cpuid_entry2,
    vm_spec: &VmSpec,
) -> Result<(), Error> {
    use cpu_leaf::leaf_0x80000008::*;

    // We don't support more then 64 threads right now.
    // It's safe to put them all on the same processor.
    entry
        .ecx
        .write_bits_in_range(&ecx::THREAD_ID_SIZE_BITRANGE, THREAD_ID_MAX_SIZE)
        .write_bits_in_range(&ecx::NUM_THREADS_BITRANGE, u32::from(vm_spec.cpu_count - 1));

    Ok(())
}

pub fn update_extended_cache_topology_entry(
    entry: &mut kvm_cpuid_entry2,
    vm_spec: &VmSpec,
) -> Result<(), Error> {
    entry.flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;

    common::update_cache_parameters_entry(entry, vm_spec)
}

pub struct AmdCpuidTransformer {}

impl CpuidTransformer for AmdCpuidTransformer {
    fn preprocess_cpuid(&self, cpuid: &mut CpuId) -> Result<(), Error> {
        use_host_cpuid_function(cpuid, leaf_0x8000001d::LEAF_NUM)
    }

    fn transform_entry(&self, entry: &mut kvm_cpuid_entry2, vm_spec: &VmSpec) -> Result<(), Error> {
        let maybe_transformer_fn: Option<EntryTransformerFn> = match entry.function {
            leaf_0x1::LEAF_NUM => Some(common::update_feature_info_entry),
            leaf_0x7::LEAF_NUM => Some(amd::update_structured_extended_entry),
            leaf_0x80000000::LEAF_NUM => Some(amd::update_largest_extended_fn_entry),
            leaf_0x80000001::LEAF_NUM => Some(amd::update_extended_feature_info_entry),
            leaf_0x80000008::LEAF_NUM => Some(amd::update_amd_features_entry),
            leaf_0x8000001d::LEAF_NUM => Some(amd::update_extended_cache_topology_entry),
            0x8000_0002..=0x8000_0004 => Some(common::update_brand_string_entry),
            _ => None,
        };

        if let Some(transformer_fn) = maybe_transformer_fn {
            return transformer_fn(entry, vm_spec);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use common::VENDOR_ID_AMD;

    #[test]
    fn test_update_structured_extended_entry() {
        use cpu_leaf::leaf_0x7::index0::*;

        // Check that if index == 0 the entry is processed
        let vm_spec = VmSpec::new(VENDOR_ID_AMD, 0, 1, false);
        let mut entry = &mut kvm_cpuid_entry2 {
            function: leaf_0x7::LEAF_NUM,
            index: 0,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: *(0 as u32).write_bit(edx::ARCH_CAPABILITIES_BITINDEX, true),
            padding: [0, 0, 0],
        };
        assert!(update_structured_extended_entry(&mut entry, &vm_spec).is_ok());
        assert_eq!(entry.edx.read_bit(edx::ARCH_CAPABILITIES_BITINDEX), false);

        // Check that if index != 0 the entry is not processed
        entry.index = 1;
        entry.edx.write_bit(edx::ARCH_CAPABILITIES_BITINDEX, true);
        assert!(update_structured_extended_entry(&mut entry, &vm_spec).is_ok());
        assert_eq!(entry.edx.read_bit(edx::ARCH_CAPABILITIES_BITINDEX), true);
    }

    #[test]
    fn test_update_largest_extended_fn_entry() {
        use cpu_leaf::leaf_0x80000000::*;

        let vm_spec = VmSpec::new(VENDOR_ID_AMD, 0, 1, false);
        let mut entry = &mut kvm_cpuid_entry2 {
            function: LEAF_NUM,
            index: 0,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };

        assert!(update_largest_extended_fn_entry(&mut entry, &vm_spec).is_ok());

        assert_eq!(
            entry
                .eax
                .read_bits_in_range(&eax::LARGEST_EXTENDED_FN_BITRANGE),
            LARGEST_EXTENDED_FN
        );
    }

    #[test]
    fn test_update_extended_feature_info_entry() {
        use cpu_leaf::leaf_0x80000001::*;

        let vm_spec = VmSpec::new(VENDOR_ID_AMD, 0, 1, false);
        let mut entry = &mut kvm_cpuid_entry2 {
            function: LEAF_NUM,
            index: 0,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };

        assert!(update_extended_feature_info_entry(&mut entry, &vm_spec).is_ok());

        assert_eq!(entry.ecx.read_bit(ecx::TOPOEXT_INDEX), true);
    }

    fn check_update_amd_features_entry(cpu_count: u8, ht_enabled: bool) {
        use cpu_leaf::leaf_0x80000008::*;

        let vm_spec = VmSpec::new(VENDOR_ID_AMD, 0, cpu_count, ht_enabled);
        let mut entry = &mut kvm_cpuid_entry2 {
            function: LEAF_NUM,
            index: 0,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };

        assert!(update_amd_features_entry(&mut entry, &vm_spec).is_ok());

        assert_eq!(
            entry.ecx.read_bits_in_range(&ecx::NUM_THREADS_BITRANGE),
            u32::from(cpu_count - 1)
        );
        assert_eq!(
            entry.ecx.read_bits_in_range(&ecx::THREAD_ID_SIZE_BITRANGE),
            THREAD_ID_MAX_SIZE
        );
    }

    #[test]
    fn test_update_extended_cache_topology_entry() {
        let vm_spec = VmSpec::new(VENDOR_ID_AMD, 0, 1, false);
        let mut entry = &mut kvm_cpuid_entry2 {
            function: leaf_0x8000001d::LEAF_NUM,
            index: 0,
            flags: 0,
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };

        assert!(update_extended_cache_topology_entry(&mut entry, &vm_spec).is_ok());

        assert_eq!(entry.flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX, 1);
    }

    #[test]
    fn test_1vcpu_ht_off() {
        check_update_amd_features_entry(1, false);
    }

    #[test]
    fn test_1vcpu_ht_on() {
        check_update_amd_features_entry(1, true);
    }

    #[test]
    fn test_2vcpu_ht_off() {
        check_update_amd_features_entry(2, false);
    }

    #[test]
    fn test_2vcpu_ht_on() {
        check_update_amd_features_entry(2, true);
    }
}
