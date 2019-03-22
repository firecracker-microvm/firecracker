// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use bit_helper::BitHelper;
use cpu_leaf::*;
use kvm::CpuId;
use kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
use transformer::common::use_host_cpuid_function;

pub fn update_structured_extended_entry(
    entry: &mut kvm_cpuid_entry2,
    _vm_spec: &VmSpec,
) -> Result<(), Error> {
    use cpu_leaf::leaf_0x7::index0::*;

    // KVM sets this bit no matter what but this feature is not supported by hardware
    entry.edx.write_bit(edx::ARCH_CAPABILITIES_BITINDEX, false);

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
    fn test_update_extended_cache_topology_entry() {
        use cpu_leaf::leaf_0x8000001d::*;

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
    fn test_update_structured_extended_entry() {
        use cpu_leaf::leaf_0x7::index0::*;

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
    }
}
