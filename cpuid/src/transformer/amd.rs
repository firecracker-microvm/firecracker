// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use cpu_leaf::*;
use kvm::CpuId;
use kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
use transformer::common::use_host_cpuid_function;

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
            leaf_0x8000001d::LEAF_NUM => Some(amd::update_extended_cache_topology_entry),
            _ => None,
        };

        if let Some(transformer_fn) = maybe_transformer_fn {
            return transformer_fn(entry, vm_spec);
        }

        Ok(())
    }
}
