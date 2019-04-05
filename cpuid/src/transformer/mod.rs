// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod amd;
pub mod common;
pub mod intel;

use brand_string::BrandString;
use brand_string::Reg as BsReg;
use kvm::CpuId;
pub use kvm_bindings::kvm_cpuid_entry2;

pub struct VmSpec {
    pub cpu_id: u8,
    pub cpu_count: u8,
    pub ht_enabled: bool,
    brand_string: BrandString,
}

impl VmSpec {
    pub fn new(vendor_id: &[u8; 12], cpu_id: u8, cpu_count: u8, ht_enabled: bool) -> VmSpec {
        VmSpec {
            cpu_id,
            cpu_count,
            ht_enabled,
            brand_string: BrandString::from_vendor_id(vendor_id),
        }
    }

    pub fn brand_string(&self) -> &BrandString {
        &self.brand_string
    }
}

/// Errors associated with processing the CPUID leaves.
#[derive(Debug, Clone)]
pub enum Error {
    /// The maximum number of addressable logical CPUs cannot be stored in an `u8`.
    VcpuCountOverflow,
    /// The max size has been exceeded
    SizeLimitExceeded,
    /// A call to an internal helper method failed
    InternalError(super::common::Error),
}

pub type EntryTransformerFn =
    fn(entry: &mut kvm_cpuid_entry2, vm_spec: &VmSpec) -> Result<(), Error>;

pub trait CpuidTransformer {
    fn preprocess_cpuid(&self, _cpuid: &mut CpuId) -> Result<(), Error> {
        Ok(())
    }

    fn transform_entry(
        &self,
        _entry: &mut kvm_cpuid_entry2,
        _vm_spec: &VmSpec,
    ) -> Result<(), Error> {
        Ok(())
    }
}
