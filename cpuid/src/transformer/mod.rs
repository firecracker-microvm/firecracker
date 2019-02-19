// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod common;
pub mod intel;

use brand_string::BrandString;
use brand_string::Reg as BsReg;
pub use kvm_bindings::kvm_cpuid_entry2;

const DEFAULT_BRAND_STRING: &[u8] = b"Intel(R) Xeon(R) Processor";

/// Generates the emulated brand string.
/// TODO: Add non-Intel CPU support.
///
/// For non-Intel CPUs, we'll just expose DEFAULT_BRAND_STRING.
///
/// For Intel CPUs, the brand string we expose will be:
///    "Intel(R) Xeon(R) Processor @ {host freq}"
/// where {host freq} is the CPU frequency, as present in the
/// host brand string (e.g. 4.01GHz).
///
/// This is safe because we know DEFAULT_BRAND_STRING to hold valid data
/// (allowed length and holding only valid ASCII chars).
pub fn build_brand_string() -> BrandString {
    let mut bstr = BrandString::from_bytes_unchecked(DEFAULT_BRAND_STRING);
    if let Ok(host_bstr) = BrandString::from_host_cpuid() {
        if host_bstr.starts_with(b"Intel") {
            if let Some(freq) = host_bstr.find_freq() {
                bstr.push_bytes(b" @ ").unwrap();
                bstr.push_bytes(freq)
                    .expect("Unexpected frequency information in host CPUID");
            }
        }
    }

    bstr
}

pub struct VmSpec {
    pub cpu_id: u8,
    pub cpu_count: u8,
    pub ht_enabled: bool,
    brand_string: BrandString,
}

impl VmSpec {
    pub fn new(cpu_id: u8, cpu_count: u8, ht_enabled: bool) -> VmSpec {
        VmSpec {
            cpu_id,
            cpu_count,
            ht_enabled,
            brand_string: build_brand_string(),
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
}

pub type EntryTransformerFn =
    fn(entry: &mut kvm_cpuid_entry2, vm_spec: &VmSpec) -> Result<(), Error>;
