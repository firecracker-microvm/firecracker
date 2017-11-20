// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::result;

use kvm;
use sys_util;

const MAX_KVM_CPUID_ENTRIES: usize = 256;
const VENDOR_EBX_VAL: u32 = 0x534f5243;
const VENDOR_ECX_VAL: u32 = 0x4d56534f;
const VENDOR_EDX_VAL: u32 = 0x52434d56;

#[derive(Debug, PartialEq)]
pub enum Error {
    GetSupportedCpusFailed(sys_util::Error),
    SetSupportedCpusFailed(sys_util::Error),
}
pub type Result<T> = result::Result<T, Error>;

// CPUID bits in ebx, ecx, and edx.
const EBX_CLFLUSH_CACHELINE: u32 = 8; // Flush a cache line size.
const EBX_CLFLUSH_SIZE_SHIFT: u32 = 8; // Bytes flushed when executing CLFLUSH.
const EBX_CPU_COUNT_SHIFT: u32 = 16; // Index of this CPU.
const EBX_CPUID_SHIFT: u32 = 24; // Index of this CPU.
const ECX_EPB_SHIFT: u32 = 3; // "Energy Performance Bias" bit.
const ECX_HYPERVISOR_SHIFT: u32 = 31; // Flag to be set when the cpu is running on a hypervisor.
const EDX_HTT_SHIFT: u32 = 28; // Hyper Threading Enabled.

fn filter_cpuid(cpu_id: u64, cpu_count: u64, kvm_cpuid: &mut kvm::CpuId) -> Result<()> {
    let entries = kvm_cpuid.mut_entries_slice();

    for entry in entries.iter_mut() {
        match entry.function {
            0 => {
                // Vendor name "CROSVMCROSVM" in little endian.
                entry.ebx = VENDOR_EBX_VAL;
                entry.ecx = VENDOR_ECX_VAL;
                entry.edx = VENDOR_EDX_VAL;
            }
            1 => {
                // X86 hypervisor feature
                if entry.index == 0 {
                    entry.ecx |= 1 << ECX_HYPERVISOR_SHIFT;
                }
                entry.ebx = (cpu_id << EBX_CPUID_SHIFT) as u32 |
                    (EBX_CLFLUSH_CACHELINE << EBX_CLFLUSH_SIZE_SHIFT);
                if cpu_count > 1 {
                    entry.ebx |= (cpu_count as u32) << EBX_CPU_COUNT_SHIFT;
                    entry.edx |= 1 << EDX_HTT_SHIFT;
                }
            }
            6 => {
                // Clear X86 EPB feature.  No frequency selection in the hypervisor.
                entry.ecx &= !(1 << ECX_EPB_SHIFT);
            }
            _ => (),
        }
    }

    Ok(())
}

/// Sets up the cpuid entries for the given vcpu.  Can fail if there are too many CPUs specified or
/// if an ioctl returns an error.
///
/// # Arguments
///
/// * `kvm` - `Kvm` structure created with KVM_CREATE_VM ioctl.
/// * `vcpu` - `Vcpu` for setting CPU ID.
/// * `cpu_id` - The index of the CPU `vcpu` is for.
/// * `nrcpus` - The number of vcpus being used by this VM.
pub fn setup_cpuid(kvm: &kvm::Kvm, vcpu: &kvm::Vcpu, cpu_id: u64, nrcpus: u64) -> Result<()> {
    let mut kvm_cpuid = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).map_err(
        Error::GetSupportedCpusFailed,
    )?;

    filter_cpuid(cpu_id, nrcpus, &mut kvm_cpuid)?;

    vcpu.set_cpuid2(&kvm_cpuid).map_err(
        Error::SetSupportedCpusFailed,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_and_vendor_name() {
        let mut cpuid = kvm::CpuId::new(2);

        {
            let entries = cpuid.mut_entries_slice();
            entries[0].function = 0;
            entries[1].function = 1;
            entries[1].ecx = 0x10;
            entries[1].edx = 0;
        }
        assert_eq!(Ok(()), filter_cpuid(1, 2, &mut cpuid));
        {
            let entries = cpuid.mut_entries_slice();
            assert_eq!(entries[0].function, 0);
            assert_eq!(entries[0].ebx, VENDOR_EBX_VAL);
            assert_eq!(entries[0].ecx, VENDOR_ECX_VAL);
            assert_eq!(entries[0].edx, VENDOR_EDX_VAL);
            assert_eq!(1, (entries[1].ebx >> EBX_CPUID_SHIFT) & 0x000000ff);
            assert_eq!(2, (entries[1].ebx >> EBX_CPU_COUNT_SHIFT) & 0x000000ff);
            assert_eq!(
                EBX_CLFLUSH_CACHELINE,
                (entries[1].ebx >> EBX_CLFLUSH_SIZE_SHIFT) & 0x000000ff
            );
            assert_ne!(0, entries[1].ecx & (1 << ECX_HYPERVISOR_SHIFT));
            assert_ne!(0, entries[1].edx & (1 << EDX_HTT_SHIFT));
        }
    }
}
