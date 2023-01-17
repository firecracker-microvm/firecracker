// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use bit_fields::CheckedAssignError;

use crate::{CpuidEntry, CpuidKey, CpuidRegisters, CpuidTrait, KvmCpuidFlags};

/// Error type for [`AmdCpuid::normalize`].
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum NormalizeCpuidError {
    /// Provided `cpu_bits` is >=8.
    #[error("Provided `cpu_bits` is >=8: {0}.")]
    CpuBits(u8),
    /// Missing leaf 0x80000000.
    #[error("Missing leaf 0x80000000.")]
    MissingLeaf0x80000000,
    /// Missing leaf 0x80000001.
    #[error("Missing leaf 0x80000001.")]
    MissingLeaf0x80000001,
    /// Failed to set feature entry leaf.
    #[error("Failed to set feature entry leaf: {0}")]
    FeatureEntry(#[from] FeatureEntryError),
    /// Failed to set extended cache topology leaf.
    #[error("Failed to set extended cache topology leaf: {0}")]
    ExtendedCacheTopology(#[from] ExtendedCacheTopologyError),
    /// Failed to set extended APIC ID leaf.
    #[error("Failed to set extended APIC ID leaf: {0}")]
    ExtendedApicId(#[from] ExtendedApicIdError),
    /// Failed to set brand string.
    #[error("Failed to set brand string: {0}")]
    BrandString(crate::MissingBrandStringLeaves),
}

/// Error type for setting leaf 0x80000008 section of [`AmdCpuid::normalize`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum FeatureEntryError {
    /// Missing leaf 0x80000008.
    #[error("Missing leaf 0x80000008.")]
    MissingLeaf0x80000008,
    /// Failed to set `nt` (number of physical threads) due to overflow.
    #[error("Failed to set `nt` (number of physical threads) due to overflow.")]
    NumberOfPhysicalThreadsOverflow,
    /// Failed to set `nt` (number of physical threads).
    #[error("Failed to set `nt` (number of physical threads).")]
    NumberOfPhysicalThreads(CheckedAssignError),
}

/// Error type for setting leaf 0x8000001d section of [`AmdCpuid::normalize`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ExtendedCacheTopologyError {
    /// Missing leaf 0x8000001d.
    #[error("Missing leaf 0x8000001d.")]
    MissingLeaf0x8000001d,
    /// Failed to set `num_sharing_cache` due to overflow.
    #[error("Failed to set `num_sharing_cache` due to overflow.")]
    NumSharingCacheOverflow,
    /// Failed to set `num_sharing_cache`.
    #[error("Failed to set `num_sharing_cache`: {0}")]
    NumSharingCache(CheckedAssignError),
}

/// Error type for setting leaf 0x8000001e section of [`AmdCpuid::normalize`].
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ExtendedApicIdError {
    /// Missing leaf 0x8000001d.
    #[error("Missing leaf 0x8000001e.")]
    MissingLeaf0x8000001e,
    /// Failed to set `extended_apic_id`.
    #[error("Failed to set `extended_apic_id`: {0}")]
    ExtendedApicId(CheckedAssignError),
    /// Failed to set `compute_unit_id`.
    #[error("Failed to set `compute_unit_id`: {0}")]
    ComputeUnitId(CheckedAssignError),
    /// Failed to set `threads_per_compute_unit`.
    #[error("Failed to set `threads_per_compute_unit`: {0}")]
    ThreadPerComputeUnit(CheckedAssignError),
}

// We use this 2nd implementation so we can conveniently define functions only used within
// `normalize`.
#[allow(clippy::multiple_inherent_impl)]
impl super::AmdCpuid {
    /// We always use this brand string.
    const DEFAULT_BRAND_STRING: &[u8; crate::BRAND_STRING_LENGTH] =
        b"AMD EPYC\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    /// Applies required modifications to CPUID respective of a vCPU.
    ///
    /// # Errors
    ///
    /// When attempting to access missing leaves or set fields within leaves to values that don't
    /// fit.
    #[inline]
    pub fn normalize(
        &mut self,
        // The index of the current logical CPU in the range [0..cpu_count].
        cpu_index: u8,
        // The total number of logical CPUs.
        cpu_count: u8,
        // The number of bits needed to enumerate logical CPUs per core.
        cpu_bits: u8,
    ) -> Result<(), NormalizeCpuidError> {
        let cpus_per_core = 1u8
            .checked_shl(u32::from(cpu_bits))
            .ok_or(NormalizeCpuidError::CpuBits(cpu_bits))?;

        self.process_cpuid();
        self.update_largest_extended_fn_entry()?;
        self.update_extended_feature_fn_entry()?;
        self.update_amd_feature_entry(cpu_count)?;
        self.update_extended_cache_topology_entry(cpu_count, cpus_per_core)?;
        self.update_extended_apic_id_entry(cpu_index, cpus_per_core)?;
        self.update_brand_string_entry()?;

        Ok(())
    }

    /// Process CPUID.
    fn process_cpuid(&mut self) {
        // Some versions of kernel may return the 0xB leaf for AMD even if this is an
        // Intel-specific leaf. Remove it.
        self.0.remove(&CpuidKey::leaf(0xB));

        // Pass-through host CPUID for leaves 0x8000001e and 0x8000001d.
        {
            // 0x8000001e - Processor Topology Information
            self.0.insert(
                CpuidKey::leaf(0x8000001e),
                CpuidEntry {
                    flags: KvmCpuidFlags::empty(),
                    // SAFETY: Safe as `cfg(cpuid)` ensure CPUID is supported.
                    result: CpuidRegisters::from(unsafe {
                        core::arch::x86_64::__cpuid(0x8000001e)
                    }),
                },
            );

            // 0x8000001d - Cache Topology Information
            for subleaf in 0.. {
                // SAFETY: Safe as `cfg(cpuid)` ensure CPUID is supported.
                let result = CpuidRegisters::from(unsafe {
                    core::arch::x86_64::__cpuid_count(0x8000001d, subleaf)
                });
                // From 'AMD64 Architecture Programmer’s Manual Volume 3: General-Purpose and System
                // Instructions':
                // > To gather information for all cache levels, software must repeatedly execute
                // > CPUID with 8000_001Dh in EAX and ECX set to increasing values beginning with 0
                // > until a value of 00h is returned in the field CacheType (EAX[4:0]) indicating
                // > no more cache descriptions are available for this processor. If CPUID
                // > Fn8000_0001_ECX[TopologyExtensions] = 0, then CPUID Fn8000_001Dh is reserved.
                if super::registers::Leaf8000001dEax::from(result.eax).cache_type() == 0 {
                    break;
                }
                self.0.insert(
                    CpuidKey::subleaf(0x8000001d, subleaf),
                    CpuidEntry {
                        flags: KvmCpuidFlags::SIGNIFICANT_INDEX,
                        result,
                    },
                );
            }
        }
    }

    /// Update largest extended fn entry.
    fn update_largest_extended_fn_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        // KVM sets the largest extended function to 0x80000000. Change it to 0x8000001f
        // Since we also use the leaf 0x8000001d (Extended Cache Topology).
        let leaf_80000000 = self
            .leaf_mut::<0x80000000>()
            .ok_or(NormalizeCpuidError::MissingLeaf0x80000000)?;
        // SAFETY: Safe, as `0x8000_001f` is within the known range.
        unsafe {
            leaf_80000000
                .eax
                .l_func_ext_mut()
                .unchecked_assign(0x8000_001f);
        }
        Ok(())
    }

    /// Updated extended feature fn entry.
    fn update_extended_feature_fn_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        // set the Topology Extension bit since we use the Extended Cache Topology leaf
        let leaf_80000001 = self
            .leaf_mut::<0x80000001>()
            .ok_or(NormalizeCpuidError::MissingLeaf0x80000001)?;
        leaf_80000001.ecx.topology_extensions_mut().on();
        Ok(())
    }

    /// Update AMD feature entry.
    fn update_amd_feature_entry(&mut self, cpu_count: u8) -> Result<(), FeatureEntryError> {
        /// This value allows at most 64 logical threads within a package.
        const THREAD_ID_MAX_SIZE: u32 = 7;

        // We don't support more then 128 threads right now.
        // It's safe to put them all on the same processor.
        let leaf_80000008 = self
            .leaf_mut::<0x80000008>()
            .ok_or(FeatureEntryError::MissingLeaf0x80000008)?;

        // SAFETY: `THREAD_ID_MAX_SIZE` is within the known range and always safe.
        unsafe {
            leaf_80000008
                .ecx
                .apic_id_size_mut()
                .unchecked_assign(THREAD_ID_MAX_SIZE);
        }
        leaf_80000008
            .ecx
            .nt_mut()
            .checked_assign(u32::from(
                cpu_count
                    .checked_sub(1)
                    .ok_or(FeatureEntryError::NumberOfPhysicalThreadsOverflow)?,
            ))
            .map_err(FeatureEntryError::NumberOfPhysicalThreads)?;
        Ok(())
    }

    /// Update extended cache topology entry.
    fn update_extended_cache_topology_entry(
        &mut self,
        cpu_count: u8,
        cpus_per_core: u8,
    ) -> Result<(), ExtendedCacheTopologyError> {
        let leaf_8000001d: super::leaves::Leaf8000001dMut = self.leaf_mut::<0x8000001d>();
        for subleaf in leaf_8000001d.0 {
            match u32::from(&subleaf.eax.cache_level()) {
                // L1 & L2 Cache
                // The L1 & L2 cache is shared by at most 2 hyper-threads
                1 | 2 => subleaf
                    .eax
                    .num_sharing_cache_mut()
                    // SAFETY: We know `cpus_per_core > 0` therefore this is always safe.
                    .checked_assign(u32::from(unsafe {
                        cpus_per_core.checked_sub(1).unwrap_unchecked()
                    }))
                    .map_err(ExtendedCacheTopologyError::NumSharingCache)?,
                // L3 Cache
                // The L3 cache is shared among all the logical threads
                3 => subleaf
                    .eax
                    .num_sharing_cache_mut()
                    .checked_assign(u32::from(
                        cpu_count
                            .checked_sub(1)
                            .ok_or(ExtendedCacheTopologyError::NumSharingCacheOverflow)?,
                    ))
                    .map_err(ExtendedCacheTopologyError::NumSharingCache)?,
                _ => (),
            }
        }
        Ok(())
    }

    /// Update extended apic id entry
    fn update_extended_apic_id_entry(
        &mut self,
        cpu_index: u8,
        cpus_per_core: u8,
    ) -> Result<(), ExtendedApicIdError> {
        /// 1 node per processor.
        const NODES_PER_PROCESSOR: u32 = 0;

        // When hyper-threading is enabled each pair of 2 consecutive logical CPUs
        // will have the same core id since they represent 2 threads in the same core.
        // For Example:
        // logical CPU 0 -> core id: 0
        // logical CPU 1 -> core id: 0
        // logical CPU 2 -> core id: 1
        // logical CPU 3 -> core id: 1
        let core_id =
            // SAFETY: We know `cpus_per_core != 0` therefore this is always safe.
            unsafe { u32::from(cpu_index.checked_div(cpus_per_core).unwrap_unchecked()) };

        let leaf_8000001e = self
            .leaf_mut::<0x8000001e>()
            .ok_or(ExtendedApicIdError::MissingLeaf0x8000001e)?;
        leaf_8000001e
            .eax
            .extended_apic_id_mut()
            .checked_assign(u32::from(cpu_index))
            .map_err(ExtendedApicIdError::ExtendedApicId)?;

        leaf_8000001e
            .ebx
            .compute_unit_id_mut()
            .checked_assign(core_id)
            .map_err(ExtendedApicIdError::ComputeUnitId)?;
        leaf_8000001e
            .ebx
            .threads_per_compute_unit_mut()
            // SAFETY: We know `cpus_per_core > 0` therefore this is always safe.
            .checked_assign(u32::from(unsafe {
                cpus_per_core.checked_sub(1).unwrap_unchecked()
            }))
            .map_err(ExtendedApicIdError::ThreadPerComputeUnit)?;

        // SAFETY: We know the value always fits within the range and thus is always safe.
        unsafe {
            // Set nodes per processor.
            leaf_8000001e
                .ecx
                .nodes_per_processor_mut()
                .unchecked_assign(NODES_PER_PROCESSOR);
            // Put all the cpus in the same node.
            leaf_8000001e.ecx.node_id_mut().unchecked_assign(0);
        }
        Ok(())
    }

    /// Update brand string entry
    fn update_brand_string_entry(&mut self) -> Result<(), NormalizeCpuidError> {
        self.apply_brand_string(Self::DEFAULT_BRAND_STRING)
            .map_err(NormalizeCpuidError::BrandString)?;
        Ok(())
    }
}
