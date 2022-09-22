// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::similar_names,
    clippy::module_name_repetitions,
    clippy::unreadable_literal,
    clippy::unsafe_derive_deserialize
)]
use std::cmp::{Ord, PartialOrd};
use std::convert::TryFrom;
use std::default::Default;

#[cfg(feature = "static")]
use arrayvec::{ArrayVec, CapacityError};
use log_derive::{logfn, logfn_inputs};

mod registers;
pub use registers::*;
mod leaves;
pub use leaves::*;
mod indexing;
pub use indexing::*;

use crate::{
    cascade_cpo, FeatureComparison, FeatureRelation, FixedString, Padding, RawCpuid, RawCpuidEntry,
};

// -------------------------------------------------------------------------------------------------
// Intel cpuid structure
// -------------------------------------------------------------------------------------------------

/// A structure containing the information as described in the Intel CPUID specification as
/// described in
/// [Intel® 64 and IA-32 Architectures Software Developer's Manual Combined Volumes 2A, 2B, 2C, and 2D: Instruction Set Reference, A-Z](https://cdrdv2.intel.com/v1/dl/getContent/671110)
/// .
///
/// # Notes
///
/// Does not support Pentium III processor.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(C)]
pub struct IntelCpuid {
    /// Basic CPUID Information
    pub leaf_0: Leaf0,
    /// Basic CPUID Information
    pub leaf_1: Leaf1,
    /// Basic CPUID Information
    pub leaf_2: Leaf2,
    /// Processor serial number (PSN) is not supported in the Pentium 4 processor or later. On all
    /// models, use the PSN flag (returned using CPUID) to check for PSN support before accessing
    /// the feature.
    pub leaf_3: Leaf3,
    // 'CPUID leaves above 2 and below 80000000H are visible only when IA32_MISC_ENABLE[bit 22] has
    // its default value of 0.' I believe we can presume this is true.
    /// Deterministic Cache Parameters Leaf
    pub leaf_4: Leaf4,
    /// MONITOR/MWAIT Leaf
    pub leaf_5: Leaf5,
    /// Thermal and Power Management Leaf
    pub leaf_6: Leaf6,
    // Presuming leaf 7 subleaf 0 (eax 7, ecx 0) eax equals 1
    /// Structured Extended Feature Flags Enumeration Leaf (Output depends on ECX input value)
    pub leaf_7: Leaf7,
    /// Direct Cache Access Information Leaf
    pub leaf_9: Leaf9,
    /// Architectural Performance Monitoring Leaf
    pub leaf_a: LeafA,
    /// Extended Topology Enumeration Leaf
    pub leaf_b: LeafB,
    /// Processor Extended State Enumeration Main Leaf
    pub leaf_d: LeafD,
    /// Intel Resource Director Technology (Intel RDT) Monitoring Enumeration *and*
    /// L3 Cache Intel RDT Monitoring Capability Enumeration
    pub leaf_f: LeafF,
    /// Intel Resource Director Technology (Intel RDT) Allocation Enumeration *and*
    /// L3 Cache Allocation Technology Enumeration *and*
    /// L2 Cache Allocation Technology Enumeration *and*
    /// Memory Bandwidth Allocation Enumeration
    pub leaf_10: Leaf10,
    /// Intel SGX Capability Enumeration *and*
    /// Intel SGX Attributes Enumeration *and*
    /// Intel SGX EPC Enumeration
    pub leaf_12: Option<Leaf12>,
    /// Intel Processor Trace Enumeration
    pub leaf_14: Leaf14,
    /// Time Stamp Counter and Nominal Core Crystal Clock Information
    pub leaf_15: Leaf15,
    /// Processor Frequency Information
    pub leaf_16: Leaf16,
    /// System-On-Chip Vendor Attribute Enumeration
    pub leaf_17: Option<Leaf17>,
    /// Deterministic Address Translation Parameters
    ///
    /// ## Notes
    ///
    /// Each sub-leaf enumerates a different address translation structure. If ECX contains an
    /// invalid sub-leaf index, EAX/EBX/ECX/EDX return 0. Sub-leaf index n is invalid if n
    /// exceeds the value that sub-leaf 0 returns in EAX. A sub-leaf index is also invalid if
    /// EDX[4:0] returns 0. Valid sub-leaves do not need to be contiguous or in any particular
    /// order. A valid sub-leaf may be in a higher input ECX value than an invalid sub-leaf or
    /// than a valid sub-leaf of a higher or lower-level structure.
    // #[serde(skip_serializing, skip_deserializing, default)]
    #[cfg(feature = "leaf_18")]
    pub leaf_18: Option<Leaf18>,
    /// Key Locker
    pub leaf_19: Option<Leaf19>,
    /// Hybrid Information
    pub leaf_1a: Option<Leaf1A>,
    /// PCONFIG Information
    pub leaf_1b: Option<Leaf1B>,
    /// Last Branch Records Information
    pub leaf_1c: Option<Leaf1C>,
    /// V2 Extended Topology Enumeration
    ///
    /// ## Notes
    ///
    /// CPUID leaf 1FH is a preferred superset to leaf 0BH. Intel recommends first checking for the
    /// existence of Leaf 1FH and using this if available. Most of Leaf 1FH output depends on the
    /// initial value in ECX. The EDX output of leaf 1FH is always valid and does not vary with
    /// input value in ECX. Output value in ECX[7:0] always equals input value in ECX[7:0].
    /// Sub-leaf index 0 enumerates SMT level. Each subsequent higher sub-leaf index enumerates a
    /// higherlevel topological entity in hierarchical order. For sub-leaves that return an invalid
    /// level-type of 0 in ECX[15:8]; EAX and EBX will return 0. If an input value n in ECX returns
    /// the invalid level-type of 0 in ECX[15:8], other input values with ECX >n also return 0 in
    /// ECX[15:8].
    pub leaf_1f: Leaf1F,
    /// Processor History Reset
    pub leaf_20: Option<Leaf20>,
    // Leaf 21 is unimplemented, described by intel with:
    // ```text
    // Invalid. No existing or future CPU will return processor identification or feature
    // information if the initial EAX value is 21H. If the value returned by CPUID.0:EAX (the
    // maximum input value for basic CPUID information) is at least 21H, 0 is returned in the
    // registers EAX, EBX, ECX, and EDX. Otherwise, the data for the highest basic information leaf
    // is returned.
    // ```
    // Leaves 40000000H to 4FFFFFFFH are unimplemented, described by intel with:
    // ```text
    // Invalid. No existing or future CPU will return processor identification or feature
    // information if the initial EAX value is in the range 40000000H to 4FFFFFFFH.
    // ```
    /// Extended Function CPUID Information
    pub leaf_80000000: Leaf80000000,
    /// Extended Function CPUID Information
    pub leaf_80000001: Leaf80000001,
    /// Extended Function CPUID Information
    pub leaf_80000002: Leaf80000002,
    /// Extended Function CPUID Information
    pub leaf_80000003: Leaf80000003,
    /// Extended Function CPUID Information
    pub leaf_80000004: Leaf80000004,
    /// Extended Function CPUID Information
    pub leaf_80000005: Leaf80000005,
    /// Extended Function CPUID Information
    pub leaf_80000006: Leaf80000006,
    /// Extended Function CPUID Information
    pub leaf_80000007: Leaf80000007,
    /// Extended Function CPUID Information
    pub leaf_80000008: Leaf80000008,
}

#[cfg(not(feature = "static"))]
/// Return type for [`IntelCpuid::new`].
pub type IntelCpuidResultType = IntelCpuid;
#[cfg(feature = "static")]
/// Return type for [`IntelCpuid::new`].
pub type IntelCpuidResultType = Result<IntelCpuid, LeafOverflowError>;
#[cfg(feature = "static")]
/// Error type for [`IntelCpuid::new`] and `TryFrom<RawCpuid> for IntelCpuid`.
#[derive(Debug, thiserror::Error)]
pub enum LeafOverflowError {
    /// Leaf 0x4 overflow
    #[error("Leaf 0x4 overflow: {0}")]
    Leaf4(CapacityError<Leaf4Subleaf>),
    /// Leaf 0xB overflow
    #[error("Leaf 0xB overflow: {0}")]
    LeafB(CapacityError<LeafBSubleaf>),
    /// Leaf 0xD overflow
    #[error("Leaf 0xD overflow: {0}")]
    LeafD(CapacityError<LeafDSubleafGt1>),
    /// Leaf 0x12 overflow
    #[error("Leaf 0x12 overflow: {0}")]
    Leaf12(CapacityError<Leaf12SubleafGt1>),
    /// Leaf 0x18 overflow
    #[cfg(feature = "leaf_18")]
    #[error("Leaf 0x18 overflow: {0}")]
    Leaf18(CapacityError<Leaf18SubleafGt0>),
    /// Leaf 0x1F overflow
    #[error("Leaf 0x1F overflow: {0}")]
    Leaf1F(CapacityError<Leaf1FSubleaf>),
}

/// Limit on number of entries allowed in subleaf (to prevent hanging)
#[cfg(debug_assertions)]
const LIMIT: u32 = 10000;

/// Convenience macro for setting limits on enumerated leaves to prevent the process hanging.
macro_rules! debug_limit {
    ($i:ident) => {
        #[cfg(debug_assertions)]
        assert!($i < LIMIT, "Limit check ({} < {})", $i, LIMIT);
    };
}

macro_rules! warn_support {
    ($($x:literal),*) => {
        $(
            log::info!("Could not validate support for Intel CPUID leaf {}.",$x);
        )*

    }
}

use bit_fields::CheckedAssignError;

/// Error type for `get_max_cpus_per_package`.
#[derive(Debug, thiserror::Error)]
pub enum GetMaxCpusPerPackageError {
    /// Failed to get max CPUs per package as `cpu_count == 0`.
    #[error("Failed to get max CPUs per package as `cpu_count == 0`")]
    Underflow,
    /// Failed to get max CPUs per package as `cpu_count > 128`.
    #[error("Failed to get max CPUs per package as `cpu_count > 128`")]
    Overflow,
}

/// Error type for [`IntelCpuid::apply_vm_spec`].
#[derive(Debug, thiserror::Error)]
pub enum ApplyVmSpecError {
    /// Failed to set feature infomation leaf.
    #[error("Failed to set feature infomation leaf: {0}")]
    FeatureInfomation(#[from] FeatireInfomationError),
    /// Failed to set deterministic cache leaf.
    #[error("Failed to set deterministic cache leaf: {0}")]
    DeterministicCache(#[from] DeterministicCacheError),
    /// Failed to set extended topology leaf.
    #[error("Failed to set extended topology leaf: {0}")]
    ExtendedTopology(#[from] ExtendedTopologyError),
}
/// Error type for setting leaf 1 section of `IntelCpuid::apply_vm_spec`.
#[derive(Debug, thiserror::Error)]
pub enum FeatireInfomationError {
    /// Failed to set `Initial APIC ID`.
    #[error("Failed to set `Initial APIC ID`: {0}")]
    InitialApicId(CheckedAssignError),
    /// Failed to set `CLFLUSH line size`.
    #[error("Failed to set `CLFLUSH line size`: {0}")]
    Clflush(CheckedAssignError),
    /// Failed to get max CPUs per package.
    #[error("Failed to get max CPUs per package: {0}")]
    GetMaxCpusPerPackage(GetMaxCpusPerPackageError),
    /// Failed to set max CPUs per package.
    #[error("Failed to set max CPUs per package: {0}")]
    SetMaxCpusPerPackage(CheckedAssignError),
}

/// Error type for setting leaf 4 section of `IntelCpuid::apply_vm_spec`.
#[derive(Debug, thiserror::Error)]
pub enum DeterministicCacheError {
    /// Failed to set `Maximum number of addressable IDs for logical processors sharing this
    /// cache`.
    #[error(
        "Failed to set `Maximum number of addressable IDs for logical processors sharing this \
         cache`: {0}"
    )]
    MaxCpusPerCore(CheckedAssignError),
    /// Failed to set `Maximum number of addressable IDs for processor cores in the physical
    /// package`.
    #[error(
        "Failed to set `Maximum number of addressable IDs for processor cores in the physical \
         package`: {0}"
    )]
    MaxCorePerPackage(CheckedAssignError),
}
/// Error type for setting leaf b section of `IntelCpuid::apply_vm_spec`.
#[derive(Debug, thiserror::Error)]
pub enum ExtendedTopologyError {
    /// Failed to set `Number of bits to shift right on x2APIC ID to get a unique topology ID of
    /// the next level type`.
    #[error(
        "Failed to set `Number of bits to shift right on x2APIC ID to get a unique topology ID of \
         the next level type`: {0}"
    )]
    ApicId(CheckedAssignError),
    /// Failed to set `Number of logical processors at this level type`.
    #[error("Failed to set `Number of logical processors at this level type`: {0}")]
    LogicalProcessors(CheckedAssignError),
    /// Failed to set `Level Type`.
    #[error("Failed to set `Level Type`: {0}")]
    LevelType(CheckedAssignError),
    /// Failed to set `Level Number`.
    #[error("Failed to set `Level Number`: {0}")]
    LevelNumber(CheckedAssignError),
}

// TODO: Replace checking of CPUID availability with `x86` and `x86_64` check and
// [`std::arch_x86_64::has_cpuid()`] when this is stabilized. CPUID is supported when:
// - We are on an x86 archtecture with `see` enabled and `sgx disabled`.
// - We are on an x86_64 architecture with `sgx` disabled
#[cfg(any(
    all(target_arch = "x86", target_feature = "sse", not(target_env = "sgx")),
    all(target_arch = "x86_64", not(target_env = "sgx"))
))]
impl IntelCpuid {
    // The number of lines may be reduced by implementing `new` for each `Leaf1`, `Leaf2` etc. This
    // may be worth doing, however at the moment I am undecided.
    /// Constructs new [`Cpuid`] via [`core::archx86_64::__cpuid_count`].
    ///
    /// # Safety
    ///
    /// The present compile time checks for implementation of CPUID are not complete, and the
    /// runtime checks within CPUID for implemented leaves have not been rigorously verified as
    /// correct. Thus while this function has not been f
    ///
    /// # Panics
    ///
    /// In debug when assertions which guard against long or endless loops trigger.
    ///
    /// # Errors
    ///
    /// When:
    /// - Manfuacturers ID is unsupported (not `GenuineIntel` or `AuthenticAMD`).
    /// - With `static` feature, number of subleaves exceeds maximum supported.
    #[allow(clippy::too_many_lines)]
    pub unsafe fn new() -> IntelCpuidResultType {
        use core::arch::x86_64::{__cpuid_count, __get_cpuid_max};

        let leaf_2 = Leaf2::from({
            let leaf = __cpuid_count(0x2, 0);
            (leaf.eax, leaf.ebx, leaf.ecx, leaf.edx)
        });

        let leaf_4 = Leaf4({
            #[cfg(feature = "static")]
            let mut vec = ArrayVec::new();
            #[cfg(not(feature = "static"))]
            let mut vec = Vec::new();
            // If ECX contains an invalid sub leaf index, EAX/EBX/ECX/EDX return 0. Sub-leaf index
            // n+1 is invalid if subleaf n returns EAX[4:0] as 0.
            for i in 0.. {
                // Get subleaf
                let subleaf = __cpuid_count(0x4, i);
                // Check if invalid
                if subleaf.eax == 0 && subleaf.ebx == 0 && subleaf.ecx == 0 && subleaf.edx == 0 {
                    break;
                }
                let valid = Leaf4Subleaf::from(subleaf);
                // Push subleaf
                #[cfg(feature = "static")]
                vec.try_push(valid).map_err(LeafOverflowError::Leaf4)?;
                #[cfg(not(feature = "static"))]
                vec.push(valid);
                // Check limit
                debug_limit!(i);
            }
            vec
        });

        let leaf_7 = Leaf7(
            Leaf7Subleaf0::from(__cpuid_count(0x7, 0)),
            (__get_cpuid_max(0x7).1 == 1).then(|| Leaf7Subleaf1::from(__cpuid_count(0x7, 1))),
        );

        // For sub-leaves that return an invalid level-type of 0 in ECX[15:8]; EAX and EBX will
        // return 0.
        // If an input value n in ECX returns the invalid level-type of 0 in ECX[15:8], other input
        // values with ECX > n also return 0 in ECX[15:8].
        let leaf_b = LeafB({
            #[cfg(feature = "static")]
            let mut vec = ArrayVec::new();
            #[cfg(not(feature = "static"))]
            let mut vec = Vec::new();

            for i in 0.. {
                // Get subleaf
                let subleaf = __cpuid_count(0xB, i);
                let valid = LeafBSubleaf::from(subleaf);
                // Check if invalid
                // > If an input value n in ECX returns the invalid level-type of 0 in ECX[15:8],
                // > other input values with ECX > n also return 0 in ECX[15:8].
                if valid.ecx.level_type == 0 {
                    // // > For sub-leaves that return an invalid level-type of 0 in ECX[15:8]; EAX
                    // and // > EBX will return 0.
                    // debug_assert_eq!(valid.eax.bit_shifts_right_2x_apic_id_unique_topology_id,0);
                    // debug_assert_eq!(valid.ebx.logical_processors,0);
                    break;
                }
                // Push subleaf
                #[cfg(feature = "static")]
                vec.try_push(valid).map_err(LeafOverflowError::LeafB)?;
                #[cfg(not(feature = "static"))]
                vec.push(valid);
                // Check limit
                debug_limit!(i);
            }
            vec
        });

        let leaf_d = {
            // Each sub-leaf index (starting at position 2) is supported if it corresponds to a
            // supported bit in either the XCR0 register or the IA32_XSS MSR.
            // * If ECX contains an invalid sub-leaf index, EAX/EBX/ECX/EDX return 0. Sub-leaf n (0
            //   ≤ n ≤ 31) is invalid
            // if sub-leaf 0 returns 0 in EAX[n] and sub-leaf 1 returns 0 in ECX[n]. Sub-leaf n (32
            // ≤ n ≤ 63) is invalid if sub-leaf 0 returns 0 in EDX[n-32] and sub-leaf 1
            // returns 0 in EDX[n-32].
            #[cfg(feature = "static")]
            let mut vec = ArrayVec::new();
            #[cfg(not(feature = "static"))]
            let mut vec = Vec::new();
            for i in 2.. {
                // Get subleaf
                let subleaf = __cpuid_count(0xD, i);
                // Check if invalid
                if subleaf.eax == 0 && subleaf.ebx == 0 && subleaf.ecx == 0 && subleaf.edx == 0 {
                    break;
                }
                let valid = LeafDSubleafGt1::from(subleaf);
                // Push subleaf
                #[cfg(feature = "static")]
                vec.try_push(valid).map_err(LeafOverflowError::LeafD)?;
                #[cfg(not(feature = "static"))]
                vec.push(valid);
                // Check limit
                debug_limit!(i);
            }
            LeafD(
                LeafDSubleaf0::from(__cpuid_count(0xD, 0)),
                LeafDSubleaf1::from(__cpuid_count(0xD, 1)),
                vec,
            )
        };

        let leaf_f = LeafF(
            LeafFSubleaf0::from(__cpuid_count(0xF, 0)),
            (__get_cpuid_max(0xF).1 == 1).then(|| LeafFSubleaf1::from(__cpuid_count(0xF, 1))),
        );

        let leaf_10 = {
            let n = __get_cpuid_max(0x10).1;
            Leaf10(
                Leaf10Subleaf0::from(__cpuid_count(0x10, 0)),
                (n > 0).then(|| Leaf10Subleaf1::from(__cpuid_count(0x10, 1))),
                (n > 1).then(|| Leaf10Subleaf2::from(__cpuid_count(0x10, 2))),
                (n > 2).then(|| Leaf10Subleaf3::from(__cpuid_count(0x10, 3))),
            )
        };

        // Leaf 12H subleaves are supported if CPUID.(EAX=07H, ECX=0H):EBX[SGX] = 1.
        let leaf_12 = if leaf_7.0.ebx.sgx == true {
            Some(Leaf12(
                Leaf12Subleaf0::from(__cpuid_count(0x12, 0)),
                Leaf12Subleaf1::from(__cpuid_count(0x12, 1)),
                {
                    #[cfg(feature = "static")]
                    let mut vec = ArrayVec::new();
                    #[cfg(not(feature = "static"))]
                    let mut vec = Vec::new();
                    for i in 2..__get_cpuid_max(0x12).1 {
                        // Get subleaf
                        let subleaf = __cpuid_count(0x12, i);
                        // > 0000b. This sub-leaf is invalid.
                        // > DX:ECX:EBX:EAX return 0.
                        #[cfg(debug_assertions)]
                        if subleaf.eax == 0 {
                            debug_assert_eq!(subleaf.ecx, 0);
                            debug_assert_eq!(subleaf.ebx, 0);
                            debug_assert_eq!(subleaf.eax, 0);
                            // TODO It doesn't specify here that subleaves following an invalid
                            // subleaf will be invalid, thus we do not break here. Although I am
                            // uncomfortable relying on `__get_cpuid_max` given how often it is
                            // wrong.
                        }

                        let valid = Leaf12SubleafGt1::from(subleaf);

                        // Push subleaf
                        #[cfg(feature = "static")]
                        vec.try_push(valid).map_err(LeafOverflowError::Leaf12)?;
                        #[cfg(not(feature = "static"))]
                        vec.push(valid);
                        // Check limit
                        debug_limit!(i);
                    }
                    vec
                },
            ))
        } else {
            None
        };

        let leaf_14 = Leaf14(
            Leaf14Subleaf0::from(__cpuid_count(0x14, 0)),
            (__get_cpuid_max(0x14).1 == 1).then(|| Leaf14Subleaf1::from(__cpuid_count(0x14, 1))),
        );

        let leaf_17 = {
            let n = __get_cpuid_max(0x17).1;
            debug_assert!(n == 0 || n >= 3);
            if n > 3 {
                Some(Leaf17(
                    Leaf17Subleaf0::from(__cpuid_count(0x17, 0)),
                    Leaf17Subleaf1::from(__cpuid_count(0x17, 1)),
                    Leaf17Subleaf2::from(__cpuid_count(0x17, 2)),
                    Leaf17Subleaf3::from(__cpuid_count(0x17, 3)),
                    // Leaf 17H sub-leaves 4 and above are reserved.
                ))
            } else {
                None
            }
        };
        #[cfg(feature = "leaf_18")]
        let leaf_18 = {
            let subleaf_0 = __cpuid_count(0x18, 0);
            let n = subleaf_0.eax;
            if n > 0 {
                // If ECX contains an invalid sub-leaf index, EAX/EBX/ECX/EDX return 0. Sub-leaf
                // index n is invalid if n exceeds the value that sub-leaf 0 returns
                // in EAX. A sub-leaf index is also invalid if EDX[4:0] returns 0.
                #[cfg(feature = "static")]
                let mut vec = ArrayVec::new();
                #[cfg(not(feature = "static"))]
                let mut vec = Vec::new();
                for i in 1..n {
                    // Get subleaf
                    let subleaf = __cpuid_count(0x18, i);
                    let valid = Leaf18SubleafGt0::from(subleaf);
                    // Push subleaf
                    #[cfg(feature = "static")]
                    vec.try_push(valid).map_err(LeafOverflowError::Leaf18)?;
                    #[cfg(not(feature = "static"))]
                    vec.push(valid);
                    // Check limit
                    debug_limit!(i);
                }
                Some(Leaf18(Leaf18Subleaf0::from(__cpuid_count(0x18, 0)), vec))
            } else {
                None
            }
        };

        let leaf_1f = Leaf1F({
            // For sub-leaves that return an invalid level-type of 0 in ECX[15:8]; EAX and EBX will
            // return 0. If an input value n in ECX returns the invalid level-type of 0
            // in ECX[15:8], other input values with ECX > n also return 0 in ECX[15:8].
            #[cfg(feature = "static")]
            let mut vec = ArrayVec::new();
            #[cfg(not(feature = "static"))]
            let mut vec = Vec::new();
            for i in 0.. {
                // Get subleaf
                let subleaf = __cpuid_count(0x1F, i);
                let valid = Leaf1FSubleaf::from(subleaf);
                // Check if invalid
                if valid.ecx.level_type == 0 {
                    break;
                }
                // Push subleaf
                #[cfg(feature = "static")]
                vec.try_push(valid).map_err(LeafOverflowError::Leaf1F)?;
                #[cfg(not(feature = "static"))]
                vec.push(valid);
                // Check limit
                debug_limit!(i);
            }
            vec
        });

        // We construct leaves which consist of a single subleaf here.
        let cpuid = Self {
            leaf_0: Leaf0::from(__cpuid_count(0x0, 0)),
            leaf_1: Leaf1::from(__cpuid_count(0x1, 0)),
            leaf_2,
            leaf_3: Leaf3::from(__cpuid_count(0x3, 0)),
            leaf_4,
            leaf_5: Leaf5::from(__cpuid_count(0x5, 0)),
            leaf_6: Leaf6::from(__cpuid_count(0x6, 0)),
            leaf_7,
            leaf_9: Leaf9::from(__cpuid_count(0x9, 0)),
            leaf_a: LeafA::from(__cpuid_count(0xA, 0)),
            leaf_b,
            leaf_d,
            leaf_f,
            leaf_10,
            leaf_12,
            leaf_14,
            leaf_15: Leaf15::from(__cpuid_count(0x15, 0)),
            leaf_16: Leaf16::from(__cpuid_count(0x16, 0)),
            leaf_17,
            #[cfg(feature = "leaf_18")]
            leaf_18,
            leaf_19: (__get_cpuid_max(0x19).1 == 1).then(|| Leaf19::from(__cpuid_count(0x19, 0))),
            leaf_1a: (__get_cpuid_max(0x1A).1 == 1).then(|| Leaf1A::from(__cpuid_count(0x1A, 0))),
            leaf_1b: (__get_cpuid_max(0x1B).1 == 1).then(|| Leaf1B::from(__cpuid_count(0x1B, 0))),
            leaf_1c: (__get_cpuid_max(0x1C).1 == 1).then(|| Leaf1C::from(__cpuid_count(0x1C, 0))),
            leaf_1f,
            leaf_20: (__get_cpuid_max(0x20).1 == 1).then(|| Leaf20::from(__cpuid_count(0x20, 0))),
            leaf_80000000: Leaf80000000::from(__cpuid_count(0x80000000, 0)),
            leaf_80000001: Leaf80000001::from(__cpuid_count(0x80000001, 0)),
            leaf_80000002: Leaf80000002::from(__cpuid_count(0x80000002, 0)),
            leaf_80000003: Leaf80000003::from(__cpuid_count(0x80000003, 0)),
            leaf_80000004: Leaf80000004::from(__cpuid_count(0x80000004, 0)),
            leaf_80000005: Leaf80000005::from(__cpuid_count(0x80000005, 0)),
            leaf_80000006: Leaf80000006::from(__cpuid_count(0x80000006, 0)),
            leaf_80000007: Leaf80000007::from(__cpuid_count(0x80000007, 0)),
            leaf_80000008: Leaf80000008::from(__cpuid_count(0x80000008, 0)),
        };
        #[cfg(feature = "static")]
        let rtn = Ok(cpuid);
        #[cfg(not(feature = "static"))]
        let rtn = cpuid;
        rtn
    }
}
impl IntelCpuid {
    /// Returns the CPUID manufacturers ID. E.g. `GenuineIntel` or `AuthenticAMD`.
    #[must_use]
    pub fn manufacturer_id(&self) -> FixedString<12> {
        FixedString::from((
            self.leaf_0.ebx.clone(),
            self.leaf_0.ecx.clone(),
            self.leaf_0.edx.clone(),
        ))
    }
    /// Applies `vm_spec` to `self`.
    ///
    /// # Errors
    ///
    /// When failing to set:
    /// - Feature infomation leaf.
    /// - Deterministic cache leaf
    /// - Extended topology leaf
    #[allow(clippy::too_many_lines)]
    pub fn apply_vm_spec(&mut self, vm_spec: &crate::VmSpec) -> Result<(), ApplyVmSpecError> {
        // Update feature infomation entry
        {
            /// Flush a cache line size.
            const EBX_CLFLUSH_CACHELINE: u32 = 8;

            /// The maximum number of logical processors per package is computed as the closest
            /// power of 2 higher or equal to the CPU count configured by the user.
            const fn get_max_cpus_per_package(
                cpu_count: u8,
            ) -> Result<u8, GetMaxCpusPerPackageError> {
                // This match is better than but approximately equivalent to
                // `2.pow((cpu_count as f32).log2().ceil() as u8)` (`2^ceil(log_2(c))`).
                match cpu_count {
                    0 => Err(GetMaxCpusPerPackageError::Underflow),
                    1 => Ok(1),
                    2 => Ok(2),
                    3..=4 => Ok(4),
                    5..=8 => Ok(8),
                    9..=16 => Ok(16),
                    17..=32 => Ok(32),
                    33..=64 => Ok(64),
                    65..=128 => Ok(128),
                    129..=u8::MAX => Err(GetMaxCpusPerPackageError::Overflow),
                }
            }

            // X86 hypervisor feature
            self.leaf_1.ecx.tsc_deadline.on();
            // Hypervisor bit
            self.leaf_1.ecx.bit_mut::<31>().on();

            self.leaf_1
                .ebx
                .initial_apic_id
                .checked_assign(u32::from(vm_spec.cpu_index))
                .map_err(FeatireInfomationError::InitialApicId)?;
            self.leaf_1
                .ebx
                .clflush
                .checked_assign(EBX_CLFLUSH_CACHELINE)
                .map_err(FeatireInfomationError::Clflush)?;
            let max_cpus_per_package = u32::from(
                get_max_cpus_per_package(vm_spec.cpu_count)
                    .map_err(FeatireInfomationError::GetMaxCpusPerPackage)?,
            );
            self.leaf_1
                .ebx
                .max_addressable_logical_processor_ids
                .checked_assign(max_cpus_per_package)
                .map_err(FeatireInfomationError::SetMaxCpusPerPackage)?;

            // A value of 1 for HTT indicates the value in CPUID.1.EBX[23:16]
            // (the Maximum number of addressable IDs for logical processors in this package)
            // is valid for the package
            self.leaf_1.edx.htt.set(vm_spec.cpu_count > 1);
        }

        // Update deterministic cache entry
        {
            for subleaf in self.leaf_4.0.iter_mut() {
                match u32::from(&subleaf.eax.cache_level) {
                    // L1 & L2 Cache
                    // The L1 & L2 cache is shared by at most 2 hyperthreads
                    1 | 2 => subleaf
                        .eax
                        .max_num_addressable_ids_for_logical_processors_sharing_this_cache
                        .checked_assign(u32::from(vm_spec.cpus_per_core() - 1))
                        .map_err(DeterministicCacheError::MaxCpusPerCore)?,
                    // L3 Cache
                    // The L3 cache is shared among all the logical threads
                    3 => subleaf
                        .eax
                        .max_num_addressable_ids_for_logical_processors_sharing_this_cache
                        .checked_assign(u32::from(vm_spec.cpu_count - 1))
                        .map_err(DeterministicCacheError::MaxCpusPerCore)?,
                    _ => (),
                }
                // Put all the cores in the same socket
                subleaf
                    .eax
                    .max_num_addressable_ids_for_processor_cores_in_physical_package
                    .checked_assign(u32::from(vm_spec.cpu_count / vm_spec.cpus_per_core()) - 1)
                    .map_err(DeterministicCacheError::MaxCorePerPackage)?
            }
        }

        // Update extended topology entry
        #[allow(clippy::doc_markdown)]
        {
            /// Level type used for setting thread level processor topology.
            pub const LEVEL_TYPE_THREAD: u32 = 1;
            /// Level type used for setting core level processor topology.
            pub const LEVEL_TYPE_CORE: u32 = 2;
            /// The APIC ID shift in leaf 0xBh specifies the number of bits to shit the x2APIC ID to
            /// get a unique topology of the next level. This allows 128 logical
            /// processors/package.
            const LEAFBH_INDEX1_APICID: u32 = 7;

            for (index, subleaf) in self.leaf_b.0.iter_mut().enumerate() {
                // reset eax, ebx, ecx
                subleaf.eax.data = 0;
                subleaf.ebx.data = 0;
                subleaf.ecx.data = 0;
                // EDX bits 31..0 contain x2APIC ID of current logical processor
                // x2APIC increases the size of the APIC ID from 8 bits to 32 bits
                subleaf.edx.data = u32::from(vm_spec.cpu_index);

                // "If SMT is not present in a processor implementation but CPUID leaf 0BH is
                // supported, CPUID.EAX=0BH, ECX=0 will return EAX = 0, EBX = 1 and
                // level type = 1. Number of logical processors at the core level is
                // reported at level type = 2." (Intel® 64 Architecture x2APIC
                // Specification, Ch. 2.8)
                match index {
                    // Thread Level Topology; index = 0
                    0 => {
                        // To get the next level APIC ID, shift right with at most 1 because we have
                        // maximum 2 hyperthreads per core that can be represented by 1 bit.
                        subleaf
                            .eax
                            .bit_shifts_right_2x_apic_id_unique_topology_id
                            .checked_assign(u32::from(vm_spec.cpu_bits))
                            .map_err(ExtendedTopologyError::ApicId)?;
                        // When cpu_count == 1 or HT is disabled, there is 1 logical core at this
                        // level Otherwise there are 2
                        subleaf
                            .ebx
                            .logical_processors
                            .checked_assign(u32::from(vm_spec.cpus_per_core()))
                            .map_err(ExtendedTopologyError::LogicalProcessors)?;

                        subleaf
                            .ecx
                            .level_type
                            .checked_assign(LEVEL_TYPE_THREAD)
                            .map_err(ExtendedTopologyError::LevelType)?;
                    }
                    // Core Level Processor Topology; index = 1
                    1 => {
                        subleaf
                            .eax
                            .bit_shifts_right_2x_apic_id_unique_topology_id
                            .checked_assign(LEAFBH_INDEX1_APICID)
                            .map_err(ExtendedTopologyError::ApicId)?;
                        subleaf
                            .ebx
                            .logical_processors
                            .checked_assign(u32::from(vm_spec.cpu_count))
                            .map_err(ExtendedTopologyError::LogicalProcessors)?;
                        // We expect here as this is an extremely rare case that is unlikely to ever
                        // occur. It would require manual editing of the CPUID structure to push
                        // more than 2^32 subleaves.
                        subleaf
                            .ecx
                            .level_number
                            .checked_assign(
                                u32::try_from(index)
                                    .expect("Failed to convert sub-leaf index to u32."),
                            )
                            .map_err(ExtendedTopologyError::LevelNumber)?;
                        subleaf
                            .ecx
                            .level_type
                            .checked_assign(LEVEL_TYPE_CORE)
                            .map_err(ExtendedTopologyError::LevelType)?;
                    }
                    // Core Level Processor Topology; index >=2
                    // No other levels available; This should already be set correctly,
                    // and it is added here as a "re-enforcement" in case we run on
                    // different hardware
                    level => {
                        // We expect here as this is an extremely rare case that is unlikely to ever
                        // occur. It would require manual editing of the CPUID structure to push
                        // more than 2^32 subleaves.
                        subleaf.ecx.data =
                            u32::try_from(level).expect("Failed to convert sub-leaf index to u32.");
                    }
                }
            }
        }

        Ok(())
    }

    /// Indexs leaf.
    #[must_use]
    pub fn leaf<const N: usize>(&self) -> &<Self as IndexLeaf<N>>::Output
    where
        Self: IndexLeaf<N>,
    {
        <Self as IndexLeaf<N>>::leaf(self)
    }
    /// Create [`IntelCpuid`] from [`RawCpuid`].
    ///
    /// # Errors
    ///
    /// When:
    /// - Manfuacturers ID is unsupported (not `GenuineIntel` or `AuthenticAMD`).
    /// - With `static` feature, number of subleaves exceeds maximum supported.
    ///
    /// # Panics
    ///
    /// TODO
    // There is no good way to reduce the number of lines here.
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
    pub fn from_raw_cpuid(raw_cpuid: RawCpuid) -> IntelCpuidResultType {
        let leaf_2 = Leaf2::from({
            let leaf = raw_cpuid.get(0x2, 0x0).unwrap();
            (leaf.eax, leaf.ebx, leaf.ecx, leaf.edx)
        });
        let leaf_4 = Leaf4({
            #[cfg(feature = "static")]
            let mut vec = ArrayVec::new();
            #[cfg(not(feature = "static"))]
            let mut vec = Vec::new();
            for i in 0.. {
                if let Some(entry) = raw_cpuid.get(0x4, i) {
                    let valid = Leaf4Subleaf::from(entry);
                    // Push subleaf
                    #[cfg(feature = "static")]
                    vec.try_push(valid).map_err(LeafOverflowError::Leaf4)?;
                    #[cfg(not(feature = "static"))]
                    vec.push(valid);
                } else {
                    break;
                }
            }
            // TODO Use this instead of the above block when we update rust
            // let vec = (0..)
            //     .map_while(|i| {
            //         let subleaf = raw_cpuid.get(0x4, i);
            //         subleaf.map(Leaf4Subleaf::from)
            //     })
            //     .collect::<Vec<_>>();
            vec
        });
        let leaf_7 = Leaf7(
            Leaf7Subleaf0::from(raw_cpuid.get(0x7, 0).unwrap()),
            raw_cpuid.get(0x7, 1).map(Leaf7Subleaf1::from),
        );

        let leaf_b = LeafB({
            #[cfg(feature = "static")]
            let mut vec = ArrayVec::new();
            #[cfg(not(feature = "static"))]
            let mut vec = Vec::new();
            for i in 0.. {
                if let Some(entry) = raw_cpuid.get(0xB, i) {
                    let valid = LeafBSubleaf::from(entry);
                    // Push subleaf
                    #[cfg(feature = "static")]
                    vec.try_push(valid).map_err(LeafOverflowError::LeafB)?;
                    #[cfg(not(feature = "static"))]
                    vec.push(valid);
                } else {
                    break;
                }
            }
            // TODO Use this instead of the above block when we update rust
            // let vec = (0..)
            //     .map_while(|i| {
            //         let subleaf = raw_cpuid.get(0xB, i);
            //         subleaf.map(LeafBSubleaf::from)
            //     })
            //     .collect::<Vec<_>>();
            vec
        });

        let leaf_d = LeafD(
            LeafDSubleaf0::from(raw_cpuid.get(0xD, 0x0).unwrap()),
            LeafDSubleaf1::from(raw_cpuid.get(0xD, 0x1).unwrap()),
            {
                #[cfg(feature = "static")]
                let mut vec = ArrayVec::new();
                #[cfg(not(feature = "static"))]
                let mut vec = Vec::new();
                for i in 2.. {
                    if let Some(entry) = raw_cpuid.get(0xD, i) {
                        let valid = LeafDSubleafGt1::from(entry);
                        // Push subleaf
                        #[cfg(feature = "static")]
                        vec.try_push(valid).map_err(LeafOverflowError::LeafD)?;
                        #[cfg(not(feature = "static"))]
                        vec.push(valid);
                    } else {
                        break;
                    }
                }
                vec
            }, /* TODO Use this instead of the above block when we update rust
                * (2..)
                *     .map_while(|i| {
                *         let subleaf = raw_cpuid.get(0xD, i);
                *         subleaf.map(LeafDSubleafGt1::from)
                *     })
                *     .collect(), */
        );

        let leaf_f = LeafF(
            LeafFSubleaf0::from(raw_cpuid.get(0xF, 0).unwrap()),
            raw_cpuid.get(0xF, 1).map(LeafFSubleaf1::from),
        );

        let leaf_10 = Leaf10(
            Leaf10Subleaf0::from(raw_cpuid.get(0x10, 0).unwrap()),
            // subleaf0.ebx.l3_alloc == true
            raw_cpuid.get(0x10, 1).map(Leaf10Subleaf1::from),
            // subleaf0.ebx.l2_alloc == true
            raw_cpuid.get(0x10, 2).map(Leaf10Subleaf2::from),
            // subleaf0.ebx.mem_band_alloc == true
            raw_cpuid.get(0x10, 3).map(Leaf10Subleaf3::from),
        );

        // Leaf 12H subleaves are supported if CPUID.(EAX=07H, ECX=0H):EBX[SGX] = 1.
        let leaf_12 = if leaf_7.0.ebx.sgx == true {
            Some(Leaf12(
                Leaf12Subleaf0::from(raw_cpuid.get(0x12, 0).unwrap()),
                Leaf12Subleaf1::from(raw_cpuid.get(0x12, 1).unwrap()),
                {
                    #[cfg(feature = "static")]
                    let mut vec = ArrayVec::new();
                    #[cfg(not(feature = "static"))]
                    let mut vec = Vec::new();

                    for i in 2.. {
                        if let Some(entry) = raw_cpuid.get(0x12, i) {
                            let valid = Leaf12SubleafGt1::from(entry);
                            // Push subleaf
                            #[cfg(feature = "static")]
                            vec.try_push(valid).map_err(LeafOverflowError::Leaf12)?;
                            #[cfg(not(feature = "static"))]
                            vec.push(valid);
                        } else {
                            break;
                        }
                    }
                    vec
                },
            ))
        } else {
            None
        };

        let leaf_14 = Leaf14(
            Leaf14Subleaf0::from(raw_cpuid.get(0x14, 0).unwrap()),
            raw_cpuid.get(0x14, 1).map(Leaf14Subleaf1::from),
        );

        let leaf_17 = raw_cpuid.get(0x17, 0).map(|first| {
            Leaf17(
                Leaf17Subleaf0::from(first),
                Leaf17Subleaf1::from(raw_cpuid.get(0x17, 1).unwrap()),
                Leaf17Subleaf2::from(raw_cpuid.get(0x17, 2).unwrap()),
                Leaf17Subleaf3::from(raw_cpuid.get(0x17, 3).unwrap()),
                // Leaf 17H sub-leaves 4 and above are reserved.
            )
        });
        #[cfg(feature = "leaf_18")]
        let leaf_18 = match raw_cpuid.get(0x18, 0) {
            Some(first) => {
                Some(Leaf18(
                    Leaf18Subleaf0::from(first),
                    {
                        #[cfg(feature = "static")]
                        let mut vec = ArrayVec::new();
                        #[cfg(not(feature = "static"))]
                        let mut vec = Vec::new();
                        for i in 1.. {
                            if let Some(entry) = raw_cpuid.get(0x18, i) {
                                let valid = Leaf18SubleafGt0::from(entry);
                                // Push subleaf
                                #[cfg(feature = "static")]
                                vec.try_push(valid).map_err(LeafOverflowError::Leaf18)?;
                                #[cfg(not(feature = "static"))]
                                vec.push(valid);
                            } else {
                                break;
                            }
                        }
                        vec
                    }, /* TODO Use this instead of the above block when we update rust
                        * (1..)
                        *     .map_while(|i| {
                        *         let subleaf = raw_cpuid.get(0x18, i);
                        *         subleaf.map(Leaf18SubleafGt0::from)
                        *     })
                        *     .collect(), */
                ))
            }
            None => None,
        };

        let leaf_1f = Leaf1F({
            #[cfg(feature = "static")]
            let mut vec = ArrayVec::new();
            #[cfg(not(feature = "static"))]
            let mut vec = Vec::new();

            for i in 0.. {
                if let Some(entry) = raw_cpuid.get(0x1F, i) {
                    let valid = Leaf1FSubleaf::from(entry);

                    // Push subleaf
                    #[cfg(feature = "static")]
                    vec.try_push(valid).map_err(LeafOverflowError::Leaf1F)?;
                    #[cfg(not(feature = "static"))]
                    vec.push(valid);
                } else {
                    break;
                }
            }
            // let vec = (0..)
            //     .map_while(|i| {
            //         let subleaf = raw_cpuid.get(0x1F, i);
            //         subleaf.map(Leaf1FSubleaf::from)
            //     })
            //     .collect::<Vec<_>>();
            vec
        });

        // We construct leaves which consist of a single subleaf here.
        let cpuid = Self {
            leaf_0: Leaf0::from(raw_cpuid.get(0x0, 0x0).unwrap()),
            leaf_1: Leaf1::from(raw_cpuid.get(0x1, 0x0).unwrap()),
            leaf_2,
            leaf_3: Leaf3::from(raw_cpuid.get(0x3, 0x0).unwrap()),
            leaf_4,
            leaf_5: Leaf5::from(raw_cpuid.get(0x5, 0x0).unwrap()),
            leaf_6: Leaf6::from(raw_cpuid.get(0x6, 0x0).unwrap()),
            leaf_7,
            leaf_9: Leaf9::from(raw_cpuid.get(0x9, 0x0).unwrap()),
            leaf_a: LeafA::from(raw_cpuid.get(0xA, 0x0).unwrap()),
            leaf_b,
            leaf_d,
            leaf_f,
            leaf_10,
            leaf_12,
            leaf_14,
            leaf_15: Leaf15::from(raw_cpuid.get(0x15, 0x0).unwrap()),
            leaf_16: Leaf16::from(raw_cpuid.get(0x16, 0x0).unwrap()),
            leaf_17,
            #[cfg(feature = "leaf_18")]
            leaf_18,
            leaf_19: raw_cpuid.get(0x19, 0).map(Leaf19::from),
            leaf_1a: raw_cpuid.get(0x1A, 0).map(Leaf1A::from),
            leaf_1b: raw_cpuid.get(0x1B, 0).map(Leaf1B::from),
            leaf_1c: raw_cpuid.get(0x1C, 0).map(Leaf1C::from),
            leaf_1f,
            leaf_20: raw_cpuid.get(0x20, 0).map(Leaf20::from),
            leaf_80000000: Leaf80000000::from(raw_cpuid.get(0x8000_0000, 0).unwrap()),
            leaf_80000001: Leaf80000001::from(raw_cpuid.get(0x8000_0001, 0).unwrap()),
            leaf_80000002: Leaf80000002::from(raw_cpuid.get(0x8000_0002, 0).unwrap()),
            leaf_80000003: Leaf80000003::from(raw_cpuid.get(0x8000_0003, 0).unwrap()),
            leaf_80000004: Leaf80000004::from(raw_cpuid.get(0x8000_0004, 0).unwrap()),
            leaf_80000005: Leaf80000005::from(raw_cpuid.get(0x8000_0005, 0).unwrap()),
            leaf_80000006: Leaf80000006::from(raw_cpuid.get(0x8000_0006, 0).unwrap()),
            leaf_80000007: Leaf80000007::from(raw_cpuid.get(0x8000_0007, 0).unwrap()),
            leaf_80000008: Leaf80000008::from(raw_cpuid.get(0x8000_0008, 0).unwrap()),
        };

        #[cfg(feature = "static")]
        let rtn = Ok(cpuid);
        #[cfg(not(feature = "static"))]
        let rtn = cpuid;
        rtn
    }
}

impl FeatureComparison for IntelCpuid {
    /// Checks if `self` is a able to support `other`.
    ///
    /// Checks if a process from an environment with CPUID `other` could be continued in an
    /// environment with the CPUID `self`.
    #[logfn(Trace)]
    #[logfn_inputs(Trace)]
    fn feature_cmp(&self, other: &Self) -> Option<FeatureRelation> {
        let excluding_leaf_18 = cascade_cpo!(
            self.leaf_0.feature_cmp(&other.leaf_0),
            self.leaf_1.feature_cmp(&other.leaf_1),
            self.leaf_5.feature_cmp(&other.leaf_5),
            self.leaf_6.feature_cmp(&other.leaf_6),
            self.leaf_7.feature_cmp(&other.leaf_7),
            self.leaf_a.feature_cmp(&other.leaf_a),
            self.leaf_f.feature_cmp(&other.leaf_f),
            self.leaf_10.feature_cmp(&other.leaf_10),
            self.leaf_14.feature_cmp(&other.leaf_14),
            self.leaf_19.feature_cmp(&other.leaf_19),
            self.leaf_1c.feature_cmp(&other.leaf_1c),
            self.leaf_20.feature_cmp(&other.leaf_20),
            self.leaf_80000000.feature_cmp(&other.leaf_80000000),
            self.leaf_80000001.feature_cmp(&other.leaf_80000001),
            self.leaf_80000007.feature_cmp(&other.leaf_80000007),
            self.leaf_80000008.feature_cmp(&other.leaf_80000008)
        );
        #[rustfmt::skip]
        warn_support!(
            0x2,0x3,0x4,0x9,0xB,0xD,0x12,0x15,0x16,0x17,0x18,0x1A,0x1B,0x1F,0x21,0x80000002_u64,
            0x80000003_u64,0x80000004_u64,0x80000005_u64,0x80000006_u64
        );

        #[cfg(feature = "leaf_18")]
        let rtn = cpo(excluding_leaf_18, self.leaf_18.feature_cmp(&other.leaf_18));
        #[cfg(not(feature = "leaf_18"))]
        let rtn = excluding_leaf_18;

        rtn
    }
}

#[cfg(not(feature = "static"))]
impl From<RawCpuid> for IntelCpuid {
    fn from(raw_cpuid: RawCpuid) -> Self {
        Self::from_raw_cpuid(raw_cpuid)
    }
}
#[cfg(feature = "static")]
impl TryFrom<RawCpuid> for IntelCpuid {
    type Error = LeafOverflowError;
    fn try_from(raw_cpuid: RawCpuid) -> Result<Self, Self::Error> {
        Self::from_raw_cpuid(raw_cpuid)
    }
}

// - There is no good way to reduce the number of lines here.
// - It is more readable without using `vec![]`
#[allow(clippy::too_many_lines, clippy::vec_init_then_push)]
impl From<IntelCpuid> for RawCpuid {
    fn from(intel_cpuid: IntelCpuid) -> Self {
        let mut entries = Vec::new();
        // Leaf 0
        entries.push(RawCpuidEntry {
            function: 0x0,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_0.eax,
            ebx: intel_cpuid.leaf_0.ebx.into(),
            ecx: intel_cpuid.leaf_0.ecx.into(),
            edx: intel_cpuid.leaf_0.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 1
        entries.push(RawCpuidEntry {
            function: 0x1,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_1.eax.into(),
            ebx: intel_cpuid.leaf_1.ebx.into(),
            ecx: intel_cpuid.leaf_1.ecx.into(),
            edx: intel_cpuid.leaf_1.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 2
        entries.push(RawCpuidEntry {
            function: 0x2,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: u32::from_be_bytes(intel_cpuid.leaf_2.0.eax),
            ebx: u32::from_be_bytes(intel_cpuid.leaf_2.0.ebx),
            ecx: u32::from_be_bytes(intel_cpuid.leaf_2.0.ecx),
            edx: u32::from_be_bytes(intel_cpuid.leaf_2.0.edx),
            padding: Padding::default(),
        });
        // Leaf 3
        entries.push(RawCpuidEntry {
            function: 0x3,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_3.eax.into(),
            ebx: intel_cpuid.leaf_3.ebx.into(),
            ecx: intel_cpuid.leaf_3.ecx.into(),
            edx: intel_cpuid.leaf_3.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 4
        for (i, leaf_4_subleaf) in intel_cpuid.leaf_4.0.into_iter().enumerate() {
            entries.push(RawCpuidEntry {
                function: 0x4,
                index: u32::try_from(i).unwrap(),
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_4_subleaf.eax.into(),
                ebx: leaf_4_subleaf.ebx.into(),
                ecx: leaf_4_subleaf.ecx.into(),
                edx: leaf_4_subleaf.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf 5
        entries.push(RawCpuidEntry {
            function: 0x5,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_5.eax.into(),
            ebx: intel_cpuid.leaf_5.ebx.into(),
            ecx: intel_cpuid.leaf_5.ecx.into(),
            edx: intel_cpuid.leaf_5.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 6
        entries.push(RawCpuidEntry {
            function: 0x6,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_6.eax.into(),
            ebx: intel_cpuid.leaf_6.ebx.into(),
            ecx: intel_cpuid.leaf_6.ecx.into(),
            edx: intel_cpuid.leaf_6.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 7
        entries.push(RawCpuidEntry {
            function: 0x7,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_7.0.eax.into(),
            ebx: intel_cpuid.leaf_7.0.ebx.into(),
            ecx: intel_cpuid.leaf_7.0.ecx.into(),
            edx: intel_cpuid.leaf_7.0.edx.into(),
            padding: Padding::default(),
        });
        if let Some(leaf_7_subleaf_1) = intel_cpuid.leaf_7.1 {
            entries.push(RawCpuidEntry {
                function: 0x7,
                index: 1,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_7_subleaf_1.eax.into(),
                ebx: leaf_7_subleaf_1.ebx.into(),
                ecx: leaf_7_subleaf_1.ecx.into(),
                edx: leaf_7_subleaf_1.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf 9
        entries.push(RawCpuidEntry {
            function: 0x9,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_9.eax.into(),
            ebx: intel_cpuid.leaf_9.ebx.into(),
            ecx: intel_cpuid.leaf_9.ecx.into(),
            edx: intel_cpuid.leaf_9.edx.into(),
            padding: Padding::default(),
        });
        // Leaf A
        entries.push(RawCpuidEntry {
            function: 0xA,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_a.eax.into(),
            ebx: intel_cpuid.leaf_a.ebx.into(),
            ecx: intel_cpuid.leaf_a.ecx.into(),
            edx: intel_cpuid.leaf_a.edx.into(),
            padding: Padding::default(),
        });
        // Leaf B
        for (i, leaf_b_subleaf) in intel_cpuid.leaf_b.0.into_iter().enumerate() {
            entries.push(RawCpuidEntry {
                function: 0xB,
                index: u32::try_from(i).unwrap(),
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_b_subleaf.eax.into(),
                ebx: leaf_b_subleaf.ebx.into(),
                ecx: leaf_b_subleaf.ecx.into(),
                edx: leaf_b_subleaf.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf D
        entries.push(RawCpuidEntry {
            function: 0xD,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_d.0.eax.into(),
            ebx: intel_cpuid.leaf_d.0.ebx.into(),
            ecx: intel_cpuid.leaf_d.0.ecx.into(),
            edx: intel_cpuid.leaf_d.0.edx.into(),
            padding: Padding::default(),
        });
        entries.push(RawCpuidEntry {
            function: 0xD,
            index: 1,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_d.1.eax.into(),
            ebx: intel_cpuid.leaf_d.1.ebx.into(),
            ecx: intel_cpuid.leaf_d.1.ecx.into(),
            edx: intel_cpuid.leaf_d.1.edx.into(),
            padding: Padding::default(),
        });
        for (i, leaf_d_subleaf) in intel_cpuid.leaf_d.2.into_iter().enumerate() {
            entries.push(RawCpuidEntry {
                function: 0xD,
                index: u32::try_from(i).unwrap() + 2,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_d_subleaf.eax.into(),
                ebx: leaf_d_subleaf.ebx.into(),
                ecx: leaf_d_subleaf.ecx.into(),
                edx: leaf_d_subleaf.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf F
        entries.push(RawCpuidEntry {
            function: 0xF,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_f.0.eax.into(),
            ebx: intel_cpuid.leaf_f.0.ebx.into(),
            ecx: intel_cpuid.leaf_f.0.ecx.into(),
            edx: intel_cpuid.leaf_f.0.edx.into(),
            padding: Padding::default(),
        });
        if let Some(leaf_f_subleaf_1) = intel_cpuid.leaf_f.1 {
            entries.push(RawCpuidEntry {
                function: 0xF,
                index: 1,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_f_subleaf_1.eax.into(),
                ebx: leaf_f_subleaf_1.ebx.into(),
                ecx: leaf_f_subleaf_1.ecx.into(),
                edx: leaf_f_subleaf_1.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf 10
        entries.push(RawCpuidEntry {
            function: 0x10,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_10.0.eax.into(),
            ebx: intel_cpuid.leaf_10.0.ebx.into(),
            ecx: intel_cpuid.leaf_10.0.ecx.into(),
            edx: intel_cpuid.leaf_10.0.edx.into(),
            padding: Padding::default(),
        });
        if let Some(leaf_10_subleaf_1) = intel_cpuid.leaf_10.1 {
            entries.push(RawCpuidEntry {
                function: 0x10,
                index: 1,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_10_subleaf_1.eax.into(),
                ebx: leaf_10_subleaf_1.ebx.into(),
                ecx: leaf_10_subleaf_1.ecx.into(),
                edx: leaf_10_subleaf_1.edx.into(),
                padding: Padding::default(),
            });
        }
        if let Some(leaf_10_subleaf_2) = intel_cpuid.leaf_10.2 {
            entries.push(RawCpuidEntry {
                function: 0x10,
                index: 2,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_10_subleaf_2.eax.into(),
                ebx: leaf_10_subleaf_2.ebx.into(),
                ecx: leaf_10_subleaf_2.ecx.into(),
                edx: leaf_10_subleaf_2.edx.into(),
                padding: Padding::default(),
            });
        }
        if let Some(leaf_10_subleaf_3) = intel_cpuid.leaf_10.3 {
            entries.push(RawCpuidEntry {
                function: 0x10,
                index: 3,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_10_subleaf_3.eax.into(),
                ebx: leaf_10_subleaf_3.ebx.into(),
                ecx: leaf_10_subleaf_3.ecx.into(),
                edx: leaf_10_subleaf_3.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf 12
        if let Some(leaf_12) = intel_cpuid.leaf_12 {
            entries.push(RawCpuidEntry {
                function: 0x12,
                index: 0,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_12.0.eax.into(),
                ebx: leaf_12.0.ebx.into(),
                ecx: leaf_12.0.ecx.into(),
                edx: leaf_12.0.edx.into(),
                padding: Padding::default(),
            });
            entries.push(RawCpuidEntry {
                function: 0x12,
                index: 1,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_12.1.eax.into(),
                ebx: leaf_12.1.ebx.into(),
                ecx: leaf_12.1.ecx.into(),
                edx: leaf_12.1.edx.into(),
                padding: Padding::default(),
            });
            for (i, leaf_12_subleaf) in leaf_12.2.into_iter().enumerate() {
                entries.push(RawCpuidEntry {
                    function: 0x12,
                    index: u32::try_from(i).unwrap() + 2,
                    // TODO Does flags matter here?
                    flags: 0,
                    eax: leaf_12_subleaf.eax.into(),
                    ebx: leaf_12_subleaf.ebx.into(),
                    ecx: leaf_12_subleaf.ecx.into(),
                    edx: leaf_12_subleaf.edx.into(),
                    padding: Padding::default(),
                });
            }
        }

        // Leaf 14
        entries.push(RawCpuidEntry {
            function: 0x14,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_14.0.eax.into(),
            ebx: intel_cpuid.leaf_14.0.ebx.into(),
            ecx: intel_cpuid.leaf_14.0.ecx.into(),
            edx: intel_cpuid.leaf_14.0.edx.into(),
            padding: Padding::default(),
        });
        if let Some(leaf_14_subleaf_1) = intel_cpuid.leaf_14.1 {
            entries.push(RawCpuidEntry {
                function: 0x14,
                index: 1,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_14_subleaf_1.eax.into(),
                ebx: leaf_14_subleaf_1.ebx.into(),
                ecx: leaf_14_subleaf_1.ecx.into(),
                edx: leaf_14_subleaf_1.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf 15
        entries.push(RawCpuidEntry {
            function: 0x15,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_15.eax.into(),
            ebx: intel_cpuid.leaf_15.ebx.into(),
            ecx: intel_cpuid.leaf_15.ecx.into(),
            edx: intel_cpuid.leaf_15.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 16
        entries.push(RawCpuidEntry {
            function: 0x16,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_16.eax.into(),
            ebx: intel_cpuid.leaf_16.ebx.into(),
            ecx: intel_cpuid.leaf_16.ecx.into(),
            edx: intel_cpuid.leaf_16.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 17
        if let Some(leaf_17) = intel_cpuid.leaf_17 {
            entries.push(RawCpuidEntry {
                function: 0x17,
                index: 0,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_17.0.eax.into(),
                ebx: leaf_17.0.ebx.into(),
                ecx: leaf_17.0.ecx.into(),
                edx: leaf_17.0.edx.into(),
                padding: Padding::default(),
            });
            entries.push(RawCpuidEntry {
                function: 0x17,
                index: 1,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_17.1.eax.into(),
                ebx: leaf_17.1.ebx.into(),
                ecx: leaf_17.1.ecx.into(),
                edx: leaf_17.1.edx.into(),
                padding: Padding::default(),
            });
            entries.push(RawCpuidEntry {
                function: 0x17,
                index: 2,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_17.2.eax.into(),
                ebx: leaf_17.2.ebx.into(),
                ecx: leaf_17.2.ecx.into(),
                edx: leaf_17.2.edx.into(),
                padding: Padding::default(),
            });
            entries.push(RawCpuidEntry {
                function: 0x17,
                index: 3,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_17.3.eax.into(),
                ebx: leaf_17.3.ebx.into(),
                ecx: leaf_17.3.ecx.into(),
                edx: leaf_17.3.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf 18
        #[cfg(feature = "leaf_18")]
        if let Some(leaf_18) = intel_cpuid.leaf_18 {
            entries.push(RawCpuidEntry {
                function: 0x18,
                index: 0,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_18.0.eax.into(),
                ebx: leaf_18.0.ebx.into(),
                ecx: leaf_18.0.ecx.into(),
                edx: leaf_18.0.edx.into(),
                padding: Padding::default(),
            });
            for (i, leaf_18_subleaf) in leaf_18.1.into_iter().enumerate() {
                entries.push(RawCpuidEntry {
                    function: 0x18,
                    index: u32::try_from(i).unwrap() + 1,
                    // TODO Does flags matter here?
                    flags: 0,
                    eax: leaf_18_subleaf.eax.into(),
                    ebx: leaf_18_subleaf.ebx.into(),
                    ecx: leaf_18_subleaf.ecx.into(),
                    edx: leaf_18_subleaf.edx.into(),
                    padding: Padding::default(),
                });
            }
        }

        // Leaf 19
        if let Some(leaf_19) = intel_cpuid.leaf_19 {
            entries.push(RawCpuidEntry {
                function: 0x19,
                index: 0,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_19.eax.into(),
                ebx: leaf_19.ebx.into(),
                ecx: leaf_19.ecx.into(),
                edx: leaf_19.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf 1A
        if let Some(leaf_1a) = intel_cpuid.leaf_1a {
            entries.push(RawCpuidEntry {
                function: 0x1A,
                index: 0,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_1a.eax.into(),
                ebx: leaf_1a.ebx.into(),
                ecx: leaf_1a.ecx.into(),
                edx: leaf_1a.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf 1B
        if let Some(leaf_1b) = intel_cpuid.leaf_1b {
            entries.push(RawCpuidEntry {
                function: 0x1B,
                index: 0,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_1b.eax.into(),
                ebx: leaf_1b.ebx.into(),
                ecx: leaf_1b.ecx.into(),
                edx: leaf_1b.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf 1C
        if let Some(leaf_1c) = intel_cpuid.leaf_1c {
            entries.push(RawCpuidEntry {
                function: 0x1C,
                index: 0,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_1c.eax.into(),
                ebx: leaf_1c.ebx.into(),
                ecx: leaf_1c.ecx.into(),
                edx: leaf_1c.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf 1F
        for (i, leaf_1f_subleaf) in intel_cpuid.leaf_1f.0.into_iter().enumerate() {
            entries.push(RawCpuidEntry {
                function: 0x1F,
                index: u32::try_from(i).unwrap(),
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_1f_subleaf.eax.into(),
                ebx: leaf_1f_subleaf.ebx.into(),
                ecx: leaf_1f_subleaf.ecx.into(),
                edx: leaf_1f_subleaf.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf 20
        if let Some(leaf_20) = intel_cpuid.leaf_20 {
            entries.push(RawCpuidEntry {
                function: 0x20,
                index: 0,
                // TODO Does flags matter here?
                flags: 0,
                eax: leaf_20.eax.into(),
                ebx: leaf_20.ebx.into(),
                ecx: leaf_20.ecx.into(),
                edx: leaf_20.edx.into(),
                padding: Padding::default(),
            });
        }
        // Leaf 80000000
        entries.push(RawCpuidEntry {
            function: 0x80000000,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_80000000.eax.into(),
            ebx: intel_cpuid.leaf_80000000.ebx.into(),
            ecx: intel_cpuid.leaf_80000000.ecx.into(),
            edx: intel_cpuid.leaf_80000000.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 80000001
        entries.push(RawCpuidEntry {
            function: 0x80000001,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_80000001.eax.into(),
            ebx: intel_cpuid.leaf_80000001.ebx.into(),
            ecx: intel_cpuid.leaf_80000001.ecx.into(),
            edx: intel_cpuid.leaf_80000001.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 80000002
        entries.push(RawCpuidEntry {
            function: 0x80000002,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_80000002.eax.into(),
            ebx: intel_cpuid.leaf_80000002.ebx.into(),
            ecx: intel_cpuid.leaf_80000002.ecx.into(),
            edx: intel_cpuid.leaf_80000002.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 80000003
        entries.push(RawCpuidEntry {
            function: 0x80000003,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_80000003.eax.into(),
            ebx: intel_cpuid.leaf_80000003.ebx.into(),
            ecx: intel_cpuid.leaf_80000003.ecx.into(),
            edx: intel_cpuid.leaf_80000003.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 80000004
        entries.push(RawCpuidEntry {
            function: 0x80000004,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_80000004.eax.into(),
            ebx: intel_cpuid.leaf_80000004.ebx.into(),
            ecx: intel_cpuid.leaf_80000004.ecx.into(),
            edx: intel_cpuid.leaf_80000004.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 80000005
        entries.push(RawCpuidEntry {
            function: 0x80000005,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_80000005.eax.into(),
            ebx: intel_cpuid.leaf_80000005.ebx.into(),
            ecx: intel_cpuid.leaf_80000005.ecx.into(),
            edx: intel_cpuid.leaf_80000005.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 80000006
        entries.push(RawCpuidEntry {
            function: 0x80000006,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_80000006.eax.into(),
            ebx: intel_cpuid.leaf_80000006.ebx.into(),
            ecx: intel_cpuid.leaf_80000006.ecx.into(),
            edx: intel_cpuid.leaf_80000006.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 80000007
        entries.push(RawCpuidEntry {
            function: 0x80000007,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_80000007.eax.into(),
            ebx: intel_cpuid.leaf_80000007.ebx.into(),
            ecx: intel_cpuid.leaf_80000007.ecx.into(),
            edx: intel_cpuid.leaf_80000007.edx.into(),
            padding: Padding::default(),
        });
        // Leaf 80000008
        entries.push(RawCpuidEntry {
            function: 0x80000008,
            index: 0,
            // TODO Does flags matter here?
            flags: 0,
            eax: intel_cpuid.leaf_80000008.eax.into(),
            ebx: intel_cpuid.leaf_80000008.ebx.into(),
            ecx: intel_cpuid.leaf_80000008.ecx.into(),
            edx: intel_cpuid.leaf_80000008.edx.into(),
            padding: Padding::default(),
        });
        Self::from(entries)
    }
}

/// Cascades the `cpo` function.
#[macro_export]
macro_rules! cascade_cpo {
    ($($x:expr),*) => {
        {
            $crate::cascade!(Some(FeatureRelation::Equal),cpo$(,$x)*)
        }
    }
}
/// Cascades a function, e.g. `add(add(1,2),add(3,4))` can be written `cascade!(0,add,1,2,3,4)`.
#[macro_export]
macro_rules! cascade {
    ($s:expr,$f:expr,$($x:expr),*) => {
        {
            let temp = $s;
            $(
                let temp = $f(temp,$x);
            )*
            temp
        }
    }
}

/// Combine Partial Ordering
#[must_use]
pub fn cpo(a: Option<FeatureRelation>, b: Option<FeatureRelation>) -> Option<FeatureRelation> {
    use FeatureRelation::{Equal, Subset, Superset};

    let (x, y) = match (a, b) {
        (Some(x), Some(y)) => (x, y),
        (_, _) => return None,
    };

    match (x, y) {
        (Equal, Equal) => Some(Equal),

        (Superset, Superset) | (Equal, Superset) | (Superset, Equal) => Some(Superset),

        (Subset, _) | (_, Subset) => Some(Subset),
    }
}
