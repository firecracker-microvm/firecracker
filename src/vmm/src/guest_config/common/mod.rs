// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// TODO - Remove allow(unused) once types have been used

use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Add;

use serde::{Deserialize, Serialize};

#[cfg(target_arch = "x86_64")]
use crate::guest_config::cpuid::Cpuid;

/// Type defined to represent registers across CPU vendors
/// (pointers and values)
pub trait Numeric: Copy + Add<Self, Output = Self> {}
impl Numeric for u32 {}
impl Numeric for u64 {}
impl Numeric for u128 {}

/// Map to find and define model-specific registers
#[cfg(target_arch = "x86_64")]
#[allow(unused)]
pub struct MsrRegisterMap {
    register_map: HashMap<RegisterPointer<u32>, RegisterValue<u32>>,
}
/// Map to find and define registers for 64-bit ARM CPUs
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(unused)]
pub struct Aarch64RegisterMap {
    register_map: HashMap<RegisterPointer<u64>, RegisterValue<u128>>,
}

/// A trait type to be customized for each CPU architecture
/// to modify CPU configuration for the Firecracker guest
pub trait ConfigurationModifier {
    /// Applies the CPUTemplate against the CPUConfiguration
    fn apply_template(&self, cpu_template: CustomCpuTemplate) -> Box<CpuConfiguration>;
}

/// CPU configuration that can be of the host or the guest.
/// Expected to be populated in part or modified by
/// types implementing ConfigurationModifier
#[allow(unused)]
pub struct CpuConfiguration {
    /// Hashed set containing register configuration
    /// divided up by type of register. See `RegisterSet`
    pub register_config: Vec<RegisterSet>,
}

impl CpuConfiguration {
    /// Factory method to instantiate CPUConfiguration
    /// with the provided `RegisterSet`
    pub fn new(register_config: Vec<RegisterSet>) -> CpuConfiguration {
        CpuConfiguration { register_config }
    }
}

/// Template indicating a modification of CPU configuration
/// to be applied against the `CPUConfiguration` type
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CustomCpuTemplate {
    /// Modifier masks with pointer data for the modifiers
    /// intended registers
    pub modifiers: Vec<RegisterModifierSet>,
}

/// Modifier for a CPU configuration containing
/// the location of the value to be modified,
/// and provides a value to be applied alongside
/// a filter to be applied
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterModifier<T: Numeric> {
    /// Location of the register to be modified
    /// by the mask value and filter
    pub pointer: RegisterPointer<T>,
    /// Mask value to be applied
    pub value: T,
    /// Mask value is to be applied according
    /// to what is allowed through by the filter
    pub filter: T,
}

/// Numeric wrapper type acting as a marker type
/// for the register's pointer
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum RegisterPointer<T: Numeric> {
    /// Pointer(location) of a specific register
    NumericPointer(T),
    /// Register pointer for CPUID that is Leaf/Subleaf aware
    CpuidPointer(CpuidRegisterPointer),
}

/// Numeric wrapper type acting as a marker type
/// for the register's value
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterValue<T: Numeric> {
    /// Value of a specific register
    pub value: T,
}

/// CPUID register enumeration
#[allow(unused)]
#[allow(missing_docs)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum CpuidRegister {
    Eax,
    Ebx,
    Ecx,
    Edx,
}

/// Composite type that holistically provides
/// the location of a specific register being used
/// in the context of a CPUID tree
#[allow(unused)]
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CpuidRegisterPointer {
    leaf: u32,
    subleaf: u32,
    pointer: CpuidRegister,
}

/// Enumerates the types of registers and contains
/// a property capable of containing the data
/// formatted for the register type
#[allow(unused)]
#[allow(missing_docs)]
pub enum RegisterSet {
    #[cfg(target_arch = "x86_64")]
    CpuId(Cpuid),
    #[cfg(target_arch = "x86_64")]
    Msrs(MsrRegisterMap),
    #[cfg(target_arch = "aarch64")]
    Aarch64Registers(Aarch64RegisterMap),
}

/// Intended to correlate to the RegisterSet.
/// Enumerates the types of register modifiers
/// with data intended to modify the correlated
/// registers
#[allow(unused)]
#[allow(missing_docs)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RegisterModifierSet {
    #[cfg(target_arch = "x86_64")]
    CpuIdModifierSet(Vec<RegisterModifier<u32>>),
    #[cfg(target_arch = "x86_64")]
    MsrsModifierSet(Vec<RegisterModifier<u64>>),
    #[cfg(target_arch = "aarch64")]
    Aarch64RegistersModifierSet(Vec<RegisterModifier<u128>>),
}
