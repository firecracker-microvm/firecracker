// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "x86_64")]
mod common_types {
    pub use crate::cpu_config::x86_64::custom_cpu_template::CustomCpuTemplate;
    pub use crate::cpu_config::x86_64::static_cpu_templates::StaticCpuTemplate;
    pub use crate::cpu_config::x86_64::{
        CpuConfiguration, CpuConfigurationError as GuestConfigError, test_utils,
    };
}

#[cfg(target_arch = "aarch64")]
mod common_types {
    pub use crate::cpu_config::aarch64::custom_cpu_template::CustomCpuTemplate;
    pub use crate::cpu_config::aarch64::static_cpu_templates::StaticCpuTemplate;
    pub use crate::cpu_config::aarch64::{
        CpuConfiguration, CpuConfigurationError as GuestConfigError, test_utils,
    };
}

#[cfg(target_arch = "riscv64")]
mod common_types {
    pub use crate::cpu_config::riscv64::custom_cpu_template::CustomCpuTemplate;
    pub use crate::cpu_config::riscv64::static_cpu_templates::StaticCpuTemplate;
    pub use crate::cpu_config::riscv64::{
        CpuConfiguration, CpuConfigurationError as GuestConfigError,
    };
}

use std::borrow::Cow;
use std::fmt::Debug;

pub use common_types::*;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Error for GetCpuTemplate trait.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum GetCpuTemplateError {
    #[cfg(target_arch = "x86_64")]
    /// Failed to get CPU vendor information: {0}
    GetCpuVendor(crate::cpu_config::x86_64::cpuid::common::GetCpuidError),
    /// CPU vendor mismatched between actual CPU and CPU template.
    CpuVendorMismatched,
    /// Invalid static CPU template: {0}
    InvalidStaticCpuTemplate(StaticCpuTemplate),
    /// The current CPU model is not permitted to apply the CPU template.
    InvalidCpuModel,
}

/// Trait to unwrap the inner [`CustomCpuTemplate`] from [`Option<CpuTemplateType>`].
///
/// This trait is needed because static CPU template and custom CPU template have different nested
/// structures: `CpuTemplateType::Static(StaticCpuTemplate::StaticTemplateType(CustomCpuTemplate))`
/// vs `CpuTemplateType::Custom(CustomCpuTemplate)`. As static CPU templates return owned
/// `CustomCpuTemplate`s, `Cow` is used here to avoid unnecessary clone of `CustomCpuTemplate` for
/// custom CPU templates and handle static CPU template and custom CPU template in a same manner.
pub trait GetCpuTemplate {
    /// Get CPU template
    fn get_cpu_template(&self) -> Result<Cow<CustomCpuTemplate>, GetCpuTemplateError>;
}

/// Enum that represents types of cpu templates available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuTemplateType {
    /// Custom cpu template
    Custom(CustomCpuTemplate),
    /// Static cpu template
    Static(StaticCpuTemplate),
}

// This conversion is only used for snapshot, but the static CPU template
// information has not been saved into snapshot since v1.1.
impl From<&Option<CpuTemplateType>> for StaticCpuTemplate {
    fn from(value: &Option<CpuTemplateType>) -> Self {
        match value {
            Some(CpuTemplateType::Static(template)) => *template,
            Some(CpuTemplateType::Custom(_)) | None => StaticCpuTemplate::None,
        }
    }
}

// This conversion is used when converting `&VmConfig` to `MachineConfig` to
// respond `GET /machine-config` and `GET /vm`.
impl From<&CpuTemplateType> for StaticCpuTemplate {
    fn from(value: &CpuTemplateType) -> Self {
        match value {
            CpuTemplateType::Static(template) => *template,
            CpuTemplateType::Custom(_) => StaticCpuTemplate::None,
        }
    }
}

impl TryFrom<&[u8]> for CustomCpuTemplate {
    type Error = serde_json::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let template: CustomCpuTemplate = serde_json::from_slice(value)?;
        template.validate()?;
        Ok(template)
    }
}

impl TryFrom<&str> for CustomCpuTemplate {
    type Error = serde_json::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        CustomCpuTemplate::try_from(value.as_bytes())
    }
}

/// Struct to represent user defined kvm capability.
/// Users can add or remove kvm capabilities to be checked
/// by FC in addition to those FC checks by default.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum KvmCapability {
    /// Add capability to the check list.
    Add(u32),
    /// Remove capability from the check list.
    Remove(u32),
}

impl Serialize for KvmCapability {
    /// Serialize KvmCapability into a string.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match self {
            KvmCapability::Add(cap) => format!("{cap}"),
            KvmCapability::Remove(cap) => format!("!{cap}"),
        };
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for KvmCapability {
    /// Deserialize string into a KvmCapability.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let original_str = <String as Deserialize>::deserialize(deserializer)?;

        let parse_err = |e| {
            D::Error::custom(format!(
                "Failed to parse string [{}] as a kvm capability - can not convert to numeric: {}",
                original_str, e
            ))
        };

        match original_str.strip_prefix('!') {
            Some(s) => {
                let v = s.parse::<u32>().map_err(parse_err)?;
                Ok(Self::Remove(v))
            }
            None => {
                let v = original_str.parse::<u32>().map_err(parse_err)?;
                Ok(Self::Add(v))
            }
        }
    }
}

/// Bit-mapped value to adjust targeted bits of a register.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Hash)]
pub struct RegisterValueFilter<V>
where
    V: Numeric,
{
    /// Filter to be used when writing the value bits.
    pub filter: V,
    /// Value to be applied.
    pub value: V,
}

impl<V> RegisterValueFilter<V>
where
    V: Numeric + Debug,
{
    /// Applies filter to the value
    #[inline]
    pub fn apply(&self, value: V) -> V {
        (value & !self.filter) | self.value
    }
}

impl<V> Serialize for RegisterValueFilter<V>
where
    V: Numeric + Debug,
{
    /// Serialize combination of value and filter into a single tri state string
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bitmap_str = Vec::with_capacity(V::BITS as usize + 2);
        bitmap_str.push(b'0');
        bitmap_str.push(b'b');

        for i in (0..V::BITS).rev() {
            match self.filter.bit(i) {
                true => {
                    let val = self.value.bit(i);
                    bitmap_str.push(b'0' + u8::from(val));
                }
                false => bitmap_str.push(b'x'),
            }
        }

        // # Safety:
        // We know that bitmap_str contains only ASCII characters
        let s = unsafe { std::str::from_utf8_unchecked(&bitmap_str) };

        serializer.serialize_str(s)
    }
}

impl<'de, V> Deserialize<'de> for RegisterValueFilter<V>
where
    V: Numeric + Debug,
{
    /// Deserialize a composite bitmap string into a value pair
    /// input string: "010x"
    /// result: {
    ///     filter: 1110
    ///     value: 0100
    /// }
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let original_str = <String as Deserialize>::deserialize(deserializer)?;

        let stripped_str = original_str.strip_prefix("0b").unwrap_or(&original_str);

        let (mut filter, mut value) = (V::zero(), V::zero());
        let mut i = 0;
        for s in stripped_str.as_bytes().iter().rev() {
            if V::BITS == i {
                return Err(D::Error::custom(format!(
                    "Failed to parse string [{}] as a bitmap - string is too long",
                    original_str
                )));
            }

            match s {
                b'_' => continue,
                b'x' => {}
                b'0' => {
                    filter |= V::one() << i;
                }
                b'1' => {
                    filter |= V::one() << i;
                    value |= V::one() << i;
                }
                c => {
                    return Err(D::Error::custom(format!(
                        "Failed to parse string [{}] as a bitmap - unknown character: {}",
                        original_str, c
                    )));
                }
            }
            i += 1;
        }
        Ok(RegisterValueFilter { filter, value })
    }
}

/// Trait for numeric types
pub trait Numeric:
    Sized
    + Copy
    + PartialEq<Self>
    + std::fmt::Binary
    + std::ops::Not<Output = Self>
    + std::ops::BitAnd<Output = Self>
    + std::ops::BitOr<Output = Self>
    + std::ops::BitOrAssign<Self>
    + std::ops::BitXor<Output = Self>
    + std::ops::Shl<u32, Output = Self>
    + std::ops::AddAssign<Self>
{
    /// Number of bits for type
    const BITS: u32;
    /// Value of bit at pos
    fn bit(&self, pos: u32) -> bool;
    /// Returns 0 of the type
    fn zero() -> Self;
    /// Returns 1 of the type
    fn one() -> Self;
}

macro_rules! impl_numeric {
    ($type:tt) => {
        impl Numeric for $type {
            const BITS: u32 = $type::BITS;
            fn bit(&self, pos: u32) -> bool {
                (self & (Self::one() << pos)) != 0
            }
            fn zero() -> Self {
                0
            }
            fn one() -> Self {
                1
            }
        }
    };
}

impl_numeric!(u8);
impl_numeric!(u16);
impl_numeric!(u32);
impl_numeric!(u64);
impl_numeric!(u128);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kvm_capability_serde() {
        let kvm_cap = KvmCapability::Add(69);

        let expected_str = "\"69\"";
        let serialized = serde_json::to_string(&kvm_cap).unwrap();
        assert_eq!(&serialized, expected_str);

        let kvm_cap = KvmCapability::Remove(69);

        let expected_str = "\"!69\"";
        let serialized = serde_json::to_string(&kvm_cap).unwrap();
        assert_eq!(&serialized, expected_str);

        let serialized = "\"69\"";
        let deserialized: KvmCapability = serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized, KvmCapability::Add(69));

        let serialized = "\"!69\"";
        let deserialized: KvmCapability = serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized, KvmCapability::Remove(69));
    }

    #[test]
    fn test_register_value_filter_serde() {
        let rvf = RegisterValueFilter::<u8> {
            value: 0b01010101,
            filter: 0b11110000,
        };

        let expected_str = "\"0b0101xxxx\"";
        let serialized = serde_json::to_string(&rvf).unwrap();
        assert_eq!(&serialized, expected_str);

        let expected_rvf = RegisterValueFilter::<u8> {
            value: 0b01010000,
            filter: 0b11110000,
        };
        let deserialized: RegisterValueFilter<u8> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, expected_rvf);

        let serialized = "\"0b0_101_xx_xx\"";
        let deserialized: RegisterValueFilter<u8> = serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized, expected_rvf);

        let serialized = "\"0b0_xϽ1_xx_xx\"";
        let deserialized: Result<RegisterValueFilter<u8>, _> = serde_json::from_str(serialized);
        deserialized.unwrap_err();

        let serialized = "\"0b0000_0000_0\"";
        let deserialized: Result<RegisterValueFilter<u8>, _> = serde_json::from_str(serialized);
        deserialized.unwrap_err();
    }
}
