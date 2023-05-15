// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// /// Module with cpu templates for x86_64
// #[cfg(target_arch = "x86_64")]
// pub mod x86_64;
//
// /// Utility module for testing cpu_configuration.
// pub mod test_utils;

#[cfg(target_arch = "x86_64")]
mod common_types {
    pub use crate::cpu_config::x86_64::custom_cpu_template::CustomCpuTemplate;
    pub use crate::cpu_config::x86_64::static_cpu_templates::StaticCpuTemplate;
    pub use crate::cpu_config::x86_64::{test_utils, CpuConfiguration, Error as GuestConfigError};
}

/// Module with cpu templates for aarch64
// #[cfg(target_arch = "aarch64")]
// pub mod aarch64;

#[cfg(target_arch = "aarch64")]
mod common_types {
    pub use crate::cpu_config::aarch64::custom_cpu_template::CustomCpuTemplate;
    pub use crate::cpu_config::aarch64::static_cpu_templates::StaticCpuTemplate;
    pub use crate::cpu_config::aarch64::{test_utils, CpuConfiguration, Error as GuestConfigError};
}

use std::borrow::Cow;
use std::num::ParseIntError;
use std::result::Result;

pub use common_types::*;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Error for GetCpuTemplate trait.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GetCpuTemplateError {
    #[cfg(target_arch = "x86_64")]
    /// Failed to get CPU vendor information.
    #[error("Failed to get CPU vendor information: {0}")]
    GetCpuVendor(crate::cpu_config::x86_64::cpuid::common::GetCpuidError),
    /// CPU Vendor mismatched between the actual CPU and CPU template.
    #[error("CPU vendor mismatched between actual CPU and CPU template.")]
    CpuVendorMismatched,
    /// Invalid static CPU template.
    #[error("Invalid static CPU template: {0}")]
    InvalidStaticCpuTemplate(StaticCpuTemplate),
    /// Invalid CPU model.
    #[error("The current CPU model is not permitted to apply the CPU template.")]
    InvalidCpuModel,
}

/// Trait to unwrap the inner `CustomCpuTemplate` from Option<CpuTemplateType>.
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

impl From<&Option<CpuTemplateType>> for StaticCpuTemplate {
    fn from(value: &Option<CpuTemplateType>) -> Self {
        match value {
            Some(CpuTemplateType::Static(template)) => *template,
            Some(CpuTemplateType::Custom(_)) | None => StaticCpuTemplate::None,
        }
    }
}

/// Bit-mapped value to adjust targeted bits of a register.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Hash)]
pub struct RegisterValueFilter<V>
where
    V: Copy
        + std::ops::Not<Output = V>
        + std::ops::BitAnd<Output = V>
        + std::ops::BitOr<Output = V>,
{
    /// Filter to be used when writing the value bits.
    pub filter: V,
    /// Value to be applied.
    pub value: V,
}

impl<V> RegisterValueFilter<V>
where
    V: Copy
        + std::ops::Not<Output = V>
        + std::ops::BitAnd<Output = V>
        + std::ops::BitOr<Output = V>,
{
    /// Applies filter to the value
    #[inline]
    pub fn apply(&self, value: V) -> V {
        (value & !self.filter) | self.value
    }
}

/// Trait for numeric types
pub trait Numeric: Sized {
    /// Number of bits for type
    const BITS: u32;
    /// Parse numeric type from string with given radix
    fn from_str_radix(s: &str, radix: u32) -> Result<Self, ParseIntError>;
    /// Value of bit at pos
    fn bit(&self, pos: u32) -> bool;
}

macro_rules! impl_numeric {
    ($type:tt) => {
        impl Numeric for $type {
            const BITS: u32 = $type::BITS;
            fn from_str_radix(s: &str, radix: u32) -> Result<Self, ParseIntError> {
                $type::from_str_radix(s, radix)
            }
            fn bit(&self, pos: u32) -> bool {
                (self & (1 << pos)) != 0
            }
        }
    };
}

impl_numeric!(u8);
impl_numeric!(u16);
impl_numeric!(u32);
impl_numeric!(u64);
impl_numeric!(u128);

impl<V> Serialize for RegisterValueFilter<V>
where
    V: Copy
        + std::ops::Not<Output = V>
        + std::ops::BitAnd<Output = V>
        + std::ops::BitOr<Output = V>
        + PartialEq<V>
        + Numeric,
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
    V: Copy
        + std::ops::Not<Output = V>
        + std::ops::BitAnd<Output = V>
        + std::ops::BitOr<Output = V>
        + Numeric,
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
        let mut bitmap_str = String::deserialize(deserializer)?;

        if bitmap_str.starts_with("0b") {
            bitmap_str = bitmap_str[2..].to_string();
        }

        let filter_str = bitmap_str.replace('0', "1");
        let filter_str = filter_str.replace('x', "0");
        let value_str = bitmap_str.replace('x', "0");

        let filter = V::from_str_radix(filter_str.as_str(), 2).map_err(|err| {
            D::Error::custom(format!(
                "Failed to parse string [{}] as a bitmap - {:?}",
                bitmap_str, err
            ))
        })?;
        let value = V::from_str_radix(value_str.as_str(), 2).map_err(|err| {
            D::Error::custom(format!(
                "Failed to parse string [{}] as a bitmap - {:?}",
                bitmap_str, err
            ))
        })?;

        Ok(RegisterValueFilter { filter, value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
