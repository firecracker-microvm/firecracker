// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serializer};

use crate::guest_config::templates::RegisterValueFilter;

macro_rules! deserialize_reg_value_filter {
    ($name:ident, $type:tt) => {
        /// Deserialize a composite bitmap string into a value pair
        /// input string: "010x"
        /// result: {
        ///     filter: 1110
        ///     value: 0100
        /// }
        pub fn $name<'de, D>(deserializer: D) -> Result<RegisterValueFilter<$type>, D::Error>
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

            let filter = $type::from_str_radix(filter_str.as_str(), 2).map_err(|err| {
                D::Error::custom(format!(
                    "Failed to parse string [{}] as a bitmap - {:?}",
                    bitmap_str, err
                ))
            })?;
            let value = $type::from_str_radix(value_str.as_str(), 2).map_err(|err| {
                D::Error::custom(format!(
                    "Failed to parse string [{}] as a bitmap - {:?}",
                    bitmap_str, err
                ))
            })?;

            Ok(RegisterValueFilter { filter, value })
        }
    };
}

deserialize_reg_value_filter!(deserialize_reg_value_filter_u32, u32);
deserialize_reg_value_filter!(deserialize_reg_value_filter_u64, u64);
deserialize_reg_value_filter!(deserialize_reg_value_filter_u128, u128);

macro_rules! serialize_reg_value_filter {
    ($name:ident, $type:tt, $fmt:expr) => {
        /// Deserialize a composite bitmap string into a value pair
        /// input string: "010x"
        /// result: {
        ///     filter: 1110
        ///     value: 0100
        /// }
        pub fn $name<S>(
            bitmap: &RegisterValueFilter<$type>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let value_str = format!($fmt, bitmap.value);
            let filter_str = format!($fmt, bitmap.filter);

            let mut bitmap_str = String::from("0b");
            for (idx, character) in filter_str.char_indices() {
                match character {
                    '1' => bitmap_str.push(value_str.as_bytes()[idx] as char),
                    _ => bitmap_str.push('x'),
                }
            }

            serializer.serialize_str(bitmap_str.as_str())
        }
    };
}

serialize_reg_value_filter!(serialize_reg_value_filter_u32, u32, "{:032b}");
serialize_reg_value_filter!(serialize_reg_value_filter_u64, u64, "{:064b}");
serialize_reg_value_filter!(serialize_reg_value_filter_u128, u128, "{:0128b}");

/// Serializes number to hex
pub fn serialize_to_hex_str<S, N>(number: &N, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    N: std::fmt::LowerHex,
{
    serializer.serialize_str(format!("{:#x}", number).as_str())
}

macro_rules! deserialize_from_str {
    ($name:ident, $type:tt) => {
        /// Deserializes number from string.
        /// Number can be in binary, hex or dec formats.
        pub fn $name<'de, D>(deserializer: D) -> Result<$type, D::Error>
        where
            D: Deserializer<'de>,
        {
            let number_str = String::deserialize(deserializer)?;
            let deserialized_number = if number_str.len() > 2 {
                match &number_str[0..2] {
                    "0b" => $type::from_str_radix(&number_str[2..], 2),
                    "0x" => $type::from_str_radix(&number_str[2..], 16),
                    _ => $type::from_str(&number_str),
                }
                .map_err(|err| {
                    D::Error::custom(format!(
                        "Failed to parse string [{}] as a number for CPU template - {:?}",
                        number_str, err
                    ))
                })?
            } else {
                $type::from_str(&number_str).map_err(|err| {
                    D::Error::custom(format!(
                        "Failed to parse string [{}] as a decimal number for CPU template - {:?}",
                        number_str, err
                    ))
                })?
            };
            Ok(deserialized_number)
        }
    };
}

deserialize_from_str!(deserialize_from_str_u32, u32);
deserialize_from_str!(deserialize_from_str_u64, u64);
