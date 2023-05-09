// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serializer};

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
