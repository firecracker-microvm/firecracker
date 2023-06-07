// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;

use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serializer};

/// Serializes number to hex
pub fn serialize_to_hex_str<S, N>(number: &N, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    N: std::fmt::LowerHex + Debug,
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
            let deserialized_number = if let Some(s) = number_str.strip_prefix("0b") {
                $type::from_str_radix(s, 2)
            } else if let Some(s) = number_str.strip_prefix("0x") {
                $type::from_str_radix(s, 16)
            } else {
                return Err(D::Error::custom(format!(
                    "No supported number system prefix found in value [{}]. Make sure to prefix \
                     the number with '0x' for hexadecimal numbers or '0b' for binary numbers.",
                    number_str,
                )));
            }
            .map_err(|err| {
                D::Error::custom(format!(
                    "Failed to parse string [{}] as a number for CPU template - {:?}",
                    number_str, err
                ))
            })?;
            Ok(deserialized_number)
        }
    };
}

deserialize_from_str!(deserialize_from_str_u32, u32);
deserialize_from_str!(deserialize_from_str_u64, u64);

#[cfg(test)]
mod tests {
    use serde::de::value::{Error, StrDeserializer};
    use serde::de::IntoDeserializer;

    use super::*;

    #[test]
    fn test_deserialize_from_str() {
        let valid_string = "0b1000101";
        let deserializer: StrDeserializer<Error> = valid_string.into_deserializer();
        let valid_value = deserialize_from_str_u32(deserializer);
        assert!(valid_value.is_ok());
        assert_eq!(valid_value.unwrap(), 69);

        let valid_string = "0x0045";
        let deserializer: StrDeserializer<Error> = valid_string.into_deserializer();
        let valid_value = deserialize_from_str_u32(deserializer);
        assert!(valid_value.is_ok());
        assert_eq!(valid_value.unwrap(), 69);

        let invalid_string = "xϽ69";
        let deserializer: StrDeserializer<Error> = invalid_string.into_deserializer();
        let invalid_value = deserialize_from_str_u32(deserializer);
        assert!(invalid_value.is_err());

        let invalid_string = "69";
        let deserializer: StrDeserializer<Error> = invalid_string.into_deserializer();
        let invalid_value = deserialize_from_str_u32(deserializer);
        assert!(invalid_value.is_err());
    }
}
