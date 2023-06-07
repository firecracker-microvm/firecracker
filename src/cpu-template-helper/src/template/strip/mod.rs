// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Debug;

use crate::utils::{ModifierMapKey, ModifierMapValue};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::strip;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::strip;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The number of inputs should be two or more.
    #[error("The number of inputs should be two or more.")]
    NumberOfInputs,
}

#[tracing::instrument(level = "trace", ret)]
fn strip_common<K, V>(maps: &mut [HashMap<K, V>]) -> Result<(), Error>
where
    K: ModifierMapKey + Debug,
    V: ModifierMapValue + Debug,
{
    if maps.len() < 2 {
        return Err(Error::NumberOfInputs);
    }

    // Get common items shared by all the sets.
    let mut common = maps[0].clone();
    common.retain(|key, value| maps[1..].iter().all(|map| map.get(key) == Some(value)));

    // Remove the common items from all the sets.
    for key in common.keys() {
        for map in maps.iter_mut() {
            map.remove(key);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::tests::{mock_modifier, MockModifierMapKey, MockModifierMapValue};

    #[test]
    fn test_strip_common_with_single_input() {
        let mut input = vec![HashMap::from([mock_modifier!(
            0x0,
            (0b1111_1111, 0b0000_0000)
        )])];

        match strip_common(&mut input) {
            Err(Error::NumberOfInputs) => (),
            _ => panic!("Should fail with `Error::NumberOfInputs`."),
        }
    }

    #[test]
    fn test_strip_common() {
        let mut input = vec![
            HashMap::from([
                mock_modifier!(0x0, (0b1111_1111, 0b0000_0000)),
                mock_modifier!(0x1, (0b1111_0000, 0b1111_1111)),
                mock_modifier!(0x2, (0b1111_1111, 0b1111_1111)),
            ]),
            HashMap::from([
                mock_modifier!(0x0, (0b1111_1111, 0b0000_0000)),
                mock_modifier!(0x1, (0b0000_1111, 0b1111_1111)),
                mock_modifier!(0x2, (0b1111_1111, 0b1111_1111)),
            ]),
            HashMap::from([
                mock_modifier!(0x0, (0b1111_1111, 0b0000_0000)),
                mock_modifier!(0x1, (0b1111_1111, 0b1111_1111)),
                mock_modifier!(0x3, (0b1111_1111, 0b1111_1111)),
            ]),
        ];
        let expected = vec![
            HashMap::from([
                mock_modifier!(0x1, (0b1111_0000, 0b1111_1111)),
                mock_modifier!(0x2, (0b1111_1111, 0b1111_1111)),
            ]),
            HashMap::from([
                mock_modifier!(0x1, (0b0000_1111, 0b1111_1111)),
                mock_modifier!(0x2, (0b1111_1111, 0b1111_1111)),
            ]),
            HashMap::from([
                mock_modifier!(0x1, (0b1111_1111, 0b1111_1111)),
                mock_modifier!(0x3, (0b1111_1111, 0b1111_1111)),
            ]),
        ];

        strip_common(&mut input).unwrap();
        assert_eq!(input, expected);
    }
}
