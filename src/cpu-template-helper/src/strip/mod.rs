// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::hash::Hash;

use vmm::guest_config::templates::CustomCpuTemplate;

#[cfg(target_arch = "x86_64")]
mod x86_64;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to serialize/deserialize.
    #[error("Failed to serialize/deserialize: {0}")]
    Serde(#[from] serde_json::Error),
}

pub fn strip(input: Vec<String>) -> Result<Vec<String>, Error> {
    // Deserialize `Vec<String>` to `Vec<CustomCpuTemplate>`.
    let input = input
        .iter()
        .map(|s| serde_json::from_str::<CustomCpuTemplate>(s))
        .collect::<Result<Vec<_>, serde_json::Error>>()?;

    // TODO: Add actual implementation to strip.

    // Serialize `Vec<CustomCpuTemplate>` to `Vec<String>`.
    let result = input
        .iter()
        .map(serde_json::to_string_pretty)
        .collect::<Result<Vec<_>, serde_json::Error>>()?;
    Ok(result)
}

pub fn remove_common<T>(sets: &mut [HashSet<T>])
where
    T: Clone + Hash + Eq + PartialEq,
{
    // Get common items shared by all the sets.
    let mut common = sets[0].clone();
    common.retain(|item| sets[1..].iter().all(|set| set.contains(item)));

    // Remove the common items from all the sets.
    for item in common {
        for set in sets.iter_mut() {
            set.remove(&item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remove_common() {
        let mut input = vec![
            HashSet::from([0, 1, 2, 3]),
            HashSet::from([0, 2, 4]),
            HashSet::from([0, 1, 2, 5, 6]),
        ];
        let expected = vec![
            HashSet::from([1, 3]),
            HashSet::from([4]),
            HashSet::from([1, 5, 6]),
        ];

        remove_common(&mut input);
        assert_eq!(input, expected);
    }
}
