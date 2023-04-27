// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::hash::Hash;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::strip;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::strip;

pub fn strip_common<T>(sets: &mut [HashSet<T>])
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
    fn test_strip_common() {
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

        strip_common(&mut input);
        assert_eq!(input, expected);
    }
}
