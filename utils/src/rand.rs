// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::time;

/// Generates pseudo random u32 numbers based on the current timestamp.
pub fn xor_rng_u32() -> u32 {
    let mut t: u32 = time::timestamp_cycles() as u32;
    // Taken from https://en.wikipedia.org/wiki/Xorshift.
    t ^= t << 13;
    t ^= t >> 17;
    t ^ (t << 5)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_rng_u32() {
        for _ in 0..1000 {
            assert_ne!(xor_rng_u32(), xor_rng_u32());
        }
    }
}
