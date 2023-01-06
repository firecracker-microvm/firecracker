// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::restriction)]

/// Structure representing a range of bits in a number.
///
/// # Example
///
/// ```
/// use cpuid::bit_helper::*;
///
/// let range = BitRange {
///     msb_index: 7,
///     lsb_index: 3,
/// };
/// ```
/// The `BitRange` specified above will represent the following part of the number 72:
/// ```text
/// +-------------------------------------+---+---+---+---+---+---+---+---+---+---+
/// | Base 2 Representation of the number | 0 | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
/// +-------------------------------------+---+---+---+---+---+---+---+---+---+---+
/// | bits indexes                        | 9 | 8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
/// +-------------------------------------+---+---+---+---+---+---+---+---+---+---+
/// | BitRange                            |   |   | * | * | * | * | * |   |   |   |
/// +-------------------------------------+---+---+---+---+---+---+---+---+---+---+
/// ```
pub struct BitRange {
    /// most significant bit index
    pub msb_index: u32,
    /// least significant bit index
    pub lsb_index: u32,
}

/// Trait containing helper methods for [`BitRange`](struct.BitRange.html)
///
/// The methods are needed for:
/// - checking if the `BitRange` is valid for a type `T`
/// - creating masks for a type `T`
pub trait BitRangeExt<T> {
    /// Checks if the current [`BitRange`] is valid for type `T`.
    fn is_valid(&self) -> bool;

    /// Asserts if `self.is_valid()` returns true.
    fn check(&self) {
        assert!(self.is_valid(), "Invalid BitRange");
    }
}

const MAX_U32_BIT_INDEX: u32 = 31;

impl BitRangeExt<u32> for BitRange {
    fn is_valid(&self) -> bool {
        self.msb_index >= self.lsb_index && self.msb_index <= MAX_U32_BIT_INDEX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn test_invalid_msb_index() {
        let range = BitRange {
            msb_index: 32,
            lsb_index: 2,
        };
        range.check();
    }

    #[test]
    #[should_panic]
    fn test_invalid_range() {
        let range = BitRange {
            msb_index: 10,
            lsb_index: 15,
        };
        range.check();
    }
}
