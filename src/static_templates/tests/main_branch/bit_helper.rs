// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![macro_use]

/// Structure representing a range of bits in a number.
///
/// # Example
///
/// ```
/// use vmm::cpuid::bit_helper::*;
///
/// let range = BitRange {
///     msb_index: 7,
///     lsb_index: 3,
/// };
/// ```
/// The BitRange specified above will represent the following part of the number 72:
/// +-------------------------------------+---+---+---+---+---+---+---+---+---+---+
/// | Base 2 Representation of the number | 0 | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
/// +-------------------------------------+---+---+---+---+---+---+---+---+---+---+
/// | bits indexes                        | 9 | 8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
/// +-------------------------------------+---+---+---+---+---+---+---+---+---+---+
/// | BitRange                            |   |   | * | * | * | * | * |   |   |   |
/// +-------------------------------------+---+---+---+---+---+---+---+---+---+---+
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
    /// Returns a value of type `T` that has all the bits in the specified bit range set to 1.
    ///
    /// # Example
    ///
    /// ```
    /// use vmm::cpuid::bit_helper::*;
    ///
    /// let range = BitRange {
    ///     msb_index: 7,
    ///     lsb_index: 3,
    /// };
    /// println!("binary value: {:b}", range.get_mask());
    /// ```
    /// The code above will print:
    /// ```bash
    /// binary value: 11111000
    /// ```
    fn get_mask(&self) -> T;

    /// Checks if the current BitRange is valid for type `T`.
    fn is_valid(&self) -> bool;

    /// Asserts if `self.is_valid()` returns true.
    fn check(&self) {
        assert!(self.is_valid(), "Invalid BitRange");
    }
}

const MAX_U64_BIT_INDEX: u32 = 63;

impl BitRangeExt<u64> for BitRange {
    fn get_mask(&self) -> u64 {
        self.check();

        ((((1_u128) << (self.msb_index - self.lsb_index + 1)) - 1) << self.lsb_index) as u64
    }

    fn is_valid(&self) -> bool {
        self.msb_index >= self.lsb_index && self.msb_index <= MAX_U64_BIT_INDEX
    }
}

impl BitRangeExt<u64> for u32 {
    fn get_mask(&self) -> u64 {
        self.check();

        1u64 << *self
    }

    fn is_valid(&self) -> bool {
        *self <= MAX_U64_BIT_INDEX
    }
}

macro_rules! bit_range {
    ($msb_index:expr, $lsb_index:expr) => {
        BitRange {
            msb_index: $msb_index,
            lsb_index: $lsb_index,
        }
    };
}

/// Trait containing helper methods for bit operations.
pub trait BitHelper {
    /// Reads the value of the bit at position `pos`
    fn read_bit(&self, pos: u32) -> bool;

    /// Changes the value of the bit at position `pos` to `val`
    fn write_bit(&mut self, pos: u32, val: bool) -> &mut Self;

    /// Reads the value stored within the specified range of bits
    ///
    /// # Example
    ///
    /// ```
    /// use vmm::cpuid::bit_helper::*;
    ///
    /// let val: u32 = 0b000010001000;
    /// let range = BitRange {
    ///     msb_index: 7,
    ///     lsb_index: 3,
    /// };
    /// println!("binary value: {:b}", val.read_bits_in_range(&range));
    /// ```
    /// The code above will print:
    /// ```bash
    /// binary value: 10001
    /// ```
    fn read_bits_in_range(&self, bit_range: &BitRange) -> Self;

    /// Stores a value within the specified range of bits
    ///
    /// # Example
    ///
    /// ```
    /// use vmm::cpuid::bit_helper::*;
    ///
    /// let mut val: u32 = 0;
    /// let range = BitRange {
    ///     msb_index: 7,
    ///     lsb_index: 3,
    /// };
    /// val.write_bits_in_range(&range, 0b10001 as u32);
    /// println!("binary value: {:b}", val);
    /// ```
    /// The code above will print:
    /// ```bash
    /// binary value: 10001000
    /// ```
    fn write_bits_in_range(&mut self, bit_range: &BitRange, val: Self) -> &mut Self;
}

impl BitHelper for u64 {
    fn read_bit(&self, pos: u32) -> bool {
        assert!(pos <= MAX_U64_BIT_INDEX, "Invalid pos");

        (*self & (1u64 << pos)) > 0
    }

    fn write_bit(&mut self, pos: u32, val: bool) -> &mut Self {
        assert!(pos <= MAX_U64_BIT_INDEX, "Invalid pos");

        *self &= !(1u64 << pos);
        *self |= (u64::from(val)) << pos;
        self
    }

    fn read_bits_in_range(&self, range: &BitRange) -> Self {
        range.check();

        (self & range.get_mask()) >> range.lsb_index
    }

    fn write_bits_in_range(&mut self, range: &BitRange, val: Self) -> &mut Self {
        range.check();
        let mask: u64 = range.get_mask();
        let max_val: u64 = mask >> range.lsb_index;
        assert!(val <= max_val, "Invalid val");

        *self &= !mask;
        *self |= val << range.lsb_index;
        self
    }
}
