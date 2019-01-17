// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Structure representing a range of bits in a number.
///
/// # Example
///
/// ```
/// #[macro_use]
/// extern crate cpuid;
/// use cpuid::bit_helper::*;
///
/// fn main() {
///     let range = BitRange {
///         msb_index: 7,
///         lsb_index: 3,
///     };
/// }
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

pub trait BitRangeExt<T> {
    /// Returns a value of type T that has all the bits in the specified bit range set to 1.
    ///
    /// # Example
    ///
    /// ```
    /// #[macro_use]
    /// extern crate cpuid;
    /// use cpuid::bit_helper::*;
    ///
    /// fn main() {
    ///     let range = BitRange {
    ///         msb_index: 7,
    ///         lsb_index: 3,
    ///     };
    ///     println!("binary value: {:b}", range.get_mask());
    /// }
    /// ```
    /// The code above will print:
    /// ```bash
    /// binary value: 11111000
    /// ```
    fn get_mask(&self) -> T;

    /// Checks if the current BitRange is valid for type T.
    ///
    fn is_valid(&self) -> bool;

    /// Asserts if `self.is_valid()` returns true.
    ///
    fn check(&self) {
        assert!(self.is_valid(), "Invalid BitRange");
    }
}

const MAX_U32_BIT_INDEX: u32 = 31;

impl BitRangeExt<u32> for BitRange {
    fn get_mask(&self) -> u32 {
        self.check();

        ((((1 as u64) << (self.msb_index - self.lsb_index + 1)) - 1) << self.lsb_index) as u32
    }

    fn is_valid(&self) -> bool {
        self.msb_index >= self.lsb_index && self.msb_index <= MAX_U32_BIT_INDEX
    }
}

/// Trait containing helper methods for bit operations.
///
pub trait BitHelper {
    /// Changes the value of the bit at position `pos` to `val`
    ///
    fn write_bit(&mut self, pos: u32, val: bool) -> &mut Self;

    /// Reads the value stored within the specified range of bits
    ///
    /// # Example
    ///
    /// ```
    /// #[macro_use]
    /// extern crate cpuid;
    /// use cpuid::bit_helper::*;
    ///
    /// fn main() {
    ///     let val: u32 = 0b000010001000;
    ///     let range = BitRange {
    ///         msb_index: 7,
    ///         lsb_index: 3,
    ///     };
    ///     println!("binary value: {:b}", val.read_bits_in_range(&range));
    /// }
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
    /// #[macro_use]
    /// extern crate cpuid;
    /// use cpuid::bit_helper::*;
    ///
    /// fn main() {
    ///     let mut val: u32 = 0;
    ///     let range = BitRange {
    ///         msb_index: 7,
    ///         lsb_index: 3,
    ///     };
    ///     val.write_bits_in_range(&range, 0b10001 as u32);
    ///     println!("binary value: {:b}", val);
    /// }
    /// ```
    /// The code above will print:
    /// ```bash
    /// binary value: 10001000
    /// ```
    fn write_bits_in_range(&mut self, bit_range: &BitRange, val: Self) -> &mut Self;
}

impl BitHelper for u32 {
    fn write_bit(&mut self, pos: u32, val: bool) -> &mut Self {
        assert!(pos <= MAX_U32_BIT_INDEX, "Invalid pos");

        *self &= !(1 << pos);
        *self |= (val as u32) << pos;
        self
    }

    fn read_bits_in_range(&self, range: &BitRange) -> Self {
        range.check();

        (self & range.get_mask()) >> range.lsb_index
    }

    fn write_bits_in_range(&mut self, range: &BitRange, val: Self) -> &mut Self {
        range.check();
        let mask = range.get_mask();
        let max_val = mask >> range.lsb_index;
        assert!(val <= max_val, "Invalid val");

        *self &= !mask;
        *self |= val << range.lsb_index;
        self
    }
}

#[cfg(test)]
mod tests {
    use bit_helper::*;

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

    #[test]
    #[should_panic]
    fn test_invalid_write_bit() {
        // Set bit to 1
        let mut val: u32 = 0;
        val.write_bit(32, true);
    }

    #[test]
    fn test_simple_write_bit() {
        // Set bit to 1
        let mut val: u32 = 0;
        val.write_bit(5, true);
        assert!(val == 1 << 5);

        // Set bit to 0
        val = 1 << 5;
        val.write_bit(5, false);
        assert!(val == 0);
    }

    #[test]
    fn test_chained_write_bit() {
        let mut val: u32 = 1 << 12;

        val.write_bit(5, true)
            .write_bit(10, true)
            .write_bit(15, true)
            .write_bit(12, false);
        assert!(val == 1 << 5 | 1 << 10 | 1 << 15);
    }

    #[test]
    fn test_get_u32_mask_for_range() {
        // Test a couple of successive ranges
        assert!(
            BitRange {
                msb_index: 3,
                lsb_index: 2
            }
            .get_mask()
                == 0b1100
        );
        assert!(
            BitRange {
                msb_index: 4,
                lsb_index: 2
            }
            .get_mask()
                == 0b11100
        );
        assert!(
            BitRange {
                msb_index: 5,
                lsb_index: 2
            }
            .get_mask()
                == 0b111100
        );
        assert!(
            BitRange {
                msb_index: 6,
                lsb_index: 2
            }
            .get_mask()
                == 0b1111100
        );
        assert!(
            BitRange {
                msb_index: 7,
                lsb_index: 2
            }
            .get_mask()
                == 0b11111100
        );
    }

    #[test]
    #[should_panic]
    fn test_invalid_read_bits() {
        let val: u32 = 30;
        val.read_bits_in_range(&BitRange {
            msb_index: 32,
            lsb_index: 2,
        });
    }

    #[test]
    fn test_read_bits() {
        let val: u32 = 0b10000000000000000011010100010000;

        // Test a couple of successive ranges
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 3,
                lsb_index: 2
            }) == 0b00
        );
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 4,
                lsb_index: 2
            }) == 0b100
        );
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 5,
                lsb_index: 2
            }) == 0b0100
        );
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 6,
                lsb_index: 2
            }) == 0b00100
        );
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 7,
                lsb_index: 2
            }) == 0b000100
        );
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 8,
                lsb_index: 2
            }) == 0b1000100
        );
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 9,
                lsb_index: 2
            }) == 0b01000100
        );
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 10,
                lsb_index: 2
            }) == 0b101000100
        );
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 11,
                lsb_index: 2
            }) == 0b0101000100
        );
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 12,
                lsb_index: 2
            }) == 0b10101000100
        );
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 13,
                lsb_index: 2
            }) == 0b110101000100
        );

        // Test max left and max right
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 31,
                lsb_index: 15
            }) == 0b10000000000000000
        );
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 14,
                lsb_index: 0
            }) == 0b011010100010000
        );
        assert!(
            val.read_bits_in_range(&BitRange {
                msb_index: 31,
                lsb_index: 0
            }) == 0b10000000000000000011010100010000
        );
    }

    #[test]
    #[should_panic]
    fn test_invalid_write_bits() {
        let mut val: u32 = 0;

        val.write_bits_in_range(
            &BitRange {
                msb_index: 32,
                lsb_index: 2,
            },
            0b100,
        );
    }

    #[test]
    #[should_panic]
    fn test_overflow_write_bits() {
        let mut val: u32 = 0;

        val.write_bits_in_range(
            &BitRange {
                msb_index: 3,
                lsb_index: 2,
            },
            0b100,
        );
    }

    #[test]
    fn test_simple_write_bits() {
        let mut val: u32 = 0;

        // Test a couple of successive ranges
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 3,
                    lsb_index: 2
                },
                0b00
            ) == &0b0000
        );
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 4,
                    lsb_index: 2
                },
                0b100
            ) == &0b10000
        );
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 5,
                    lsb_index: 2
                },
                0b0100
            ) == &0b010000
        );
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 6,
                    lsb_index: 2
                },
                0b00100
            ) == &0b0010000
        );
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 7,
                    lsb_index: 2
                },
                0b000100
            ) == &0b00010000
        );
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 8,
                    lsb_index: 2
                },
                0b1000100
            ) == &0b100010000
        );
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 9,
                    lsb_index: 2
                },
                0b01000100
            ) == &0b0100010000
        );
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 10,
                    lsb_index: 2
                },
                0b101000100
            ) == &0b10100010000
        );
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 11,
                    lsb_index: 2
                },
                0b0101000100
            ) == &0b010100010000
        );
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 12,
                    lsb_index: 2
                },
                0b10101000100
            ) == &0b1010100010000
        );
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 13,
                    lsb_index: 2
                },
                0b110101000100
            ) == &0b11010100010000
        );

        // Test max left and max right
        val = 0;
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 31,
                    lsb_index: 15
                },
                0b10000000000000000
            ) == &0b10000000000000000000000000000000
        );
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 14,
                    lsb_index: 0
                },
                0b011010100010000
            ) == &0b10000000000000000011010100010000
        );
        assert!(
            val.write_bits_in_range(
                &BitRange {
                    msb_index: 31,
                    lsb_index: 0
                },
                0b10000000000000000011010100010000
            ) == &0b10000000000000000011010100010000
        );
    }

    #[test]
    fn test_chained_write_bits() {
        let mut val: u32 = 0;

        // Test a couple of ranges
        val.write_bits_in_range(
            &BitRange {
                msb_index: 4,
                lsb_index: 2,
            },
            0b100,
        )
        .write_bits_in_range(
            &BitRange {
                msb_index: 12,
                lsb_index: 10,
            },
            0b110,
        )
        .write_bits_in_range(
            &BitRange {
                msb_index: 24,
                lsb_index: 20,
            },
            0b10101,
        )
        .write_bits_in_range(
            &BitRange {
                msb_index: 31,
                lsb_index: 28,
            },
            0b1011,
        );

        assert!(val == 0b10110001010100000001100000010000);
    }
}
