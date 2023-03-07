// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![warn(clippy::pedantic, clippy::restriction)]
#![allow(
    clippy::blanket_clippy_restriction_lints,
    clippy::implicit_return,
    clippy::pattern_type_mismatch,
    clippy::std_instead_of_alloc,
    clippy::std_instead_of_core,
    clippy::pub_use,
    clippy::non_ascii_literal,
    clippy::single_char_lifetime_names,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::unseparated_literal_suffix,
    clippy::mod_module_files,
    clippy::missing_trait_methods
)]

//! A macro to generate structures which support bit flags and sub-bytes ranges.
//!
//! A [bitflags](https://crates.io/crates/bitflags) like library which also supports value ranges.
//!
//! Originally designed to support efficiently interacting with [CPUID](https://en.wikipedia.org/wiki/CPUID).
//!
//! See [`example::ExampleBitFieldU32`] for an example.

/// Example bit fields.
#[cfg(doc)]
pub mod example;

pub use bit_fields_macros::*;

/// Bit flag types.
mod bit;
pub use bit::*;

/// Bit range types.
mod bit_range;
pub use bit_range::*;

/// Exported error types.
mod errors;
pub use errors::*;

/// Trait used for indexing into a bit field.
///
/// ```ignore
/// let bit_field = bit_fields::bitfield!(MyBitField,u8,{A:0,B:1,C:3,D:7});
/// let _a = bit_field.bit::<0>();
/// let _b = bit_field.bit::<1>();
/// let _c = bit_field.bit::<3>();
///
/// // You can index to unnamed bits like this.
/// let _ = bit_field.bit::<4>();
/// let _ = bit_field.bit::<5>();
/// let sixth = bit_field.bit::<6>();
/// println!("sixth: {}",sixth);
///
/// let d = bit_field.bit::<7>();
/// println!("d: {}",d);
/// ```
pub trait BitIndex<T, const P: u8> {
    /// Gets a reference to a bit.
    fn bit(&self) -> Bit<'_, T, P>;
}
/// Trait used for mutable indexing into a bit field.
///
/// ```ignore
/// let bit_field = bit_fields::bitfield!(MyBitField,u8,{A:0,B:1,C:3,D:7});
/// let _a = bit_field.bit_mut::<0>();
/// let _b = bit_field.bit_mut::<1>();
/// let _c = bit_field.bit_mut::<3>();
///
/// // You can index to unnamed bits like this.
/// let _ = bit_field.bit_mut::<4>();
/// let _ = bit_field.bit_mut::<5>();
///
/// // We set the 6th bit to 0.
/// let mut sixth = bit_field.bit_mut::<6>();
/// sixth.off();
///
/// // We set the 7th bit to 1.
/// let mut d = bit_field.bit_mut::<7>();
/// d.on();
/// ```
pub trait BitIndexMut<T, const P: u8> {
    /// Gets a mutable reference to a bit.
    fn bit_mut(&mut self) -> BitMut<'_, T, P>;
}
/// Trait defining function that returns if all defined bits are equal, ignoring undefined bits.
pub trait Equal {
    /// Returns if all defined bits are equal, ignoring undefined bits.
    fn equal(&self, other: &Self) -> bool;
}
impl<T: Equal> Equal for &T {
    #[inline]
    fn equal(&self, other: &Self) -> bool {
        (**self).equal(other)
    }
}
impl<T: Equal> Equal for &mut T {
    #[inline]
    fn equal(&self, other: &Self) -> bool {
        (**self).equal(other)
    }
}
/// Convenience macro for defining `Equal` implementations on primitives.
macro_rules! impl_equal {
    ($t:ty) => {
        impl Equal for $t {
            #[inline]
            fn equal(&self, other: &Self) -> bool {
                self == other
            }
        }
    };
}
impl_equal!(usize);
impl_equal!(u128);
impl_equal!(u64);
impl_equal!(u32);
impl_equal!(u16);
impl_equal!(u8);
impl_equal!(isize);
impl_equal!(i128);
impl_equal!(i64);
impl_equal!(i32);
impl_equal!(i16);
impl_equal!(i8);

impl<T: Equal, const N: usize> Equal for [T; N] {
    #[inline]
    fn equal(&self, other: &Self) -> bool {
        self.iter().zip(other.iter()).all(|(a, b)| a.equal(b))
    }
}
impl<T: Equal> Equal for [T] {
    #[inline]
    fn equal(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().zip(other.iter()).all(|(a, b)| a.equal(b))
    }
}
impl<T: Equal> Equal for Option<T> {
    #[inline]
    fn equal(&self, other: &Self) -> bool {
        match (self.as_ref(), other.as_ref()) {
            (Some(_), None) | (None, Some(_)) => false,
            (None, None) => true,
            (Some(a), Some(b)) => a.equal(b),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        non_snake_case,
        clippy::dbg_macro,
        clippy::unwrap_used,
        clippy::as_conversions,
        clippy::shadow_unrelated,
        clippy::decimal_literal_representation
    )]
    use std::convert::TryFrom;

    use rand::Rng;

    use super::*;
    use crate as bit_fields;

    bitfield!(BitFieldIndexedU16, u16, {
        #[skip]
        one: 0..1,
        one0: one[0..1],
        #[skip]
        one00: one0[0],
        #[skip]
        two: 1..3,
        two0: two[0..1],
        #[skip]
        two00: two0[0],
        two1: two[1],
        #[skip]
        three: 3..6,
        #[skip]
        three0: three[0..1],
        three00: three0[0],
        three1: three[1..3],
        #[skip]
        three10: three1[0..1],
        #[skip]
        three11: three1[1],
        four: 6..10,
        five: 10..15,
        six: 15
    });

    bitfield!(BitFieldu128, u128, {
        one: 0..1,
        two: 1..3,
        three: 3..6,
        four: 6..10,
        five: 10..15,
        six: 15..21,
        seven: 21..28,
        eight: 28..36,
        nine: 36..45,
        ten: 45..55,
        eleven: 55..66,
        twelve: 66..78,
        thirteen: 78..91,
        fourteen: 91..105,
        fifteen: 105..120,
        sixteen: 120,
        seventeen: 121,
        eighteen: 122,
        nineteen: 123,
        twenty: 124,
        twentyone: 125,
        twentytwo: 126,
        twentythree: 127,
    });
    bitfield!(BitFieldu64, u64, {
        one: 0..1,
        two: 1..3,
        three: 3..6,
        four: 6..10,
        five: 10..15,
        six: 15..21,
        seven: 21..28,
        eight: 28..36,
        nine: 36..45,
        ten: 45..55,
        eleven: 55,
        twelve: 56,
        thirteen: 57,
        fourteen: 58,
        fifteen: 59,
        sixteen: 60,
        seventeen: 61,
        eighteen: 62,
        nineteen: 63
    });
    bitfield!(BitFieldu32, u32, {
        one: 0..1,
        two: 1..3,
        three: 3..6,
        four: 6..10,
        five: 10..15,
        six: 15..21,
        seven: 21..28,
        eight: 28,
        nine: 29,
        ten: 30,
        eleven: 31
    });
    bitfield!(BitFieldu16, u16, {
        one: 0..1,
        two: 1..3,
        three: 3..6,
        four: 6..10,
        five: 10..15,
        six: 15
    });
    bitfield!(BitFieldu8, u8, {
        one: 0..1,
        two: 1..3,
        three: 3..6,
        four: 6,
        five: 7
    });

    bitfield!(
        GeneratedBitField,
        u32,
        {
            RANGE1:
            0..1,
            SSE:
            2,
            SSE1:
            3,
            RANGE2:
            4..6,
            SSE2:
            9,
            SSE3:
            10,
            RANGE3:
            12..15,
            SSE4:
            18
        }
    );

    const ITERATIONS: usize = 100_000;
    const MAX: u32 = 100;

    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn check(bitfield: &GeneratedBitField, r1: u32, r2: u32, r3: u32) {
        assert_eq!(bitfield.RANGE1(), r1);
        assert_eq!(bitfield.SSE(), true);
        assert_eq!(bitfield.SSE1(), true);
        assert_eq!(bitfield.RANGE2(), r2);
        assert_eq!(bitfield.SSE2(), true);
        assert_eq!(bitfield.SSE3(), false);
        assert_eq!(bitfield.RANGE3(), r3);
        assert_eq!(bitfield.SSE4(), false);
    }

    #[test]
    fn indexed() {
        let bit_field = BitFieldIndexedU16(0b1010_1110_0101_0111);

        assert_eq!(bit_field.one().read(), 1);
        assert_eq!(bit_field.one0().read(), 1);
        assert!(bit_field.one00().is_on());

        assert_eq!(bit_field.two().read(), 3);
        assert_eq!(bit_field.two0().read(), 1);
        assert!(bit_field.two00().is_on());
        assert!(bit_field.two1().is_on());

        assert_eq!(bit_field.three().read(), 2);
        assert_eq!(bit_field.three0().read(), 0);
        assert!(bit_field.three00().is_off());
        assert_eq!(bit_field.three1().read(), 1);
        assert_eq!(bit_field.three10().read(), 1);
        assert!(bit_field.three11().is_off());

        assert_eq!(bit_field.four().read(), 9);
        assert_eq!(bit_field.five().read(), 11);
        assert!(bit_field.six().is_on());
    }

    #[test]
    fn display() {
        let field_u16 = BitFieldu16(0b1010_1110_0101_0111);
        let field_u8 = BitFieldu8(0b1010_1110);
        #[rustfmt::skip]
        assert_eq!(field_u16.to_string(),"\
            ┌───────┬─────────────┬─────────────┬─────────────┬─────────────┬─────────────┬───────┐\n\
            │ \x1b[1mBit/s\x1b[0m │      00..01 │      01..03 │      03..06 │      06..10 │      10..15 │    15 │\n\
            ├───────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼───────┤\n\
            │ \x1b[1mDesc\x1b[0m  │         one │         two │       three │        four │        five │   six │\n\
            ├───────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼───────┤\n\
            │ \x1b[1mValue\x1b[0m │           1 │           3 │           2 │           9 │          11 │  true │\n\
            └───────┴─────────────┴─────────────┴─────────────┴─────────────┴─────────────┴───────┘\n\
        ");
        #[rustfmt::skip]
        assert_eq!(field_u8.to_string(),"\
            ┌───────┬─────────────┬─────────────┬─────────────┬───────┬───────┐\n\
            │ \x1b[1mBit/s\x1b[0m │      00..01 │      01..03 │      03..06 │    06 │    07 │\n\
            ├───────┼─────────────┼─────────────┼─────────────┼───────┼───────┤\n\
            │ \x1b[1mDesc\x1b[0m  │         one │         two │       three │  four │  five │\n\
            ├───────┼─────────────┼─────────────┼─────────────┼───────┼───────┤\n\
            │ \x1b[1mValue\x1b[0m │           0 │           3 │           5 │ false │  true │\n\
            └───────┴─────────────┴─────────────┴─────────────┴───────┴───────┘\n\
        ");
    }
    // Testing bit field sizes
    #[test]
    fn size() {
        use std::mem::size_of;
        assert_eq!(size_of::<BitFieldu128>(), size_of::<u128>());
        assert_eq!(size_of::<BitFieldu64>(), size_of::<u64>());
        assert_eq!(size_of::<BitFieldu32>(), size_of::<u32>());
        assert_eq!(size_of::<BitFieldu16>(), size_of::<u16>());
        assert_eq!(size_of::<BitFieldu8>(), size_of::<u8>());
    }
    #[test]
    fn type_max() {
        // u128
        assert_eq!(BitRange::<u128, 0, 1>::MAX, 1);
        assert_eq!(BitRange::<u128, 1, 3>::MAX, 3);
        assert_eq!(BitRange::<u128, 3, 6>::MAX, 7);
        assert_eq!(BitRange::<u128, 6, 10>::MAX, 15);
        assert_eq!(BitRange::<u128, 10, 15>::MAX, 31);
        assert_eq!(BitRange::<u128, 15, 21>::MAX, 63);
        assert_eq!(BitRange::<u128, 21, 28>::MAX, 127);
        assert_eq!(BitRange::<u128, 28, 36>::MAX, 255);
        assert_eq!(BitRange::<u128, 36, 45>::MAX, 511);
        assert_eq!(BitRange::<u128, 45, 55>::MAX, 1023);
        assert_eq!(BitRange::<u128, 55, 66>::MAX, 2047);
        assert_eq!(BitRange::<u128, 66, 78>::MAX, 4095);
        assert_eq!(BitRange::<u128, 78, 91>::MAX, 8191);
        assert_eq!(BitRange::<u128, 91, 105>::MAX, 16383);
        assert_eq!(BitRange::<u128, 105, 120>::MAX, 32767);

        // u64
        assert_eq!(BitRange::<u64, 0, 1>::MAX, 1);
        assert_eq!(BitRange::<u64, 1, 3>::MAX, 3);
        assert_eq!(BitRange::<u64, 3, 6>::MAX, 7);
        assert_eq!(BitRange::<u64, 6, 10>::MAX, 15);
        assert_eq!(BitRange::<u64, 10, 15>::MAX, 31);
        assert_eq!(BitRange::<u64, 15, 21>::MAX, 63);
        assert_eq!(BitRange::<u64, 21, 28>::MAX, 127);
        assert_eq!(BitRange::<u64, 28, 36>::MAX, 255);
        assert_eq!(BitRange::<u64, 36, 45>::MAX, 511);
        assert_eq!(BitRange::<u64, 45, 55>::MAX, 1023);

        // u32
        assert_eq!(BitRange::<u32, 0, 1>::MAX, 1);
        assert_eq!(BitRange::<u32, 1, 3>::MAX, 3);
        assert_eq!(BitRange::<u32, 3, 6>::MAX, 7);
        assert_eq!(BitRange::<u32, 6, 10>::MAX, 15);
        assert_eq!(BitRange::<u32, 10, 15>::MAX, 31);
        assert_eq!(BitRange::<u32, 15, 21>::MAX, 63);
        assert_eq!(BitRange::<u32, 21, 28>::MAX, 127);

        // u16
        assert_eq!(BitRange::<u16, 0, 1>::MAX, 1);
        assert_eq!(BitRange::<u16, 1, 3>::MAX, 3);
        assert_eq!(BitRange::<u16, 3, 6>::MAX, 7);
        assert_eq!(BitRange::<u16, 6, 10>::MAX, 15);
        assert_eq!(BitRange::<u16, 10, 15>::MAX, 31);

        assert_eq!(BitRange::<u16, 0, 16>::MAX, 65535);
        assert_eq!(BitRange::<u16, 0, 8>::MAX, 255);
        assert_eq!(BitRange::<u16, 8, 16>::MAX, 255);
        assert_eq!(BitRange::<u16, 4, 12>::MAX, 255);
        assert_eq!(BitRange::<u16, 6, 10>::MAX, 15);
        assert_eq!(BitRange::<u16, 7, 9>::MAX, 3);

        // u8
        assert_eq!(BitRange::<u8, 0, 1>::MAX, 1);
        assert_eq!(BitRange::<u8, 1, 3>::MAX, 3);
        assert_eq!(BitRange::<u8, 3, 6>::MAX, 7);

        assert_eq!(BitRange::<u8, 0, 8>::MAX, 255);
        assert_eq!(BitRange::<u8, 0, 4>::MAX, 15);
        assert_eq!(BitRange::<u8, 4, 8>::MAX, 15);
        assert_eq!(BitRange::<u8, 2, 6>::MAX, 15);
        assert_eq!(BitRange::<u8, 3, 5>::MAX, 3);
    }
    #[test]
    fn value_max() {
        let field_u128: BitFieldu128 = BitFieldu128(0);
        let field_u64: BitFieldu64 = BitFieldu64(0);
        let field_u32: BitFieldu32 = BitFieldu32(0);
        let field_u16: BitFieldu16 = BitFieldu16(0);
        let field_u8: BitFieldu8 = BitFieldu8(0);

        // u128
        assert_eq!(field_u128.one().get_max(), 1);
        assert_eq!(field_u128.two().get_max(), 3);
        assert_eq!(field_u128.three().get_max(), 7);
        assert_eq!(field_u128.four().get_max(), 15);
        assert_eq!(field_u128.five().get_max(), 31);
        assert_eq!(field_u128.six().get_max(), 63);
        assert_eq!(field_u128.seven().get_max(), 127);
        assert_eq!(field_u128.eight().get_max(), 255);
        assert_eq!(field_u128.nine().get_max(), 511);
        assert_eq!(field_u128.ten().get_max(), 1023);
        assert_eq!(field_u128.eleven().get_max(), 2047);
        assert_eq!(field_u128.twelve().get_max(), 4095);
        assert_eq!(field_u128.thirteen().get_max(), 8191);
        assert_eq!(field_u128.fourteen().get_max(), 16383);
        assert_eq!(field_u128.fifteen().get_max(), 32767);
        // u64
        assert_eq!(field_u64.one().get_max(), 1);
        assert_eq!(field_u64.two().get_max(), 3);
        assert_eq!(field_u64.three().get_max(), 7);
        assert_eq!(field_u64.four().get_max(), 15);
        assert_eq!(field_u64.five().get_max(), 31);
        assert_eq!(field_u64.six().get_max(), 63);
        assert_eq!(field_u64.seven().get_max(), 127);
        assert_eq!(field_u64.eight().get_max(), 255);
        assert_eq!(field_u64.nine().get_max(), 511);
        assert_eq!(field_u64.ten().get_max(), 1023);
        // u32
        assert_eq!(field_u32.one().get_max(), 1);
        assert_eq!(field_u32.two().get_max(), 3);
        assert_eq!(field_u32.three().get_max(), 7);
        assert_eq!(field_u32.four().get_max(), 15);
        assert_eq!(field_u32.five().get_max(), 31);
        assert_eq!(field_u32.six().get_max(), 63);
        assert_eq!(field_u32.seven().get_max(), 127);
        // u16
        assert_eq!(field_u16.one().get_max(), 1);
        assert_eq!(field_u16.two().get_max(), 3);
        assert_eq!(field_u16.three().get_max(), 7);
        assert_eq!(field_u16.four().get_max(), 15);
        assert_eq!(field_u16.five().get_max(), 31);
        // u8
        assert_eq!(field_u8.one().get_max(), 1);
        assert_eq!(field_u8.two().get_max(), 3);
        assert_eq!(field_u8.three().get_max(), 7);
    }
    #[test]
    fn access() {
        let bitfield = GeneratedBitField::from(23548);
        assert_eq!(bitfield.RANGE1(), 0);
        assert_eq!(bitfield.SSE(), true);
        assert_eq!(bitfield.SSE1(), true);
        assert_eq!(bitfield.RANGE2(), 3);
        assert_eq!(bitfield.SSE2(), true);
        assert_eq!(bitfield.SSE3(), false);
        assert_eq!(bitfield.RANGE3(), 5);
        assert_eq!(bitfield.SSE4(), false);
    }
    #[test]
    fn flip() {
        let mut bitfield = GeneratedBitField::from(23548);
        assert_eq!(bitfield.RANGE1(), 0);
        assert_eq!(bitfield.SSE(), true);
        assert_eq!(bitfield.SSE1(), true);
        assert_eq!(bitfield.RANGE2(), 3);
        assert_eq!(bitfield.SSE2(), true);
        assert_eq!(bitfield.SSE3(), false);
        assert_eq!(bitfield.RANGE3(), 5);
        assert_eq!(bitfield.SSE4(), false);

        bitfield.SSE_mut().flip();
        bitfield.SSE1_mut().flip();
        bitfield.SSE2_mut().flip();
        bitfield.SSE3_mut().flip();
        bitfield.SSE4_mut().flip();

        assert_eq!(bitfield.RANGE1(), 0);
        assert_eq!(bitfield.SSE(), false);
        assert_eq!(bitfield.SSE1(), false);
        assert_eq!(bitfield.RANGE2(), 3);
        assert_eq!(bitfield.SSE2(), false);
        assert_eq!(bitfield.SSE3(), true);
        assert_eq!(bitfield.RANGE3(), 5);
        assert_eq!(bitfield.SSE4(), true);
    }
    #[test]
    fn set() {
        let mut bitfield = GeneratedBitField::from(23548);
        assert_eq!(bitfield.RANGE1(), 0);
        assert_eq!(bitfield.SSE(), true);
        assert_eq!(bitfield.SSE1(), true);
        assert_eq!(bitfield.RANGE2(), 3);
        assert_eq!(bitfield.SSE2(), true);
        assert_eq!(bitfield.SSE3(), false);
        assert_eq!(bitfield.RANGE3(), 5);
        assert_eq!(bitfield.SSE4(), false);

        bitfield.SSE_mut().set(false);
        bitfield.SSE1_mut().set(false);
        bitfield.SSE2_mut().set(true);
        bitfield.SSE3_mut().set(true);
        bitfield.SSE4_mut().set(false);

        assert_eq!(bitfield.RANGE1(), 0);
        assert_eq!(bitfield.SSE(), false);
        assert_eq!(bitfield.SSE1(), false);
        assert_eq!(bitfield.RANGE2(), 3);
        assert_eq!(bitfield.SSE2(), true);
        assert_eq!(bitfield.SSE3(), true);
        assert_eq!(bitfield.RANGE3(), 5);
        assert_eq!(bitfield.SSE4(), false);
    }
    #[test]
    fn on_off() {
        let mut bitfield = GeneratedBitField::from(23548);
        assert_eq!(bitfield.RANGE1(), 0);
        assert_eq!(bitfield.SSE(), true);
        assert_eq!(bitfield.SSE1(), true);
        assert_eq!(bitfield.RANGE2(), 3);
        assert_eq!(bitfield.SSE2(), true);
        assert_eq!(bitfield.SSE3(), false);
        assert_eq!(bitfield.RANGE3(), 5);
        assert_eq!(bitfield.SSE4(), false);

        bitfield.SSE_mut().off();
        bitfield.SSE1_mut().on();
        bitfield.SSE2_mut().on();
        bitfield.SSE4_mut().on();

        assert_eq!(bitfield.RANGE1(), 0);
        assert_eq!(bitfield.SSE(), false);
        assert_eq!(bitfield.SSE1(), true);
        assert_eq!(bitfield.RANGE2(), 3);
        assert_eq!(bitfield.SSE2(), true);
        assert_eq!(bitfield.SSE3(), false);
        assert_eq!(bitfield.RANGE3(), 5);
        assert_eq!(bitfield.SSE4(), true);
    }
    #[test]
    fn checked_assign() {
        let mut bitfield = GeneratedBitField::from(23548);

        let (mut range1, mut range2, mut range3) = (0, 3, 5);
        check(&bitfield, range1, range2, range3);

        let mut rng = rand::thread_rng();
        // Randomly assign to `range1`
        for _ in 0..ITERATIONS {
            let next = rng.gen_range(0..MAX);
            dbg!(next);
            range1 = match bitfield.RANGE1_mut().checked_assign(next) {
                Ok(()) => next,
                Err(CheckedAssignError) => range1,
            };
            check(&bitfield, range1, range2, range3);
        }
        // Randomly assign to `RANGE2`
        for _ in 0..ITERATIONS {
            let next = rng.gen_range(0..MAX);
            dbg!(next);
            range2 = match bitfield.RANGE2_mut().checked_assign(next) {
                Ok(()) => next,
                Err(CheckedAssignError) => range2,
            };
            check(&bitfield, range1, range2, range3);
        }
        // Randomly assign to `RANGE3`
        for _ in 0..ITERATIONS {
            let next = rng.gen_range(0..MAX);
            dbg!(next);
            range3 = match bitfield.RANGE3_mut().checked_assign(next) {
                Ok(()) => next,
                Err(CheckedAssignError) => range3,
            };
            check(&bitfield, range1, range2, range3);
        }
    }
    #[test]
    fn conversion() {
        use std::collections::{HashMap, HashSet};

        let mut rng = rand::thread_rng();

        let bitfield_u8_before = BitFieldu8::from(rng.gen::<u8>());
        let (set, map) =
            <(HashSet<&'static str>, HashMap<&'static str, u8>)>::from(&bitfield_u8_before);
        let bitfield_u8_after = BitFieldu8::try_from((set, map)).unwrap();
        assert_eq!(bitfield_u8_before, bitfield_u8_after);

        let bitfield_u16_before = BitFieldu16::from(rng.gen::<u16>());
        let (set, map) =
            <(HashSet<&'static str>, HashMap<&'static str, u16>)>::from(&bitfield_u16_before);
        let bitfield_u16_after = BitFieldu16::try_from((set, map)).unwrap();
        assert_eq!(bitfield_u16_before, bitfield_u16_after);

        let bitfield_u32_before = BitFieldu32::from(rng.gen::<u32>());
        let (set, map) =
            <(HashSet<&'static str>, HashMap<&'static str, u32>)>::from(&bitfield_u32_before);
        let bitfield_u32_after = BitFieldu32::try_from((set, map)).unwrap();
        assert_eq!(bitfield_u32_before, bitfield_u32_after);

        let bitfield_u64_before = BitFieldu64::from(rng.gen::<u64>());
        let (set, map) =
            <(HashSet<&'static str>, HashMap<&'static str, u64>)>::from(&bitfield_u64_before);
        let bitfield_u64_after = BitFieldu64::try_from((set, map)).unwrap();
        assert_eq!(bitfield_u64_before, bitfield_u64_after);

        let bitfield_u128_before = BitFieldu128::from(rng.gen::<u128>());
        let (set, map) =
            <(HashSet<&'static str>, HashMap<&'static str, u128>)>::from(&bitfield_u128_before);
        let bitfield_u128_after = BitFieldu128::try_from((set, map)).unwrap();
        assert_eq!(bitfield_u128_before, bitfield_u128_after);
    }
    #[test]
    fn serialize() {
        let mut rng = rand::thread_rng();

        let bitfield_u8_before = BitFieldu8::from(rng.gen::<u8>());
        let serialized = serde_json::to_vec(&bitfield_u8_before).unwrap();
        let bitfield_u8_after = serde_json::from_slice::<BitFieldu8>(&serialized).unwrap();
        assert_eq!(bitfield_u8_before, bitfield_u8_after);

        let bitfield_u16_before = BitFieldu16::from(rng.gen::<u16>());
        let serialized = serde_json::to_vec(&bitfield_u16_before).unwrap();
        let bitfield_u16_after = serde_json::from_slice::<BitFieldu16>(&serialized).unwrap();
        assert_eq!(bitfield_u16_before, bitfield_u16_after);

        let bitfield_u32_before = BitFieldu32::from(rng.gen::<u32>());
        let serialized = serde_json::to_vec(&bitfield_u32_before).unwrap();
        let bitfield_u32_after = serde_json::from_slice::<BitFieldu32>(&serialized).unwrap();
        assert_eq!(bitfield_u32_before, bitfield_u32_after);

        let bitfield_u64_before = BitFieldu64::from(rng.gen::<u64>());
        let serialized = serde_json::to_vec(&bitfield_u64_before).unwrap();
        let bitfield_u64_after = serde_json::from_slice::<BitFieldu64>(&serialized).unwrap();
        assert_eq!(bitfield_u64_before, bitfield_u64_after);

        let bitfield_u128_before = BitFieldu128::from(rng.gen::<u128>());
        let serialized = serde_json::to_vec(&bitfield_u128_before).unwrap();
        let bitfield_u128_after = serde_json::from_slice::<BitFieldu128>(&serialized).unwrap();
        assert_eq!(bitfield_u128_before, bitfield_u128_after);
    }
}
