// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// A type interface for a range of bits.
#[derive(Debug, Clone)]
pub struct BitRange<'a, T, const START: u8, const END: u8>(pub &'a T);

/// A type interface for a range of bits.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct BitRangeMut<'a, T, const START: u8, const END: u8>(pub &'a mut T);

/// Macro for defining `impl Disply for BitRange`.
macro_rules! bit_range_display {
    ($x:ty) => {
        impl<const START: u8, const END: u8> std::fmt::Display for BitRange<'_, $x, START, END> {
            #[doc = concat!("
                ```
                use bit_fields::BitRange;
                let x = 18", stringify!($x), ";
                assert_eq!(BitRange::<_,0,4>(&x).to_string(),2", stringify!($x),".to_string());
                assert_eq!(BitRange::<_,4,8>(&x).to_string(),1", stringify!($x),".to_string());
                ```
            ")]
            #[inline]
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}", self.read())
            }
        }
    };
}

bit_range_display!(u128);
bit_range_display!(u64);
bit_range_display!(u32);
bit_range_display!(u16);
bit_range_display!(u8);

/// Macro for defining `impl Disply for BitRangeMut`.
macro_rules! bit_range_mut_display {
    ($x:ty) => {
        impl<const START: u8, const END: u8> std::fmt::Display for BitRangeMut<'_, $x, START, END> {
            #[doc = concat!("
                ```
                use bit_fields::BitRangeMut;
                let mut x = 18", stringify!($x), ";
                assert_eq!(BitRangeMut::<_,0,4>(&mut x).to_string(),2", stringify!($x),".to_string());
                assert_eq!(BitRangeMut::<_,4,8>(&mut x).to_string(),1", stringify!($x),".to_string());
                ```
            ")]
            #[inline]
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}", self.read())
            }
        }
    };
}

bit_range_mut_display!(u128);
bit_range_mut_display!(u64);
bit_range_mut_display!(u32);
bit_range_mut_display!(u16);
bit_range_mut_display!(u8);

/// Macro for defining `impl BitRange`.
macro_rules! bit_range {
    ($x:ty, $mask:ident, $max:ident) => {
        impl<const START: u8, const END: u8> BitRange<'_, $x, START, END> {
            pub const MASK: $x = $mask::<START, END>();
            /// The maximum value this range can store
            pub const MAX: $x = $max::<START, END>();

            #[doc = concat!("
                Returns the value of the bit range.
                ```
                use bit_fields::BitRange;
                let x = 18", stringify!($x), ";
                assert_eq!(BitRange::<_,0,4>(&x),2);
                assert_eq!(BitRange::<_,4,8>(&x),1);
                ```
            ")]
            #[must_use]
            #[inline]
            pub fn read(&self) -> $x {
                <$x>::from(self)
            }

            #[doc = concat!("
                Convenience alias for [`Self::MAX`].
                
                ```
                use bit_fields::BitRange;
                let x = ", stringify!($x), "::default();

                assert_eq!(BitRange::<_,0,1>(&x).get_max(),1);
                assert_eq!(BitRange::<_,0,2>(&x).get_max(),3);
                assert_eq!(BitRange::<_,0,3>(&x).get_max(),7);
                assert_eq!(BitRange::<_,0,4>(&x).get_max(),15);
                assert_eq!(BitRange::<_,0,5>(&x).get_max(),31);
                assert_eq!(BitRange::<_,0,6>(&x).get_max(),63);
                assert_eq!(BitRange::<_,0,7>(&x).get_max(),127);
                assert_eq!(BitRange::<_,0,8>(&x).get_max(),255);
                ```
            ")]
            #[must_use]
            #[inline]
            pub const fn get_max(&self) -> $x {
                Self::MAX
            }
            #[doc = concat!("
                Convenience alias for [`Self::MASK`].
                
                ```
                use bit_fields::BitRange;
                let x = ", stringify!($x), "::default();

                assert_eq!(BitRange::<_,0,1>(&x).get_mask(),1);
                assert_eq!(BitRange::<_,1,3>(&x).get_mask(),6);
                assert_eq!(BitRange::<_,3,7>(&x).get_mask(),120);
                assert_eq!(BitRange::<_,7,8>(&x).get_mask(),128);
                ```
            ")]
            #[must_use]
            #[inline]
            pub const fn get_mask(&self) -> $x {
                Self::MASK
            }
        }
    };
}

bit_range!(u128, mask_u128, max_u128);
bit_range!(u64, mask_u64, max_u64);
bit_range!(u32, mask_u32, max_u32);
bit_range!(u16, mask_u16, max_u16);
bit_range!(u8, mask_u8, max_u8);

/// Macro for defining `impl BitRangeMut`.
macro_rules! bit_mut_range {
    ($x:ty, $mask:ident, $max:ident) => {
        impl<const START: u8, const END: u8> BitRangeMut<'_, $x, START, END> {
            pub const MASK: $x = $mask::<START, END>();
            /// The maximum value this range can store
            pub const MAX: $x = $max::<START, END>();

            #[doc = concat!("
                Returns the value of the bit range.
                ```
                use bit_fields::BitRangeMut;
                let mut x = 18", stringify!($x), ";
                assert_eq!(BitRangeMut::<_,0,4>(&mut x),2", stringify!($x),");
                assert_eq!(BitRangeMut::<_,4,8>(&mut x),1", stringify!($x),");
                ```
            ")]
            #[must_use]
            #[inline]
            pub fn read(&self) -> $x {
                <$x>::from(self)
            }

            // `x <= Self::MAX` guarantees `x << START` is safe.
            #[doc = concat!("
                Alias for [`Self::checked_assign`].

                # Errors

                When `x` is greater than the maximum storable value in `self`.
                ```
                use bit_fields::{BitRangeMut, CheckedAssignError};
                let mut x = 18", stringify!($x), ";

                let mut nibble = BitRangeMut::<_,0,4>(&mut x);
                assert_eq!(nibble.write(16),Err(CheckedAssignError));
                assert_eq!(nibble.write(15),Ok(()));

                let mut nibble = BitRangeMut::<_,4,8>(&mut x);
                assert_eq!(nibble.write(16),Err(CheckedAssignError));
                assert_eq!(nibble.write(15),Ok(()));
                ```
            ")]
            #[inline]
            pub fn write(&mut self, x: $x) -> Result<(), $crate::CheckedAssignError> {
                self.checked_assign(x)
            }

            #[doc = concat!("
                Adds `x` to the value of the bit range.

                # Errors

                1. When `x` is greater than the maximum value storable in the bit range.
                2. When adding `x` to the value of the bit range would overflow.

                ```
                use bit_fields::{BitRangeMut, CheckedAddAssignError};
                let mut x = 18", stringify!($x), ";

                let mut nibble = BitRangeMut::<_,0,4>(&mut x);
                assert_eq!(nibble,2);
                assert_eq!(nibble.checked_add_assign(16),Err(CheckedAddAssignError::OutOfRange));
                assert_eq!(nibble.checked_add_assign(14),Err(CheckedAddAssignError::Overflow));
                assert_eq!(nibble.checked_add_assign(2),Ok(()));
                assert_eq!(nibble,4);
                assert_eq!(x,20);
                
                let mut nibble = BitRangeMut::<_,4,8>(&mut x);
                assert_eq!(nibble,1);
                assert_eq!(nibble.checked_add_assign(16),Err(CheckedAddAssignError::OutOfRange));
                assert_eq!(nibble.checked_add_assign(15),Err(CheckedAddAssignError::Overflow));
                assert_eq!(nibble.checked_add_assign(2),Ok(()));
                assert_eq!(nibble,3);
                assert_eq!(x,52);
                ```
            ")]
            #[allow(clippy::integer_arithmetic, clippy::arithmetic_side_effects)]
            #[inline]
            pub fn checked_add_assign(
                &mut self,
                x: $x,
            ) -> Result<(), $crate::CheckedAddAssignError> {
                if x <= Self::MAX {
                    let cur = self.read();
                    if x <= Self::MAX - cur {
                        debug_assert!(cur + x <= Self::MAX);
                        // SAFETY: `x <= Self::MAX - cur` implies `cur + x <= Self::MAX`.
                        unsafe {
                            self.unchecked_assign(cur + x)
                        }
                        Ok(())
                    } else {
                        Err($crate::CheckedAddAssignError::Overflow)
                    }
                } else {
                    Err($crate::CheckedAddAssignError::OutOfRange)
                }
            }

            // `x <= Self::MAX` guarantees `x << START` is safe and `x <= cur` guarantees
            // `self.data_mut() -= shift` is safe.
            #[doc = concat!("
                Subtract `x` from the value of the bit range.

                # Errors

                1. When `x` is greater than the maximum value storable in the bit range.
                2. When subtracting `x` from the value of the bit range would underflow.

                ```
                use bit_fields::{BitRangeMut, CheckedSubAssignError};
                let mut x = 18", stringify!($x), ";

                let mut nibble = BitRangeMut::<_,0,4>(&mut x);
                assert_eq!(nibble,2);
                assert_eq!(nibble.checked_sub_assign(16),Err(CheckedSubAssignError::OutOfRange));
                assert_eq!(nibble.checked_sub_assign(3),Err(CheckedSubAssignError::Underflow));
                assert_eq!(nibble.checked_sub_assign(1),Ok(()));
                assert_eq!(nibble,1);
                assert_eq!(x,17);
                
                let mut nibble = BitRangeMut::<_,4,8>(&mut x);
                assert_eq!(nibble,1);
                assert_eq!(nibble.checked_sub_assign(16),Err(CheckedSubAssignError::OutOfRange));
                assert_eq!(nibble.checked_sub_assign(2),Err(CheckedSubAssignError::Underflow));
                assert_eq!(nibble.checked_sub_assign(1),Ok(()));
                assert_eq!(nibble,0);
                assert_eq!(x,1);
                ```
            ")]
            #[allow(clippy::integer_arithmetic, clippy::arithmetic_side_effects)]
            #[inline]
            pub fn checked_sub_assign(
                &mut self,
                x: $x,
            ) -> Result<(), $crate::CheckedSubAssignError> {
                if x <= Self::MAX {
                    let cur = self.read();
                    if x <= cur {
                        // SAFETY: `x <= cur` implies `cur - x >= 0`.
                        unsafe {
                            self.unchecked_assign(cur - x);
                        }
                        Ok(())
                    } else {
                        Err($crate::CheckedSubAssignError::Underflow)
                    }
                } else {
                    Err($crate::CheckedSubAssignError::OutOfRange)
                }
            }

            // `x <= Self::MAX` guarantees `x << START` is safe.
            #[doc = concat!("
                Sets the bit range returning `Err(())` when the given `x` is not storable in the
                range.

                # Errors

                When `x` is greater than the maximum storable value in `self`.
                ```
                use bit_fields::{BitRangeMut, CheckedAssignError};
                let mut x = 18", stringify!($x), ";

                let mut nibble = BitRangeMut::<_,0,4>(&mut x);
                assert_eq!(nibble.checked_assign(16),Err(CheckedAssignError));
                assert_eq!(nibble.checked_assign(15),Ok(()));
                assert_eq!(x,31);

                let mut nibble = BitRangeMut::<_,4,8>(&mut x);
                assert_eq!(nibble.checked_assign(16),Err(CheckedAssignError));
                assert_eq!(nibble.checked_assign(15),Ok(()));
                assert_eq!(x,255);
                ```
            ")]
            #[allow(clippy::integer_arithmetic, clippy::arithmetic_side_effects)]
            #[inline]
            pub fn checked_assign(&mut self, x: $x) -> Result<(), $crate::CheckedAssignError> {
                if x <= Self::MAX {
                    // SAFETY: Safe due to checking `x <= Self::MAX`.
                    unsafe {
                        self.unchecked_assign(x);
                    }
                    Ok(())
                } else {
                    Err($crate::CheckedAssignError)
                }
            }
            #[doc="
                Sets the bit range.

                # Panics

                In debug when `x > Self::MAX`.
            "]
            #[allow(clippy::integer_arithmetic, clippy::arithmetic_side_effects)]
            #[inline]
            pub unsafe fn unchecked_assign(&mut self, x: $x) {
                debug_assert!(x <= Self::MAX);
                let shift = x << START;
                *self.0 = shift | (*self.0 & !Self::MASK);
            }
            #[doc = concat!("
                Convenience alias for [`Self::MAX`].
                
                ```
                use bit_fields::BitRangeMut;
                let mut x = ", stringify!($x), "::default();

                assert_eq!(BitRangeMut::<_,0,1>(&mut x).get_max(),1);
                assert_eq!(BitRangeMut::<_,0,2>(&mut x).get_max(),3);
                assert_eq!(BitRangeMut::<_,0,3>(&mut x).get_max(),7);
                assert_eq!(BitRangeMut::<_,0,4>(&mut x).get_max(),15);
                assert_eq!(BitRangeMut::<_,0,5>(&mut x).get_max(),31);
                assert_eq!(BitRangeMut::<_,0,6>(&mut x).get_max(),63);
                assert_eq!(BitRangeMut::<_,0,7>(&mut x).get_max(),127);
                assert_eq!(BitRangeMut::<_,0,8>(&mut x).get_max(),255);
                ```
            ")]
            #[must_use]
            #[inline]
            pub const fn get_max(&self) -> $x {
                Self::MAX
            }
            #[doc = concat!("
                Convenience alias for [`Self::MASK`].
                
                ```
                use bit_fields::BitRangeMut;
                let mut x = ", stringify!($x), "::default();

                assert_eq!(BitRangeMut::<_,0,1>(&mut x).get_mask(),1);
                assert_eq!(BitRangeMut::<_,1,3>(&mut x).get_mask(),6);
                assert_eq!(BitRangeMut::<_,3,7>(&mut x).get_mask(),120);
                assert_eq!(BitRangeMut::<_,7,8>(&mut x).get_mask(),128);
                ```
            ")]
            #[must_use]
            #[inline]
            pub const fn get_mask(&self) -> $x {
                Self::MASK
            }
        }
    };
}

bit_mut_range!(u128, mask_u128, max_u128);
bit_mut_range!(u64, mask_u64, max_u64);
bit_mut_range!(u32, mask_u32, max_u32);
bit_mut_range!(u16, mask_u16, max_u16);
bit_mut_range!(u8, mask_u8, max_u8);

/// Macro for defining `From` implementations on `BitRange` and `BitRangeMut`.
macro_rules! bit_range_from {
    ($x:ty, $bit_range: ident) => {
        // `START < 8 * size_of::<$x>()` is always true so the right shift will not panic.
        #[allow(clippy::integer_arithmetic, clippy::arithmetic_side_effects)]
        impl<const START: u8, const END: u8> From<&$bit_range<'_, $x, START, END>> for $x {
            #[inline]
            fn from(this: &$bit_range<'_, $x, START, END>) -> Self {
                let a = $bit_range::<'_, $x, START, END>::MASK & *this.0;
                a >> START
            }
        }
    };
}

bit_range_from!(u128, BitRange);
bit_range_from!(u64, BitRange);
bit_range_from!(u32, BitRange);
bit_range_from!(u16, BitRange);
bit_range_from!(u8, BitRange);

bit_range_from!(u128, BitRangeMut);
bit_range_from!(u64, BitRangeMut);
bit_range_from!(u32, BitRangeMut);
bit_range_from!(u16, BitRangeMut);
bit_range_from!(u8, BitRangeMut);

/// Macro for defining `PartialEq` and `Eq` implementations on `BitRange` and `BitRangeMut`.
macro_rules! bit_range_eq {
    ($x:ty, $bit_range: ident) => {
        impl<const START: u8, const END: u8> PartialEq<$x> for $bit_range<'_, $x, START, END> {
            #[inline]
            fn eq(&self, other: &$x) -> bool {
                self.read() == *other
            }
        }
        impl<const START: u8, const END: u8> PartialEq for $bit_range<'_, $x, START, END> {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                self.read() == other.read()
            }
        }
        impl<const START: u8, const END: u8> Eq for $bit_range<'_, $x, START, END> {}
    };
}

bit_range_eq!(u128, BitRange);
bit_range_eq!(u64, BitRange);
bit_range_eq!(u32, BitRange);
bit_range_eq!(u16, BitRange);
bit_range_eq!(u8, BitRange);

bit_range_eq!(u128, BitRangeMut);
bit_range_eq!(u64, BitRangeMut);
bit_range_eq!(u32, BitRangeMut);
bit_range_eq!(u16, BitRangeMut);
bit_range_eq!(u8, BitRangeMut);

/// Macro for defining `PartialOrd` and `Ord` implementations on `BitRange` and `BitRangeMut`.
macro_rules! bit_range_ord {
    ($x:ty, $bit_range: ident) => {
        impl<const START: u8, const END: u8> PartialOrd<$x> for $bit_range<'_, $x, START, END> {
            #[inline]
            fn partial_cmp(&self, other: &$x) -> Option<std::cmp::Ordering> {
                Some(self.read().cmp(&other))
            }
        }
        impl<const START: u8, const END: u8> PartialOrd for $bit_range<'_, $x, START, END> {
            #[inline]
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.read().cmp(&other.read()))
            }
        }
        impl<const START: u8, const END: u8> Ord for $bit_range<'_, $x, START, END> {
            #[inline]
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.read().cmp(&other.read())
            }
        }
    };
}

bit_range_ord!(u128, BitRange);
bit_range_ord!(u64, BitRange);
bit_range_ord!(u32, BitRange);
bit_range_ord!(u16, BitRange);
bit_range_ord!(u8, BitRange);

bit_range_ord!(u128, BitRangeMut);
bit_range_ord!(u64, BitRangeMut);
bit_range_ord!(u32, BitRangeMut);
bit_range_ord!(u16, BitRangeMut);
bit_range_ord!(u8, BitRangeMut);

/// Returns a value where in the binary representation all bits to the right of the x'th bit from
/// the left are 1.
macro_rules! shift {
    ($x:ident, $max:expr, $ty:path) => {{
        // These values are only evaluated at compile-time, thus a failure can only occur at
        // compile-time and would be immediately obvious. Thus it is safe to use arithmetic here.
        #[allow(clippy::integer_arithmetic)]
        if $x == 0 {
            0
        } else if $x < $max {
            (1 << $x) - 1
        } else if $x == $max {
            $ty
        } else {
            unreachable!()
        }
    }};
}

/// Macro for defining mask functions.
macro_rules! mask_fn {
    ($f:ident, $x:ty, $y:path) => {
        /// Returns mask over range.
        ///
        /// We take `START`and `END` as const generics to ensure compile-time
        /// evaluation.
        // These values are only evaluated at compile-time, thus a failure can only occur at
        // compile-time. This makes most fallible operations safe.
        #[allow(
            clippy::as_conversions,
            clippy::arithmetic_side_effects,
            clippy::integer_arithmetic
        )]
        #[must_use]
        #[inline]
        pub const fn $f<const START: u8, const END: u8>() -> $x {
            assert!(END >= START);
            let size = 8 * std::mem::size_of::<$x>();
            assert!(END as usize <= size);

            let front = shift!(START, size as u8, $y);
            let back = shift!(END, size as u8, $y);
            !front & back
        }
    };
}
mask_fn!(mask_u128, u128, u128::MAX);
mask_fn!(mask_u64, u64, u64::MAX);
mask_fn!(mask_u32, u32, u32::MAX);
mask_fn!(mask_u16, u16, u16::MAX);
mask_fn!(mask_u8, u8, u8::MAX);

/// Macro for defining max functions.
macro_rules! max_fn {
    ($f:ident, $x:ty) => {
        /// Returns maximum value storable in a range.
        ///
        /// We take `START`and `END` as const generics to ensure compile-time
        /// evaluation.
        // These values are only evaluated at compile-time, thus a failure can only occur at
        // compile-time. This makes most fallible operations safe.
        #[allow(
            clippy::integer_arithmetic,
            clippy::as_conversions,
            clippy::arithmetic_side_effects
        )]
        #[must_use]
        #[inline]
        pub const fn $f<const START: u8, const END: u8>() -> $x {
            assert!(END >= START);
            assert!(END as usize <= 8 * std::mem::size_of::<$x>());

            match (2 as $x).overflowing_pow((END - START) as u32) {
                (_, true) => <$x>::MAX,
                (max, false) => max - 1,
            }
        }
    };
}
max_fn!(max_u128, u128);
max_fn!(max_u64, u64);
max_fn!(max_u32, u32);
max_fn!(max_u16, u16);
max_fn!(max_u8, u8);

#[cfg(test)]
mod tests {
    #![allow(
        non_snake_case,
        clippy::dbg_macro,
        clippy::unwrap_used,
        clippy::as_conversions,
        clippy::shadow_unrelated
    )]

    use super::*;

    // Testing masks work
    #[test]
    fn mask() {
        // These top level checks exists to communicate to code coverage that this function is
        // covered
        assert_eq!(mask_u128::<0, 0>(), 0);
        assert_eq!(mask_u64::<0, 0>(), 0);
        assert_eq!(mask_u32::<0, 0>(), 0);
        assert_eq!(mask_u16::<0, 0>(), 0);
        assert_eq!(mask_u8::<0, 0>(), 0);
        // u128
        assert_eq!(
            mask_u128::<0, 128>(),
            0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff
        );
        assert_eq!(
            mask_u128::<0, 64>(),
            0x0000_0000_0000_0000_ffff_ffff_ffff_ffff
        );
        assert_eq!(
            mask_u128::<64, 128>(),
            0xffff_ffff_ffff_ffff_0000_0000_0000_0000
        );
        // u64
        assert_eq!(mask_u64::<0, 64>(), 0xffff_ffff_ffff_ffff);
        assert_eq!(mask_u64::<0, 32>(), 0x0000_0000_ffff_ffff);
        assert_eq!(mask_u64::<32, 64>(), 0xffff_ffff_0000_0000);
        assert_eq!(mask_u64::<4, 60>(), 0x0fff_ffff_ffff_fff0);
        assert_eq!(mask_u64::<8, 56>(), 0x00ff_ffff_ffff_ff00);
        assert_eq!(mask_u64::<12, 52>(), 0x000f_ffff_ffff_f000);
        assert_eq!(mask_u64::<16, 48>(), 0x0000_ffff_ffff_0000);
        assert_eq!(mask_u64::<20, 44>(), 0x0000_0fff_fff0_0000);
        assert_eq!(mask_u64::<24, 40>(), 0x0000_00ff_ff00_0000);
        assert_eq!(mask_u64::<28, 36>(), 0x0000_000f_f000_0000);
        assert_eq!(
            mask_u64::<30, 34>(),
            0b0000_0000_0000_0000_0000_0000_0000_0011_1100_0000_0000_0000_0000_0000_0000_0000
        );
        assert_eq!(
            mask_u64::<31, 33>(),
            0b0000_0000_0000_0000_0000_0000_0000_0001_1000_0000_0000_0000_0000_0000_0000_0000
        );
        // u32
        assert_eq!(mask_u32::<0, 32>(), 0xffff_ffff);
        assert_eq!(mask_u32::<0, 16>(), 0x0000_ffff);
        assert_eq!(mask_u32::<16, 32>(), 0xffff_0000);
        assert_eq!(mask_u32::<4, 28>(), 0x0fff_fff0);
        assert_eq!(mask_u32::<8, 24>(), 0x00ff_ff00);
        assert_eq!(mask_u32::<12, 20>(), 0x000f_f000);
        assert_eq!(
            mask_u32::<14, 18>(),
            0b0000_0000_0000_0011_1100_0000_0000_0000
        );
        assert_eq!(
            mask_u32::<15, 17>(),
            0b0000_0000_0000_0001_1000_0000_0000_0000
        );
        // u16
        assert_eq!(mask_u16::<0, 16>(), 0xffff);
        assert_eq!(mask_u16::<0, 8>(), 0x00ff);
        assert_eq!(mask_u16::<8, 16>(), 0xff00);
        assert_eq!(mask_u16::<4, 12>(), 0x0ff0);
        assert_eq!(mask_u16::<6, 10>(), 0b0000_0011_1100_0000);
        assert_eq!(mask_u16::<7, 9>(), 0b0000_0001_1000_0000);
        // u8
        assert_eq!(mask_u8::<0, 8>(), 0b1111_1111);
        assert_eq!(mask_u8::<0, 4>(), 0b0000_1111);
        assert_eq!(mask_u8::<4, 8>(), 0b1111_0000);
        assert_eq!(mask_u8::<2, 6>(), 0b0011_1100);
        assert_eq!(mask_u8::<3, 5>(), 0b0001_1000);
    }
}
