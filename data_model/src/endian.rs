// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Explicit endian types useful for embedding in structs or reinterpreting data.
//!
//! Each endian type is guarnteed to have the same size and alignment as a regular unsigned primiive
//! of the equal size.
//!
//! # Examples
//!
//! ```
//! # use  data_model::*;
//!   let b: Be32 = From::from(3);
//!   let l: Le32 = From::from(3);
//!
//!   assert_eq!(b.to_native(), 3);
//!   assert_eq!(l.to_native(), 3);
//!   assert!(b == 3);
//!   assert!(l == 3);
//!
//!   let b_trans: u32 = unsafe { std::mem::transmute(b) };
//!   let l_trans: u32 = unsafe { std::mem::transmute(l) };
//!
//!   #[cfg(target_endian = "little")]
//!   assert_eq!(l_trans, 3);
//!   #[cfg(target_endian = "big")]
//!   assert_eq!(b_trans, 3);
//!
//!   assert_ne!(b_trans, l_trans);
//! ```

use DataInit;

macro_rules! endian_type {
    ($old_type:ident, $new_type:ident, $to_new:ident, $from_new:ident) => (
        /// An unsigned integer type of with an explicit endianness.
        ///
        /// See module level documentation for examples.
        #[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
        pub struct $new_type($old_type);

        impl $new_type {
            /// Converts `self` to the native endianness.
            pub fn to_native(self) -> $old_type {
                $old_type::$from_new(self.0)
            }
        }

        unsafe impl DataInit for $new_type {}

        impl PartialEq<$old_type> for $new_type {
            fn eq(&self, other: &$old_type) -> bool {
                self.0 == $old_type::$to_new(*other)
            }
        }

        impl PartialEq<$new_type> for $old_type {
            fn eq(&self, other: &$new_type) -> bool {
                $old_type::$to_new(other.0) == *self
            }
        }

        impl Into<$old_type> for $new_type {
            fn into(self) -> $old_type {
                $old_type::$from_new(self.0)
            }
        }

        impl From<$old_type> for $new_type {
            fn from(v: $old_type) -> $new_type {
                $new_type($old_type::$to_new(v))
            }
        }
    )
}

endian_type!(u16, Le16, to_le, from_le);
endian_type!(u32, Le32, to_le, from_le);
endian_type!(u64, Le64, to_le, from_le);
endian_type!(usize, LeSize, to_le, from_le);
endian_type!(u16, Be16, to_be, from_be);
endian_type!(u32, Be32, to_be, from_be);
endian_type!(u64, Be64, to_be, from_be);
endian_type!(usize, BeSize, to_be, from_be);

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::From;
    use std::mem::{align_of, size_of, transmute};

    #[cfg(target_endian = "little")]
    const NATIVE_LITTLE: bool = true;
    #[cfg(target_endian = "big")]
    const NATIVE_LITTLE: bool = false;
    const NATIVE_BIG: bool = !NATIVE_LITTLE;

    macro_rules! endian_test {
        ($old_type:ty, $new_type:ty, $test_name:ident, $native:expr) => (
            mod $test_name {
                use super::*;

                #[test]
                fn align() {
                    assert_eq!(align_of::<$new_type>(), align_of::<$old_type>());
                }

                #[test]
                fn size() {
                    assert_eq!(size_of::<$new_type>(), size_of::<$old_type>());
                }

                #[allow(overflowing_literals)]
                #[test]
                fn equality() {
                    let v = 0x0123456789ABCDEF as $old_type;
                    let endian_v: $new_type = From::from(v);
                    let endian_into: $old_type = endian_v.into();
                    let endian_transmute: $old_type = unsafe { transmute(endian_v) };

                    if $native {
                        assert_eq!(endian_v, endian_transmute);
                    } else {
                        assert_eq!(endian_v, endian_transmute.swap_bytes());
                    }

                    assert_eq!(v, endian_into);
                    assert!(v == endian_v);
                    assert!(endian_v == v);
                }
            }
        )
    }

    endian_test!(u16, Le16, test_le16, NATIVE_LITTLE);
    endian_test!(u32, Le32, test_le32, NATIVE_LITTLE);
    endian_test!(u64, Le64, test_le64, NATIVE_LITTLE);
    endian_test!(usize, LeSize, test_le_size, NATIVE_LITTLE);
    endian_test!(u16, Be16, test_be16, NATIVE_BIG);
    endian_test!(u32, Be32, test_be32, NATIVE_BIG);
    endian_test!(u64, Be64, test_be64, NATIVE_BIG);
    endian_test!(usize, BeSize, test_be_size, NATIVE_BIG);
}
