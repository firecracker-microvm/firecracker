// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Represents an address in the guest's memory space.

use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::ops::{Add, BitAnd, BitOr, Sub};

/// Simple helper trait used to store a raw address value.
pub trait AddressValue {
    /// Type of the address raw value.
    type V: Copy
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Add<Output = Self::V>
        + Sub<Output = Self::V>
        + BitAnd<Output = Self::V>
        + BitOr<Output = Self::V>;
}

/// Trait to represent an address within an address space.
///
/// To simplify the design and implementation, assume the same raw data type (AddressValue::V)
/// could be used to store address, size and offset for the address space. Thus the Address trait
/// could be used to manage address, size and offset. On the other hand, type aliases may be
/// defined to improve code readability.
///
/// One design rule is applied to the Address trait that operators (+, -, &, | etc) are not
/// supported and it forces clients to explicitly invoke corresponding methods. But there are
/// always exceptions:
///     Address (BitAnd|BitOr) AddressValue are supported.
pub trait Address:
    AddressValue
    + Sized
    + Default
    + Copy
    + Eq
    + PartialEq
    + Ord
    + PartialOrd
    + BitAnd<<Self as AddressValue>::V, Output = Self>
    + BitOr<<Self as AddressValue>::V, Output = Self>
{
    /// Get the raw value of the address.
    fn raw_value(&self) -> Self::V;

    /// Returns the offset from this address to the given base address.
    /// Only use this when `base` is guaranteed not to overflow.
    fn unchecked_offset_from(&self, base: Self) -> Self::V {
        self.raw_value() - base.raw_value()
    }

    /// Returns the result of the add or None if there is overflow.
    fn checked_add(&self, other: Self::V) -> Option<Self>;

    /// Returns the result of the base address + the size.
    /// Only use this when `offset` is guaranteed not to overflow.
    fn unchecked_add(&self, offset: Self::V) -> Self;

    /// Returns the result of the subtraction or None if there is underflow.
    fn checked_sub(&self, other: Self::V) -> Option<Self>;
}

/// Represents an Address in the guest's memory.
#[derive(Clone, Copy, Debug)]
pub struct GuestAddress(pub u64);

impl AddressValue for GuestAddress {
    type V = u64;
}

impl Address for GuestAddress {
    /// Returns the address as a `Self::V` offset from 0x0.
    /// Use this when a raw number is needed to pass to the kernel.
    fn raw_value(&self) -> Self::V {
        self.0
    }

    /// Returns the result of the add or None if there is overflow.
    fn checked_add(&self, other: Self::V) -> Option<GuestAddress> {
        self.0.checked_add(other).map(GuestAddress)
    }

    /// Returns the result of the base address + the size.
    /// Only use this when `offset` is guaranteed not to overflow.
    fn unchecked_add(&self, offset: Self::V) -> GuestAddress {
        GuestAddress(self.0 + offset)
    }

    /// Returns the result of the subtraction of None if there is underflow.
    fn checked_sub(&self, other: Self::V) -> Option<GuestAddress> {
        self.0.checked_sub(other).map(GuestAddress)
    }
}

impl Default for GuestAddress {
    fn default() -> GuestAddress {
        GuestAddress(0)
    }
}

impl BitAnd<<GuestAddress as AddressValue>::V> for GuestAddress {
    type Output = GuestAddress;

    fn bitand(self, other: <GuestAddress as AddressValue>::V) -> GuestAddress {
        GuestAddress(self.0 & other)
    }
}

impl BitOr<<GuestAddress as AddressValue>::V> for GuestAddress {
    type Output = GuestAddress;

    fn bitor(self, other: <GuestAddress as AddressValue>::V) -> GuestAddress {
        GuestAddress(self.0 | other)
    }
}

impl PartialEq for GuestAddress {
    fn eq(&self, other: &GuestAddress) -> bool {
        self.0 == other.0
    }
}
impl Eq for GuestAddress {}

impl Ord for GuestAddress {
    fn cmp(&self, other: &GuestAddress) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for GuestAddress {
    fn partial_cmp(&self, other: &GuestAddress) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equals() {
        let a = GuestAddress(0x300);
        let b = GuestAddress(0x300);
        let c = GuestAddress(0x301);
        assert_eq!(a, GuestAddress(a.raw_value()));
        assert_eq!(a, b);
        assert_eq!(b, a);
        assert_ne!(a, c);
        assert_ne!(c, a);
    }

    #[test]
    fn test_cmp() {
        for i in 1..10 {
            for j in 1..10 {
                assert_eq!(i < j, GuestAddress(i) < GuestAddress(j));
                assert_eq!(i > j, GuestAddress(i) > GuestAddress(j));
            }
        }
    }

    #[test]
    fn test_add_sub() {
        let a = GuestAddress(0x50);
        let b = GuestAddress(0x60);
        assert_eq!(Some(GuestAddress(0xb0)), a.checked_add(0x60));
        assert_eq!(0x10, b.unchecked_offset_from(a));
    }

    #[test]
    fn test_checked_add_with_overflow() {
        let a = GuestAddress(0xffff_ffff_ffff_ff55);
        assert_eq!(Some(GuestAddress(0xffff_ffff_ffff_ff57)), a.checked_add(2));
        assert!(a.checked_add(0xf0).is_none());
    }

    #[test]
    fn test_checked_sub_with_underflow() {
        let a = GuestAddress(0xff);
        assert_eq!(Some(GuestAddress(0x0f)), a.checked_sub(0xf0));
        assert!(a.checked_sub(0xffff).is_none());
    }

    #[test]
    fn test_default() {
        assert_eq!(GuestAddress::default(), GuestAddress(0));
    }

    #[test]
    fn test_bit_and() {
        let a = GuestAddress(0x00);
        let b = GuestAddress(0xff);
        assert_eq!(a & b.raw_value(), a);
    }

    #[test]
    fn test_bit_or() {
        let a = GuestAddress(0x00);
        let b = GuestAddress(0xff);
        assert_eq!(a | b.raw_value(), b);
    }
}
