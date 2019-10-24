// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Represents an address in the guest's memory space.

use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::ops::{BitAnd, BitOr};

/// Represents an Address in the guest's memory.
#[derive(Clone, Copy, Debug)]
pub struct GuestAddress(pub usize);

impl GuestAddress {
    /// Returns the offset from this address to the given base address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use memory_model::GuestAddress;
    ///   let base = GuestAddress(0x100);
    ///   let addr = GuestAddress(0x150);
    ///   assert_eq!(addr.offset_from(base), 0x50usize);
    /// ```
    pub fn offset_from(self, base: GuestAddress) -> usize {
        self.0 - base.0
    }

    /// Returns the address as a usize offset from 0x0.
    /// Use this when a raw number is needed to pass to the kernel.
    pub fn raw_value(self) -> usize {
        self.0
    }

    /// Returns the result of the add or None if there is overflow.
    pub fn checked_add(self, other: usize) -> Option<GuestAddress> {
        self.0.checked_add(other).map(GuestAddress)
    }

    /// Returns the result of the base address + the size.
    /// Only use this when `offset` is guaranteed not to overflow.
    pub fn unchecked_add(self, offset: usize) -> GuestAddress {
        GuestAddress(self.0 + offset)
    }

    /// Returns the result of the subtraction of None if there is underflow.
    pub fn checked_sub(self, other: usize) -> Option<GuestAddress> {
        self.0.checked_sub(other).map(GuestAddress)
    }

    /// Returns the bitwise and of the address with the given mask.
    pub fn mask(self, mask: u64) -> GuestAddress {
        GuestAddress(self.0 & mask as usize)
    }
}

impl BitAnd<u64> for GuestAddress {
    type Output = GuestAddress;

    fn bitand(self, other: u64) -> GuestAddress {
        GuestAddress(self.0 & other as usize)
    }
}

impl BitOr<u64> for GuestAddress {
    type Output = GuestAddress;

    fn bitor(self, other: u64) -> GuestAddress {
        GuestAddress(self.0 | other as usize)
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
    fn equals() {
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
    fn cmp() {
        for i in 1..10 {
            for j in 1..10 {
                assert_eq!(i < j, GuestAddress(i) < GuestAddress(j));
                assert_eq!(i > j, GuestAddress(i) > GuestAddress(j));
            }
        }
    }

    #[test]
    fn mask() {
        let a = GuestAddress(0x5050);
        assert_eq!(GuestAddress(0x5000), a & 0xff00u64);
        assert_eq!(GuestAddress(0x5000), a.mask(0xff00u64));
        assert_eq!(GuestAddress(0x5055), a | 0x0005u64);
    }

    #[test]
    fn add_sub() {
        let a = GuestAddress(0x50);
        let b = GuestAddress(0x60);
        assert_eq!(Some(GuestAddress(0xb0)), a.checked_add(0x60));
        assert_eq!(0x10, b.offset_from(a));
    }

    #[test]
    fn checked_add_overflow() {
        let a = GuestAddress(0xffff_ffff_ffff_ff55);
        assert_eq!(Some(GuestAddress(0xffff_ffff_ffff_ff57)), a.checked_add(2));
        assert!(a.checked_add(0xf0).is_none());
    }

    #[test]
    fn checked_sub_underflow() {
        let a = GuestAddress(0xff);
        assert_eq!(Some(GuestAddress(0x0f)), a.checked_sub(0xf0));
        assert!(a.checked_sub(0xffff).is_none());
    }
}
