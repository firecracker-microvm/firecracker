// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Types for which it is safe to initialize from raw data.
///
/// A type `T` is `DataInit` if and only if it can be initialized by reading its contents from a
/// byte array.  This is generally true for all plain-old-data structs.  It is notably not true for
/// any type that includes a reference.
///
/// Implementing this trait guarantees that it is safe to instantiate the struct with random data.
pub unsafe trait DataInit: Copy + Send + Sync {}

// All intrinsic types and arays of intrinsic types are DataInit.  They are just numbers.
macro_rules! array_data_init {
    ($T:ty, $($N:expr)+) => {
        $(
            unsafe impl DataInit for [$T; $N] {}
        )+
    }
}
macro_rules! data_init_type {
    ($T:ty) => {
        unsafe impl DataInit for $T {}
        array_data_init! {
            $T,
            0  1  2  3  4  5  6  7  8  9
            10 11 12 13 14 15 16 17 18 19
            20 21 22 23 24 25 26 27 28 29
            30 31 32
        }
    }
}
data_init_type!(u8);
data_init_type!(u16);
data_init_type!(u32);
data_init_type!(u64);
data_init_type!(usize);
data_init_type!(i8);
data_init_type!(i16);
data_init_type!(i32);
data_init_type!(i64);
data_init_type!(isize);

pub mod endian;
pub use endian::*;

pub mod volatile_memory;
pub use volatile_memory::*;
