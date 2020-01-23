// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Provides a wrapper for allocating, handling and interacting with the guest memory regions.

#![deny(missing_docs)]

extern crate libc;

mod bytes;
mod guest_address;
mod guest_memory;
mod mmap;

pub use bytes::{ByteValued, Bytes};
pub use guest_address::Address;
pub use guest_address::GuestAddress;
pub use guest_memory::Error as GuestMemoryError;
pub use guest_memory::GuestMemoryMmap;
pub use guest_memory::GuestMemoryRegion;
pub use guest_memory::MemoryRegion;
pub use mmap::{Error as MemoryMappingError, MemoryMapping};
