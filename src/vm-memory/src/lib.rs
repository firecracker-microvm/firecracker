// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! This is a "proxy" crate for Firecracker. It links to upstream vm-memory implementation
//! and re-exports symbols for consumption.
//! This crate implements a custom vm-memory backend implementation that overrides the
//! upstream implementation and adds dirty page tracking functionality.
pub mod bitmap;
pub mod mmap;

// Export local backend implementation.
pub use mmap::{GuestMemoryMmap, GuestRegionMmap};

// Re-export only what is needed in Firecracker.
pub use vm_memory_upstream::{
    address, Address, ByteValued, Bytes, Error, FileOffset, GuestAddress, GuestMemory,
    GuestMemoryError, GuestMemoryRegion, MemoryRegionAddress, MmapRegion,
};
