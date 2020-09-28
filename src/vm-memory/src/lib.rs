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
mod bitmap;
mod mmap;

pub use mmap::{GuestMemoryMmap, GuestRegionMmap};
// TODO: re-export things from upstream so we don't need to import both this crate and the real
// vm-memory locally and consume the wrong `GuestMemoryMmap`.
