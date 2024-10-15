// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
#![deny(missing_docs)]

//! Manages system resources that can be allocated to VMs and their devices.

mod address;
mod gsi;
/// page size related utility functions
pub mod page_size;
mod system;

pub use crate::address::AddressAllocator;
pub use crate::gsi::GsiAllocator;
#[cfg(target_arch = "x86_64")]
pub use crate::gsi::GsiApic;
pub use crate::system::SystemAllocator;
