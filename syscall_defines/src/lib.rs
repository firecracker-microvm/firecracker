// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(target_arch = "x86_64")]
#[path = "linux-x86_64/mod.rs"]
pub mod linux;

#[cfg(target_arch = "x86")]
#[path = "linux-x86/mod.rs"]
pub mod linux;

#[cfg(target_arch = "aarch64")]
#[path = "linux-aarch64/mod.rs"]
pub mod linux;

#[cfg(target_arch = "arm")]
#[path = "linux-arm/mod.rs"]
pub mod linux;
