// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#[cfg(target_arch = "x86_64")]
use self::legacy::PortIODeviceManager;
use self::mmio::MMIODeviceManager;

/// Legacy Device Manager.
pub mod legacy;
/// Memory Mapped I/O Manager.
pub mod mmio;
/// Device managers (de)serialization support.
pub mod persist;

#[derive(Debug)]
pub struct DeviceManager {
    pub mmio_devices: MMIODeviceManager,
    #[cfg(target_arch = "x86_64")]
    pub pio_diveces: PortIODeviceManager,
}
