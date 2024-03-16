// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#[cfg(target_arch = "x86_64")]
use self::legacy::PortIODeviceManager;
use self::mmio::persist::{DevicePersistError, DeviceStates, MMIODevManagerConstructorArgs};
use self::mmio::MMIODeviceManager;
use crate::snapshot::Persist;

/// Legacy Device Manager.
pub mod legacy;
/// Memory Mapped I/O Manager.
pub mod mmio;

#[derive(Debug)]
pub struct DeviceManager {
    pub mmio_devices: MMIODeviceManager,
    #[cfg(target_arch = "x86_64")]
    pub pio_diveces: PortIODeviceManager,
}

impl DeviceManager {
    pub fn save(&self) -> DeviceStates {
        self.mmio_devices.save()
    }

    pub fn restore(
        &mut self,
        constructor_args: MMIODevManagerConstructorArgs,
        state: &DeviceStates,
    ) -> Result<(), DevicePersistError> {
        self.mmio_devices = MMIODeviceManager::restore(constructor_args, state)?;
        Ok(())
    }
}
