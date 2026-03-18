// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod common_config;
pub mod device;

/// Virtio device status field values
/// https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-110001
///
/// These are u8 because the PCI transport's device_status register is 8 bits wide.
/// https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-1420003
pub(crate) mod device_status {
    pub const INIT: u8 = 0x00;
    pub const ACKNOWLEDGE: u8 = 0x01;
    pub const DRIVER: u8 = 0x02;
    pub const DRIVER_OK: u8 = 0x04;
    pub const FEATURES_OK: u8 = 0x08;
    pub const FAILED: u8 = 0x80;
}
