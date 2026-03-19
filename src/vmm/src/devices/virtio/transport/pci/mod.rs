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
    pub const DEVICE_NEEDS_RESET: u8 = 0x40;
    pub const FAILED: u8 = 0x80;
}

/// Virtio PCI common configuration register offsets
/// https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-1420003
/// ```c
/// struct virtio_pci_common_config {
///         /* About the whole device. */
///         le32 device_feature_select;     /* read-write */
///         le32 device_feature;            /* read-only for driver */
///         le32 driver_feature_select;     /* read-write */
///         le32 driver_feature;            /* read-write */
///         le16 msix_config;               /* read-write */
///         le16 num_queues;                /* read-only for driver */
///         u8 device_status;               /* read-write */
///         u8 config_generation;           /* read-only for driver */
///
///         /* About a specific virtqueue. */
///         le16 queue_select;              /* read-write */
///         le16 queue_size;                /* read-write, power of 2, or 0. */
///         le16 queue_msix_vector;         /* read-write */
///         le16 queue_enable;              /* read-write */
///         le16 queue_notify_off;          /* read-only for driver */
///         le64 queue_desc;                /* read-write */
///         le64 queue_avail;               /* read-write */
///         le64 queue_used;                /* read-write */
/// };
/// ```
pub(crate) mod common_config_offset {
    pub const DEVICE_FEATURE_SELECT: u64 = 0x00;
    pub const DEVICE_FEATURE: u64 = 0x04;
    pub const DRIVER_FEATURE_SELECT: u64 = 0x08;
    pub const DRIVER_FEATURE: u64 = 0x0c;
    pub const MSIX_CONFIG: u64 = 0x10;
    pub const NUM_QUEUES: u64 = 0x12;
    pub const DEVICE_STATUS: u64 = 0x14;
    pub const CONFIG_GENERATION: u64 = 0x15;

    pub const QUEUE_SELECT: u64 = 0x16;
    pub const QUEUE_SIZE: u64 = 0x18;
    pub const QUEUE_MSIX_VECTOR: u64 = 0x1a;
    pub const QUEUE_ENABLE: u64 = 0x1c;
    pub const QUEUE_NOTIFY_OFF: u64 = 0x1e;
    pub const QUEUE_DESC_LO: u64 = 0x20;
    pub const QUEUE_DESC_HI: u64 = 0x24;
    pub const QUEUE_AVAIL_LO: u64 = 0x28;
    pub const QUEUE_AVAIL_HI: u64 = 0x2c;
    pub const QUEUE_USED_LO: u64 = 0x30;
    pub const QUEUE_USED_HI: u64 = 0x34;
}
