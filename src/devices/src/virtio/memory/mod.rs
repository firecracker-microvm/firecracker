// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

pub mod device;
pub mod event_handler;

pub use self::device::Memory;
pub use self::event_handler::*;

pub const QUEUE_SIZE: u16 = 256;
// the index of guest requests queue from Memory device queues/queues_evts vector.
pub const GUEST_REQUESTS_INDEX: usize = 0;
pub const CONFIG_SPACE_SIZE: usize = 56;

// The feature bitmap for virtio memory.
const _VIRTIO_MEM_F_ACPI_PXM: u32 = 0; // The node id is valid and corresponds to an ACPI PXM.
const _VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE: u32 = 1; // The driver is not allowed to access unplugged memory.

#[derive(Debug)]
pub enum Error {
    /// Start address already set
    AddressAlreadySet,
    /// Block Size is zero bytes.
    BlockSizeIsZero,
    /// Block Size not a multiple of page size.
    BlockSizeNotMultipleOfPageSize(u64),
    /// Block Size not a power of 2.
    BlockSizeNotPowerOf2,
    /// Device not activated yet.
    DeviceNotActive,
    /// No memory device found.
    DeviceNotFound,
    /// EventFd error.
    EventFd(std::io::Error),
    /// Quereying page size error.
    PageSize(utils::errno::Error),
    /// Size is not a multiple of Block Size.
    SizeNotMultipleOfBlockSize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use self::Error::*;
        match &self {
            AddressAlreadySet => write!(f, "Memory region start address is already set"),
            BlockSizeIsZero => write!(f, "Block size cannot be 0"),
            BlockSizeNotMultipleOfPageSize(size) => write!(
                f,
                "Block size must be a multiple of host page size: {:#x}",
                size
            ),
            BlockSizeNotPowerOf2 => write!(f, "Block size must be a power of 2"),
            DeviceNotActive => write!(f, "The device is not active"),
            DeviceNotFound => write!(f, "The device was not found. Check the device id"),
            EventFd(err) => write!(f, "EventFd error: {}", err),
            PageSize(err) => write!(f, "Cannot get host page size: {}", err),
            SizeNotMultipleOfBlockSize => write!(
                f,
                "Device memory region size is not a multiple of block size"
            ),
        }
    }
}

pub type MemoryResult<T> = std::result::Result<T, Error>;
