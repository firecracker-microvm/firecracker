// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

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
    /// Activation error.
    Activate(super::ActivateError),
    /// Start address already set
    AddressAlreadySet,
    /// Block Size is zero bytes.
    BlockSizeIsZero,
    /// Block Size not alligned to page size.
    BlockSizeNotAllignedToPage,
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
