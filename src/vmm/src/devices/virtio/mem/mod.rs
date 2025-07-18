// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
mod event_handler;
pub mod metrics;
pub mod persist;
pub mod request;
pub mod response;

use vm_memory::GuestAddress;

pub use self::device::{VirtioMem, VirtioMemError};
use crate::arch::FIRST_ADDR_PAST_64BITS_MMIO;

pub(crate) const MEM_NUM_QUEUES: usize = 1;

pub(crate) const MEM_QUEUE: usize = 0;

pub const VIRTIO_MEM_BLOCK_SIZE: usize = 2 << 20; // 2MiB
pub const VIRTIO_MEM_REGION_SIZE: usize = 128 << 20; // 128 MiB
pub const VIRTIO_MEM_GUEST_ADDRESS: GuestAddress = GuestAddress(FIRST_ADDR_PAST_64BITS_MMIO); // 512GiB
