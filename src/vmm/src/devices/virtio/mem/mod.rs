// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
mod event_handler;
pub mod metrics;
pub mod persist;
mod request;

use vm_memory::GuestAddress;

pub use self::device::{VirtioMem, VirtioMemError, VirtioMemStatus};
use crate::arch::FIRST_ADDR_PAST_64BITS_MMIO;

pub(crate) const MEM_NUM_QUEUES: usize = 1;

pub(crate) const MEM_QUEUE: usize = 0;

pub const VIRTIO_MEM_DEFAULT_BLOCK_SIZE_MIB: usize = 2;
pub const VIRTIO_MEM_DEFAULT_SLOT_SIZE_MIB: usize = 128;

pub const VIRTIO_MEM_DEV_ID: &str = "mem";
