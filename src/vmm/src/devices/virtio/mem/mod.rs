// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod device;
mod event_handler;

use vm_memory::GuestAddress;

pub use self::device::{VirtioMem, VirtioMemError, VirtioMemStatus};
use crate::arch::FIRST_ADDR_PAST_64BITS_MMIO;

pub(crate) const MEM_NUM_QUEUES: usize = 1;

pub(crate) const MEM_QUEUE: usize = 0;

pub const VIRTIO_MEM_DEFAULT_BLOCK_SIZE: usize = 2 << 20; // 2MiB
pub const VIRTIO_MEM_DEFAULT_SLOT_SIZE: usize = 128 << 20; // 128 MiB

pub const VIRTIO_MEM_DEV_ID: &str = "mem";
