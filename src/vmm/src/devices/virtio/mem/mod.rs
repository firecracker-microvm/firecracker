// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
mod event_handler;
pub mod metrics;
pub mod persist;

use vm_memory::GuestAddress;

pub use self::device::{VirtioMem, VirtioMemError};

pub(crate) const MEM_NUM_QUEUES: usize = 1;

pub(crate) const MEM_QUEUE: usize = 0;

pub const VIRTIO_MEM_BLOCK_SIZE: usize = 2 << 20; // 2MiB
pub const VIRTIO_MEM_GUEST_ADDRESS: GuestAddress = GuestAddress(512 << 30); // 512GiB
