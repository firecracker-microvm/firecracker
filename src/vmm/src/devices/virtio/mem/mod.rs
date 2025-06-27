// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
mod event_handler;
pub mod metrics;
pub mod persist;

pub use self::device::{VirtioMem, VirtioMemError};

pub(crate) const MEM_NUM_QUEUES: usize = 1;

pub(crate) const MEM_QUEUE: usize = 0;
