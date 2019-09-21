// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Implements virtio devices, queues, and transport mechanisms.
use std;
use std::any::Any;
use std::io::Error as IOError;
use std::os::unix::io::RawFd;
use std::sync::mpsc;

pub mod block;
mod mmio;
pub mod net;
mod queue;
pub mod vsock;

pub use self::block::*;
pub use self::mmio::*;
pub use self::net::*;
pub use self::queue::*;
pub use self::vsock::*;

use super::EpollHandler;

const DEVICE_INIT: u32 = 0x0;
const DEVICE_ACKNOWLEDGE: u32 = 0x01;
const DEVICE_DRIVER: u32 = 0x02;
const DEVICE_DRIVER_OK: u32 = 0x04;
const DEVICE_FEATURES_OK: u32 = 0x08;
const DEVICE_FAILED: u32 = 0x80;

/// Types taken from linux/virtio_ids.h.
/// Type 0 is not used by virtio. Use it as wildcard for non-virtio devices
pub const TYPE_NET: u32 = 1;
pub const TYPE_BLOCK: u32 = 2;

/// Interrupt flags (re: interrupt status & acknowledge registers).
/// See linux/virtio_mmio.h.
pub const VIRTIO_MMIO_INT_VRING: u32 = 0x01;
pub const VIRTIO_MMIO_INT_CONFIG: u32 = 0x02;

/// Offset from the base MMIO address of a virtio device used by the guest to notify the device of
/// queue events.
pub const NOTIFY_REG_OFFSET: u32 = 0x50;

#[derive(Debug)]
pub enum ActivateError {
    EpollCtl(IOError),
    BadActivate,
}

pub type ActivateResult = std::result::Result<(), ActivateError>;

pub trait EpollConfigConstructor {
    fn new(first_token: u64, epoll_raw_fd: RawFd, sender: mpsc::Sender<Box<EpollHandler>>) -> Self;
}

/// Trait that helps in upcasting an object to Any
pub trait AsAny {
    fn as_any(&self) -> &Any;

    fn as_mut_any(&mut self) -> &mut Any;
}
impl<T: Any> AsAny for T {
    fn as_any(&self) -> &Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut Any {
        self
    }
}
