// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements virtio devices, queues, and transport mechanisms.
use std;
use sys_util::Error as SysError;
use std::io::Error as IOError;

pub mod block;
mod mmio;
pub mod net;
mod queue;

pub use self::block::*;
pub use self::mmio::*;
pub use self::net::*;
pub use self::queue::*;

const DEVICE_ACKNOWLEDGE: u32 = 0x01;
const DEVICE_DRIVER: u32 = 0x02;
const DEVICE_DRIVER_OK: u32 = 0x04;
const DEVICE_FEATURES_OK: u32 = 0x08;
const DEVICE_FAILED: u32 = 0x80;

/// Types taken from linux/virtio_ids.h.
const TYPE_NET: u32 = 1;
const TYPE_BLOCK: u32 = 2;

/// Interrupt flags (re: interrupt status & acknowledge registers).
/// See linux/virtio_mmio.h.
pub const VIRTIO_MMIO_INT_VRING: u32 = 0x01;
pub const VIRTIO_MMIO_INT_CONFIG: u32 = 0x02;

/// Offset from the base MMIO address of a virtio device used by the guest to notify the device of
/// queue events.
pub const NOTIFY_REG_OFFSET: u32 = 0x50;

#[derive(Debug)]
pub enum ActivateError {
    EventFd(SysError),
    TryClone(SysError),
    EpollCtl(IOError),
    BadActivate,
}

pub type ActivateResult = std::result::Result<(), ActivateError>;
