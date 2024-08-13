// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Implements virtio devices, queues, and transport mechanisms.

use std::any::Any;

use crate::devices::virtio::net::TapError;

pub mod balloon;
pub mod block;
pub mod device;
pub mod gen;
pub mod iovec;
pub mod mmio;
pub mod net;
pub mod persist;
pub mod queue;
pub mod rng;
pub mod test_utils;
pub mod vhost_user;
pub mod vhost_user_metrics;
pub mod vsock;

/// When the driver initializes the device, it lets the device know about the
/// completed stages using the Device Status Field.
///
/// These following consts are defined in the order in which the bits would
/// typically be set by the driver. INIT -> ACKNOWLEDGE -> DRIVER and so on.
///
/// This module is a 1:1 mapping for the Device Status Field in the virtio 1.0
/// specification, section 2.1.
mod device_status {
    pub const INIT: u32 = 0;
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const FAILED: u32 = 128;
    pub const FEATURES_OK: u32 = 8;
    pub const DRIVER_OK: u32 = 4;
    pub const DEVICE_NEEDS_RESET: u32 = 64;
}

/// Types taken from linux/virtio_ids.h.
/// Type 0 is not used by virtio. Use it as wildcard for non-virtio devices
/// Virtio net device ID.
pub const TYPE_NET: u32 = 1;
/// Virtio block device ID.
pub const TYPE_BLOCK: u32 = 2;
/// Virtio rng device ID.
pub const TYPE_RNG: u32 = 4;
/// Virtio balloon device ID.
pub const TYPE_BALLOON: u32 = 5;

/// Offset from the base MMIO address of a virtio device used by the guest to notify the device of
/// queue events.
pub const NOTIFY_REG_OFFSET: u32 = 0x50;

/// Errors triggered when activating a VirtioDevice.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ActivateError {
    /// Wrong number of queue for virtio device: expected {expected}, got {got}
    QueueMismatch { expected: usize, got: usize },
    /// Failed to write to activate eventfd
    EventFd,
    /// Vhost user: {0}
    VhostUser(vhost_user::VhostUserError),
    /// Setting tap interface offload flags failed: {0}
    TapSetOffload(TapError),
}

/// Trait that helps in upcasting an object to Any
pub trait AsAny {
    /// Return the immutable any encapsulated object.
    fn as_any(&self) -> &dyn Any;

    /// Return the mutable encapsulated any object.
    fn as_mut_any(&mut self) -> &mut dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}
