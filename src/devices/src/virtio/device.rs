// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::sync::{atomic::AtomicUsize, Arc};

use super::{ActivateResult, Queue};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. The virtio devices needs to create queues, events and event fds for interrupts and expose
/// them to the transport via get_queues/get_queue_events/get_interrupt/get_interrupt_status fns.
pub trait VirtioDevice: Send {
    /// Get the available features offered by device.
    fn avail_features(&self) -> u64;

    /// Get acknowledged features of the driver.
    fn acked_features(&self) -> u64;

    /// Set acknowledged features of the driver.
    /// This function must maintain the following invariant:
    /// - self.avail_features() & self.acked_features() = self.get_acked_features()
    fn set_acked_features(&mut self, acked_features: u64);

    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// Returns the device queues.
    fn get_queues(&mut self) -> &mut Vec<Queue>;

    /// Returns the device queues event fds.
    fn get_queue_events(&self) -> Result<Vec<EventFd>, std::io::Error>;

    /// Returns the device interrupt eventfd.
    fn get_interrupt(&self) -> Result<EventFd, std::io::Error>;

    /// Returns the current device interrupt status.
    fn get_interrupt_status(&self) -> Arc<AtomicUsize>;

    /// The set of feature bits shifted by `page * 32`.
    fn avail_features_by_page(&self, page: u32) -> u32 {
        let avail_features = self.avail_features();
        match page {
            // Get the lower 32-bits of the features bitfield.
            0 => avail_features as u32,
            // Get the upper 32-bits of the features bitfield.
            1 => (avail_features >> 32) as u32,
            _ => {
                warn!("Received request for unknown features page.");
                0u32
            }
        }
    }

    /// Acknowledges that this set of features should be enabled.
    fn ack_features_by_page(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => u64::from(value),
            1 => u64::from(value) << 32,
            _ => {
                warn!("Cannot acknowledge unknown features page: {}", page);
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let avail_features = self.avail_features();
        let unrequested_features = v & !avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature: {:x}", v);
            // Don't count these features as acked.
            v &= !unrequested_features;
        }

        self.set_acked_features(self.acked_features() | v);
    }

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, offset: u64, data: &[u8]);

    /// Activates this device for real usage.
    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult;

    /// Optionally deactivates this device and returns ownership of the guest memory map, interrupt
    /// event, and queue events.
    fn reset(&mut self) -> Option<(EventFd, Vec<EventFd>)> {
        None
    }
}
