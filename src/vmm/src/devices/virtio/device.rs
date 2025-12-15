// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use vmm_sys_util::eventfd::EventFd;

use super::ActivateError;
use super::queue::{Queue, QueueError};
use super::transport::VirtioInterrupt;
use crate::devices::virtio::AsAny;
use crate::logger::warn;
use crate::vstate::memory::GuestMemoryMmap;

/// State of an active VirtIO device
#[derive(Debug, Clone)]
pub struct ActiveState {
    pub mem: GuestMemoryMmap,
    pub interrupt: Arc<dyn VirtioInterrupt>,
}

/// Enum that indicates if a VirtioDevice is inactive or has been activated
/// and memory attached to it.
#[derive(Debug)]
pub enum DeviceState {
    Inactive,
    Activated(ActiveState),
}

impl DeviceState {
    /// Checks if the device is activated.
    pub fn is_activated(&self) -> bool {
        match self {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }

    /// Gets the memory and interrupt attached to the device if it is activated.
    pub fn active_state(&self) -> Option<&ActiveState> {
        match self {
            DeviceState::Activated(state) => Some(state),
            DeviceState::Inactive => None,
        }
    }
}

/// Trait for virtio devices to be driven by a virtio transport.
///
/// The lifecycle of a virtio device is to be moved to a virtio transport, which will then query the
/// device. The virtio devices needs to create queues, events and event fds for interrupts and
/// expose them to the transport via get_queues/get_queue_events/get_interrupt/get_interrupt_status
/// fns.
pub trait VirtioDevice: AsAny + Send {
    /// Get the available features offered by device.
    fn avail_features(&self) -> u64;

    /// Get acknowledged features of the driver.
    fn acked_features(&self) -> u64;

    /// Set acknowledged features of the driver.
    /// This function must maintain the following invariant:
    /// - self.avail_features() & self.acked_features() = self.get_acked_features()
    fn set_acked_features(&mut self, acked_features: u64);

    /// Check if virtio device has negotiated given feature.
    fn has_feature(&self, feature: u64) -> bool {
        (self.acked_features() & (1 << feature)) != 0
    }

    /// The virtio device type (as a constant of the struct).
    fn const_device_type() -> u32
    where
        Self: Sized;

    /// The virtio device type.
    ///
    /// It should be the same as returned by Self::const_device_type().
    fn device_type(&self) -> u32;

    /// Returns the device queues.
    fn queues(&self) -> &[Queue];

    /// Returns a mutable reference to the device queues.
    fn queues_mut(&mut self) -> &mut [Queue];

    /// Returns the device queues event fds.
    fn queue_events(&self) -> &[EventFd];

    /// Returns the current device interrupt status.
    fn interrupt_status(&self) -> Arc<AtomicU32> {
        self.interrupt_trigger().status()
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt;

    /// The set of feature bits shifted by `page * 32`.
    fn avail_features_by_page(&self, page: u32) -> u32 {
        let avail_features = self.avail_features();
        match page {
            // Get the lower 32-bits of the features bitfield.
            0 => (avail_features & 0xFFFFFFFF) as u32,
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
            warn!("Received acknowledge request for unknown feature: {:#x}", v);
            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.set_acked_features(self.acked_features() | v);
    }

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, data: &mut [u8]);

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, offset: u64, data: &[u8]);

    /// Performs the formal activation for a device, which can be verified also with `is_activated`.
    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError>;

    /// Checks if the resources of this device are activated.
    fn is_activated(&self) -> bool;

    /// Optionally deactivates this device and returns ownership of the guest memory map, interrupt
    /// event, and queue events.
    fn reset(&mut self) -> Option<(Arc<dyn VirtioInterrupt>, Vec<EventFd>)> {
        None
    }

    /// Mark pages used by queues as dirty.
    fn mark_queue_memory_dirty(&mut self, mem: &GuestMemoryMmap) -> Result<(), QueueError> {
        for queue in self.queues_mut() {
            queue.initialize(mem)?
        }
        Ok(())
    }

    /// Kick the device, as if it had received external events.
    fn kick(&mut self) {}

    /// Prepare the device for saving its state
    fn prepare_save(&mut self) {}
}

impl fmt::Debug for dyn VirtioDevice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VirtioDevice type {}", self.device_type())
    }
}

/// Utility to define both const_device_type and device_type with a u32 constant
#[macro_export]
macro_rules! impl_device_type {
    ($const_type:expr) => {
        fn const_device_type() -> u32 {
            $const_type
        }

        fn device_type(&self) -> u32 {
            Self::const_device_type()
        }
    };
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockVirtioDevice {
        avail_features: u64,
        acked_features: u64,
    }

    impl VirtioDevice for MockVirtioDevice {
        impl_device_type!(0);

        fn avail_features(&self) -> u64 {
            self.avail_features
        }

        fn acked_features(&self) -> u64 {
            self.acked_features
        }

        fn set_acked_features(&mut self, acked_features: u64) {
            self.acked_features = acked_features
        }

        fn queues(&self) -> &[Queue] {
            todo!()
        }

        fn queues_mut(&mut self) -> &mut [Queue] {
            todo!()
        }

        fn queue_events(&self) -> &[EventFd] {
            todo!()
        }

        fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
            todo!()
        }

        fn read_config(&self, _offset: u64, _data: &mut [u8]) {
            todo!()
        }

        fn write_config(&mut self, _offset: u64, _data: &[u8]) {
            todo!()
        }

        fn activate(
            &mut self,
            _mem: GuestMemoryMmap,
            _interrupt: Arc<dyn VirtioInterrupt>,
        ) -> Result<(), ActivateError> {
            todo!()
        }

        fn is_activated(&self) -> bool {
            todo!()
        }
    }

    #[test]
    fn test_has_feature() {
        let mut device = MockVirtioDevice {
            avail_features: 0,
            acked_features: 0,
        };

        let mock_feature_1 = 1u64;
        assert!(!device.has_feature(mock_feature_1));
        device.acked_features = 1 << mock_feature_1;
        assert!(device.has_feature(mock_feature_1));

        let mock_feature_2 = 2u64;
        assert!(!device.has_feature(mock_feature_2));
        device.acked_features = (1 << mock_feature_1) | (1 << mock_feature_2);
        assert!(device.has_feature(mock_feature_1));
        assert!(device.has_feature(mock_feature_2));
    }

    #[test]
    fn test_features() {
        let features: u64 = 0x11223344_55667788;

        let mut device = MockVirtioDevice {
            avail_features: features,
            acked_features: 0,
        };

        assert_eq!(
            device.avail_features_by_page(0),
            (features & 0xFFFFFFFF) as u32,
        );
        assert_eq!(device.avail_features_by_page(1), (features >> 32) as u32);
        for i in 2..10 {
            assert_eq!(device.avail_features_by_page(i), 0u32);
        }

        for i in 0..10 {
            device.ack_features_by_page(i, u32::MAX);
        }

        assert_eq!(device.acked_features, features);
    }
}
