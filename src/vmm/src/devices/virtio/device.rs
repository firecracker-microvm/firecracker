// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt;
#[cfg(target_arch = "riscv64")]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use vmm_sys_util::eventfd::EventFd;
#[cfg(target_arch = "riscv64")]
use vmm_sys_util::{errno, ioctl::ioctl_with_ref, ioctl_ioc_nr, ioctl_iow_nr};

use super::ActivateError;
use super::mmio::{VIRTIO_MMIO_INT_CONFIG, VIRTIO_MMIO_INT_VRING};
use super::queue::{Queue, QueueError};
use crate::devices::virtio::AsAny;
use crate::logger::{error, warn};
use crate::vstate::memory::GuestMemoryMmap;

/// Enum that indicates if a VirtioDevice is inactive or has been activated
/// and memory attached to it.
#[derive(Debug)]
pub enum DeviceState {
    Inactive,
    Activated(GuestMemoryMmap),
}

impl DeviceState {
    /// Checks if the device is activated.
    pub fn is_activated(&self) -> bool {
        match self {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }

    /// Gets the memory attached to the device if it is activated.
    pub fn mem(&self) -> Option<&GuestMemoryMmap> {
        match self {
            DeviceState::Activated(mem) => Some(mem),
            DeviceState::Inactive => None,
        }
    }
}

/// The 2 types of interrupt sources in MMIO transport.
#[derive(Debug)]
pub enum IrqType {
    /// Interrupt triggered by change in config.
    Config,
    /// Interrupt triggered by used vring buffers.
    Vring,
}

/// Helper struct that is responsible for triggering guest IRQs
#[derive(Debug)]
pub struct IrqTrigger {
    pub(crate) irq_status: Arc<AtomicU32>,
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(crate) irq_evt: EventFd,
    #[cfg(target_arch = "riscv64")]
    pub(crate) raw_vmfd: Option<i32>,
    #[cfg(target_arch = "riscv64")]
    pub(crate) gsi: Option<u32>,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl IrqTrigger {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            irq_status: Arc::new(AtomicU32::new(0)),
            irq_evt: EventFd::new(libc::EFD_NONBLOCK)?,
        })
    }

    pub fn trigger_irq(&self, irq_type: IrqType) -> Result<(), std::io::Error> {
        let irq = match irq_type {
            IrqType::Config => VIRTIO_MMIO_INT_CONFIG,
            IrqType::Vring => VIRTIO_MMIO_INT_VRING,
        };
        self.irq_status.fetch_or(irq, Ordering::SeqCst);

        self.irq_evt.write(1).map_err(|err| {
            error!("Failed to send irq to the guest: {:?}", err);
            err
        })?;

        Ok(())
    }
}

#[cfg(target_arch = "riscv64")]
impl IrqTrigger {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            irq_status: Arc::new(AtomicU32::new(0)),
            raw_vmfd: None,
            gsi: None,
        })
    }

    pub fn trigger_irq(&self, irq_type: IrqType) -> Result<(), std::io::Error> {
        let irq = match irq_type {
            IrqType::Config => VIRTIO_MMIO_INT_CONFIG,
            IrqType::Vring => VIRTIO_MMIO_INT_VRING,
        };
        self.irq_status.fetch_or(irq, Ordering::SeqCst);

        // Safe to unwrap since `gsi` and `vmfd` have been set
        let gsi = self.gsi.unwrap();
        IrqTrigger::set_irq_line(self.raw_vmfd.unwrap(), gsi, true).map_err(|err| {
            error!("Failed to set IRQ line: {:?}", err);
            std::io::Error::last_os_error()
        })?;
        IrqTrigger::set_irq_line(self.raw_vmfd.unwrap(), gsi, false).map_err(|err| {
            error!("Failed to set IRQ line: {:?}", err);
            std::io::Error::last_os_error()
        })?;

        Ok(())
    }

    pub fn set_vmfd_and_gsi(&mut self, raw_vmfd: i32, gsi: u32) {
        self.raw_vmfd = Some(raw_vmfd);
        self.gsi = Some(gsi);
    }

    // This function is taken from kvm-ioctls because it requires VmFd, which we don't
    // have at this point. However, it only uses the raw file descriptor, which is just
    // an i32. So, we copy it here and use it directly with the raw fd.
    fn set_irq_line<F: AsRawFd>(fd: F, irq: u32, active: bool) -> Result<(), kvm_ioctls::Error> {
        let mut irq_level = kvm_bindings::kvm_irq_level::default();
        irq_level.__bindgen_anon_1.irq = irq;
        irq_level.level = u32::from(active);

        // SAFETY: Safe because we know that our file is a VM fd, we know the kernel will only read
        // the correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(&fd, IrqTrigger::KVM_IRQ_LINE(), &irq_level) };
        if ret == 0 {
            Ok(())
        } else {
            Err(errno::Error::last())
        }
    }

    ioctl_iow_nr!(
        KVM_IRQ_LINE,
        kvm_bindings::KVMIO,
        0x61,
        kvm_bindings::kvm_irq_level
    );
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

    /// The virtio device type.
    fn device_type(&self) -> u32;

    /// Returns the device queues.
    fn queues(&self) -> &[Queue];

    /// Returns a mutable reference to the device queues.
    fn queues_mut(&mut self) -> &mut [Queue];

    /// Returns the device queues event fds.
    fn queue_events(&self) -> &[EventFd];

    /// Returns the current device interrupt status.
    fn interrupt_status(&self) -> Arc<AtomicU32> {
        Arc::clone(&self.interrupt_trigger().irq_status)
    }

    fn interrupt_trigger(&self) -> &IrqTrigger;

    #[cfg(target_arch = "riscv64")]
    fn interrupt_trigger_mut(&mut self) -> &mut IrqTrigger;

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
    fn activate(&mut self, mem: GuestMemoryMmap) -> Result<(), ActivateError>;

    /// Checks if the resources of this device are activated.
    fn is_activated(&self) -> bool;

    /// Optionally deactivates this device and returns ownership of the guest memory map, interrupt
    /// event, and queue events.
    fn reset(&mut self) -> Option<(EventFd, Vec<EventFd>)> {
        None
    }

    /// Mark pages used by queues as dirty.
    fn mark_queue_memory_dirty(&self, mem: &GuestMemoryMmap) -> Result<(), QueueError> {
        for queue in self.queues() {
            queue.mark_memory_dirty(mem)?
        }
        Ok(())
    }
}

impl fmt::Debug for dyn VirtioDevice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "VirtioDevice type {}", self.device_type())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    impl IrqTrigger {
        pub fn has_pending_irq(&self, irq_type: IrqType) -> bool {
            if let Ok(num_irqs) = self.irq_evt.read() {
                if num_irqs == 0 {
                    return false;
                }

                let irq_status = self.irq_status.load(Ordering::SeqCst);
                return matches!(
                    (irq_status, irq_type),
                    (VIRTIO_MMIO_INT_CONFIG, IrqType::Config)
                        | (VIRTIO_MMIO_INT_VRING, IrqType::Vring)
                );
            }

            false
        }
    }

    #[test]
    fn irq_trigger() {
        let irq_trigger = IrqTrigger::new().unwrap();
        assert_eq!(irq_trigger.irq_status.load(Ordering::SeqCst), 0);

        // Check that there are no pending irqs.
        assert!(!irq_trigger.has_pending_irq(IrqType::Config));
        assert!(!irq_trigger.has_pending_irq(IrqType::Vring));

        // Check that trigger_irq() correctly generates irqs.
        irq_trigger.trigger_irq(IrqType::Config).unwrap();
        assert!(irq_trigger.has_pending_irq(IrqType::Config));
        irq_trigger.irq_status.store(0, Ordering::SeqCst);
        irq_trigger.trigger_irq(IrqType::Vring).unwrap();
        assert!(irq_trigger.has_pending_irq(IrqType::Vring));

        // Check trigger_irq() failure case (irq_evt is full).
        irq_trigger.irq_evt.write(u64::MAX - 1).unwrap();
        irq_trigger.trigger_irq(IrqType::Config).unwrap_err();
        irq_trigger.trigger_irq(IrqType::Vring).unwrap_err();
    }

    #[derive(Debug)]
    struct MockVirtioDevice {
        acked_features: u64,
    }

    impl VirtioDevice for MockVirtioDevice {
        fn avail_features(&self) -> u64 {
            todo!()
        }

        fn acked_features(&self) -> u64 {
            self.acked_features
        }

        fn set_acked_features(&mut self, _acked_features: u64) {
            todo!()
        }

        fn device_type(&self) -> u32 {
            todo!()
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

        fn interrupt_trigger(&self) -> &IrqTrigger {
            todo!()
        }

        fn read_config(&self, _offset: u64, _data: &mut [u8]) {
            todo!()
        }

        fn write_config(&mut self, _offset: u64, _data: &[u8]) {
            todo!()
        }

        fn activate(&mut self, _mem: GuestMemoryMmap) -> Result<(), ActivateError> {
            todo!()
        }

        fn is_activated(&self) -> bool {
            todo!()
        }
    }

    #[test]
    fn test_has_feature() {
        let mut device = MockVirtioDevice { acked_features: 0 };

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
}
