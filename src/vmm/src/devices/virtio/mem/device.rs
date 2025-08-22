// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use log::info;
use serde::{Deserialize, Serialize};
use vm_memory::{
    Address, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryRegion, GuestUsize,
};
use vmm_sys_util::eventfd::EventFd;

use super::{MEM_NUM_QUEUES, MEM_QUEUE};
use crate::devices::DeviceError;
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ids::VIRTIO_ID_MEM;
use crate::devices::virtio::generated::virtio_mem::{
    VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE, virtio_mem_config,
};
use crate::devices::virtio::iov_deque::IovDequeError;
use crate::devices::virtio::mem::{VIRTIO_MEM_DEV_ID, VIRTIO_MEM_GUEST_ADDRESS};
use crate::devices::virtio::queue::{FIRECRACKER_MAX_QUEUE_SIZE, InvalidAvailIdx, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::logger::{IncMetric, debug, error};
use crate::utils::{bytes_to_mib, mib_to_bytes, u64_to_usize, usize_to_u64};
use crate::vstate::interrupts::InterruptError;
use crate::vstate::memory::{ByteValued, GuestMemoryMmap, GuestRegionMmap};
use crate::vstate::vm::VmError;
use crate::{Vm, impl_device_type};

// SAFETY: virtio_mem_config only contains plain data types
unsafe impl ByteValued for virtio_mem_config {}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VirtioMemError {
    /// Error while handling an Event file descriptor: {0}
    EventFd(#[from] io::Error),
    /// Received error while sending an interrupt: {0}
    InterruptError(#[from] InterruptError),
}

#[derive(Debug)]
pub struct VirtioMem {
    // VirtIO fields
    avail_features: u64,
    acked_features: u64,
    activate_event: EventFd,

    // Transport fields
    device_state: DeviceState,
    pub(crate) queues: Vec<Queue>,
    queue_events: Vec<EventFd>,

    // Device specific fields
    pub(crate) config: virtio_mem_config,
    pub(crate) slot_size: usize,
    vm: Arc<Vm>,
}

/// Memory hotplug device status information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VirtioMemStatus {
    /// Block size in MiB.
    pub block_size_mib: usize,
    /// Total memory size in MiB that can be hotplugged.
    pub total_size_mib: usize,
    /// Size of the KVM slots in MiB.
    pub slot_size_mib: usize,
    /// Currently plugged memory size in MiB.
    pub plugged_size_mib: usize,
    /// Requested memory size in MiB.
    pub requested_size_mib: usize,
}

impl VirtioMem {
    pub fn new(
        vm: Arc<Vm>,
        total_size_mib: usize,
        block_size_mib: usize,
        slot_size_mib: usize,
    ) -> Result<Self, VirtioMemError> {
        let queues = vec![Queue::new(FIRECRACKER_MAX_QUEUE_SIZE); MEM_NUM_QUEUES];
        let config = virtio_mem_config {
            addr: VIRTIO_MEM_GUEST_ADDRESS.raw_value(),
            region_size: mib_to_bytes(total_size_mib) as u64,
            block_size: mib_to_bytes(block_size_mib) as u64,
            ..Default::default()
        };

        Self::from_state(vm, queues, config, mib_to_bytes(slot_size_mib))
    }

    pub fn from_state(
        vm: Arc<Vm>,
        queues: Vec<Queue>,
        config: virtio_mem_config,
        slot_size: usize,
    ) -> Result<Self, VirtioMemError> {
        let activate_event = EventFd::new(libc::EFD_NONBLOCK)?;
        let queue_events = (0..MEM_NUM_QUEUES)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK))
            .collect::<Result<Vec<EventFd>, io::Error>>()?;

        Ok(Self {
            avail_features: (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE),
            acked_features: 0u64,
            activate_event,
            device_state: DeviceState::Inactive,
            queues,
            queue_events,
            config,
            vm,
            slot_size,
        })
    }

    pub fn id(&self) -> &str {
        VIRTIO_MEM_DEV_ID
    }

    /// Gets the total hotpluggable size.
    pub fn total_size_mib(&self) -> usize {
        bytes_to_mib(u64_to_usize(self.config.region_size))
    }

    /// Gets the block size.
    pub fn block_size_mib(&self) -> usize {
        bytes_to_mib(u64_to_usize(self.config.block_size))
    }

    /// Gets the block size.
    pub fn slot_size_mib(&self) -> usize {
        bytes_to_mib(self.slot_size)
    }

    /// Gets the total size of the plugged memory blocks.
    pub fn plugged_size_mib(&self) -> usize {
        bytes_to_mib(u64_to_usize(self.config.plugged_size))
    }

    /// Gets the requested size
    pub fn requested_size_mib(&self) -> usize {
        bytes_to_mib(u64_to_usize(self.config.requested_size))
    }

    pub fn status(&self) -> VirtioMemStatus {
        VirtioMemStatus {
            block_size_mib: self.block_size_mib(),
            total_size_mib: self.total_size_mib(),
            slot_size_mib: self.slot_size_mib(),
            plugged_size_mib: self.plugged_size_mib(),
            requested_size_mib: self.requested_size_mib(),
        }
    }

    fn signal_used_queue(&self) -> Result<(), VirtioMemError> {
        self.interrupt_trigger()
            .trigger(VirtioInterruptType::Queue(MEM_QUEUE.try_into().unwrap()))
            .map_err(VirtioMemError::InterruptError)
    }

    fn process_mem_queue(&mut self) -> Result<(), VirtioMemError> {
        info!("TODO: Received mem queue event, but it's not implemented.");
        Ok(())
    }

    pub(crate) fn process_mem_queue_event(&mut self) {
        if let Err(err) = self.queue_events[MEM_QUEUE].read() {
            error!("Failed to read mem queue event: {err}");
            return;
        }

        if let Err(err) = self.process_mem_queue() {
            error!("virtio-mem: Failed to process queue: {err}");
        }
    }

    pub fn process_virtio_queues(&mut self) -> Result<(), VirtioMemError> {
        self.process_mem_queue()
    }

    pub(crate) fn set_avail_features(&mut self, features: u64) {
        self.avail_features = features;
    }

    pub(crate) fn set_acked_features(&mut self, features: u64) {
        self.acked_features = features;
    }

    pub(crate) fn activate_event(&self) -> &EventFd {
        &self.activate_event
    }
}

impl VirtioDevice for VirtioMem {
    impl_device_type!(VIRTIO_ID_MEM);

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not activated")
            .interrupt
            .deref()
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let offset = u64_to_usize(offset);
        self.config
            .as_slice()
            .get(offset..offset + data.len())
            .map(|s| data.copy_from_slice(s))
            .unwrap_or_else(|| {
                error!(
                    "virtio-mem: Config read offset+length {offset}+{} out of bounds",
                    data.len()
                )
            })
    }

    fn write_config(&mut self, offset: u64, _data: &[u8]) {
        error!("virtio-mem: Attempted write to read-only config space at offset {offset}");
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        if (self.acked_features & (1 << VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE)) == 0 {
            error!(
                "virtio-mem: VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE feature not acknowledged by guest"
            );
            // TODO(virtio-mem): activation failed metric
            return Err(ActivateError::RequiredFeatureNotAcked(
                "VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE",
            ));
        }

        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        if self.activate_event.write(1).is_err() {
            // TODO(virtio-mem): activation failed metric
            self.device_state = DeviceState::Inactive;
            return Err(ActivateError::EventFd);
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use crate::vstate::vm::tests::setup_vm_with_memory;

    pub(crate) fn default_virtio_mem() -> VirtioMem {
        let (_, vm) = setup_vm_with_memory(0x1000);
        let vm = Arc::new(vm);
        VirtioMem::new(vm, 1024, 2, 128).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;

    use vm_memory::mmap::MmapRegionBuilder;

    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::mem::device::test_utils::default_virtio_mem;
    use crate::vstate::vm::tests::setup_vm_with_memory;

    #[test]
    fn test_new() {
        let mem = default_virtio_mem();

        assert_eq!(mem.total_size_mib(), 1024);
        assert_eq!(mem.block_size_mib(), 2);
        assert_eq!(mem.plugged_size_mib(), 0);
        assert_eq!(mem.id(), VIRTIO_MEM_DEV_ID);
        assert_eq!(mem.device_type(), VIRTIO_ID_MEM);

        let features = (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE);
        assert_eq!(mem.avail_features(), features);
        assert_eq!(mem.acked_features(), 0);

        assert!(!mem.is_activated());

        assert_eq!(mem.queues().len(), MEM_NUM_QUEUES);
        assert_eq!(mem.queue_events().len(), MEM_NUM_QUEUES);
    }

    #[test]
    fn test_from_state() {
        let (_, vm) = setup_vm_with_memory(0x1000);
        let vm = Arc::new(vm);
        let queues = vec![Queue::new(FIRECRACKER_MAX_QUEUE_SIZE); MEM_NUM_QUEUES];
        let region_size_mib = 2048;
        let block_size_mib = 2;
        let slot_size_mib = 128;
        let plugged_size_mib = 512;
        let usable_region_size = mib_to_bytes(1024) as u64;
        let config = virtio_mem_config {
            addr: VIRTIO_MEM_GUEST_ADDRESS.raw_value(),
            region_size: mib_to_bytes(region_size_mib) as u64,
            block_size: mib_to_bytes(block_size_mib) as u64,
            plugged_size: mib_to_bytes(plugged_size_mib) as u64,
            usable_region_size,
            ..Default::default()
        };
        let mem = VirtioMem::from_state(vm, queues, config, mib_to_bytes(slot_size_mib)).unwrap();
        assert_eq!(mem.total_size_mib(), region_size_mib);
        assert_eq!(mem.block_size_mib(), block_size_mib);
        assert_eq!(mem.slot_size_mib(), slot_size_mib);
        assert_eq!(mem.plugged_size_mib(), plugged_size_mib);
        assert_eq!(mem.config.usable_region_size, usable_region_size);
    }

    #[test]
    fn test_read_config() {
        let mem = default_virtio_mem();
        let mut data = [0u8; 8];

        mem.read_config(0, &mut data);
        assert_eq!(
            u64::from_le_bytes(data),
            mib_to_bytes(mem.block_size_mib()) as u64
        );

        mem.read_config(16, &mut data);
        assert_eq!(
            u64::from_le_bytes(data),
            VIRTIO_MEM_GUEST_ADDRESS.raw_value()
        );

        mem.read_config(24, &mut data);
        assert_eq!(
            u64::from_le_bytes(data),
            mib_to_bytes(mem.total_size_mib()) as u64
        );
    }

    #[test]
    fn test_read_config_out_of_bounds() {
        let mem = default_virtio_mem();

        let mut data = [0u8; 8];
        let config_size = std::mem::size_of::<virtio_mem_config>();
        mem.read_config(config_size as u64, &mut data);
        assert_eq!(data, [0u8; 8]); // Should remain unchanged

        let mut data = vec![0u8; config_size];
        mem.read_config(8, &mut data);
        assert_eq!(data, vec![0u8; config_size]); // Should remain unchanged
    }

    #[test]
    fn test_write_config() {
        let mut mem = default_virtio_mem();
        let data = [1u8; 8];
        mem.write_config(0, &data); // Should log error but not crash

        // should not change config
        let mut data = [0u8; 8];
        mem.read_config(0, &mut data);
        let block_size = u64::from_le_bytes(data);
        assert_eq!(block_size, mib_to_bytes(2) as u64);
    }

    #[test]
    fn test_set_features() {
        let mut mem = default_virtio_mem();
        mem.set_avail_features(123);
        assert_eq!(mem.avail_features(), 123);
        mem.set_acked_features(456);
        assert_eq!(mem.acked_features(), 456);
    }

    #[test]
    fn test_status() {
        let mut mem = default_virtio_mem();
        let status = mem.status();
        assert_eq!(
            status,
            VirtioMemStatus {
                block_size_mib: 2,
                total_size_mib: 1024,
                slot_size_mib: 128,
                plugged_size_mib: 0,
                requested_size_mib: 0,
            }
        );
    }
}
