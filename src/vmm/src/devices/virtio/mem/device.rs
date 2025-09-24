// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use log::info;
use serde::{Deserialize, Serialize};
use vm_memory::{
    Address, Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryRegion, GuestUsize,
};
use vmm_sys_util::eventfd::EventFd;

use super::{MEM_NUM_QUEUES, MEM_QUEUE};
use crate::devices::DeviceError;
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ids::VIRTIO_ID_MEM;
use crate::devices::virtio::generated::virtio_mem::{
    self, VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE, virtio_mem_config,
};
use crate::devices::virtio::iov_deque::IovDequeError;
use crate::devices::virtio::mem::metrics::METRICS;
use crate::devices::virtio::mem::request::{BlockRangeState, Request, RequestedRange, Response};
use crate::devices::virtio::mem::{VIRTIO_MEM_DEV_ID, VIRTIO_MEM_GUEST_ADDRESS};
use crate::devices::virtio::queue::{
    DescriptorChain, FIRECRACKER_MAX_QUEUE_SIZE, InvalidAvailIdx, Queue, QueueError,
};
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
    /// Size {0} is invalid: it must be a multiple of block size and less than the total size
    InvalidSize(u64),
    /// Device is not active
    DeviceNotActive,
    /// Descriptor is write-only
    UnexpectedWriteOnlyDescriptor,
    /// Error reading virtio descriptor
    DescriptorWriteFailed,
    /// Error writing virtio descriptor
    DescriptorReadFailed,
    /// Unknown request type: {0}
    UnknownRequestType(u32),
    /// Descriptor chain is too short
    DescriptorChainTooShort,
    /// Descriptor is too small
    DescriptorLengthTooSmall,
    /// Descriptor is read-only
    UnexpectedReadOnlyDescriptor,
    /// Error popping from virtio queue: {0}
    InvalidAvailIdx(#[from] InvalidAvailIdx),
    /// Error adding used queue: {0}
    QueueError(#[from] QueueError),
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

    fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.device_state.active_state().unwrap().mem
    }

    fn parse_request(
        &self,
        avail_desc: &DescriptorChain,
    ) -> Result<(Request, GuestAddress, u16), VirtioMemError> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(VirtioMemError::UnexpectedWriteOnlyDescriptor);
        }

        if (avail_desc.len as usize) < size_of::<virtio_mem::virtio_mem_req>() {
            return Err(VirtioMemError::DescriptorLengthTooSmall);
        }

        let request: virtio_mem::virtio_mem_req = self
            .guest_memory()
            .read_obj(avail_desc.addr)
            .map_err(|_| VirtioMemError::DescriptorReadFailed)?;

        let resp_desc = avail_desc
            .next_descriptor()
            .ok_or(VirtioMemError::DescriptorChainTooShort)?;

        // The response MUST always be writable.
        if !resp_desc.is_write_only() {
            return Err(VirtioMemError::UnexpectedReadOnlyDescriptor);
        }

        if (resp_desc.len as usize) < std::mem::size_of::<virtio_mem::virtio_mem_resp>() {
            return Err(VirtioMemError::DescriptorLengthTooSmall);
        }

        Ok((request.into(), resp_desc.addr, avail_desc.index))
    }

    fn write_response(
        &mut self,
        resp: Response,
        resp_addr: GuestAddress,
        used_idx: u16,
    ) -> Result<(), VirtioMemError> {
        debug!("virtio-mem: Response: {:?}", resp);
        self.guest_memory()
            .write_obj(virtio_mem::virtio_mem_resp::from(resp), resp_addr)
            .map_err(|_| VirtioMemError::DescriptorWriteFailed)
            .map(|_| size_of::<virtio_mem::virtio_mem_resp>())?;
        self.queues[MEM_QUEUE]
            .add_used(
                used_idx,
                u32::try_from(std::mem::size_of::<virtio_mem::virtio_mem_resp>()).unwrap(),
            )
            .map_err(VirtioMemError::QueueError)
    }

    fn handle_plug_request(
        &mut self,
        range: &RequestedRange,
        resp_addr: GuestAddress,
        used_idx: u16,
    ) -> Result<(), VirtioMemError> {
        METRICS.plug_count.inc();
        let _metric = METRICS.plug_agg.record_latency_metrics();

        // TODO: implement PLUG request
        let response = Response::ack();
        self.write_response(response, resp_addr, used_idx)
    }

    fn handle_unplug_request(
        &mut self,
        range: &RequestedRange,
        resp_addr: GuestAddress,
        used_idx: u16,
    ) -> Result<(), VirtioMemError> {
        METRICS.unplug_count.inc();
        let _metric = METRICS.unplug_agg.record_latency_metrics();

        // TODO: implement UNPLUG request
        let response = Response::ack();
        self.write_response(response, resp_addr, used_idx)
    }

    fn handle_unplug_all_request(
        &mut self,
        resp_addr: GuestAddress,
        used_idx: u16,
    ) -> Result<(), VirtioMemError> {
        METRICS.unplug_all_count.inc();
        let _metric = METRICS.unplug_all_agg.record_latency_metrics();

        // TODO: implement UNPLUG ALL request
        let response = Response::ack();
        self.write_response(response, resp_addr, used_idx)
    }

    fn handle_state_request(
        &mut self,
        range: &RequestedRange,
        resp_addr: GuestAddress,
        used_idx: u16,
    ) -> Result<(), VirtioMemError> {
        METRICS.state_count.inc();
        let _metric = METRICS.state_agg.record_latency_metrics();

        // TODO: implement STATE request
        let response = Response::ack_with_state(BlockRangeState::Mixed);
        self.write_response(response, resp_addr, used_idx)
    }

    fn process_mem_queue(&mut self) -> Result<(), VirtioMemError> {
        while let Some(desc) = self.queues[MEM_QUEUE].pop()? {
            let index = desc.index;

            let (req, resp_addr, used_idx) = self.parse_request(&desc)?;
            debug!("virtio-mem: Request: {:?}", req);
            // Handle request and write response
            match req {
                Request::State(ref range) => self.handle_state_request(range, resp_addr, used_idx),
                Request::Plug(ref range) => self.handle_plug_request(range, resp_addr, used_idx),
                Request::Unplug(ref range) => {
                    self.handle_unplug_request(range, resp_addr, used_idx)
                }
                Request::UnplugAll => self.handle_unplug_all_request(resp_addr, used_idx),
                Request::Unsupported(t) => Err(VirtioMemError::UnknownRequestType(t)),
            }?;
        }

        self.queues[MEM_QUEUE].advance_used_ring_idx();
        self.signal_used_queue()?;

        Ok(())
    }

    pub(crate) fn process_mem_queue_event(&mut self) {
        METRICS.queue_event_count.inc();
        if let Err(err) = self.queue_events[MEM_QUEUE].read() {
            METRICS.queue_event_fails.inc();
            error!("Failed to read mem queue event: {err}");
            return;
        }

        if let Err(err) = self.process_mem_queue() {
            METRICS.queue_event_fails.inc();
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

    /// Updates the requested size of the virtio-mem device.
    pub fn update_requested_size(
        &mut self,
        requested_size_mib: usize,
    ) -> Result<(), VirtioMemError> {
        let requested_size = usize_to_u64(mib_to_bytes(requested_size_mib));
        if !self.is_activated() {
            return Err(VirtioMemError::DeviceNotActive);
        }

        if requested_size % self.config.block_size != 0 {
            return Err(VirtioMemError::InvalidSize(requested_size));
        }
        if requested_size > self.config.region_size {
            return Err(VirtioMemError::InvalidSize(requested_size));
        }

        // Increase the usable_region_size if it's not enough for the guest to plug new
        // memory blocks.
        // The device cannot decrease the usable_region_size unless the guest requests
        // to reset it with an UNPLUG_ALL request.
        if self.config.usable_region_size < requested_size {
            self.config.usable_region_size =
                requested_size.next_multiple_of(usize_to_u64(self.slot_size));
            debug!(
                "virtio-mem: Updated usable size to {} bytes",
                self.config.usable_region_size
            );
        }

        self.config.requested_size = requested_size;
        debug!(
            "virtio-mem: Updated requested size to {} bytes",
            requested_size
        );
        self.interrupt_trigger()
            .trigger(VirtioInterruptType::Config)
            .map_err(VirtioMemError::InterruptError)
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
            METRICS.activate_fails.inc();
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
            METRICS.activate_fails.inc();
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
