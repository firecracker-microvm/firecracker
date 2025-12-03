// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::ops::{Deref, Range};
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use bitvec::vec::BitVec;
use log::info;
use serde::{Deserialize, Serialize};
use vm_memory::{
    Address, Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryRegion, GuestUsize,
};
use vmm_sys_util::eventfd::EventFd;

use super::{MEM_NUM_QUEUES, MEM_QUEUE};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ids::VIRTIO_ID_MEM;
use crate::devices::virtio::generated::virtio_mem::{
    self, VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE, virtio_mem_config,
};
use crate::devices::virtio::iov_deque::IovDequeError;
use crate::devices::virtio::mem::VIRTIO_MEM_DEV_ID;
use crate::devices::virtio::mem::metrics::METRICS;
use crate::devices::virtio::mem::request::{BlockRangeState, Request, RequestedRange, Response};
use crate::devices::virtio::queue::{
    DescriptorChain, FIRECRACKER_MAX_QUEUE_SIZE, InvalidAvailIdx, Queue, QueueError,
};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::logger::{IncMetric, debug, error};
use crate::utils::{bytes_to_mib, mib_to_bytes, u64_to_usize, usize_to_u64};
use crate::vstate::interrupts::InterruptError;
use crate::vstate::memory::{
    ByteValued, GuestMemoryExtension, GuestMemoryMmap, GuestRegionMmap, GuestRegionType,
};
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
    /// Invalid requested range: {0:?}.
    InvalidRange(RequestedRange),
    /// The requested range cannot be plugged because it's {0:?}.
    PlugRequestBlockStateInvalid(BlockRangeState),
    /// Plug request rejected as plugged_size would be greater than requested_size
    PlugRequestIsTooBig,
    /// The requested range cannot be unplugged because it's {0:?}.
    UnplugRequestBlockStateInvalid(BlockRangeState),
    /// There was an error updating the KVM slot.
    UpdateKvmSlot(VmError),
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
    // Bitmap to track which blocks are plugged
    pub(crate) plugged_blocks: BitVec,
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
        addr: GuestAddress,
        total_size_mib: usize,
        block_size_mib: usize,
        slot_size_mib: usize,
    ) -> Result<Self, VirtioMemError> {
        let queues = vec![Queue::new(FIRECRACKER_MAX_QUEUE_SIZE); MEM_NUM_QUEUES];
        let config = virtio_mem_config {
            addr: addr.raw_value(),
            region_size: mib_to_bytes(total_size_mib) as u64,
            block_size: mib_to_bytes(block_size_mib) as u64,
            ..Default::default()
        };
        let plugged_blocks = BitVec::repeat(false, total_size_mib / block_size_mib);

        Self::from_state(
            vm,
            queues,
            config,
            mib_to_bytes(slot_size_mib),
            plugged_blocks,
        )
    }

    pub fn from_state(
        vm: Arc<Vm>,
        queues: Vec<Queue>,
        config: virtio_mem_config,
        slot_size: usize,
        plugged_blocks: BitVec,
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
            plugged_blocks,
        })
    }

    pub fn id(&self) -> &str {
        VIRTIO_MEM_DEV_ID
    }

    pub fn guest_address(&self) -> GuestAddress {
        GuestAddress(self.config.addr)
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

    fn nb_blocks_to_len(&self, nb_blocks: usize) -> usize {
        nb_blocks * u64_to_usize(self.config.block_size)
    }

    /// Returns the state of all the blocks in the given range.
    ///
    /// Note: the range passed to this function must be within the device memory to avoid
    /// out-of-bound panics.
    fn range_state(&self, range: &RequestedRange) -> BlockRangeState {
        let plugged_count = self.plugged_blocks[self.unchecked_block_range(range)].count_ones();

        match plugged_count {
            nb_blocks if nb_blocks == range.nb_blocks => BlockRangeState::Plugged,
            0 => BlockRangeState::Unplugged,
            _ => BlockRangeState::Mixed,
        }
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

    /// Checks that the range provided by the driver is within the usable memory region
    fn validate_range(&self, range: &RequestedRange) -> Result<(), VirtioMemError> {
        // Ensure the range is aligned
        if !range
            .addr
            .raw_value()
            .is_multiple_of(self.config.block_size)
        {
            return Err(VirtioMemError::InvalidRange(*range));
        }

        if range.nb_blocks == 0 {
            return Err(VirtioMemError::InvalidRange(*range));
        }

        // Ensure the start addr is within the usable region
        let start_off = range
            .addr
            .checked_offset_from(self.guest_address())
            .filter(|&off| off < self.config.usable_region_size)
            .ok_or(VirtioMemError::InvalidRange(*range))?;

        // Ensure the end offset (exclusive) is within the usable region
        let end_off = start_off
            .checked_add(usize_to_u64(self.nb_blocks_to_len(range.nb_blocks)))
            .filter(|&end_off| end_off <= self.config.usable_region_size)
            .ok_or(VirtioMemError::InvalidRange(*range))?;

        Ok(())
    }

    fn unchecked_block_range(&self, range: &RequestedRange) -> Range<usize> {
        let start_block = u64_to_usize((range.addr.0 - self.config.addr) / self.config.block_size);

        start_block..(start_block + range.nb_blocks)
    }

    fn process_plug_request(&mut self, range: &RequestedRange) -> Result<(), VirtioMemError> {
        self.validate_range(range)?;

        if self.config.plugged_size + usize_to_u64(self.nb_blocks_to_len(range.nb_blocks))
            > self.config.requested_size
        {
            return Err(VirtioMemError::PlugRequestIsTooBig);
        }

        match self.range_state(range) {
            // the range was validated
            BlockRangeState::Unplugged => self.update_range(range, true),
            state => Err(VirtioMemError::PlugRequestBlockStateInvalid(state)),
        }
    }

    fn handle_plug_request(
        &mut self,
        range: &RequestedRange,
        resp_addr: GuestAddress,
        used_idx: u16,
    ) -> Result<(), VirtioMemError> {
        METRICS.plug_count.inc();
        let _metric = METRICS.plug_agg.record_latency_metrics();

        let response = match self.process_plug_request(range) {
            Err(err) => {
                METRICS.plug_fails.inc();
                error!("virtio-mem: Failed to plug range: {}", err);
                Response::error()
            }
            Ok(_) => {
                METRICS
                    .plug_bytes
                    .add(usize_to_u64(self.nb_blocks_to_len(range.nb_blocks)));
                Response::ack()
            }
        };
        self.write_response(response, resp_addr, used_idx)
    }

    fn process_unplug_request(&mut self, range: &RequestedRange) -> Result<(), VirtioMemError> {
        self.validate_range(range)?;

        match self.range_state(range) {
            // the range was validated
            BlockRangeState::Plugged => self.update_range(range, false),
            state => Err(VirtioMemError::UnplugRequestBlockStateInvalid(state)),
        }
    }

    fn handle_unplug_request(
        &mut self,
        range: &RequestedRange,
        resp_addr: GuestAddress,
        used_idx: u16,
    ) -> Result<(), VirtioMemError> {
        METRICS.unplug_count.inc();
        let _metric = METRICS.unplug_agg.record_latency_metrics();
        let response = match self.process_unplug_request(range) {
            Err(err) => {
                METRICS.unplug_fails.inc();
                error!("virtio-mem: Failed to unplug range: {}", err);
                Response::error()
            }
            Ok(_) => {
                METRICS
                    .unplug_bytes
                    .add(usize_to_u64(self.nb_blocks_to_len(range.nb_blocks)));
                Response::ack()
            }
        };
        self.write_response(response, resp_addr, used_idx)
    }

    fn handle_unplug_all_request(
        &mut self,
        resp_addr: GuestAddress,
        used_idx: u16,
    ) -> Result<(), VirtioMemError> {
        METRICS.unplug_all_count.inc();
        let _metric = METRICS.unplug_all_agg.record_latency_metrics();
        let range = RequestedRange {
            addr: self.guest_address(),
            nb_blocks: self.plugged_blocks.len(),
        };
        let response = match self.update_range(&range, false) {
            Err(err) => {
                METRICS.unplug_all_fails.inc();
                error!("virtio-mem: Failed to unplug all: {}", err);
                Response::error()
            }
            Ok(_) => {
                self.config.usable_region_size = 0;
                Response::ack()
            }
        };
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
        let response = match self.validate_range(range) {
            Err(err) => {
                METRICS.state_fails.inc();
                error!("virtio-mem: Failed to retrieve state of range: {}", err);
                Response::error()
            }
            // the range was validated
            Ok(_) => Response::ack_with_state(self.range_state(range)),
        };
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

    fn update_kvm_slots(&self, updated_range: &RequestedRange) -> Result<(), VirtioMemError> {
        let hp_region = self
            .guest_memory()
            .iter()
            .find(|r| r.region_type == GuestRegionType::Hotpluggable)
            .expect("there should be one and only one hotpluggable region");
        hp_region
            .slots_intersecting_range(
                updated_range.addr,
                self.nb_blocks_to_len(updated_range.nb_blocks),
            )
            .try_for_each(|slot| {
                let slot_range = RequestedRange {
                    addr: slot.guest_addr,
                    nb_blocks: slot.slice.len() / u64_to_usize(self.config.block_size),
                };
                match self.range_state(&slot_range) {
                    BlockRangeState::Mixed | BlockRangeState::Plugged => {
                        hp_region.update_slot(&self.vm, &slot, true)
                    }
                    BlockRangeState::Unplugged => hp_region.update_slot(&self.vm, &slot, false),
                }
                .map_err(VirtioMemError::UpdateKvmSlot)
            })
    }

    /// Plugs/unplugs the given range
    ///
    /// Note: the range passed to this function must be within the device memory to avoid
    /// out-of-bound panics.
    fn update_range(&mut self, range: &RequestedRange, plug: bool) -> Result<(), VirtioMemError> {
        // Update internal state
        let block_range = self.unchecked_block_range(range);
        let plugged_blocks_slice = &mut self.plugged_blocks[block_range];
        let plugged_before = plugged_blocks_slice.count_ones();
        plugged_blocks_slice.fill(plug);
        let plugged_after = plugged_blocks_slice.count_ones();
        self.config.plugged_size -= usize_to_u64(self.nb_blocks_to_len(plugged_before));
        self.config.plugged_size += usize_to_u64(self.nb_blocks_to_len(plugged_after));

        // If unplugging, discard the range
        if !plug {
            self.guest_memory()
                .discard_range(range.addr, self.nb_blocks_to_len(range.nb_blocks))
                .inspect_err(|err| {
                    // Failure to discard is not fatal and is not reported to the driver. It only
                    // gets logged.
                    METRICS.unplug_discard_fails.inc();
                    error!("virtio-mem: Failed to discard memory range: {}", err);
                });
        }

        self.update_kvm_slots(range)
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

    fn kick(&mut self) {
        if self.is_activated() {
            info!("kick mem {}.", self.id());
            self.process_virtio_queues();
        }
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use crate::devices::virtio::test_utils::test::VirtioTestDevice;
    use crate::test_utils::single_region_mem;
    use crate::vmm_config::machine_config::HugePageConfig;
    use crate::vstate::memory;
    use crate::vstate::vm::tests::setup_vm_with_memory;

    impl VirtioTestDevice for VirtioMem {
        fn set_queues(&mut self, queues: Vec<Queue>) {
            self.queues = queues;
        }

        fn num_queues(&self) -> usize {
            MEM_NUM_QUEUES
        }
    }

    pub(crate) fn default_virtio_mem() -> VirtioMem {
        let (_, mut vm) = setup_vm_with_memory(0x1000);
        let addr = GuestAddress(512 << 30);
        vm.register_hotpluggable_memory_region(
            memory::anonymous(
                std::iter::once((addr, mib_to_bytes(1024))),
                false,
                HugePageConfig::None,
            )
            .unwrap()
            .pop()
            .unwrap(),
            mib_to_bytes(128),
        );
        let vm = Arc::new(vm);
        VirtioMem::new(vm, addr, 1024, 2, 128).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;

    use serde_json::de;
    use vm_memory::guest_memory;
    use vm_memory::mmap::MmapRegionBuilder;

    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::mem::device::test_utils::default_virtio_mem;
    use crate::devices::virtio::queue::VIRTQ_DESC_F_WRITE;
    use crate::devices::virtio::test_utils::test::VirtioTestHelper;
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
        let addr = 512 << 30;
        let region_size_mib = 2048;
        let block_size_mib = 2;
        let slot_size_mib = 128;
        let plugged_size_mib = 512;
        let usable_region_size = mib_to_bytes(1024) as u64;
        let config = virtio_mem_config {
            addr,
            region_size: mib_to_bytes(region_size_mib) as u64,
            block_size: mib_to_bytes(block_size_mib) as u64,
            plugged_size: mib_to_bytes(plugged_size_mib) as u64,
            usable_region_size,
            ..Default::default()
        };
        let plugged_blocks = BitVec::repeat(
            false,
            mib_to_bytes(region_size_mib) / mib_to_bytes(block_size_mib),
        );
        let mem = VirtioMem::from_state(
            vm,
            queues,
            config,
            mib_to_bytes(slot_size_mib),
            plugged_blocks,
        )
        .unwrap();
        assert_eq!(mem.config.addr, addr);
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
        assert_eq!(u64::from_le_bytes(data), 512 << 30);

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

    #[allow(clippy::cast_possible_truncation)]
    const REQ_SIZE: u32 = std::mem::size_of::<virtio_mem::virtio_mem_req>() as u32;
    #[allow(clippy::cast_possible_truncation)]
    const RESP_SIZE: u32 = std::mem::size_of::<virtio_mem::virtio_mem_resp>() as u32;

    fn test_helper<'a>(
        mut dev: VirtioMem,
        mem: &'a GuestMemoryMmap,
    ) -> VirtioTestHelper<'a, VirtioMem> {
        dev.set_acked_features(dev.avail_features);

        let mut th = VirtioTestHelper::<VirtioMem>::new(mem, dev);
        th.activate_device(mem);
        th
    }

    fn emulate_request(
        th: &mut VirtioTestHelper<VirtioMem>,
        mem: &GuestMemoryMmap,
        req: Request,
    ) -> Response {
        th.add_desc_chain(
            MEM_QUEUE,
            0,
            &[(0, REQ_SIZE, 0), (1, RESP_SIZE, VIRTQ_DESC_F_WRITE)],
        );
        mem.write_obj(
            virtio_mem::virtio_mem_req::from(req),
            th.desc_address(MEM_QUEUE, 0),
        )
        .unwrap();
        assert_eq!(th.emulate_for_msec(100).unwrap(), 1);
        mem.read_obj::<virtio_mem::virtio_mem_resp>(th.desc_address(MEM_QUEUE, 1))
            .unwrap()
            .into()
    }

    #[test]
    fn test_event_fail_descriptor_chain_too_short() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);

        let queue_event_count = METRICS.queue_event_count.count();
        let queue_event_fails = METRICS.queue_event_fails.count();

        th.add_desc_chain(MEM_QUEUE, 0, &[(0, REQ_SIZE, 0)]);
        assert_eq!(th.emulate_for_msec(100).unwrap(), 1);

        assert_eq!(METRICS.queue_event_count.count(), queue_event_count + 1);
        assert_eq!(METRICS.queue_event_fails.count(), queue_event_fails + 1);
    }

    #[test]
    fn test_event_fail_descriptor_length_too_small() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);

        let queue_event_count = METRICS.queue_event_count.count();
        let queue_event_fails = METRICS.queue_event_fails.count();

        th.add_desc_chain(MEM_QUEUE, 0, &[(0, 1, 0)]);
        assert_eq!(th.emulate_for_msec(100).unwrap(), 1);

        assert_eq!(METRICS.queue_event_count.count(), queue_event_count + 1);
        assert_eq!(METRICS.queue_event_fails.count(), queue_event_fails + 1);
    }

    #[test]
    fn test_event_fail_unexpected_writeonly_descriptor() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);

        let queue_event_count = METRICS.queue_event_count.count();
        let queue_event_fails = METRICS.queue_event_fails.count();

        th.add_desc_chain(MEM_QUEUE, 0, &[(0, REQ_SIZE, VIRTQ_DESC_F_WRITE)]);
        assert_eq!(th.emulate_for_msec(100).unwrap(), 1);

        assert_eq!(METRICS.queue_event_count.count(), queue_event_count + 1);
        assert_eq!(METRICS.queue_event_fails.count(), queue_event_fails + 1);
    }

    #[test]
    fn test_event_fail_unexpected_readonly_descriptor() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);

        let queue_event_count = METRICS.queue_event_count.count();
        let queue_event_fails = METRICS.queue_event_fails.count();

        th.add_desc_chain(MEM_QUEUE, 0, &[(0, REQ_SIZE, 0), (1, RESP_SIZE, 0)]);
        assert_eq!(th.emulate_for_msec(100).unwrap(), 1);

        assert_eq!(METRICS.queue_event_count.count(), queue_event_count + 1);
        assert_eq!(METRICS.queue_event_fails.count(), queue_event_fails + 1);
    }

    #[test]
    fn test_event_fail_response_descriptor_length_too_small() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);

        let queue_event_count = METRICS.queue_event_count.count();
        let queue_event_fails = METRICS.queue_event_fails.count();

        th.add_desc_chain(
            MEM_QUEUE,
            0,
            &[(0, REQ_SIZE, 0), (1, 1, VIRTQ_DESC_F_WRITE)],
        );
        assert_eq!(th.emulate_for_msec(100).unwrap(), 1);

        assert_eq!(METRICS.queue_event_count.count(), queue_event_count + 1);
        assert_eq!(METRICS.queue_event_fails.count(), queue_event_fails + 1);
    }

    #[test]
    fn test_update_requested_size_device_not_active() {
        let mut mem_dev = default_virtio_mem();
        let result = mem_dev.update_requested_size(512);
        assert!(matches!(result, Err(VirtioMemError::DeviceNotActive)));
    }

    #[test]
    fn test_update_requested_size_invalid_size() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);

        // Size not multiple of block size
        let result = th.device().update_requested_size(3);
        assert!(matches!(result, Err(VirtioMemError::InvalidSize(_))));

        // Size too large
        let result = th.device().update_requested_size(2048);
        assert!(matches!(result, Err(VirtioMemError::InvalidSize(_))));
    }

    #[test]
    fn test_update_requested_size_success() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);

        th.device().update_requested_size(512).unwrap();
        assert_eq!(th.device().requested_size_mib(), 512);
    }

    #[test]
    fn test_plug_request_success() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);
        th.device().update_requested_size(1024);
        let addr = th.device().guest_address();

        let queue_event_count = METRICS.queue_event_count.count();
        let queue_event_fails = METRICS.queue_event_fails.count();
        let plug_count = METRICS.plug_count.count();
        let plug_bytes = METRICS.plug_bytes.count();
        let plug_fails = METRICS.plug_fails.count();

        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::Plug(RequestedRange { addr, nb_blocks: 1 }),
        );
        assert!(resp.is_ack());
        assert_eq!(th.device().plugged_size_mib(), 2);

        assert_eq!(METRICS.queue_event_count.count(), queue_event_count + 1);
        assert_eq!(METRICS.queue_event_fails.count(), queue_event_fails);
        assert_eq!(METRICS.plug_count.count(), plug_count + 1);
        assert_eq!(METRICS.plug_bytes.count(), plug_bytes + (2 << 20));
        assert_eq!(METRICS.plug_fails.count(), plug_fails);
    }

    #[test]
    fn test_plug_request_too_big() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);
        th.device().update_requested_size(2);
        let addr = th.device().guest_address();

        let plug_count = METRICS.plug_count.count();
        let plug_bytes = METRICS.plug_bytes.count();
        let plug_fails = METRICS.plug_fails.count();

        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::Plug(RequestedRange { addr, nb_blocks: 2 }),
        );
        assert!(resp.is_error());

        assert_eq!(METRICS.plug_count.count(), plug_count + 1);
        assert_eq!(METRICS.plug_bytes.count(), plug_bytes);
        assert_eq!(METRICS.plug_fails.count(), plug_fails + 1);
    }

    #[test]
    fn test_plug_request_already_plugged() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);
        th.device().update_requested_size(1024);
        let addr = th.device().guest_address();

        // First plug succeeds
        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::Plug(RequestedRange { addr, nb_blocks: 1 }),
        );
        assert!(resp.is_ack());

        // Second plug fails
        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::Plug(RequestedRange { addr, nb_blocks: 1 }),
        );
        assert!(resp.is_error());
    }

    #[test]
    fn test_unplug_request_success() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);
        th.device().update_requested_size(1024);
        let addr = th.device().guest_address();

        let unplug_count = METRICS.unplug_count.count();
        let unplug_bytes = METRICS.unplug_bytes.count();
        let unplug_fails = METRICS.unplug_fails.count();

        // First plug
        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::Plug(RequestedRange { addr, nb_blocks: 1 }),
        );
        assert!(resp.is_ack());
        assert_eq!(th.device().plugged_size_mib(), 2);

        // Then unplug
        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::Unplug(RequestedRange { addr, nb_blocks: 1 }),
        );
        assert!(resp.is_ack());
        assert_eq!(th.device().plugged_size_mib(), 0);

        assert_eq!(METRICS.unplug_count.count(), unplug_count + 1);
        assert_eq!(METRICS.unplug_bytes.count(), unplug_bytes + (2 << 20));
        assert_eq!(METRICS.unplug_fails.count(), unplug_fails);
    }

    #[test]
    fn test_unplug_request_not_plugged() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);
        th.device().update_requested_size(1024);
        let addr = th.device().guest_address();

        let unplug_count = METRICS.unplug_count.count();
        let unplug_bytes = METRICS.unplug_bytes.count();
        let unplug_fails = METRICS.unplug_fails.count();

        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::Unplug(RequestedRange { addr, nb_blocks: 1 }),
        );
        assert!(resp.is_error());

        assert_eq!(METRICS.unplug_count.count(), unplug_count + 1);
        assert_eq!(METRICS.unplug_bytes.count(), unplug_bytes);
        assert_eq!(METRICS.unplug_fails.count(), unplug_fails + 1);
    }

    #[test]
    fn test_unplug_all_request() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);
        th.device().update_requested_size(1024);
        let addr = th.device().guest_address();

        let unplug_all_count = METRICS.unplug_all_count.count();
        let unplug_all_fails = METRICS.unplug_all_fails.count();

        // Plug some blocks
        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::Plug(RequestedRange { addr, nb_blocks: 2 }),
        );
        assert!(resp.is_ack());
        assert_eq!(th.device().plugged_size_mib(), 4);

        // Unplug all
        let resp = emulate_request(&mut th, &guest_mem, Request::UnplugAll);
        assert!(resp.is_ack());
        assert_eq!(th.device().plugged_size_mib(), 0);

        assert_eq!(METRICS.unplug_all_count.count(), unplug_all_count + 1);
        assert_eq!(METRICS.unplug_all_fails.count(), unplug_all_fails);
    }

    #[test]
    fn test_state_request_unplugged() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);
        th.device().update_requested_size(1024);
        let addr = th.device().guest_address();

        let state_count = METRICS.state_count.count();
        let state_fails = METRICS.state_fails.count();

        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::State(RequestedRange { addr, nb_blocks: 1 }),
        );
        assert_eq!(resp, Response::ack_with_state(BlockRangeState::Unplugged));

        assert_eq!(METRICS.state_count.count(), state_count + 1);
        assert_eq!(METRICS.state_fails.count(), state_fails);
    }

    #[test]
    fn test_state_request_plugged() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);
        th.device().update_requested_size(1024);
        let addr = th.device().guest_address();

        // Plug first
        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::Plug(RequestedRange { addr, nb_blocks: 1 }),
        );
        assert!(resp.is_ack());

        // Check state
        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::State(RequestedRange { addr, nb_blocks: 1 }),
        );
        assert_eq!(resp, Response::ack_with_state(BlockRangeState::Plugged));
    }

    #[test]
    fn test_state_request_mixed() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);
        th.device().update_requested_size(1024);
        let addr = th.device().guest_address();

        // Plug first block only
        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::Plug(RequestedRange { addr, nb_blocks: 1 }),
        );
        assert!(resp.is_ack());

        // Check state of 2 blocks (one plugged, one unplugged)
        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::State(RequestedRange { addr, nb_blocks: 2 }),
        );
        assert_eq!(resp, Response::ack_with_state(BlockRangeState::Mixed));
    }

    #[test]
    fn test_invalid_range_unaligned() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);
        th.device().update_requested_size(1024);
        let addr = th.device().guest_address().unchecked_add(1);

        let state_count = METRICS.state_count.count();
        let state_fails = METRICS.state_fails.count();

        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::State(RequestedRange { addr, nb_blocks: 1 }),
        );
        assert!(resp.is_error());

        assert_eq!(METRICS.state_count.count(), state_count + 1);
        assert_eq!(METRICS.state_fails.count(), state_fails + 1);
    }

    #[test]
    fn test_invalid_range_zero_blocks() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);
        th.device().update_requested_size(1024);
        let addr = th.device().guest_address();

        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::State(RequestedRange { addr, nb_blocks: 0 }),
        );
        assert!(resp.is_error());
    }

    #[test]
    fn test_invalid_range_out_of_bounds() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);
        th.device().update_requested_size(4);
        let addr = th.device().guest_address();

        let resp = emulate_request(
            &mut th,
            &guest_mem,
            Request::State(RequestedRange {
                addr,
                nb_blocks: 1024,
            }),
        );
        assert!(resp.is_error());
    }

    #[test]
    fn test_unsupported_request() {
        let mut mem_dev = default_virtio_mem();
        let guest_mem = mem_dev.vm.guest_memory().clone();
        let mut th = test_helper(mem_dev, &guest_mem);

        let queue_event_count = METRICS.queue_event_count.count();
        let queue_event_fails = METRICS.queue_event_fails.count();

        th.add_desc_chain(
            MEM_QUEUE,
            0,
            &[(0, REQ_SIZE, 0), (1, RESP_SIZE, VIRTQ_DESC_F_WRITE)],
        );
        guest_mem
            .write_obj(
                virtio_mem::virtio_mem_req::from(Request::Unsupported(999)),
                th.desc_address(MEM_QUEUE, 0),
            )
            .unwrap();
        assert_eq!(th.emulate_for_msec(100).unwrap(), 1);

        assert_eq!(METRICS.queue_event_count.count(), queue_event_count + 1);
        assert_eq!(METRICS.queue_event_fails.count(), queue_event_fails + 1);
    }
}
