// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use vm_memory::{
    Address, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryRegion, GuestUsize,
};
use vmm_sys_util::eventfd::EventFd;

use super::metrics::METRICS;
use super::{MEM_NUM_QUEUES, MEM_QUEUE};
use crate::Vm;
use crate::devices::DeviceError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::iov_deque::IovDequeError;
use crate::devices::virtio::mem::request::{Request, RequestType};
use crate::devices::virtio::mem::response::{
    Response, ResponseCode, ResponseStateCode, ResponseType,
};
use crate::devices::virtio::mem::{VIRTIO_MEM_BLOCK_SIZE, VIRTIO_MEM_GUEST_ADDRESS};
use crate::devices::virtio::queue::{FIRECRACKER_MAX_QUEUE_SIZE, InvalidAvailIdx, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::devices::virtio::{ActivateError, TYPE_MEM};
use crate::logger::{IncMetric, debug, error};
use crate::utils::usize_to_u64;
use crate::vstate::memory::{ByteValued, GuestMemoryMmap, GuestRegionMmap};
use crate::vstate::vm::VmError;

pub const VIRTIO_MEM_DEV_ID: &str = "mem";

// Virtio-mem feature bits
const VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE: u64 = 1;

// Virtio-mem configuration structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtioMemConfig {
    pub block_size: u64,
    pub node_id: u16,
    pub padding: [u8; 6],
    pub addr: u64,
    pub region_size: u64,
    pub usable_region_size: u64,
    pub plugged_size: u64,
    pub requested_size: u64,
}

impl VirtioMemConfig {
    fn new(addr: GuestAddress, size: usize) -> Self {
        Self {
            block_size: VIRTIO_MEM_BLOCK_SIZE as u64,
            node_id: 0,
            padding: [0; 6],
            addr: addr.0,
            region_size: size as u64,
            usable_region_size: 0,
            plugged_size: 0,
            requested_size: 0,
        }
    }
}

// SAFETY: VirtioMemConfig only contains plain data types
unsafe impl ByteValued for VirtioMemConfig {}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VirtioMemError {
    /// Error while handling an Event file descriptor: {0}
    EventFd(#[from] io::Error),
    /// Bad guest memory buffer: {0}
    GuestMemory(#[from] GuestMemoryError),
    /// Underlying IovDeque error: {0}
    IovDeque(#[from] IovDequeError),
    /// Received error while sending an interrupt: {0}
    InterruptError(std::io::Error),
    /// Descriptor is write-only
    UnexpectedWriteOnlyDescriptor,
    /// Error reading virtio descriptor
    DescriptorWriteFailed,
    /// Error writing virtio descriptor
    DescriptorReadFailed,
    /// Unknown request type: {0:?}
    UnknownRequestType(RequestType),
    /// Descriptor chain is too short
    DescriptorChainTooShort,
    /// Descriptor is too small
    DescriptorLengthTooSmall,
    /// Descriptor is read-only
    UnexpectedReadOnlyDescriptor,
    /// {0}
    InvalidAvailIdx(#[from] InvalidAvailIdx),
    /// Size {0} is invalid: it must be a multiple of block size and less than the total size
    InvalidSize(u64),
    /// Device is not active
    DeviceNotActive,
    /// Device wasn't found in the device manager.
    DeviceNotFound,
    /// Error while registering a new memory region with KVM: {0}
    RegisterMemoryRegion(VmError),
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
    config: VirtioMemConfig,
    // Bitmap to track which blocks are plugged (1 bit per 2MB block)
    plugged_blocks: Vec<u64>,
    // Total number of blocks
    total_blocks: usize,
    vm: Arc<Vm>,
}

impl VirtioMem {
    pub fn new(size: usize, vm: Arc<Vm>) -> Result<Self, VirtioMemError> {
        let queues = vec![Queue::new(FIRECRACKER_MAX_QUEUE_SIZE); MEM_NUM_QUEUES];
        Self::new_with_queues(queues, size, vm)
    }

    pub fn new_with_queues(
        queues: Vec<Queue>,
        size: usize,
        vm: Arc<Vm>,
    ) -> Result<Self, VirtioMemError> {
        let activate_event = EventFd::new(libc::EFD_NONBLOCK)?;
        let queue_events = (0..MEM_NUM_QUEUES)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK))
            .collect::<Result<Vec<EventFd>, io::Error>>()?;

        let total_blocks = size / VIRTIO_MEM_BLOCK_SIZE;
        let bitmap_size = (total_blocks + 63) / 64; // Round up to u64 boundary

        Ok(Self {
            avail_features: (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE),
            acked_features: 0u64,
            activate_event,
            device_state: DeviceState::Inactive,
            queues,
            queue_events,
            config: VirtioMemConfig::new(VIRTIO_MEM_GUEST_ADDRESS, size),
            plugged_blocks: vec![0; bitmap_size],
            total_blocks,
            vm,
        })
    }

    pub fn id(&self) -> &str {
        VIRTIO_MEM_DEV_ID
    }

    fn signal_used_queue(&self) -> Result<(), VirtioMemError> {
        self.interrupt_trigger()
            .trigger(VirtioInterruptType::Queue(MEM_QUEUE.try_into().unwrap()))
            .map_err(|err| {
                METRICS.mem_event_fails.inc();
                VirtioMemError::InterruptError(err)
            })
    }

    fn is_block_plugged(&self, block_idx: usize) -> bool {
        if block_idx >= self.total_blocks {
            return false;
        }
        let word_idx = block_idx / 64;
        let bit_idx = block_idx % 64;
        (self.plugged_blocks[word_idx] & (1u64 << bit_idx)) != 0
    }

    fn is_range_plugged(&self, addr: GuestAddress, size: GuestUsize) -> ResponseStateCode {
        let start_block = (addr.0 - self.config.addr) / self.config.block_size as u64;
        assert!(size % self.config.block_size == 0);
        let nb_blocks = size / self.config.block_size;
        let end_block = start_block + nb_blocks;

        let mut plugged_count = 0;

        for block_idx in start_block..end_block {
            if self.is_block_plugged(block_idx as usize) {
                plugged_count += 1;
            }
        }

        if plugged_count == nb_blocks {
            ResponseStateCode::Plugged
        } else if plugged_count == 0 {
            ResponseStateCode::Unplugged
        } else {
            ResponseStateCode::Mixed
        }
    }

    fn set_block_plugged(&mut self, block_idx: usize, plugged: bool) {
        if block_idx >= self.total_blocks {
            return;
        }
        let word_idx = block_idx / 64;
        let bit_idx = block_idx % 64;
        if plugged {
            self.plugged_blocks[word_idx] |= 1u64 << bit_idx;
        } else {
            self.plugged_blocks[word_idx] &= !(1u64 << bit_idx);
        }
    }

    fn write_response(&mut self, req: &Request, resp: &Response) -> Result<(), VirtioMemError> {
        debug!("virtio-mem: Response: {:?}", resp);
        let mem = &self.device_state.active_state().unwrap().mem;
        let num_bytes = resp.write(mem, req.resp_addr)?;
        // TODO error handling
        if let Err(err) = self.queues[MEM_QUEUE].add_used(req.index, num_bytes as u32) {
            error!("virtio-mem: Failed to add used descriptor: {err}");
            METRICS.mem_event_fails.inc();
        }
        Ok(())
    }

    fn handle_plug_request(&mut self, request: &Request) -> Result<(), VirtioMemError> {
        METRICS.plug_count.inc();
        let _metric = METRICS.plug_agg.record_latency_metrics();
        let req = request.request.as_ref().unwrap();
        let start_block = (req.addr - self.config.addr) / VIRTIO_MEM_BLOCK_SIZE as u64;
        let end_block = start_block + req.nb_blocks as u64;

        if end_block > self.total_blocks as u64 {
            return self.write_response(
                request,
                &Response {
                    resp_code: ResponseCode::Nack,
                    resp_type: ResponseType::Plug,
                },
            );
        }

        for block_idx in start_block..end_block {
            if !self.is_block_plugged(block_idx as usize) {
                self.set_block_plugged(block_idx as usize, true);
                self.config.plugged_size += VIRTIO_MEM_BLOCK_SIZE as u64;
            }
        }

        self.write_response(
            request,
            &Response {
                resp_code: ResponseCode::Ack,
                resp_type: ResponseType::Plug,
            },
        )
    }

    fn handle_unplug_request(&mut self, request: &Request) -> Result<(), VirtioMemError> {
        METRICS.unplug_count.inc();
        let _metric = METRICS.unplug_agg.record_latency_metrics();
        let req = request.request.as_ref().unwrap();
        let start_block = (req.addr - self.config.addr) / VIRTIO_MEM_BLOCK_SIZE as u64;
        let end_block = start_block + req.nb_blocks as u64;

        if end_block > self.total_blocks as u64 {
            return self.write_response(
                request,
                &Response {
                    resp_code: ResponseCode::Nack,
                    resp_type: ResponseType::Unplug,
                },
            );
        }

        for block_idx in start_block..end_block {
            if self.is_block_plugged(block_idx as usize) {
                self.set_block_plugged(block_idx as usize, false);
                self.config.plugged_size -= VIRTIO_MEM_BLOCK_SIZE as u64;

                let gpa = GuestAddress(self.config.addr)
                    .checked_add(block_idx * VIRTIO_MEM_BLOCK_SIZE as u64)
                    .unwrap();
                let hva = self
                    .device_state
                    .active_state()
                    .unwrap()
                    .mem
                    .get_host_address(gpa)
                    .unwrap();

                // TODO handle file-backed devices
                unsafe {
                    libc::madvise(hva.cast(), VIRTIO_MEM_BLOCK_SIZE, libc::MADV_DONTNEED);
                }
            }
        }

        self.write_response(
            request,
            &Response {
                resp_code: ResponseCode::Ack,
                resp_type: ResponseType::Unplug,
            },
        )
    }

    fn handle_unplug_all_request(&mut self, request: &Request) -> Result<(), VirtioMemError> {
        METRICS.unplug_all_count.inc();
        let _metric = METRICS.unplug_all_agg.record_latency_metrics();
        for block_idx in 0..self.total_blocks {
            if self.is_block_plugged(block_idx) {
                self.set_block_plugged(block_idx, false);

                let gpa = GuestAddress(self.config.addr)
                    .checked_add((block_idx * VIRTIO_MEM_BLOCK_SIZE) as u64)
                    .unwrap();
                let hva = self
                    .device_state
                    .active_state()
                    .unwrap()
                    .mem
                    .get_host_address(gpa)
                    .unwrap();

                // TODO handle file-backed devices
                unsafe {
                    libc::madvise(hva.cast(), VIRTIO_MEM_BLOCK_SIZE, libc::MADV_DONTNEED);
                }
            }
        }

        self.config.plugged_size = 0;
        self.write_response(
            request,
            &Response {
                resp_code: ResponseCode::Ack,
                resp_type: ResponseType::UnplugAll,
            },
        )
    }

    fn handle_state_request(&mut self, request: &Request) -> Result<(), VirtioMemError> {
        METRICS.state_count.inc();
        let _metric = METRICS.state_agg.record_latency_metrics();
        let req = request.request.as_ref().unwrap();

        if req.addr % self.config.block_size != 0 || req.nb_blocks == 0 {
            return self.write_response(
                request,
                &Response {
                    resp_code: ResponseCode::Error,
                    resp_type: ResponseType::Error,
                },
            );
        }

        let state_type = self.is_range_plugged(
            GuestAddress(req.addr),
            (req.nb_blocks as u64) * self.config.block_size,
        );

        self.write_response(
            request,
            &Response {
                resp_code: ResponseCode::Ack,
                resp_type: ResponseType::State(state_type),
            },
        )
    }

    fn process_mem_queue(&mut self) -> Result<(), VirtioMemError> {
        while let Some(desc) = self.queues[MEM_QUEUE].pop()? {
            let index = desc.index;
            let mem = &self.device_state.active_state().unwrap().mem;
            METRICS.mem_event_count.inc();

            let req = Request::parse(&desc, mem)?;
            debug!("virtio-mem: Request: {:?}", req);
            // Handle request and write response
            match req.req_type {
                RequestType::State => self.handle_state_request(&req)?,
                RequestType::Plug => self.handle_plug_request(&req)?,
                RequestType::Unplug => self.handle_unplug_request(&req)?,
                RequestType::UnplugAll => self.handle_unplug_all_request(&req)?,
                _ => {
                    error!("virtio-mem: Unknown request type: {:?}", req.req_type);
                    METRICS.mem_event_fails.inc();

                    self.write_response(
                        &req,
                        &Response {
                            resp_code: ResponseCode::Error,
                            resp_type: ResponseType::Error,
                        },
                    )?
                }
            };
        }

        self.queues[MEM_QUEUE].advance_used_ring_idx();
        if let Err(err) = self.signal_used_queue() {
            error!("virtio-mem: Failed to signal used queue: {err}");
            METRICS.mem_event_fails.inc();
        }

        Ok(())
    }

    pub(crate) fn process_mem_queue_event(&mut self) {
        if let Err(err) = self.queue_events[MEM_QUEUE].read() {
            error!("Failed to read mem queue event: {err}");
            METRICS.mem_event_fails.inc();
            return;
        }

        if let Err(err) = self.process_mem_queue() {
            error!("virtio-mem: Failed to process queue: {err}");
            METRICS.mem_event_fails.inc();
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

    fn plug_kvm_slots(
        &self,
        start_addr: GuestAddress,
        size: GuestUsize,
        plug: bool,
    ) -> Result<u64, VirtioMemError> {
        let mem = self.vm.guest_memory();
        let mut addr = start_addr;
        let end_addr = start_addr.checked_add(size).unwrap();
        while addr < end_addr {
            let region = mem.find_region(addr).unwrap();
            self.vm
                .set_user_memory_region(region, plug)
                .map_err(VirtioMemError::RegisterMemoryRegion)?;
            addr = addr.checked_add(region.len()).unwrap();
        }
        Ok(addr.checked_offset_from(start_addr).unwrap())
    }

    /// Updates the requested size of the virtio-mem device.
    pub fn update_requested_size(
        &mut self,
        requested_size: u64,
        vm: &Vm,
    ) -> Result<(), VirtioMemError> {
        if !self.is_activated() {
            return Err(VirtioMemError::DeviceNotActive);
        }

        if requested_size % self.config.block_size != 0 {
            return Err(VirtioMemError::InvalidSize(requested_size));
        }
        if requested_size > self.config.region_size {
            return Err(VirtioMemError::InvalidSize(requested_size));
        }

        if self.config.usable_region_size < requested_size {
            let start_addr = GuestAddress(self.config.addr + self.config.usable_region_size);
            let size = requested_size - self.config.usable_region_size;
            let size = self.plug_kvm_slots(start_addr, size, true)?;

            self.config.usable_region_size += size;
        }

        self.config.requested_size = requested_size;
        debug!(
            "virtio-mem: Updated requested size to {} bytes",
            requested_size
        );
        self.device_state
            .active_state()
            .unwrap()
            .interrupt
            .trigger(VirtioInterruptType::Config)
            .map_err(VirtioMemError::InterruptError)
    }

    /// Gets the configuration of the virtio-mem device.
    pub fn config(&self) -> &VirtioMemConfig {
        &self.config
    }
}

impl VirtioDevice for VirtioMem {
    fn device_type(&self) -> u32 {
        TYPE_MEM
    }

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
        let config_bytes = self.config.as_slice();
        let offset = offset as usize;

        if offset >= config_bytes.len() {
            error!(
                "virtio-mem: Config read offset {offset} exceeds config size {}",
                config_bytes.len()
            );
            return;
        }

        let end = std::cmp::min(offset + data.len(), config_bytes.len());
        let len = end - offset;
        data[..len].copy_from_slice(&config_bytes[offset..end]);
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
            return Err(ActivateError::EventFd);
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
mod tests {
    use std::ptr::null_mut;

    use vm_memory::mmap::MmapRegionBuilder;

    use super::*;
    use crate::devices::virtio::device::VirtioDevice;

    fn default_virtio_mem() -> VirtioMem {
        let region = unsafe {
            MmapRegionBuilder::new(0x1000)
                .with_raw_mmap_pointer(null_mut())
                .build()
                .unwrap()
        };

        let region = GuestRegionMmap::new(region, GuestAddress(0)).unwrap();
        VirtioMem::new(&region, 0).unwrap()
    }

    #[test]
    fn test_new() {
        let mem_dev = default_virtio_mem();

        assert_eq!(
            mem_dev.avail_features(),
            (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE)
        );
        assert_eq!(mem_dev.acked_features(), 0);
        assert!(!mem_dev.is_activated());
    }

    #[test]
    fn test_id() {
        let mem_dev = default_virtio_mem();
        assert_eq!(mem_dev.id(), VIRTIO_MEM_DEV_ID);
    }

    #[test]
    fn test_device_type() {
        let mem_dev = default_virtio_mem();
        assert_eq!(mem_dev.device_type(), TYPE_MEM);
    }
}
