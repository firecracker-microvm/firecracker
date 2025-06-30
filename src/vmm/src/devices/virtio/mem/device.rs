// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use vm_memory::{GuestAddress, GuestMemoryError};
use vmm_sys_util::eventfd::EventFd;

use super::metrics::METRICS;
use super::{MEM_NUM_QUEUES, MEM_QUEUE};
use crate::devices::DeviceError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::iov_deque::IovDequeError;
use crate::devices::virtio::mem::VIRTIO_MEM_BLOCK_SIZE;
use crate::devices::virtio::mem::request::{Request, RequestType};
use crate::devices::virtio::mem::response::{
    Response, ResponseCode, ResponseStateCode, ResponseType,
};
use crate::devices::virtio::queue::{FIRECRACKER_MAX_QUEUE_SIZE, InvalidAvailIdx, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::devices::virtio::{ActivateError, TYPE_MEM};
use crate::logger::{IncMetric, debug, error};
use crate::vstate::memory::{ByteValued, GuestMemoryMmap};

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
            usable_region_size: size as u64, // All memory is usable since it's pre-allocated
            plugged_size: 0,
            requested_size: size as u64,
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
}

impl VirtioMem {
    pub fn new(addr: GuestAddress, size: usize) -> Result<Self, VirtioMemError> {
        let queues = vec![Queue::new(FIRECRACKER_MAX_QUEUE_SIZE); MEM_NUM_QUEUES];
        Self::new_with_queues(queues, addr, size)
    }

    pub fn new_with_queues(
        queues: Vec<Queue>,
        addr: GuestAddress,
        size: usize,
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
            config: VirtioMemConfig::new(addr, size),
            plugged_blocks: vec![0; bitmap_size],
            total_blocks,
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

                // TODO handle file-backed devices
                let addr = self.config.addr + block_idx * VIRTIO_MEM_BLOCK_SIZE as u64;
                unsafe {
                    libc::madvise(
                        addr as *mut libc::c_void,
                        VIRTIO_MEM_BLOCK_SIZE,
                        libc::MADV_DONTNEED,
                    );
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
        for block_idx in 0..self.total_blocks {
            if self.is_block_plugged(block_idx) {
                self.set_block_plugged(block_idx, false);

                let addr = self.config.addr + (block_idx as u64) * VIRTIO_MEM_BLOCK_SIZE as u64;
                unsafe {
                    libc::madvise(
                        addr as *mut libc::c_void,
                        VIRTIO_MEM_BLOCK_SIZE,
                        libc::MADV_DONTNEED,
                    );
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
        let req = request.request.as_ref().unwrap();
        let start_block = (req.addr - self.config.addr) / VIRTIO_MEM_BLOCK_SIZE as u64;
        let end_block = start_block + req.nb_blocks as u64;

        if req.addr % self.config.block_size != 0
            || req.nb_blocks == 0
            || end_block > self.total_blocks as u64
        {
            return self.write_response(
                request,
                &Response {
                    resp_code: ResponseCode::Error,
                    resp_type: ResponseType::Error,
                },
            );
        }

        let mut plugged_count = 0;

        for block_idx in start_block..end_block {
            if self.is_block_plugged(block_idx as usize) {
                plugged_count += 1;
            }
        }

        let state_type = if plugged_count == req.nb_blocks {
            ResponseStateCode::Plugged
        } else if plugged_count == 0 {
            ResponseStateCode::Unplugged
        } else {
            ResponseStateCode::Mixed
        };

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
    use super::*;
    use crate::devices::virtio::device::VirtioDevice;

    fn default_virtio_mem() -> VirtioMem {
        VirtioMem::new(GuestAddress(0), 0).unwrap()
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
