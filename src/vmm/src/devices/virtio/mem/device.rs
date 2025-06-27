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
use crate::devices::virtio::iovec::IoVecBufferMut;
use crate::devices::virtio::mem::VIRTIO_MEM_BLOCK_SIZE;
use crate::devices::virtio::queue::{FIRECRACKER_MAX_QUEUE_SIZE, InvalidAvailIdx, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::devices::virtio::{ActivateError, TYPE_MEM};
use crate::logger::{IncMetric, debug, error};
use crate::vstate::memory::{ByteValued, GuestMemoryMmap};

pub const VIRTIO_MEM_DEV_ID: &str = "mem";

// Virtio-mem feature bits
const VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE: u64 = 1;

// Virtio-mem request types
const VIRTIO_MEM_REQ_PLUG: u16 = 0;
const VIRTIO_MEM_REQ_UNPLUG: u16 = 1;
const VIRTIO_MEM_REQ_UNPLUG_ALL: u16 = 2;
const VIRTIO_MEM_REQ_STATE: u16 = 3;

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

    buffer: IoVecBufferMut,
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

        Ok(Self {
            avail_features: (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE),
            acked_features: 0u64,
            activate_event,
            device_state: DeviceState::Inactive,
            queues,
            queue_events,
            config: VirtioMemConfig::new(addr, size),
            buffer: IoVecBufferMut::new()?,
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

    fn handle_plug_request(&mut self) -> Result<(), VirtioMemError> {
        // TODO: Implement memory plugging
        debug!("Memory plugging not implemented");
        Ok(())
    }

    fn handle_unplug_request(&mut self) -> Result<(), VirtioMemError> {
        // TODO: Implement memory unplugging
        debug!("Memory unplugging not implemented");
        Ok(())
    }

    fn handle_unplug_all_request(&mut self) -> Result<(), VirtioMemError> {
        // TODO: Implement memory unplug all
        debug!("Memory unplug all not implemented");
        Ok(())
    }

    fn handle_state_request(&mut self) -> Result<(), VirtioMemError> {
        // TODO: Implement state querying
        debug!("State querying not implemented");
        Ok(())
    }

    fn process_mem_queue(&mut self) -> Result<(), InvalidAvailIdx> {
        while let Some(desc) = self.queues[MEM_QUEUE].pop()? {
            let mem = &self.device_state.active_state().unwrap().mem;
            let index = desc.index;
            METRICS.mem_event_count.inc();

            // SAFETY: This descriptor chain is only loaded into one buffer
            if let Err(err) = unsafe { self.buffer.load_descriptor_chain(mem, desc) } {
                error!("virtio-mem: Failed to load descriptor chain: {err}");
                METRICS.mem_event_fails.inc();
                continue;
            }

            if self.buffer.len() < 2 {
                error!("virtio-mem: Request too small");
                METRICS.mem_event_fails.inc();
                continue;
            }

            // For now, assume request type 0 (PLUG) as we can't easily read from IoVecBufferMut
            // TODO: Implement proper request parsing when needed
            let req_type = VIRTIO_MEM_REQ_PLUG;

            let result = match req_type {
                VIRTIO_MEM_REQ_PLUG => self.handle_plug_request(),
                VIRTIO_MEM_REQ_UNPLUG => self.handle_unplug_request(),
                VIRTIO_MEM_REQ_UNPLUG_ALL => self.handle_unplug_all_request(),
                VIRTIO_MEM_REQ_STATE => self.handle_state_request(),
                _ => {
                    error!("virtio-mem: Unknown request type: {req_type}");
                    METRICS.mem_event_fails.inc();
                    continue;
                }
            };

            if result.is_err() {
                METRICS.mem_event_fails.inc();
            }

            // Add used descriptor back to queue
            if let Err(err) = self.queues[MEM_QUEUE].add_used(index, 0) {
                error!("virtio-mem: Failed to add used descriptor: {err}");
                METRICS.mem_event_fails.inc();
            }
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

    pub fn process_virtio_queues(&mut self) -> Result<(), InvalidAvailIdx> {
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
        VirtioMem::new().unwrap()
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
