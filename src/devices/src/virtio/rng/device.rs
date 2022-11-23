// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use logger::{debug, error};
use rand::rngs::OsRng;
use rand::RngCore;
use utils::eventfd::EventFd;
use utils::vm_memory::{GuestMemoryError, GuestMemoryMmap};
use virtio_gen::virtio_rng::VIRTIO_F_VERSION_1;

use super::{NUM_QUEUES, QUEUE_SIZE, RNG_QUEUE};
use crate::virtio::device::{IrqTrigger, IrqType};
use crate::virtio::iovec::IoVecBufferMut;
use crate::virtio::{ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_RNG};
use crate::Error as DeviceError;

pub const ENTROPY_DEV_ID: &str = "rng";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error while handling an Event file descriptor: {0}")]
    EventFd(#[from] io::Error),
    #[error("Bad guest memory buffer: {0}")]
    GuestMemory(#[from] GuestMemoryError),
    #[error("Could not get random bytes: {0}")]
    Random(#[from] rand::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub struct Entropy {
    // VirtIO fields
    avail_features: u64,
    acked_features: u64,
    activate_event: EventFd,

    // Transport fields
    device_state: DeviceState,
    queues: Vec<Queue>,
    queue_events: Vec<EventFd>,
    irq_trigger: IrqTrigger,
}

impl Entropy {
    pub fn new() -> Result<Self> {
        let queues = vec![Queue::new(QUEUE_SIZE); NUM_QUEUES];
        Self::new_with_queues(queues)
    }

    pub fn new_with_queues(queues: Vec<Queue>) -> Result<Self> {
        let activate_event = EventFd::new(libc::EFD_NONBLOCK)?;
        let queue_events = (0..NUM_QUEUES)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK))
            .collect::<std::result::Result<Vec<EventFd>, io::Error>>()?;
        let irq_trigger = IrqTrigger::new()?;

        Ok(Self {
            avail_features: 1 << VIRTIO_F_VERSION_1,
            acked_features: 0u64,
            activate_event,
            device_state: DeviceState::Inactive,
            queues,
            queue_events,
            irq_trigger,
        })
    }

    pub fn id(&self) -> &str {
        ENTROPY_DEV_ID
    }

    fn signal_used_queue(&self) -> std::result::Result<(), DeviceError> {
        debug!("entropy: raising IRQ");
        self.irq_trigger
            .trigger_irq(IrqType::Vring)
            .map_err(DeviceError::FailedSignalingIrq)
    }

    fn handle_one(&self, iovec: &mut IoVecBufferMut) -> Result<u32> {
        let mut rand_bytes = vec![0; iovec.len()];
        OsRng.try_fill_bytes(&mut rand_bytes)?;

        // It is ok to unwrap here. We are writing `iovec.len()` bytes at offset 0.
        Ok(iovec.write_at(&rand_bytes, 0).unwrap().try_into().unwrap())
    }

    fn process_entropy_queue(&mut self) {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();

        let mut used_any = false;
        while let Some(desc) = self.queues[RNG_QUEUE].pop(mem) {
            let index = desc.index;
            let bytes = match IoVecBufferMut::from_descriptor_chain(mem, desc) {
                Ok(mut iovec) => self.handle_one(&mut iovec).unwrap_or_else(|err| {
                    error!("entropy: {err}");
                    0
                }),
                Err(err) => {
                    error!("entropy: Could not parse descriptor chain: {err}");
                    0
                }
            };

            match self.queues[RNG_QUEUE].add_used(mem, index, bytes) {
                Ok(_) => {
                    used_any = true;
                }
                Err(err) => {
                    error!("entropy: Could not add used descriptor to queue: {err}");
                    // If we are not able to add a buffer to the used queue, something
                    // is probably seriously wrong, so just stop processing additional
                    // buffers
                    break;
                }
            }
        }

        if used_any {
            self.signal_used_queue()
                .unwrap_or_else(|err| error!("entropy: {err:?}"));
        }
    }

    pub(crate) fn process_entropy_queue_event(&mut self) {
        match self.queue_events[RNG_QUEUE].read() {
            Ok(_) => self.process_entropy_queue(),
            Err(err) => error!("Failed to read entropy queue event: {err}"),
        }
    }

    pub fn process_virtio_queues(&mut self) {
        self.process_entropy_queue();
    }

    pub(crate) fn activate_event(&self) -> &EventFd {
        &self.activate_event
    }
}

impl VirtioDevice for Entropy {
    fn device_type(&self) -> u32 {
        TYPE_RNG
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

    fn interrupt_evt(&self) -> &EventFd {
        &self.irq_trigger.irq_evt
    }

    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.irq_trigger.irq_status.clone()
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

    fn read_config(&self, _offset: u64, mut _data: &mut [u8]) {}

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        self.activate_event.write(1).map_err(|err| {
            error!("entropy: Cannot write to activate_evt: {err}");
            super::super::ActivateError::BadActivate
        })?;
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::device::VirtioDevice;
    use crate::virtio::test_utils::test::{create_virtio_mem, VirtioTestDevice, VirtioTestHelper};
    use crate::virtio::VIRTQ_DESC_F_WRITE;

    impl VirtioTestDevice for Entropy {
        fn set_queues(&mut self, queues: Vec<Queue>) {
            self.queues = queues;
        }

        fn num_queues() -> usize {
            NUM_QUEUES
        }
    }

    fn default_entropy() -> Entropy {
        Entropy::new().unwrap()
    }

    #[test]
    fn test_new() {
        let entropy_dev = Entropy::new().unwrap();

        assert_eq!(entropy_dev.avail_features(), 1 << VIRTIO_F_VERSION_1);
        assert_eq!(entropy_dev.acked_features(), 0);
        assert!(!entropy_dev.is_activated());
    }

    #[test]
    fn test_id() {
        let entropy_dev = Entropy::new().unwrap();
        assert_eq!(entropy_dev.id(), ENTROPY_DEV_ID);
    }

    #[test]
    fn test_device_type() {
        let entropy_dev = Entropy::new().unwrap();
        assert_eq!(entropy_dev.device_type(), TYPE_RNG);
    }

    #[test]
    fn test_read_config() {
        let entropy_dev = Entropy::new().unwrap();
        let mut config = vec![0; 10];

        entropy_dev.read_config(0, &mut config);
        assert_eq!(config, vec![0; 10]);

        entropy_dev.read_config(1, &mut config);
        assert_eq!(config, vec![0; 10]);

        entropy_dev.read_config(2, &mut config);
        assert_eq!(config, vec![0; 10]);

        entropy_dev.read_config(1024, &mut config);
        assert_eq!(config, vec![0; 10]);
    }

    #[test]
    fn test_write_config() {
        let mut entropy_dev = Entropy::new().unwrap();
        let mut read_config = vec![0; 10];
        let write_config = vec![42; 10];

        entropy_dev.write_config(0, &write_config);
        entropy_dev.read_config(0, &mut read_config);
        assert_eq!(read_config, vec![0; 10]);

        entropy_dev.write_config(1, &write_config);
        entropy_dev.read_config(1, &mut read_config);
        assert_eq!(read_config, vec![0; 10]);

        entropy_dev.write_config(2, &write_config);
        entropy_dev.read_config(2, &mut read_config);
        assert_eq!(read_config, vec![0; 10]);

        entropy_dev.write_config(1024, &write_config);
        entropy_dev.read_config(1024, &mut read_config);
        assert_eq!(read_config, vec![0; 10]);
    }

    #[test]
    fn test_virtio_device_features() {
        let mut entropy_dev = Entropy::new().unwrap();

        let features = 1 << VIRTIO_F_VERSION_1;

        assert_eq!(entropy_dev.avail_features_by_page(0), features as u32);
        assert_eq!(
            entropy_dev.avail_features_by_page(1),
            (features >> 32) as u32
        );
        for i in 2..10 {
            assert_eq!(entropy_dev.avail_features_by_page(i), 0u32);
        }

        for i in 0..10 {
            entropy_dev.ack_features_by_page(i, std::u32::MAX);
        }

        assert_eq!(entropy_dev.acked_features, features);
    }

    #[test]
    fn test_handle_one() {
        let mem = create_virtio_mem();
        let mut th = VirtioTestHelper::<Entropy>::new(&mem, default_entropy());

        // Checks that device activation works
        th.activate_device(&mem);

        // Add a read-only descriptor (this should fail)
        th.add_desc_chain(RNG_QUEUE, 0, &[(0, 64, 0)]);

        // Add a write-only descriptor with 10 bytes
        th.add_desc_chain(RNG_QUEUE, 0, &[(1, 10, VIRTQ_DESC_F_WRITE)]);

        let mut entropy_dev = th.device();

        // This should succeed, we just added two descriptors
        let desc = entropy_dev.queues_mut()[RNG_QUEUE].pop(&mem).unwrap();
        assert!(matches!(
            IoVecBufferMut::from_descriptor_chain(&mem, desc,),
            Err(crate::virtio::iovec::Error::ReadOnlyDescriptor)
        ));

        // This should succeed, we should have one more descriptor
        let desc = entropy_dev.queues_mut()[RNG_QUEUE].pop(&mem).unwrap();
        let mut iovec = IoVecBufferMut::from_descriptor_chain(&mem, desc).unwrap();
        assert!(entropy_dev.handle_one(&mut iovec).is_ok());
    }
}
