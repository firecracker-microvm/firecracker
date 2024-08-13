// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use aws_lc_rs::rand;
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryError;

use super::metrics::METRICS;
use super::{RNG_NUM_QUEUES, RNG_QUEUE};
use crate::devices::virtio::device::{DeviceState, IrqTrigger, IrqType, VirtioDevice};
use crate::devices::virtio::gen::virtio_rng::VIRTIO_F_VERSION_1;
use crate::devices::virtio::iovec::IoVecBufferMut;
use crate::devices::virtio::queue::{Queue, FIRECRACKER_MAX_QUEUE_SIZE};
use crate::devices::virtio::{ActivateError, TYPE_RNG};
use crate::devices::DeviceError;
use crate::logger::{debug, error, IncMetric};
use crate::rate_limiter::{RateLimiter, TokenType};
use crate::vstate::memory::GuestMemoryMmap;

pub const ENTROPY_DEV_ID: &str = "rng";

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EntropyError {
    /// Error while handling an Event file descriptor: {0}
    EventFd(#[from] io::Error),
    /// Bad guest memory buffer: {0}
    GuestMemory(#[from] GuestMemoryError),
    /// Could not get random bytes: {0}
    Random(#[from] aws_lc_rs::error::Unspecified),
}

#[derive(Debug)]
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

    // Device specific fields
    rate_limiter: RateLimiter,
}

impl Entropy {
    pub fn new(rate_limiter: RateLimiter) -> Result<Self, EntropyError> {
        let queues = vec![Queue::new(FIRECRACKER_MAX_QUEUE_SIZE); RNG_NUM_QUEUES];
        Self::new_with_queues(queues, rate_limiter)
    }

    pub fn new_with_queues(
        queues: Vec<Queue>,
        rate_limiter: RateLimiter,
    ) -> Result<Self, EntropyError> {
        let activate_event = EventFd::new(libc::EFD_NONBLOCK)?;
        let queue_events = (0..RNG_NUM_QUEUES)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK))
            .collect::<Result<Vec<EventFd>, io::Error>>()?;
        let irq_trigger = IrqTrigger::new()?;

        Ok(Self {
            avail_features: 1 << VIRTIO_F_VERSION_1,
            acked_features: 0u64,
            activate_event,
            device_state: DeviceState::Inactive,
            queues,
            queue_events,
            irq_trigger,
            rate_limiter,
        })
    }

    pub fn id(&self) -> &str {
        ENTROPY_DEV_ID
    }

    fn signal_used_queue(&self) -> Result<(), DeviceError> {
        self.irq_trigger
            .trigger_irq(IrqType::Vring)
            .map_err(DeviceError::FailedSignalingIrq)
    }

    fn rate_limit_request(rate_limiter: &mut RateLimiter, bytes: u64) -> bool {
        if !rate_limiter.consume(1, TokenType::Ops) {
            return false;
        }

        if !rate_limiter.consume(bytes, TokenType::Bytes) {
            rate_limiter.manual_replenish(1, TokenType::Ops);
            return false;
        }

        true
    }

    fn rate_limit_replenish_request(rate_limiter: &mut RateLimiter, bytes: u64) {
        rate_limiter.manual_replenish(1, TokenType::Ops);
        rate_limiter.manual_replenish(bytes, TokenType::Bytes);
    }

    fn handle_one(&self, iovec: &mut IoVecBufferMut) -> Result<u32, EntropyError> {
        // If guest provided us with an empty buffer just return directly
        if iovec.len() == 0 {
            return Ok(0);
        }

        let mut rand_bytes = vec![0; iovec.len() as usize];
        rand::fill(&mut rand_bytes).map_err(|err| {
            METRICS.host_rng_fails.inc();
            err
        })?;

        // It is ok to unwrap here. We are writing `iovec.len()` bytes at offset 0.
        iovec.write_all_volatile_at(&rand_bytes, 0).unwrap();
        Ok(iovec.len())
    }

    fn process_entropy_queue(&mut self) {
        // This is safe since we checked in the event handler that the device is activated.
        let mem = self.device_state.mem().unwrap();

        let mut used_any = false;
        while let Some(desc) = self.queues[RNG_QUEUE].pop(mem) {
            let index = desc.index;
            METRICS.entropy_event_count.inc();

            let bytes = match IoVecBufferMut::from_descriptor_chain(desc) {
                Ok(mut iovec) => {
                    debug!(
                        "entropy: guest request for {} bytes of entropy",
                        iovec.len()
                    );

                    // Check for available rate limiting budget.
                    // If not enough budget is available, leave the request descriptor in the queue
                    // to handle once we do have budget.
                    if !Self::rate_limit_request(&mut self.rate_limiter, u64::from(iovec.len())) {
                        debug!("entropy: throttling entropy queue");
                        METRICS.entropy_rate_limiter_throttled.inc();
                        self.queues[RNG_QUEUE].undo_pop();
                        break;
                    }

                    self.handle_one(&mut iovec).unwrap_or_else(|err| {
                        error!("entropy: {err}");
                        METRICS.entropy_event_fails.inc();
                        0
                    })
                }
                Err(err) => {
                    error!("entropy: Could not parse descriptor chain: {err}");
                    METRICS.entropy_event_fails.inc();
                    0
                }
            };

            match self.queues[RNG_QUEUE].add_used(mem, index, bytes) {
                Ok(_) => {
                    used_any = true;
                    METRICS.entropy_bytes.add(bytes.into());
                }
                Err(err) => {
                    error!("entropy: Could not add used descriptor to queue: {err}");
                    Self::rate_limit_replenish_request(&mut self.rate_limiter, bytes.into());
                    METRICS.entropy_event_fails.inc();
                    // If we are not able to add a buffer to the used queue, something
                    // is probably seriously wrong, so just stop processing additional
                    // buffers
                    break;
                }
            }
        }

        if used_any {
            self.signal_used_queue().unwrap_or_else(|err| {
                error!("entropy: {err:?}");
                METRICS.entropy_event_fails.inc()
            });
        }
    }

    pub(crate) fn process_entropy_queue_event(&mut self) {
        if let Err(err) = self.queue_events[RNG_QUEUE].read() {
            error!("Failed to read entropy queue event: {err}");
            METRICS.entropy_event_fails.inc();
        } else if !self.rate_limiter.is_blocked() {
            // We are not throttled, handle the entropy queue
            self.process_entropy_queue();
        } else {
            METRICS.rate_limiter_event_count.inc();
        }
    }

    pub(crate) fn process_rate_limiter_event(&mut self) {
        METRICS.rate_limiter_event_count.inc();
        match self.rate_limiter.event_handler() {
            Ok(_) => {
                // There might be enough budget now to process entropy requests.
                self.process_entropy_queue();
            }
            Err(err) => {
                error!("entropy: Failed to handle rate-limiter event: {err:?}");
                METRICS.entropy_event_fails.inc();
            }
        }
    }

    pub fn process_virtio_queues(&mut self) {
        self.process_entropy_queue();
    }

    pub fn rate_limiter(&self) -> &RateLimiter {
        &self.rate_limiter
    }

    pub(crate) fn set_avail_features(&mut self, features: u64) {
        self.avail_features = features;
    }

    pub(crate) fn set_acked_features(&mut self, features: u64) {
        self.acked_features = features;
    }

    pub(crate) fn set_irq_status(&mut self, status: u32) {
        self.irq_trigger.irq_status = Arc::new(AtomicU32::new(status));
    }

    pub(crate) fn set_activated(&mut self, mem: GuestMemoryMmap) {
        self.device_state = DeviceState::Activated(mem);
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

    fn interrupt_trigger(&self) -> &IrqTrigger {
        &self.irq_trigger
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

    fn activate(&mut self, mem: GuestMemoryMmap) -> Result<(), ActivateError> {
        self.activate_event.write(1).map_err(|_| {
            METRICS.activate_fails.inc();
            ActivateError::EventFd
        })?;
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::check_metric_after_block;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::queue::VIRTQ_DESC_F_WRITE;
    use crate::devices::virtio::test_utils::test::{
        create_virtio_mem, VirtioTestDevice, VirtioTestHelper,
    };

    impl VirtioTestDevice for Entropy {
        fn set_queues(&mut self, queues: Vec<Queue>) {
            self.queues = queues;
        }

        fn num_queues() -> usize {
            RNG_NUM_QUEUES
        }
    }

    fn default_entropy() -> Entropy {
        Entropy::new(RateLimiter::default()).unwrap()
    }

    #[test]
    fn test_new() {
        let entropy_dev = default_entropy();

        assert_eq!(entropy_dev.avail_features(), 1 << VIRTIO_F_VERSION_1);
        assert_eq!(entropy_dev.acked_features(), 0);
        assert!(!entropy_dev.is_activated());
    }

    #[test]
    fn test_id() {
        let entropy_dev = default_entropy();
        assert_eq!(entropy_dev.id(), ENTROPY_DEV_ID);
    }

    #[test]
    fn test_device_type() {
        let entropy_dev = default_entropy();
        assert_eq!(entropy_dev.device_type(), TYPE_RNG);
    }

    #[test]
    fn test_read_config() {
        let entropy_dev = default_entropy();
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
        let mut entropy_dev = default_entropy();
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
        let mut entropy_dev = default_entropy();

        let features = 1 << VIRTIO_F_VERSION_1;

        assert_eq!(
            entropy_dev.avail_features_by_page(0),
            (features & 0xFFFFFFFF) as u32,
        );
        assert_eq!(
            entropy_dev.avail_features_by_page(1),
            (features >> 32) as u32
        );
        for i in 2..10 {
            assert_eq!(entropy_dev.avail_features_by_page(i), 0u32);
        }

        for i in 0..10 {
            entropy_dev.ack_features_by_page(i, u32::MAX);
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

        // Add a write-only descriptor with 0 bytes. This should not fail.
        th.add_desc_chain(RNG_QUEUE, 0, &[(2, 0, VIRTQ_DESC_F_WRITE)]);

        let mut entropy_dev = th.device();

        // This should succeed, we just added two descriptors
        let desc = entropy_dev.queues_mut()[RNG_QUEUE].pop(&mem).unwrap();
        assert!(matches!(
            IoVecBufferMut::from_descriptor_chain(desc),
            Err(crate::devices::virtio::iovec::IoVecError::ReadOnlyDescriptor)
        ));

        // This should succeed, we should have one more descriptor
        let desc = entropy_dev.queues_mut()[RNG_QUEUE].pop(&mem).unwrap();
        let mut iovec = IoVecBufferMut::from_descriptor_chain(desc).unwrap();
        entropy_dev.handle_one(&mut iovec).unwrap();
    }

    #[test]
    fn test_entropy_event() {
        let mem = create_virtio_mem();
        let mut th = VirtioTestHelper::<Entropy>::new(&mem, default_entropy());

        th.activate_device(&mem);

        // Add a read-only descriptor (this should fail)
        th.add_desc_chain(RNG_QUEUE, 0, &[(0, 64, 0)]);

        let entropy_event_fails = METRICS.entropy_event_fails.count();
        let entropy_event_count = METRICS.entropy_event_count.count();
        let entropy_bytes = METRICS.entropy_bytes.count();
        let host_rng_fails = METRICS.host_rng_fails.count();
        assert_eq!(th.emulate_for_msec(100).unwrap(), 1);
        assert_eq!(METRICS.entropy_event_fails.count(), entropy_event_fails + 1);
        assert_eq!(METRICS.entropy_event_count.count(), entropy_event_count + 1);
        assert_eq!(METRICS.entropy_bytes.count(), entropy_bytes);
        assert_eq!(METRICS.host_rng_fails.count(), host_rng_fails);

        // Add two good descriptors
        th.add_desc_chain(RNG_QUEUE, 0, &[(1, 10, VIRTQ_DESC_F_WRITE)]);
        th.add_desc_chain(RNG_QUEUE, 100, &[(2, 20, VIRTQ_DESC_F_WRITE)]);

        let entropy_event_fails = METRICS.entropy_event_fails.count();
        let entropy_event_count = METRICS.entropy_event_count.count();
        let entropy_bytes = METRICS.entropy_bytes.count();
        let host_rng_fails = METRICS.host_rng_fails.count();
        assert_eq!(th.emulate_for_msec(100).unwrap(), 1);
        assert_eq!(METRICS.entropy_event_fails.count(), entropy_event_fails);
        assert_eq!(METRICS.entropy_event_count.count(), entropy_event_count + 2);
        assert_eq!(METRICS.entropy_bytes.count(), entropy_bytes + 30);
        assert_eq!(METRICS.host_rng_fails.count(), host_rng_fails);

        th.add_desc_chain(
            RNG_QUEUE,
            0,
            &[
                (3, 128, VIRTQ_DESC_F_WRITE),
                (4, 128, VIRTQ_DESC_F_WRITE),
                (5, 256, VIRTQ_DESC_F_WRITE),
            ],
        );

        let entropy_event_fails = METRICS.entropy_event_fails.count();
        let entropy_event_count = METRICS.entropy_event_count.count();
        let entropy_bytes = METRICS.entropy_bytes.count();
        let host_rng_fails = METRICS.host_rng_fails.count();
        assert_eq!(th.emulate_for_msec(100).unwrap(), 1);
        assert_eq!(METRICS.entropy_event_fails.count(), entropy_event_fails);
        assert_eq!(METRICS.entropy_event_count.count(), entropy_event_count + 1);
        assert_eq!(METRICS.entropy_bytes.count(), entropy_bytes + 512);
        assert_eq!(METRICS.host_rng_fails.count(), host_rng_fails);
    }

    #[test]
    fn test_bad_rate_limiter_event() {
        let mem = create_virtio_mem();
        let mut th = VirtioTestHelper::<Entropy>::new(&mem, default_entropy());

        th.activate_device(&mem);
        let mut dev = th.device();

        check_metric_after_block!(
            &METRICS.entropy_event_fails,
            1,
            dev.process_rate_limiter_event()
        );
    }

    #[test]
    fn test_bandwidth_rate_limiter() {
        let mem = create_virtio_mem();
        // Rate Limiter with 4000 bytes / sec allowance and no initial burst allowance
        let device = Entropy::new(RateLimiter::new(4000, 0, 1000, 0, 0, 0).unwrap()).unwrap();
        let mut th = VirtioTestHelper::<Entropy>::new(&mem, device);

        th.activate_device(&mem);

        // We are asking for 4000 bytes which should be available, so the
        // buffer should be processed normally
        th.add_desc_chain(RNG_QUEUE, 0, &[(0, 4000, VIRTQ_DESC_F_WRITE)]);
        check_metric_after_block!(
            METRICS.entropy_bytes,
            4000,
            th.device().process_entropy_queue()
        );
        assert!(!th.device().rate_limiter.is_blocked());

        // Completely replenish the rate limiter
        th.device()
            .rate_limiter
            .manual_replenish(4000, TokenType::Bytes);

        // Add two descriptors. The first one should drain the available budget,
        // so the next one should be throttled.
        th.add_desc_chain(RNG_QUEUE, 0, &[(0, 4000, VIRTQ_DESC_F_WRITE)]);
        th.add_desc_chain(RNG_QUEUE, 1, &[(1, 1000, VIRTQ_DESC_F_WRITE)]);
        check_metric_after_block!(
            METRICS.entropy_bytes,
            4000,
            th.device().process_entropy_queue()
        );
        check_metric_after_block!(
            METRICS.entropy_rate_limiter_throttled,
            1,
            th.device().process_entropy_queue()
        );
        assert!(th.device().rate_limiter().is_blocked());

        // 250 msec should give enough time for replenishing 1000 bytes worth of tokens.
        // Give it an extra 100 ms just to be sure the timer event reaches us from the kernel.
        std::thread::sleep(Duration::from_millis(350));
        check_metric_after_block!(METRICS.entropy_bytes, 1000, th.emulate_for_msec(100));
        assert!(!th.device().rate_limiter().is_blocked());
    }

    #[test]
    fn test_ops_rate_limiter() {
        let mem = create_virtio_mem();
        // Rate Limiter with unlimited bandwidth and allowance for 1 operation every 100 msec,
        // (10 ops/sec), without initial burst.
        let device = Entropy::new(RateLimiter::new(0, 0, 0, 1, 0, 100).unwrap()).unwrap();
        let mut th = VirtioTestHelper::<Entropy>::new(&mem, device);

        th.activate_device(&mem);

        // We don't have a bandwidth limit and we can do 10 requests per sec
        // so this should succeed.
        th.add_desc_chain(RNG_QUEUE, 0, &[(0, 4000, VIRTQ_DESC_F_WRITE)]);
        check_metric_after_block!(
            METRICS.entropy_bytes,
            4000,
            th.device().process_entropy_queue()
        );
        assert!(!th.device().rate_limiter.is_blocked());

        // Sleep for 1 second to completely replenish the rate limiter
        std::thread::sleep(Duration::from_millis(1000));

        // First one should succeed
        let entropy_bytes = METRICS.entropy_bytes.count();
        th.add_desc_chain(RNG_QUEUE, 0, &[(0, 64, VIRTQ_DESC_F_WRITE)]);
        check_metric_after_block!(METRICS.entropy_bytes, 64, th.emulate_for_msec(100));
        assert_eq!(METRICS.entropy_bytes.count(), entropy_bytes + 64);
        // The rate limiter is not blocked yet.
        assert!(!th.device().rate_limiter().is_blocked());
        // But immediately asking another operation should block it because we have 1 op every 100
        // msec.
        th.add_desc_chain(RNG_QUEUE, 0, &[(0, 64, VIRTQ_DESC_F_WRITE)]);
        check_metric_after_block!(
            METRICS.entropy_rate_limiter_throttled,
            1,
            th.emulate_for_msec(50)
        );
        // Entropy bytes count should not have increased.
        assert_eq!(METRICS.entropy_bytes.count(), entropy_bytes + 64);
        // After 100 msec (plus 50 msec for ensuring the event reaches us from the kernel), the
        // timer of the rate limiter should fire saying that there's now more tokens available
        check_metric_after_block!(
            METRICS.rate_limiter_event_count,
            1,
            th.emulate_for_msec(150)
        );
        // The rate limiter event should have processed the pending buffer as well
        assert_eq!(METRICS.entropy_bytes.count(), entropy_bytes + 128);
    }
}
