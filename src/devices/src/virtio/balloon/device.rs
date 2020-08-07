// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cmp;
use std::io::{self, Write};
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use logger::{error, Metric, METRICS};
use utils::eventfd::EventFd;
use virtio_gen::virtio_blk::*;
use vm_memory::{
    Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap,
};

use super::{
    super::{
        ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_BALLOON, VIRTIO_MMIO_INT_VRING,
    },
    DEFLATE_INDEX, INFLATE_INDEX, MAX_PAGES_IN_DESC, NUM_QUEUES, QUEUE_SIZES,
    VIRTIO_BALLOON_F_DEFLATE_ON_OOM, VIRTIO_BALLOON_F_MUST_TELL_HOST, VIRTIO_BALLOON_PFN_SHIFT,
    utils::{compact_page_frame_numbers, remove_range},
};

use crate::{report_balloon_event_fail, Error as DeviceError};

const SIZE_OF_U32: usize = 4;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct ConfigSpace {
    num_pages: u32,
    actual_pages: u32,
}

// Safe because ConfigSpace only contains plain data.
unsafe impl ByteValued for ConfigSpace {}

// Virtio balloon device.
pub struct Balloon {
    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) config_space: ConfigSpace,
    pub(crate) activate_evt: EventFd,

    // Transport related fields.
    pub(crate) queues: Vec<Queue>,
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    pub(crate) queue_evts: [EventFd; NUM_QUEUES],
    pub(crate) device_state: DeviceState,
}

impl Balloon {
    pub fn new(num_pages: u32, must_tell_host: bool, deflate_on_oom: bool) -> io::Result<Balloon> {
        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1;

        if must_tell_host {
            avail_features |= 1u64 << VIRTIO_BALLOON_F_MUST_TELL_HOST;
        };

        if deflate_on_oom {
            avail_features |= 1u64 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM;
        };

        let queue_evts = [
            EventFd::new(libc::EFD_NONBLOCK)?,
            EventFd::new(libc::EFD_NONBLOCK)?,
        ];

        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        Ok(Balloon {
            avail_features,
            acked_features: 0u64,
            config_space: ConfigSpace {
                num_pages,
                actual_pages: 0,
            },
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK)?,
            queue_evts,
            queues,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK)?,
        })
    }

    pub(crate) fn process_inflate_queue_event(&mut self) {
        if let Err(e) = self.queue_evts[INFLATE_INDEX].read() {
            error!("Failed to get queue event: {:?}", e);
            METRICS.balloon.event_fails.inc();
        } else {
            self.process_inflate()
                .unwrap_or_else(report_balloon_event_fail);
        }
    }

    pub(crate) fn process_deflate_queue_event(&mut self) {
        if let Err(e) = self.queue_evts[DEFLATE_INDEX].read() {
            error!("Failed to get queue event: {:?}", e);
            METRICS.balloon.event_fails.inc();
        } else if self.process_deflate_queue() {
            let _ = self.signal_used_queue();
        }
    }

    pub(crate) fn process_inflate(&mut self) -> Result<(), DeviceError> {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };
        METRICS.balloon.inflate_count.inc();

        let queue = &mut self.queues[INFLATE_INDEX];
        let mut pages = Vec::with_capacity(MAX_PAGES_IN_DESC);
        let mut needs_interrupt = false;

        while let Some(head) = queue.pop(&mem) {
            let len = head.len;
            if !head.is_write_only() && len % SIZE_OF_U32 as u32 == 0 {
                for index in (0..len).step_by(SIZE_OF_U32) {
                    let addr = head
                        .addr
                        .checked_add(index as u64)
                        .ok_or(DeviceError::MalformedDescriptor)?;

                    let page_frame_number = mem
                        .read_obj::<u32>(addr)
                        .map_err(|_| DeviceError::MalformedDescriptor)?;

                    pages.push(page_frame_number);
                }
            }

            // Acknowledge the receipt of the descriptor.
            // 0 is number of bytes the device has written to memory.
            queue.add_used(&mem, head.index, 0);
            needs_interrupt = true;
        }

        if needs_interrupt {
            let _ = self.signal_used_queue();
        }

        // Compact pages into ranges.
        let page_ranges = compact_page_frame_numbers(&mut pages);

        // Remove the page ranges.
        for (page_frame_number, range_len) in page_ranges {
            let guest_addr = GuestAddress((page_frame_number as u64) << VIRTIO_BALLOON_PFN_SHIFT);

            match remove_range(
                &mem,
                (guest_addr, u64::from(range_len) << VIRTIO_BALLOON_PFN_SHIFT),
            ) {
                Ok(_) => continue,
                Err(e) => {
                    error!("Error removing memory range: {:?}", e);
                }
            };
        }

        Ok(())
    }

    pub(crate) fn process_deflate_queue(&mut self) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };
        METRICS.balloon.deflate_count.inc();

        let queue = &mut self.queues[DEFLATE_INDEX];
        let mut needs_interrupt = false;

        while let Some(head) = queue.pop(&mem) {
            queue.add_used(&mem, head.index, 0);
            needs_interrupt = true;
        }

        needs_interrupt
    }

    pub(crate) fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);

        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            DeviceError::FailedSignalingUsedQueue(e)
        })?;
        Ok(())
    }

    pub fn update_num_pages(&mut self, num_pages: u32) {
        self.config_space.num_pages = num_pages;
    }

    pub fn num_pages(&self) -> u32 {
        self.config_space.num_pages
    }
}

impl VirtioDevice for Balloon {
    fn device_type(&self) -> u32 {
        TYPE_BALLOON
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.interrupt_status.clone()
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

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_space_bytes = self.config_space.as_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }

        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(
                &config_space_bytes[offset as usize..cmp::min(end, config_len) as usize],
            )
            .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_space_bytes = self.config_space.as_mut_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        config_space_bytes[offset as usize..(offset + data_len) as usize].copy_from_slice(data);
    }

    fn is_activated(&self) -> bool {
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.activate_evt.write(1).is_err() {
            error!("Balloon: Cannot write to activate_evt");
            METRICS.balloon.activate_fails.inc();
            return Err(super::super::ActivateError::BadActivate);
        }
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::unix::io::AsRawFd;
    use std::u32;

    use super::super::CONFIG_SPACE_SIZE;
    use super::*;
    use crate::virtio::queue::tests::*;
    use polly::event_manager::{EventManager, Subscriber};
    use utils::epoll::{EpollEvent, EventSet};
    use vm_memory::GuestAddress;

    /// Will read $metric, run the code in $block, then assert metric has increased by $delta.
    macro_rules! check_metric_after_block {
        ($metric:expr, $delta:expr, $block:expr) => {{
            let before = $metric.count();
            let _ = $block;
            assert_eq!($metric.count(), before + $delta, "unexpected metric value");
        }};
    }

    impl Balloon {
        pub(crate) fn set_queue(&mut self, idx: usize, q: Queue) {
            self.queues[idx] = q;
        }

        pub(crate) fn actual_pages(&self) -> u32 {
            self.config_space.actual_pages
        }

        pub fn update_actual_pages(&mut self, actual_pages: u32) {
            self.config_space.actual_pages = actual_pages;
        }
    }

    pub fn default_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap()
    }

    fn invoke_handler_for_queue_event(b: &mut Balloon, queue_index: usize) {
        assert!(queue_index < NUM_QUEUES);
        // Trigger the queue event.
        b.queue_evts[queue_index].write(1).unwrap();
        // Handle event.
        b.process(
            &EpollEvent::new(EventSet::IN, b.queue_evts[queue_index].as_raw_fd() as u64),
            &mut EventManager::new().unwrap(),
        );
        // Validate the queue operation finished successfully.
        assert_eq!(b.interrupt_evt.read().unwrap(), 1);
    }

    pub(crate) fn set_request(queue: &VirtQueue, idx: usize, addr: u64, len: u32, flags: u16) {
        // Set the index of the next request.
        queue.avail.idx.set((idx + 1) as u16);
        // Set the current descriptor table entry index.
        queue.avail.ring[idx].set(idx as u16);
        // Set the current descriptor table entry.
        queue.dtable[idx].set(addr, len, flags, 1);
    }

    pub(crate) fn check_request_completion(queue: &VirtQueue, idx: usize) {
        // Check that the next used will be idx + 1.
        assert_eq!(queue.used.idx.get(), (idx + 1) as u16);
        // Check that the current used is idx.
        assert_eq!(queue.used.ring[idx].get().id, idx as u32);
        // The length of the completed request is 0.
        assert_eq!(queue.used.ring[idx].get().len, 0);
    }

    #[test]
    fn test_virtio_features() {
        // Test all feature combinations.
        for must_tell_host in vec![true, false].iter() {
            for deflate_on_oom in vec![true, false].iter() {
                let mut balloon = Balloon::new(0, *must_tell_host, *deflate_on_oom).unwrap();
                assert_eq!(balloon.device_type(), TYPE_BALLOON);

                let features: u64 = (1u64 << VIRTIO_F_VERSION_1)
                    | ((if *must_tell_host { 1 } else { 0 }) << VIRTIO_BALLOON_F_MUST_TELL_HOST)
                    | ((if *deflate_on_oom { 1 } else { 0 }) << VIRTIO_BALLOON_F_DEFLATE_ON_OOM);

                assert_eq!(balloon.avail_features_by_page(0), features as u32);
                assert_eq!(balloon.avail_features_by_page(1), (features >> 32) as u32);
                for i in 2..10 {
                    assert_eq!(balloon.avail_features_by_page(i), 0u32);
                }

                for i in 0..10 {
                    balloon.ack_features_by_page(i, u32::MAX);
                }
                // Only present features should be acknowledged.
                assert_eq!(balloon.acked_features, features);
            }
        }
    }

    #[test]
    fn test_virtio_read_config() {
        let balloon = Balloon::new(0x10, true, true).unwrap();

        let mut actual_config_space = [0u8; CONFIG_SPACE_SIZE];
        balloon.read_config(0, &mut actual_config_space);
        // The first 4 bytes are num_pages, the last 4 bytes are actual_pages.
        // The config space is little endian.
        let expected_config_space: [u8; CONFIG_SPACE_SIZE] =
            [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(actual_config_space, expected_config_space);

        // Invalid read.
        let expected_config_space: [u8; CONFIG_SPACE_SIZE] =
            [0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf];
        actual_config_space = expected_config_space;
        balloon.read_config(CONFIG_SPACE_SIZE as u64 + 1, &mut actual_config_space);

        // Validate read failed (the config space was not updated).
        assert_eq!(actual_config_space, expected_config_space);
    }

    #[test]
    fn test_virtio_write_config() {
        let mut balloon = Balloon::new(0, true, true).unwrap();

        let expected_config_space: [u8; CONFIG_SPACE_SIZE] =
            [0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        balloon.write_config(0, &expected_config_space);

        let mut actual_config_space = [0u8; CONFIG_SPACE_SIZE];
        balloon.read_config(0, &mut actual_config_space);
        assert_eq!(actual_config_space, expected_config_space);

        // Invalid write.
        let new_config_space = [0xd, 0xe, 0xa, 0xd, 0xb, 0xe, 0xe, 0xf];
        balloon.write_config(5, &new_config_space);
        // Make sure nothing got written.
        balloon.read_config(0, &mut actual_config_space);
        assert_eq!(actual_config_space, expected_config_space);
    }

    #[test]
    fn test_invalid_request() {
        let mut balloon = Balloon::new(0, true, true).unwrap();
        let mem = default_mem();
        // Only initialize the inflate queue to demonstrate invalid request handling.
        let infq = VirtQueue::new(GuestAddress(0), &mem, 16);
        balloon.set_queue(INFLATE_INDEX, infq.create_queue());
        balloon.activate(mem.clone()).unwrap();

        // Fill the second page with non-zero bytes.
        for i in 0..0x1000 {
            assert!(mem.write_obj::<u8>(1, GuestAddress((1 << 12) + i)).is_ok());
        }

        // Will write the page frame number of the affected frame at this
        // arbitrary address in memory.
        let page_addr = 0x10;

        // Invalid case: the descriptor is write-only.
        {
            mem.write_obj::<u32>(0x1, GuestAddress(page_addr)).unwrap();
            set_request(
                &infq,
                0,
                page_addr,
                SIZE_OF_U32 as u32,
                VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
            );

            invoke_handler_for_queue_event(&mut balloon, INFLATE_INDEX);
            check_request_completion(&infq, 0);

            // Check that the page was not zeroed.
            for i in 0..0x1000 {
                assert_eq!(mem.read_obj::<u8>(GuestAddress((1 << 12) + i)).unwrap(), 1);
            }
        }

        // Invalid case: descriptor len is not a multiple of 'SIZE_OF_U32'.
        {
            mem.write_obj::<u32>(0x1, GuestAddress(page_addr)).unwrap();
            set_request(
                &infq,
                1,
                page_addr,
                SIZE_OF_U32 as u32 + 1,
                VIRTQ_DESC_F_NEXT,
            );

            invoke_handler_for_queue_event(&mut balloon, INFLATE_INDEX);
            check_request_completion(&infq, 1);

            // Check that the page was not zeroed.
            for i in 0..0x1000 {
                assert_eq!(mem.read_obj::<u8>(GuestAddress((1 << 12) + i)).unwrap(), 1);
            }
        }
    }

    #[test]
    fn test_inflate() {
        let mut balloon = Balloon::new(0, true, true).unwrap();
        let mem = default_mem();
        let infq = VirtQueue::new(GuestAddress(0), &mem, 16);
        balloon.set_queue(INFLATE_INDEX, infq.create_queue());
        balloon.activate(mem.clone()).unwrap();

        let mut event_manager = EventManager::new().unwrap();
        let queue_evt = EpollEvent::new(
            EventSet::IN,
            balloon.queue_evts[INFLATE_INDEX].as_raw_fd() as u64,
        );

        // Fill the third page with non-zero bytes.
        for i in 0..0x1000 {
            assert!(mem.write_obj::<u8>(1, GuestAddress((1 << 12) + i)).is_ok());
        }

        // Will write the page frame number of the affected frame at this
        // arbitrary address in memory.
        let page_addr = 0x10;

        // Error case: the request is well-formed, but we forgot
        // to trigger the inflate event queue.
        {
            mem.write_obj::<u32>(0x1, GuestAddress(page_addr)).unwrap();
            set_request(&infq, 0, page_addr, SIZE_OF_U32 as u32, VIRTQ_DESC_F_NEXT);

            check_metric_after_block!(
                METRICS.balloon.event_fails,
                1,
                balloon.process(&queue_evt, &mut event_manager)
            );
            // Verify that nothing got processed.
            assert_eq!(infq.used.idx.get(), 0);

            // Check that the page was not zeroed.
            for i in 0..0x1000 {
                assert_eq!(mem.read_obj::<u8>(GuestAddress((1 << 12) + i)).unwrap(), 1);
            }
        }

        // Test the happy case.
        {
            mem.write_obj::<u32>(0x1, GuestAddress(page_addr)).unwrap();
            set_request(&infq, 0, page_addr, SIZE_OF_U32 as u32, VIRTQ_DESC_F_NEXT);

            check_metric_after_block!(
                METRICS.balloon.inflate_count,
                1,
                invoke_handler_for_queue_event(&mut balloon, INFLATE_INDEX)
            );
            check_request_completion(&infq, 0);

            // Check that the page was zeroed.
            for i in 0..0x1000 {
                assert_eq!(mem.read_obj::<u8>(GuestAddress((1 << 12) + i)).unwrap(), 0);
            }
        }
    }

    #[test]
    fn test_deflate() {
        let mut balloon = Balloon::new(0, true, true).unwrap();
        let mem = default_mem();
        let defq = VirtQueue::new(GuestAddress(0), &mem, 16);
        balloon.set_queue(DEFLATE_INDEX, defq.create_queue());
        balloon.activate(mem.clone()).unwrap();

        let mut event_manager = EventManager::new().unwrap();
        let queue_evt = EpollEvent::new(
            EventSet::IN,
            balloon.queue_evts[DEFLATE_INDEX].as_raw_fd() as u64,
        );

        let page_addr = 0x10;

        // Error case: forgot to trigger deflate event queue.
        {
            set_request(&defq, 0, page_addr, SIZE_OF_U32 as u32, VIRTQ_DESC_F_NEXT);
            check_metric_after_block!(
                METRICS.balloon.event_fails,
                1,
                balloon.process(&queue_evt, &mut event_manager)
            );
            // Verify that nothing got processed.
            assert_eq!(defq.used.idx.get(), 0);
        }

        // Happy case.
        {
            set_request(&defq, 1, page_addr, SIZE_OF_U32 as u32, VIRTQ_DESC_F_NEXT);
            check_metric_after_block!(
                METRICS.balloon.deflate_count,
                1,
                invoke_handler_for_queue_event(&mut balloon, DEFLATE_INDEX)
            );
            check_request_completion(&defq, 1);
        }
    }

    #[test]
    fn test_num_pages() {
        let mut balloon = Balloon::new(0, true, true).unwrap();
        assert_eq!(balloon.num_pages(), 0);
        assert_eq!(balloon.actual_pages(), 0);

        // Update fields through the API.
        balloon.update_actual_pages(0x1234);
        balloon.update_num_pages(0x1000);

        let mut actual_config = vec![0; CONFIG_SPACE_SIZE];
        balloon.read_config(0, &mut actual_config);
        assert_eq!(actual_config, vec![0x0, 0x10, 0x0, 0x0, 0x34, 0x12, 0, 0]);
        assert_eq!(balloon.num_pages(), 0x1000);
        assert_eq!(balloon.actual_pages(), 0x1234);

        // Update fields through the config space.
        let expected_config = vec![0x44, 0x33, 0x22, 0x11, 0x78, 0x56, 0x34, 0x12];
        balloon.write_config(0, &expected_config);
        assert_eq!(balloon.num_pages(), 0x11223344);
        assert_eq!(balloon.actual_pages(), 0x12345678);
    }
}
