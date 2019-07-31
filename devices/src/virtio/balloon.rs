// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use epoll;
use std::cmp;
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use super::super::Error as DeviceError;
use super::{
    ActivateError, ActivateResult, EpollConfigConstructor, Queue, VirtioDevice, TYPE_BALLOON,
};
use logger::{Metric, METRICS};
use memory_model::{GuestAddress, GuestMemory};
use sys_util::EventFd;
use virtio::{VIRTIO_MMIO_INT_CONFIG, VIRTIO_MMIO_INT_VRING};
use {DeviceEventT, EpollHandler};

// Balloon has three virt IO queues: Inflate, Deflate, and Stats.
// Stats is currently not used.
const QUEUE_SIZE: u16 = 128;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE, QUEUE_SIZE];
const VIRTIO_BALLOON_PFN_SHIFT: u32 = 12;

// The feature bitmap for virtio balloon
const VIRTIO_BALLOON_F_MUST_TELL_HOST: u32 = 0; // Tell before reclaiming pages
const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 2; // Deflate balloon on OOM
const VIRTIO_F_VERSION_1: u32 = 32;

const BALLOON_INFLATE_EVENT: DeviceEventT = 0;
const BALLOON_DEFLATE_EVENT: DeviceEventT = 1;
pub const BALLOON_EVENTS_COUNT: usize = 2;

// The maximum number of pages that can be received in a single descriptor.
const MAX_PAGES_IN_DESC: usize = 256;

/// Handler that drives the execution of the Balloon device
pub struct BalloonEpollHandler {
    mem: GuestMemory,
    inflate_queue: Queue,
    deflate_queue: Queue,
    interrupt_status: Arc<AtomicUsize>,
    inflate_queue_evt: EventFd,
    deflate_queue_evt: EventFd,
    interrupt_evt: EventFd,
    num_pages: Arc<AtomicUsize>,
}

/// This takes a vector of page frame numbers, and compacts them
/// into ranges of consecutive pages. The result is a vector
/// of (start_page_frame_number, range_length) pairs.
fn compact_page_frame_numbers(v: &mut Vec<u32>) -> Vec<(u32, u32)> {
    // Simple special case.
    if v.is_empty() {
        return vec![];
    }

    // First sort the vector.
    // Note that, since the total number of pages that can be
    // received at once from a single descriptor is `MAX_PAGES_IN_DESC`,
    // this sort does not change the complexity of handling
    // an inflation.
    v.sort();

    // We store the result in `result`. Since there are at most
    // `MAX_PAGES_IN_DESC` pages, setting the capacity of `result`
    // to this makes sense.
    let mut result = Vec::with_capacity(MAX_PAGES_IN_DESC);

    // The most recent range of pages is [previous..previous + length).
    let mut previous = v[0];
    let mut length = 1;

    // Go through all page indices.
    for page_frame_number in &v[1..] {
        // Check if the current page frame number is adjacent to the most recent page range.
        if *page_frame_number == previous + length {
            // If so, extend that range.
            length += 1;
        } else {
            // Otherwise, if appropriate, push (previous, length) to the result vector.
            if length > 0 {
                result.push((previous, length));
            }
            // And update the most recent range of pages.
            previous = *page_frame_number;
            length = 1;
        }
    }

    // Don't forget to push the last range to the result.
    if length > 0 {
        result.push((previous, length));
    }

    result
}

impl BalloonEpollHandler {
    /// This function will signal to the guest kernel to read
    /// from a virtio used ring buffer.
    fn signal_used_queue(&self) {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }

    /// Process an inflation.
    fn process_inflate(&mut self) -> Result<(), DeviceError> {
        // Read event.
        self.inflate_queue_evt.read().map_err(|e| {
            error!("failed reading inflate queue EventFd: {}", e);
            METRICS.balloon.event_fails.inc();
            DeviceError::FailedReadingQueue {
                event_type: "queue event",
                underlying: e,
            }
        })?;

        // Increment a metric.
        METRICS.balloon.inflate_count.inc();

        let mut needs_interrupt = false;

        // We store the pages we want to remove in `pages`.
        // Since there are at most `MAX_PAGES_IN_DESC` pages, setting the
        // capacity of `pages` to this makes sense.
        let mut pages = Vec::with_capacity(MAX_PAGES_IN_DESC);

        // Repeatedly remove descriptors from the inflation queue
        // until there are none left.
        while let Some(avail_desc) = self.inflate_queue.pop(&self.mem) {
            let desc_len = avail_desc.len;
            // Then, for each descriptor, check if it is a valid
            // inflate descriptor (that is, we can read from it,
            // and it has a length that agrees with the fact that
            // it contains only 4 byte addresses).
            if !avail_desc.is_write_only() && desc_len % 4 == 0 {
                // Now, for all addresses in the descriptor, try to
                // remove the corresponding pages from the guest.
                for index in (0..desc_len).step_by(4) {
                    // Read the address at position `index`. The only case
                    // in which this fails is if there is overflow,
                    // in which case this descriptor is malformed,
                    // so we ignore the rest of it.
                    let addr = avail_desc
                        .addr
                        .checked_add(index as usize)
                        .ok_or(DeviceError::MalformedDescriptor)?;

                    // Get the page frame number that the guest
                    // says we should remove. If this read fails,
                    // then clearly the descriptor is malformed.
                    let page_frame_number: u32 = self
                        .mem
                        .read_obj_from_addr(addr)
                        .map_err(|_| DeviceError::MalformedDescriptor)?;

                    // Add page frame number to the collection of pages
                    // that we will remove.
                    pages.push(page_frame_number);
                }
            }

            // Acknowlege receipt of the descriptor.
            self.inflate_queue.add_used(&self.mem, avail_desc.index, 0);

            // Eventually, the guest must receive an interrupt
            // to be able to react to this acknowlegement.
            needs_interrupt = true;
        }

        // Compact pages into ranges.
        let page_ranges = compact_page_frame_numbers(&mut pages);

        // Remove the page ranges.
        for (page_frame_number, range_len) in page_ranges {
            // Transform the page frame number into a GuestAddress address,
            // by multiplying with the length of a page.
            let guest_address =
                GuestAddress((page_frame_number as usize) << VIRTIO_BALLOON_PFN_SHIFT);

            // Finally, actually remove the page from memory.
            self.mem
                .remove_range(
                    guest_address,
                    u64::from(range_len) << VIRTIO_BALLOON_PFN_SHIFT,
                )
                .map_err(DeviceError::GuestMemory)?;
        }

        if needs_interrupt {
            self.signal_used_queue();
        }
        Ok(())
    }

    /// Process a deflation.
    fn process_deflate(&mut self) -> Result<(), DeviceError> {
        // Read event.
        self.deflate_queue_evt.read().map_err(|e| {
            error!("failed reading deflate queue EventFd: {}", e);
            METRICS.balloon.event_fails.inc();
            DeviceError::FailedReadingQueue {
                event_type: "queue event",
                underlying: e,
            }
        })?;

        // Increment a metric.
        METRICS.balloon.deflate_count.inc();

        let mut needs_interrupt = false;

        // Repeatedly remove descriptors from the deflation queue
        // until there are none left.
        while let Some(avail_desc) = self.deflate_queue.pop(&self.mem) {
            // Acknowlege receipt of the descriptor.
            self.deflate_queue.add_used(&self.mem, avail_desc.index, 0);

            // Eventually, the guest must receive an interrupt
            // to be able to react to this acknowlegement.
            needs_interrupt = true;
        }
        if needs_interrupt {
            self.signal_used_queue();
        }
        Ok(())
    }

    pub fn update_balloon_size(&self, num_pages: usize) {
        // Update the configuration variable.
        self.num_pages.store(num_pages, Ordering::Relaxed);

        // Signal that the configuration has changed to the guest kernel.
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_CONFIG as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).unwrap();
    }
}

impl EpollHandler for BalloonEpollHandler {
    fn handle_event(
        &mut self,
        device_event: DeviceEventT,
        _evset: epoll::Events,
    ) -> std::result::Result<(), DeviceError> {
        match device_event {
            BALLOON_INFLATE_EVENT => self.process_inflate(),
            BALLOON_DEFLATE_EVENT => self.process_deflate(),
            unknown => Err(DeviceError::UnknownEvent {
                device: "balloon",
                event: unknown,
            }),
        }
    }
}

pub struct EpollConfig {
    inflate_token: u64,
    deflate_token: u64,
    epoll_raw_fd: RawFd,
    sender: mpsc::Sender<Box<EpollHandler>>,
}

impl EpollConfigConstructor for EpollConfig {
    fn new(first_token: u64, epoll_raw_fd: RawFd, sender: mpsc::Sender<Box<EpollHandler>>) -> Self {
        EpollConfig {
            inflate_token: first_token + u64::from(BALLOON_INFLATE_EVENT),
            deflate_token: first_token + u64::from(BALLOON_DEFLATE_EVENT),
            epoll_raw_fd,
            sender,
        }
    }
}

/// Virtio device for memory balloon inflation/deflation.
pub struct Balloon {
    num_pages: Arc<AtomicUsize>,
    actual_pages: Arc<AtomicUsize>,
    avail_features: u64,
    acked_features: u64,
    epoll_config: EpollConfig,
}

impl Balloon {
    /// Create a new virtio balloon device.
    pub fn new(
        num_pages: usize,
        must_tell_host: bool,
        deflate_on_oom: bool,
        epoll_config: EpollConfig,
    ) -> Result<Balloon, DeviceError> {
        Ok(Balloon {
            num_pages: Arc::new(AtomicUsize::new(num_pages)),
            actual_pages: Arc::new(AtomicUsize::new(0)),
            avail_features: (if must_tell_host {
                1 << VIRTIO_BALLOON_F_MUST_TELL_HOST
            } else {
                0
            }) | (if deflate_on_oom {
                1 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM
            } else {
                0
            }) | 1 << VIRTIO_F_VERSION_1,
            acked_features: 0u64,
            epoll_config,
        })
    }
}

impl VirtioDevice for Balloon {
    fn device_type(&self) -> u32 {
        TYPE_BALLOON
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self, page: u32) -> u32 {
        match page {
            // Get the lower 32-bits of the features bitfield.
            0 => self.avail_features as u32,
            // Get the upper 32-bits of the features bitfield.
            1 => (self.avail_features >> 32) as u32,
            _ => {
                warn!("Received request for unknown features page.");
                0u32
            }
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => u64::from(value),
            1 => u64::from(value) << 32,
            _ => {
                warn!("Cannot acknowledge unknown features page.");
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("Received acknowledge request for unknown feature.");

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        if offset >= 8 {
            return;
        }
        let num_pages = self.num_pages.load(Ordering::Relaxed) as u32;
        let actual_pages = self.actual_pages.load(Ordering::Relaxed) as u32;
        let mut config = [0u8; 8];
        // These writes can't fail as they fit in the declared array so unwrap is fine.
        (&mut config[0..])
            .write_u32::<LittleEndian>(num_pages)
            .unwrap();
        (&mut config[4..])
            .write_u32::<LittleEndian>(actual_pages)
            .unwrap();
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against the length of config.
            data.write_all(&config[offset as usize..cmp::min(end, 8) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, mut data: &[u8]) {
        // Only allow writing to `actual` pages from the guest.
        if offset != 4 || data.len() != 4 {
            return;
        }
        // This read can't fail as it fits in the declared array so unwrap is fine.
        let new_actual: u32 = data.read_u32::<LittleEndian>().unwrap();
        self.actual_pages
            .store(new_actual as usize, Ordering::Relaxed);
    }

    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt_evt: EventFd,
        status: Arc<AtomicUsize>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != QUEUE_SIZES.len() || queue_evts.len() != QUEUE_SIZES.len() {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                QUEUE_SIZES.len(),
                queues.len()
            );
            METRICS.balloon.activate_fails.inc();
            return Err(ActivateError::BadActivate);
        }

        let handler = BalloonEpollHandler {
            mem,
            inflate_queue: queues.remove(0),
            deflate_queue: queues.remove(0),
            interrupt_status: status,
            inflate_queue_evt: queue_evts.remove(0),
            deflate_queue_evt: queue_evts.remove(0),
            interrupt_evt,
            num_pages: self.num_pages.clone(),
        };

        let inflate_rawfd = handler.inflate_queue_evt.as_raw_fd();
        let deflate_rawfd = handler.deflate_queue_evt.as_raw_fd();

        // Channel should be open and working.
        self.epoll_config
            .sender
            .send(Box::new(handler))
            .expect("Failed to send through the channel");

        //TODO: barrier needed here by any chance?
        epoll::ctl(
            self.epoll_config.epoll_raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            inflate_rawfd,
            epoll::Event::new(epoll::Events::EPOLLIN, self.epoll_config.inflate_token),
        )
        .map_err(|e| {
            METRICS.balloon.activate_fails.inc();
            ActivateError::EpollCtl(e)
        })?;

        epoll::ctl(
            self.epoll_config.epoll_raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            deflate_rawfd,
            epoll::Event::new(epoll::Events::EPOLLIN, self.epoll_config.deflate_token),
        )
        .map_err(|e| {
            METRICS.balloon.activate_fails.inc();
            ActivateError::EpollCtl(e)
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use libc;
    use std::sync::mpsc::Receiver;
    use std::u32;

    use byteorder::LittleEndian;

    use virtio::queue::tests::*;

    /// Will read $metric, run the code in $block, then assert metric has increased by $delta.
    macro_rules! check_metric_after_block {
        ($metric:expr, $delta:expr, $block:expr) => {{
            let before = $metric.count();
            let _ = $block;
            assert_eq!($metric.count(), before + $delta, "unexpected metric value");
        }};
    }

    /// This asserts that $lhs matches $rhs.
    macro_rules! assert_match {
        ($lhs:expr, $rhs:pat) => {{
            assert!(match $lhs {
                $rhs => true,
                _ => false,
            })
        }};
    }

    #[test]
    fn test_compact_page_indices() {
        // Test empty input.
        assert!(compact_page_frame_numbers(&mut vec![]).is_empty());

        // Test single compact range.
        assert_eq!(
            compact_page_frame_numbers(&mut (0 as u32..100 as u32).collect()),
            vec![(0, 100)]
        );

        // `compact_page_frame_numbers` works even when given out of order input.
        assert_eq!(
            compact_page_frame_numbers(&mut (0 as u32..100 as u32).rev().collect()),
            vec![(0, 100)]
        );

        // Test with 100 distinct ranges.
        assert_eq!(
            compact_page_frame_numbers(
                &mut (0 as u32..10000 as u32)
                    .step_by(100)
                    .flat_map(|x| (x..x + 10).rev())
                    .collect()
            ),
            (0 as u32..10000 as u32)
                .step_by(100)
                .map(|x| (x, 10 as u32))
                .collect::<Vec<(u32, u32)>>()
        );
    }

    struct DummyBalloon {
        balloon: Balloon,
        epoll_raw_fd: i32,
        _receiver: Receiver<Box<EpollHandler>>,
    }

    impl DummyBalloon {
        fn new(num_pages: usize, must_tell_host: bool, deflate_on_oom: bool) -> Self {
            let epoll_raw_fd = epoll::create(true).unwrap();
            let (sender, _receiver) = mpsc::channel();

            let epoll_config = EpollConfig::new(0, epoll_raw_fd, sender);

            DummyBalloon {
                balloon: Balloon::new(num_pages, deflate_on_oom, must_tell_host, epoll_config)
                    .ok()
                    .unwrap(),
                epoll_raw_fd,
                _receiver,
            }
        }

        fn balloon(&mut self) -> &mut Balloon {
            &mut self.balloon
        }
    }

    impl Drop for DummyBalloon {
        fn drop(&mut self) {
            unsafe { libc::close(self.epoll_raw_fd) };
        }
    }

    impl Balloon {
        fn get_acked_features(&self) -> u64 {
            self.acked_features
        }

        fn get_actual_pages(&self) -> usize {
            self.actual_pages.load(Ordering::Relaxed)
        }
    }

    /// Helper function for varying the parameters of the function activating a balloon device.
    fn activate_balloon_with_modifiers(
        b: &mut Balloon,
        bad_qlen: bool,
        bad_evtlen: bool,
    ) -> ActivateResult {
        let m = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let ievt = EventFd::new().unwrap();
        let stat = Arc::new(AtomicUsize::new(0));

        let mut queues = vec![
            VirtQueue::new(GuestAddress(0), &m, 16).create_queue(),
            VirtQueue::new(GuestAddress(0), &m, 16).create_queue(),
        ];
        let mut queue_evts = vec![EventFd::new().unwrap(), EventFd::new().unwrap()];

        // Invalidate queues list to test this failure case.
        if bad_qlen {
            queues.pop();
        }

        // Invalidate queue-events list to test this failure case.
        if bad_evtlen {
            queue_evts.pop();
        }

        b.activate(m.clone(), ievt, stat, queues, queue_evts)
    }

    impl BalloonEpollHandler {
        fn get_num_pages(&mut self) -> usize {
            self.num_pages.load(Ordering::Relaxed)
        }
    }

    /// Helper function to create a balloon device epoll handler.
    fn make_test_balloonepollhandler(
        mem: &'_ GuestMemory,
        num_pages: usize,
    ) -> (BalloonEpollHandler, VirtQueue<'_>, VirtQueue<'_>) {
        let infq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let defq = VirtQueue::new(GuestAddress(0x1000), &mem, 16);

        assert!(infq.end().0 < defq.start().0);

        let inflate_queue = infq.create_queue();
        let deflate_queue = defq.create_queue();
        let interrupt_status = Arc::new(AtomicUsize::new(0));
        let interrupt_evt = EventFd::new().unwrap();
        let inflate_queue_evt = EventFd::new().unwrap();
        let deflate_queue_evt = EventFd::new().unwrap();

        (
            BalloonEpollHandler {
                mem: mem.clone(),
                inflate_queue,
                deflate_queue,
                interrupt_status,
                inflate_queue_evt,
                deflate_queue_evt,
                interrupt_evt,
                num_pages: Arc::new(AtomicUsize::new(num_pages)),
            },
            infq,
            defq,
        )
    }

    #[test]
    fn test_update_balloon_size() {
        let mem = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (mut h, _, _) = make_test_balloonepollhandler(&mem, 100);

        assert_eq!(h.get_num_pages(), 100);

        h.update_balloon_size(200 as usize);

        assert_eq!(h.get_num_pages(), 200);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_handle_inflate_event() {
        // The testing methodology will be to dirty a page,
        // send an inflate request for that page, and then
        // check that the ballooned memory page is set to 0 (since
        // this is a checkable side effect of using madvise
        // to remove memory).

        // Create a balloon epoll handler.
        let mem = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (mut h, infq, _) = make_test_balloonepollhandler(&mem, 100);

        // Fill a page with non-zero bytes.
        for i in 0..0x1000 {
            assert!(mem
                .write_obj_at_addr::<u8>(1, GuestAddress((2 << 12) + i))
                .is_ok());
        }

        // Set the queues readiness.
        infq.create_queue().ready = true;

        // Write the page frame number of the affected frame
        // in memory.
        assert!(mem
            .write_obj_at_addr::<u32>(0x2, GuestAddress(0x10))
            .is_ok());

        // Test an event that forgets to trigger `inflate_queue_evt`.
        check_metric_after_block!(METRICS.balloon.event_fails, 1, {
            // Send a good request on the inflate queue.
            infq.avail.idx.set(3);
            infq.avail.ring[2].set(0);
            infq.dtable[0].set(0x10, 4, VIRTQ_DESC_F_NEXT, 1);
            // But don't trigger `h.inflate_queue_evt`.
            // Now check that we get an appropriate error.
            assert_match!(
                h.handle_event(BALLOON_INFLATE_EVENT, epoll::Events::EPOLLIN),
                Err(DeviceError::FailedReadingQueue {
                    event_type: "queue event",
                    ..
                })
            );
        });

        // Test a bad event.
        check_metric_after_block!(METRICS.balloon.inflate_count, 1, {
            // Send a bad request on the inflate queue.
            infq.avail.idx.set(1);
            infq.avail.ring[0].set(0);
            infq.dtable[0].set(0x10, 5, VIRTQ_DESC_F_NEXT, 1);
            h.inflate_queue_evt.write(1).unwrap();
            assert!(h
                .handle_event(BALLOON_INFLATE_EVENT, epoll::Events::EPOLLIN)
                .is_ok());

            // Check that the interrupt status is correct.
            assert_eq!(
                h.interrupt_status.load(Ordering::Relaxed) as u32,
                VIRTIO_MMIO_INT_VRING
            );
            h.interrupt_status.store(0, Ordering::Relaxed);

            // Check that event is given on `interrupt_evt`.
            assert!(h.interrupt_evt.read().is_ok());

            // Check that no memory has been affected by
            // this bad request.
            for i in 0..0x1000 {
                assert_match!(
                    mem.read_obj_from_addr::<u8>(GuestAddress((2 << 12) + i)),
                    Ok(1)
                );
            }
        });

        // Test a bad event.
        check_metric_after_block!(METRICS.balloon.inflate_count, 1, {
            // Send a bad request on the inflate queue.
            infq.avail.idx.set(2);
            infq.avail.ring[1].set(0);
            infq.dtable[0].set(0x10, 4, VIRTQ_DESC_F_WRITE, 1);
            h.inflate_queue_evt.write(1).unwrap();
            assert!(h
                .handle_event(BALLOON_INFLATE_EVENT, epoll::Events::EPOLLIN)
                .is_ok());

            // Check that the interrupt status is correct.
            assert_eq!(
                h.interrupt_status.load(Ordering::Relaxed) as u32,
                VIRTIO_MMIO_INT_VRING
            );
            h.interrupt_status.store(0, Ordering::Relaxed);

            // Check that event is given on `interrupt_evt`.
            assert!(h.interrupt_evt.read().is_ok());

            // Check that no memory has been affected by
            // this bad request.
            for i in 0..0x1000 {
                assert_match!(
                    mem.read_obj_from_addr::<u8>(GuestAddress((2 << 12) + i)),
                    Ok(1)
                );
            }
        });

        // Test a good event.
        check_metric_after_block!(METRICS.balloon.inflate_count, 1, {
            // Send an inflate request on the inflate queue.
            infq.avail.idx.set(3);
            infq.avail.ring[2].set(0);
            infq.dtable[0].set(0x10, 4, VIRTQ_DESC_F_NEXT, 1);
            h.inflate_queue_evt.write(1).unwrap();
            assert!(h
                .handle_event(BALLOON_INFLATE_EVENT, epoll::Events::EPOLLIN)
                .is_ok());

            // Check that the interrupt status is correct.
            assert_eq!(
                h.interrupt_status.load(Ordering::Relaxed) as u32,
                VIRTIO_MMIO_INT_VRING
            );
            h.interrupt_status.store(0, Ordering::Relaxed);

            // Check that event is given on `interrupt_evt`.
            assert!(h.interrupt_evt.read().is_ok());

            // Check that the range of memory written to before
            // now contains only 0.
            for i in 0..0x1000 {
                assert_match!(
                    mem.read_obj_from_addr::<u8>(GuestAddress((2 << 12) + i)),
                    Ok(0)
                );
            }
        });

        // Now, check that the device has placed a proper descriptor
        // on the used ring.
        assert_eq!(infq.used.idx.get(), 3);
        assert_eq!(infq.used.ring[0].get().id, 0);
        assert_eq!(infq.used.ring[0].get().len, 0);
    }

    #[test]
    fn test_handle_deflate_event() {
        // Create a balloon epoll handler.
        let mem = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (mut h, _, defq) = make_test_balloonepollhandler(&mem, 100);

        // Set the queues readiness.
        defq.create_queue().ready = true;

        // Test an event that forgets to trigger `deflate_queue_evt`.
        check_metric_after_block!(METRICS.balloon.event_fails, 1, {
            // Send a good request on the deflate queue.
            defq.avail.idx.set(1);
            defq.avail.ring[0].set(0);
            defq.dtable[0].set(0x10, 4, VIRTQ_DESC_F_NEXT, 1);
            // Forget to trigger `deflate_queue_evt`.
            // Now check that we get an appropriate error.
            assert_match!(
                h.handle_event(BALLOON_DEFLATE_EVENT, epoll::Events::EPOLLIN),
                Err(DeviceError::FailedReadingQueue {
                    event_type: "queue event",
                    ..
                })
            );
        });

        check_metric_after_block!(METRICS.balloon.deflate_count, 1, {
            // Send a request on the deflate queue.
            defq.avail.idx.set(2);
            defq.avail.ring[1].set(0);
            defq.dtable[0].set(0x10, 4, VIRTQ_DESC_F_NEXT, 1);
            h.deflate_queue_evt.write(1).unwrap();
            assert!(h
                .handle_event(BALLOON_DEFLATE_EVENT, epoll::Events::EPOLLIN)
                .is_ok());

            // Check that the interrupt status is correct.
            assert_eq!(
                h.interrupt_status.load(Ordering::Relaxed) as u32,
                VIRTIO_MMIO_INT_VRING
            );
            h.interrupt_status.store(0, Ordering::Relaxed);

            // Check that event is given on `interrupt_evt`.
            assert!(h.interrupt_evt.read().is_ok());
        });
        // Now, check that the device has placed a proper descriptor
        // on the used ring.
        assert_eq!(defq.used.idx.get(), 2);
        assert_eq!(defq.used.ring[0].get().id, 0);
        assert_eq!(defq.used.ring[0].get().len, 0);
    }

    #[test]
    fn test_handle_invalid_event() {
        // Create a balloon epoll handler.
        let mem = GuestMemory::new(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (mut h, _, _) = make_test_balloonepollhandler(&mem, 100);

        // Check that an invalid event leads to the
        // propper error.
        assert_match!(
            h.handle_event(123, epoll::Events::EPOLLIN),
            Err(DeviceError::UnknownEvent {
                device: "balloon",
                event: 123,
            })
        );
    }

    #[test]
    fn test_device_type() {
        let mut dummy = DummyBalloon::new(123, true, true);
        let b = dummy.balloon();
        assert_eq!(b.device_type(), TYPE_BALLOON);
    }

    #[test]
    fn test_queue_max_sizes() {
        let mut dummy = DummyBalloon::new(123, true, true);
        let b = dummy.balloon();
        assert_eq!(b.queue_max_sizes(), QUEUE_SIZES);
    }

    #[test]
    fn test_features() {
        // Try all used feature configurations.
        for deflate_on_oom in vec![true, false].iter() {
            for must_tell_host in vec![true, false].iter() {
                let mut dummy = DummyBalloon::new(123, *deflate_on_oom, *must_tell_host);
                let b = dummy.balloon();

                // First page will contain VIRTIO_BALLOON_F_MUST_TELL_HOST
                // and VIRTIO_BALLOON_F_DEFLATE_ON_OOM.
                assert_eq!(
                    b.features(0),
                    ((if *must_tell_host { 1 } else { 0 }) as u32)
                        << VIRTIO_BALLOON_F_MUST_TELL_HOST
                        | ((if *deflate_on_oom { 1 } else { 0 }) as u32)
                            << VIRTIO_BALLOON_F_DEFLATE_ON_OOM
                );
                // Second page contains VIRTIO_F_VERSION_1.
                assert_eq!(b.features(1), (1 << (VIRTIO_F_VERSION_1 - 32) as u32));

                // Other pages should return 0.
                assert_eq!(b.features(2), 0 as u32);
            }
        }
    }

    #[test]
    fn test_ack_features() {
        // Try all used feature configurations.
        for deflate_on_oom in vec![true, false].iter() {
            for must_tell_host in vec![true, false].iter() {
                let mut dummy = DummyBalloon::new(123, *deflate_on_oom, *must_tell_host);
                let b = dummy.balloon();

                assert_eq!(b.get_acked_features(), 0 as u64);

                // Try to acknowledge all features, even those that aren't
                // present.
                b.ack_features(0, 1 << VIRTIO_BALLOON_F_MUST_TELL_HOST);
                b.ack_features(0, 1 << VIRTIO_BALLOON_F_DEFLATE_ON_OOM);
                // Try to acknowledge features from inexistent pages.
                b.ack_features(3, 123);

                // Only those present should be acknowledged.
                assert_eq!(
                    b.get_acked_features(),
                    ((if *must_tell_host { 1 } else { 0 }) as u64)
                        << VIRTIO_BALLOON_F_MUST_TELL_HOST
                        | ((if *deflate_on_oom { 1 } else { 0 }) as u64)
                            << VIRTIO_BALLOON_F_DEFLATE_ON_OOM
                );
            }
        }
    }

    #[test]
    fn test_write_config() {
        let mut dummy = DummyBalloon::new(1234, true, false);
        let b = dummy.balloon();
        let mut good_data = [0u8; 4];
        let mut bad_data = [0u8; 5];
        let good_offset = 4 as u64;
        let bad_offset = 3 as u64;

        // These writes can't fail as they fit in the declared array;
        // so unwrap is fine.
        (&mut good_data[0..])
            .write_u32::<LittleEndian>(1000)
            .unwrap();
        (&mut bad_data[0..])
            .write_u32::<LittleEndian>(1100)
            .unwrap();

        // This write should have no effect, since
        // it is malformed.
        b.write_config(good_offset, &bad_data);

        // Check that it had no effect.
        assert_eq!(b.get_actual_pages(), 0);

        // Similarly for this one.
        b.write_config(bad_offset, &good_data);

        // Check that it had no effect.
        assert_eq!(b.get_actual_pages(), 0);

        // Whereas this one should work.
        b.write_config(good_offset, &good_data);

        // Check that it had an effect.
        assert_eq!(b.get_actual_pages(), 1000);
    }

    #[test]
    fn test_read_config() {
        let mut dummy = DummyBalloon::new(12_341_234, true, false);
        let b = dummy.balloon();

        // Here we use a dummy value rather than 0,
        // since we'll want to check that 0 is written
        // later into this buffer.
        let mut data = [1u8; 8];

        // This read should not work, since the offset
        // is too large.
        b.read_config(8, &mut data);

        // Check that `data` is not modified.
        assert!(data.iter().all(|x| *x == 1u8));

        // Check that `read_config` works for all correct
        // offsets.
        for offset in 0 as usize..8 as usize {
            // Reset values of `data`.
            data = [1u8; 8];

            // Try `offset`.
            b.read_config(offset as u64, &mut data);

            // Check that the last `offset` bytes of `data` are
            // unchanged.
            assert!(data.iter().rev().take(offset).all(|x| *x == 1u8));

            // Check that the bytes for `num_pages` are where they're
            // supposed to be.
            for i in 0 as usize..4 as usize {
                if offset <= i {
                    assert_eq!(data[i - offset], (12_341_234 >> (8 * i)) as u8);
                }
            }

            // Check that the bytes for `actual_pages` are where they're
            // supposed to be.
            for i in 4 as usize..8 as usize {
                if offset <= i {
                    assert_eq!(data[i - offset], 0);
                }
            }
        }
    }

    #[test]
    fn test_activate() {
        let mut dummy = DummyBalloon::new(123, true, true);
        let b = dummy.balloon();
        // It should fail when not enough queues and/or evts are provided.
        check_metric_after_block!(
            &METRICS.balloon.activate_fails,
            1,
            assert_match!(
                activate_balloon_with_modifiers(b, true, false),
                Err(ActivateError::BadActivate)
            )
        );

        check_metric_after_block!(
            &METRICS.balloon.activate_fails,
            1,
            assert_match!(
                activate_balloon_with_modifiers(b, false, true),
                Err(ActivateError::BadActivate)
            )
        );

        check_metric_after_block!(
            &METRICS.balloon.activate_fails,
            1,
            assert_match!(
                activate_balloon_with_modifiers(b, true, true),
                Err(ActivateError::BadActivate)
            )
        );

        // Otherwise, it should be ok.
        check_metric_after_block!(
            &METRICS.balloon.activate_fails,
            0,
            assert!(activate_balloon_with_modifiers(b, false, false).is_ok())
        );
    }
}
