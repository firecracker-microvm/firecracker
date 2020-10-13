// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;
use std::u32;

use crate::virtio::balloon::NUM_QUEUES;
use crate::virtio::test_utils::VirtQueue;
use crate::virtio::Balloon;
use ::utils::epoll::{EpollEvent, EventSet};
use polly::event_manager::{EventManager, Subscriber};

pub fn invoke_handler_for_queue_event(b: &mut Balloon, queue_index: usize) {
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

pub fn set_request(queue: &VirtQueue, idx: usize, addr: u64, len: u32, flags: u16) {
    // Set the index of the next request.
    queue.avail.idx.set((idx + 1) as u16);
    // Set the current descriptor table entry index.
    queue.avail.ring[idx].set(idx as u16);
    // Set the current descriptor table entry.
    queue.dtable[idx].set(addr, len, flags, 1);
}

pub fn check_request_completion(queue: &VirtQueue, idx: usize) {
    // Check that the next used will be idx + 1.
    assert_eq!(queue.used.idx.get(), (idx + 1) as u16);
    // Check that the current used is idx.
    assert_eq!(queue.used.ring[idx].get().id, idx as u32);
    // The length of the completed request is 0.
    assert_eq!(queue.used.ring[idx].get().len, 0);
}
