// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc(hidden)]

#[cfg(test)]
use crate::devices::virtio::balloon::Balloon;
#[cfg(test)]
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::test_utils::VirtQueue;

#[cfg(test)]
/// Max number of virtio queues.
const BALLOON_MAX_NUM_QUEUES: usize = 5;

#[cfg(test)]
pub fn invoke_handler_for_queue_event(b: &mut Balloon, queue_index: usize) {
    use crate::devices::virtio::balloon::{DEFLATE_INDEX, INFLATE_INDEX, STATS_INDEX};
    use crate::devices::virtio::transport::VirtioInterruptType;

    let hinting_idx = b.free_page_hinting_idx();
    let reporting_idx = b.free_page_reporting_idx();

    assert!(queue_index < BALLOON_MAX_NUM_QUEUES);
    // Trigger the queue event.
    b.queue_evts[queue_index].write(1).unwrap();
    // Handle event.
    // Reporting -> hinting -> stats ordering is important as they will change
    // depending on enabled features
    match queue_index {
        INFLATE_INDEX => b.process_inflate_queue_event().unwrap(),
        DEFLATE_INDEX => b.process_deflate_queue_event().unwrap(),
        reporting_idx if b.free_page_reporting() => {
            b.process_free_page_reporting_queue_event().unwrap()
        }
        hinting_idx if b.free_page_hinting() => b.process_free_page_hinting_queue_event().unwrap(),
        STATS_INDEX => b.process_stats_queue_event().unwrap(),
        _ => unreachable!(),
    };
    // Validate the queue operation finished successfully.
    let interrupt = b.interrupt_trigger();
    assert!(
        interrupt
            .has_pending_interrupt(VirtioInterruptType::Queue(queue_index.try_into().unwrap()))
    );

    interrupt.ack_interrupt(VirtioInterruptType::Queue(queue_index.try_into().unwrap()));
}

pub fn set_request(queue: &VirtQueue, idx: u16, addr: u64, len: u32, flags: u16) {
    // Set the index of the next request.
    queue.avail.idx.set(idx + 1);
    // Set the current descriptor table entry index.
    queue.avail.ring[idx as usize].set(idx);
    // Set the current descriptor table entry.
    queue.dtable[idx as usize].set(addr, len, flags, 1);
}

pub fn check_request_completion(queue: &VirtQueue, idx: usize) {
    // Check that the next used will be idx + 1.
    assert_eq!(queue.used.idx.get() as usize, idx + 1);
    // Check that the current used is idx.
    assert_eq!(queue.used.ring[idx].get().id as usize, idx);
    // The length of the completed request is 0.
    assert_eq!(queue.used.ring[idx].get().len, 0);
}
