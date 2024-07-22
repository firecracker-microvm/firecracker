// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc(hidden)]

use crate::devices::virtio::test_utils::VirtQueue;
#[cfg(test)]
use crate::devices::virtio::{balloon::Balloon, balloon::BALLOON_NUM_QUEUES};

#[cfg(test)]
pub fn invoke_handler_for_queue_event(b: &mut Balloon, queue_index: usize) {
    use crate::devices::virtio::balloon::{DEFLATE_INDEX, INFLATE_INDEX, STATS_INDEX};
    use crate::devices::virtio::device::IrqType;

    assert!(queue_index < BALLOON_NUM_QUEUES);
    // Trigger the queue event.
    b.queue_evts[queue_index].write(1).unwrap();
    // Handle event.
    match queue_index {
        INFLATE_INDEX => b.process_inflate_queue_event().unwrap(),
        DEFLATE_INDEX => b.process_deflate_queue_event().unwrap(),
        STATS_INDEX => b.process_stats_queue_event().unwrap(),
        _ => unreachable!(),
    };
    // Validate the queue operation finished successfully.
    assert!(b.irq_trigger.has_pending_irq(IrqType::Vring));
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
