// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Benchmarking cases:
//   * `Queue.pop`
//   * `Queue.add_used`
//   * `DescriptorChain.next_descriptor`

use std::num::Wrapping;

use criterion::{Criterion, criterion_group, criterion_main};
use vm_memory::GuestAddress;
use vmm::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use vmm::devices::virtio::test_utils::VirtQueue;
use vmm::test_utils::single_region_mem;

/// Create one chain with n descriptors
/// Descriptor buffers will leave at the offset of 2048 bytes
/// to leave some room for queue objects.
/// We don't really care about sizes of descriptors,
/// so pick 1024.
fn set_dtable_one_chain(rxq: &VirtQueue, n: usize) {
    let desc_size = 1024;
    for i in 0..n {
        rxq.dtable[i].set(
            (2048 + desc_size * i) as u64,
            desc_size as u32,
            VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
            (i + 1) as u16,
        );
    }
    rxq.dtable[n - 1].flags.set(VIRTQ_DESC_F_WRITE);
    rxq.dtable[n - 1].next.set(0);
    rxq.avail.ring[0].set(0);
    rxq.avail.idx.set(n as u16);
}

/// Create n chains with 1 descriptors each
/// Descriptor buffers will leave at the offset of 2048 bytes
/// to leave some room for queue objects.
/// We don't really care about sizes of descriptors,
/// so pick 1024.
fn set_dtable_many_chains(rxq: &VirtQueue, n: usize) {
    let desc_size = 1024;
    for i in 0..n {
        rxq.dtable[i].set(
            (2048 + desc_size * i) as u64,
            desc_size as u32,
            VIRTQ_DESC_F_WRITE,
            0,
        );
        rxq.avail.ring[i].set(i as u16);
    }
    rxq.avail.idx.set(n as u16);
}

pub fn queue_benchmark(c: &mut Criterion) {
    let mem = single_region_mem(65562);
    let rxq = VirtQueue::new(GuestAddress(0), &mem, 256);
    let mut queue = rxq.create_queue();

    set_dtable_one_chain(&rxq, 16);
    queue.next_avail = Wrapping(0);
    let desc = queue.pop().unwrap();
    c.bench_function("next_descriptor_16", |b| {
        b.iter(|| {
            let mut head = Some(desc);
            while let Some(d) = head {
                head = std::hint::black_box(d.next_descriptor());
            }
        })
    });

    set_dtable_many_chains(&rxq, 16);
    c.bench_function("queue_pop_16", |b| {
        b.iter(|| {
            queue.next_avail = Wrapping(0);
            while let Some(desc) = queue.pop() {
                std::hint::black_box(desc);
            }
        })
    });

    c.bench_function("queue_add_used_16", |b| {
        b.iter(|| {
            queue.num_added = Wrapping(0);
            queue.next_used = Wrapping(0);
            for i in 0_u16..16_u16 {
                let index = std::hint::black_box(i);
                let len = std::hint::black_box(i + 1);
                _ = queue.add_used(index, len as u32);
            }
        })
    });

    c.bench_function("queue_add_used_256", |b| {
        b.iter(|| {
            queue.num_added = Wrapping(0);
            queue.next_used = Wrapping(0);
            for i in 0_u16..256_u16 {
                let index = std::hint::black_box(i);
                let len = std::hint::black_box(i + 1);
                _ = queue.add_used(index, len as u32);
            }
        })
    });
}

criterion_group! {
    name = queue_benches;
    config = Criterion::default().sample_size(1000).noise_threshold(0.15);
    targets = queue_benchmark
}

criterion_main! {
    queue_benches
}
