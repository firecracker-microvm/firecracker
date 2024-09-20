// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Benchmarking cases:
//   * `Queue.pop`
//   * `Queue.add_used`
//   * `DescriptorChain.next_descriptor`

use std::num::Wrapping;

use criterion::{criterion_group, criterion_main, Criterion};
use vm_memory::GuestAddress;
use vmm::devices::virtio::test_utils::{set_dtable_many_chains, set_dtable_one_chain, VirtQueue};
use vmm::test_utils::single_region_mem;

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
                _ = queue.add_used(index as u16, len as u32);
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
                _ = queue.add_used(index as u16, len as u32);
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
