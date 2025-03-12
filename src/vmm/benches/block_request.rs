// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Benchmarking cases:
//   * `Queue.pop`
//   * `Queue.add_used`
//   * `DescriptorChain.next_descriptor`

use criterion::{Criterion, criterion_group, criterion_main};
use vm_memory::GuestAddress;
use vmm::devices::virtio::block::virtio::test_utils::RequestDescriptorChain;
use vmm::devices::virtio::block::virtio::{Request, RequestHeader, VIRTIO_BLK_T_IN};
use vmm::devices::virtio::test_utils::VirtQueue;
use vmm::test_utils::single_region_mem;

pub fn block_request_benchmark(c: &mut Criterion) {
    let mem = single_region_mem(65562);
    let virt_queue = VirtQueue::new(GuestAddress(0), &mem, 16);

    // We don't really care about what request is. We just
    // need it to be valid.
    let chain = RequestDescriptorChain::new(&virt_queue);
    let request_header = RequestHeader::new(VIRTIO_BLK_T_IN, 99);
    chain.set_header(request_header);

    let mut queue = virt_queue.create_queue();
    let desc = queue.pop().unwrap();

    c.bench_function("request_parse", |b| {
        b.iter(|| {
            let desc = std::hint::black_box(&desc);
            _ = Request::parse(desc, &mem, 1024);
        })
    });
}

criterion_group! {
    name = block_request_benches;
    config = Criterion::default().sample_size(1000).noise_threshold(0.05);
    targets = block_request_benchmark
}

criterion_main! {
    block_request_benches
}
