// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;

use fuzzer::*;

#[cfg(feature = "afl_fuzz")]
afl_main!(fuzzing::target);

#[cfg(feature = "stdin_fuzz")]
stdin_main!(fuzzing::target);

pub mod fuzzing {
    use std::sync::Arc;

    use fuzzer::block::{
        DeviceOptions, GuestMemoryError, guest_memory, loose_rate_limiter, new_device,
    };
    use fuzzer::virtio::{FuzzData, InsufficientData, fuzz_data_descriptor};
    use vmm::devices::virtio::block::virtio::device::FileEngineType;
    use vmm::devices::virtio::block::virtio::test_utils::set_queue;
    use vmm::devices::virtio::device::VirtioDevice;
    use vmm::devices::virtio::test_utils::VirtQueue;
    use vmm::devices::virtio::transport::mmio::IrqTrigger;
    use vmm::vstate::memory::GuestAddress;

    pub fn target(mut data: &[u8]) -> Result<(), InsufficientData> {
        const MEMORY_64K: usize = 0x10000;
        const MEMORY_8M: usize = 0x800000;

        let input = &mut data;
        // The queue size is fuzzed too, as a driver may set up a queue smaller than the device's
        // default (256 entries for the block device).
        let options = DeviceOptions::take(input)?;

        let gm = match guest_memory(options.huge_pages, MEMORY_64K, MEMORY_8M, false) {
            Ok(gm) => gm,
            // Exit gracefully if we don't have enough hugepages, as otherwise the fuzz target
            // would fail with SIGBUS.
            Err(GuestMemoryError::NotEnoughHugepages) => return Ok(()),
            Err(err) => panic!("Cannot initialize memory: {err:?}"),
        };
        // Rate limiting is enabled, loosely. No num_queues: the inline data path, on the VMM
        // thread.
        let rate_limiter = loose_rate_limiter();
        let (mut block, _backing) =
            new_device(&options, None, Some(&rate_limiter), FileEngineType::Sync);

        let irq = Arc::new(IrqTrigger::new());

        let mut vq = VirtQueue::new(GuestAddress(0), &gm, options.queue_size);

        set_queue(&mut block, 0, vq.create_queue());
        block.set_acked_features(block.avail_features() & options.features);
        block.activate(gm.clone(), irq).unwrap();

        // We need to prevent overwriting the virtio queue here, as the GetDeviceID operation will
        // write data to guest memory that depends on the inode of the _backing file_. This value
        // changes independently of the fuzz-input and thus introduces non-determinism (and
        // therefore spurious failures: If the GetDeviceID data partially overwrites the virtio
        // queue in a way that triggers an allow-listed panic only for some values, this can lead to
        // unreproducible crashes)
        while let Ok(()) = input.fill_virt_queue(&mut vq, fuzz_data_descriptor, true) {
            _ = block.process_virtio_queues()
        }

        Ok(())
    }
}

#[cfg(test)]
mod seed_gen {
    //! Module used for generating the binary input seeds
    //!
    //! Each test builds a seed and writes it to a file in /in/block.
    use fuzzer::block::seed::{push_device_options, push_write_fill, save_seed};

    #[test]
    fn generate_input_seed() {
        // No features; writeback, read-write, non-root, anonymous memory, no discard. One fill
        // of the queue with a write of "Hello World" to sector 0. The buffers start at 0x2000,
        // above the 256-entry queue at 0: fill_virt_queue() raises any address below the queue's
        // end to that end, which would put all three buffers at one address.
        let mut seed = Vec::new();
        push_device_options(&mut seed, 0, 0x0);
        push_write_fill(&mut seed, &[0x2000]);

        save_seed("block", "simple_write", &seed);
    }
}
