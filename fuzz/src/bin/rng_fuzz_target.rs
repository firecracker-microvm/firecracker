// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;

use fuzzer::*;

// Generate main functions for supported features
#[cfg(feature = "afl_fuzz")]
afl_main!(fuzzing::target); // main function used by afl.rs

#[cfg(feature = "stdin_fuzz")]
stdin_main!(fuzzing::target); // main function used when replaying corpus items to collect backtraces/coverage

mod fuzzing {
    //! Fuzzes the virtio-rng device by placing random virtio descriptors in its
    //! queue and then asking it to process them.
    use std::sync::Arc;

    use fuzzer::check_hugepages_available;
    use fuzzer::virtio::{FuzzData, InsufficientData, fuzz_data_descriptor};
    use vmm::devices::virtio::device::VirtioDevice;
    use vmm::devices::virtio::rng::Entropy;
    use vmm::devices::virtio::test_utils::VirtQueue;
    use vmm::devices::virtio::transport::mmio::IrqTrigger;
    use vmm::rate_limiter::RateLimiter;
    use vmm::vmm_config::machine_config::HugePageConfig;
    use vmm::vstate::memory::test_utils::into_region_ext;
    use vmm::vstate::memory::{GuestAddress, anonymous};

    pub fn target(mut input: &[u8]) -> Result<(), InsufficientData> {
        const MEMORY_64K: usize = 0x10000;
        const MEMORY_8M: usize = 0x800000;

        let input = &mut input;
        let features = input.take_u64()?;

        // We fuzz the queue size, as it is possible that a driver sets up a queue smaller than the
        // device's default queue size. For the block device, the default queue size is 256 entries,
        // so there is no point in setting up queues larger than that (and the fuzzer uses u8 to
        // index into the descriptor table, so it could not make use of larger queues anyway).
        // Note that queue size has to be a power of two. This is verified via assert! by
        // VirtQueue::new
        let queue_size = (input.take_u8()? as u16).next_power_of_two();

        let [huge_pages, ..] = input.take_bools()?;

        let (huge_page_config, mem_size) = match huge_pages {
            true => {
                // Exit gracefully if we don't have enough hugepages, as otherwise the fuzz target
                // would fail with SIGBUS.
                if !check_hugepages_available(MEMORY_8M) {
                    return Ok(());
                }
                (HugePageConfig::Hugetlbfs2M, MEMORY_8M)
            }
            false => (HugePageConfig::None, MEMORY_64K),
        };

        // Make sure to only allocate after all early returns (via '?'), otherwise we'll not free
        // the memory and go OOM.
        let regions = anonymous(&[(GuestAddress(0), mem_size)], false, huge_page_config)
            .expect("Cannot initialize memory");
        let mem = into_region_ext(regions);
        let irq = Arc::new(IrqTrigger::new());
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, queue_size);

        let ratelimiter = RateLimiter::new(1_000_000_000, 0, 1, 1_000_000_000, 0, 1);
        let mut device = Entropy::new_with_queues(vec![vq.create_queue()], ratelimiter).unwrap();

        device.set_acked_features(device.avail_features() & features);
        device.activate(mem.clone(), irq).unwrap();

        // We need to prevent overwriting the queue as the rng device inherently writes
        // non-deterministic values to memory, and aws-lc does not provide an option to specify a
        // seed for its random generator.
        while let Ok(()) = input.fill_virt_queue(&mut vq, fuzz_data_descriptor, true) {
            _ = device.process_virtio_queues()
        }

        Ok(())
    }
}

#[cfg(test)]
mod seed_gen {
    //! Module used for generating the binary input seeds
    //!
    //! Each test contains a seed as a u8 array, which is written to a file in fuzzer/in/rng
    //! at the end.
    use std::fs::OpenOptions;
    use std::io::Write;

    #[test]
    fn generate_input_seed() {
        #[rustfmt::skip]
        let seed = [
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // features to enable (none)
            0xff, // queue size (will be rounded up to next multiple of two, e.g. 256
            0b00000000u8, // first byte used to determine device config

            // fill virt queue first time
            0x1, // byte used to determine how many descriptors to write to queue. The entropy device is very simple, is fills every descriptor it finds with random bytes

            // first descriptor header
            0x4, // byte used to determine index at which first descriptor will be placed
            0x0, 0x1, // address at which descriptor will be put in guest memory
            0x2, // descriptor flags (VIRTQ_DESC_F_WRITE)
            0x0, // index at which the next descriptor in the chain will be placed

            // first descriptor buffer (request header)
            0x10, 0x0, // length of buffer (16 bytes here)
            0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0,
        ];

        let _ = std::fs::create_dir_all("in/rng");
        let mut seed_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open("in/rng/request.in")
            .unwrap();

        seed_file.write_all(&seed).unwrap();
    }
}
