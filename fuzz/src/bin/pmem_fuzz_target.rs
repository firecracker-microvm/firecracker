// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;

use fuzzer::*;

#[cfg(feature = "afl_fuzz")]
afl_main!(fuzzing::target);

#[cfg(feature = "stdin_fuzz")]
stdin_main!(fuzzing::target);

mod fuzzing {
    use std::sync::Arc;

    use fuzzer::check_hugepages_available;
    use fuzzer::virtio::{FuzzData, InsufficientData, fuzz_data_descriptor};
    use vmm::devices::virtio::device::VirtioDevice;
    use vmm::devices::virtio::pmem::device::Pmem;
    use vmm::devices::virtio::test_utils::VirtQueue;
    use vmm::devices::virtio::transport::mmio::IrqTrigger;
    use vmm::rate_limiter::RateLimiter;
    use vmm::vmm_config::machine_config::HugePageConfig;
    use vmm::vmm_config::pmem::PmemConfig;
    use vmm::vstate::kvm::Kvm;
    use vmm::vstate::memory::test_utils::into_region_ext;
    use vmm::vstate::memory::{GuestAddress, anonymous};
    use vmm::vstate::vm::KvmVm;

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

        let [read_only, root_device, huge_pages, ..] = input.take_bools()?;
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

        // The backign size will determine if there is a single mmap or double mmap scheme
        // is used.
        // Limit size to range of 1 to 3MB.
        //   - 1 byte is the minimal allowed size, 0 size are explecitly checked
        //   - 3MB is arbitrary upper limit which only contains a single "nicely" aligned
        //   size of 2MB in the middle of it.
        let backing_file_size = input.take_u32()?.clamp(1, 3 << 20);

        let (f, path) = fuzzer::make_memfd("pmem_backing");
        f.set_len(backing_file_size as u64).unwrap();

        // Rate limiting is enabled but with a high operation rate (10 million ops/s).
        let rate_limiter = RateLimiter::new(0, 0, 0, 100_000, 0, 10);

        let config = PmemConfig {
            id: "fuzzing".to_string(),
            root_device,
            read_only,
            path_on_host: path,
            rate_limiter: Some((&rate_limiter).into()),
        };

        let regions = anonymous(&[(GuestAddress(0), mem_size)], false, huge_page_config).unwrap();
        let mem = into_region_ext(regions);
        let irq = Arc::new(IrqTrigger::new());
        let mut vq = VirtQueue::new(GuestAddress(0), &mem, queue_size);

        let kvm = Kvm::new(vec![]).unwrap();
        let vm = Arc::new(KvmVm::new(kvm).unwrap());

        let mut device =
            Pmem::new_with_queues(vm, config, vec![vq.create_queue()], 0, None).unwrap();

        device.set_acked_features(device.avail_features & features);
        device.activate(mem.clone(), irq).unwrap();

        while let Ok(()) = input.fill_virt_queue(&mut vq, fuzz_data_descriptor, false) {
            _ = device.handle_queue()
        }

        Ok(())
    }
}

#[cfg(test)]
mod seed_gen {
    use std::fs::OpenOptions;
    use std::io::Write;

    #[repr(C, packed)]
    struct InputSeed {
        features: u64,
        queue_size: u8,
        read_only_root_device_huge_pages: u8,
        backing_file_size: u32,

        first_fill_descriptor_count: u8,

        first_descriptor_index: u8,
        first_descriptor_address: u16,
        first_descriptor_flags: u8,
        first_descriptor_next_index: u8,
        first_descriptor_buffer_size: u16,
        first_descriptor_data: u32,

        second_descriptor_index: u8,
        second_descriptor_address: u16,
        second_descriptor_flags: u8,
        second_descriptor_next_index: u8,
        second_descriptor_buffer_size: u16,
        second_descriptor_data: u32,
    }

    #[test]
    fn generate_input_seed() {
        let seed = InputSeed {
            features: 0,
            queue_size: 255,
            read_only_root_device_huge_pages: 0,
            backing_file_size: 1,

            // Initial chain is a correct flush request
            first_fill_descriptor_count: 2,

            first_descriptor_index: 0,
            first_descriptor_address: 0x100,
            first_descriptor_flags: 1, // VIRTQ_DESC_F_NEXT
            first_descriptor_next_index: 1,
            first_descriptor_buffer_size: 4,
            first_descriptor_data: 0, // VIRTIO_PMEM_REQ_TYPE_FLUSH

            second_descriptor_index: 1,
            second_descriptor_address: 0x200,
            second_descriptor_flags: 2, // VIRTQ_DESC_F_WRITE
            second_descriptor_next_index: 0,
            second_descriptor_buffer_size: 4,
            second_descriptor_data: 0,
        };

        let _ = std::fs::create_dir_all("in/pmem");
        let mut seed_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open("in/pmem/request.in")
            .unwrap();

        let byte_slice: &[u8; std::mem::size_of::<InputSeed>()] =
            unsafe { std::mem::transmute(&seed) };
        seed_file.write_all(byte_slice).unwrap();
    }
}
