// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;

use fuzzer::*;

// Generate main functions for supported features
#[cfg(feature = "afl_fuzz")]
afl_main!(fuzzing::target); // main function used by afl.rs

#[cfg(all(feature = "stdin_fuzz", not(feature = "afl_fuzz")))]
stdin_main!(fuzzing::target); // main function used when replaying corpus items to collect backtraces/coverage

mod fuzzing {
    //! Fuzzes the virtio-mem device by placing random virtio descriptors in its
    //! queue and then asking it to process them.
    use std::sync::Arc;

    use fuzzer::check_hugepages_available;
    use fuzzer::virtio::{FuzzData, InsufficientData, fuzz_data_descriptor};
    use vmm::devices::virtio::device::VirtioDevice;
    use vmm::devices::virtio::generated::virtio_mem::virtio_mem_config;
    use vmm::devices::virtio::mem::{
        VIRTIO_MEM_DEFAULT_BLOCK_SIZE_MIB, VIRTIO_MEM_DEFAULT_SLOT_SIZE_MIB, VirtioMem,
    };
    use vmm::devices::virtio::test_utils::VirtQueue;
    use vmm::devices::virtio::transport::mmio::IrqTrigger;
    use vmm::utils::{mib_to_bytes, u32_mib_to_bytes};
    use vmm::vmm_config::machine_config::HugePageConfig;
    use vmm::vstate::kvm::Kvm;
    use vmm::vstate::memory::{GuestAddress, anonymous};
    use vmm::vstate::vm::KvmVm;

    pub fn target(mut input: &[u8]) -> Result<(), InsufficientData> {
        const MEMORY_16MB: usize = 16 << 20;
        // Due to AFL++ limit of 512MiB of virtual memory, we can only allocate up to
        // 256MiB of hotpluggable memory.
        const MAX_HOTPLUG_SIZE_MIB: usize = 256;

        let default_block_size_mib = usize::try_from(VIRTIO_MEM_DEFAULT_BLOCK_SIZE_MIB)
            .expect("virtio-mem block size does not fit in usize");
        let default_slot_size_mib = usize::try_from(VIRTIO_MEM_DEFAULT_SLOT_SIZE_MIB)
            .expect("virtio-mem slot size does not fit in usize");

        let input = &mut input;

        // We fuzz the queue size, as it is possible that a driver sets up a queue smaller than the
        // device's default queue size. For the mem device, the default queue size is 256 entries,
        // so there is no point in setting up queues larger than that (and the fuzzer uses u8 to
        // index into the descriptor table, so it could not make use of larger queues anyway).
        // Note that queue size has to be a power of two. This is verified via assert! by
        // VirtQueue::new
        let queue_size = (input.take_u8()? as u16).next_power_of_two();

        let [huge_pages, ..] = input.take_bools()?;
        let huge_page_config = match huge_pages {
            true => {
                // Exit gracefully if we don't have enough hugepages, as otherwise the fuzz target
                // would fail with SIGBUS.
                if !check_hugepages_available(MEMORY_16MB) {
                    return Ok(());
                }
                HugePageConfig::Hugetlbfs2M
            }
            false => HugePageConfig::None,
        };

        let regions = anonymous(&[(GuestAddress(0), MEMORY_16MB)], false, huge_page_config)
            .expect("Cannot initialize memory");
        // Set up VM for virtio-mem device
        let kvm = Kvm::new(vec![]).unwrap();
        let mut vm = KvmVm::new(kvm).unwrap();
        vm.register_dram_memory_regions(regions).unwrap();

        // Fuzz the location of the hotpluggable memory in [512GiB, 1024GiB]
        let virtio_mem_addr = input
            .take_clamp_u64(512 << 30, 1024 << 30)?
            .next_multiple_of(u32_mib_to_bytes(VIRTIO_MEM_DEFAULT_SLOT_SIZE_MIB));

        // Fuzz the block size as a power of 2 >= 2MiB (and less than the max hotplug size)
        let block_size_mib = input
            .take_clamp_usize(default_block_size_mib, MAX_HOTPLUG_SIZE_MIB)?
            .next_power_of_two();

        // Fuzz the block size as a power of 2 >= block_size (and less than the max hotplug size)
        let slot_size_mib = input
            .take_clamp_usize(
                block_size_mib.max(default_slot_size_mib),
                MAX_HOTPLUG_SIZE_MIB,
            )?
            .next_power_of_two();

        // Fuzz the total size as a multiple of slot size (and less than the max hotplug size)
        let total_size_mib = input
            .take_clamp_usize(slot_size_mib, MAX_HOTPLUG_SIZE_MIB)?
            .next_multiple_of(slot_size_mib);

        // Fuzz the initial requested size
        let requested_size_mib = input
            .take_clamp_usize(0, total_size_mib)?
            .next_multiple_of(block_size_mib);

        // Fuzz the initial usable region size
        let usable_region_size_mib = input
            .take_clamp_usize(requested_size_mib, total_size_mib)?
            .next_multiple_of(block_size_mib);

        // Register hotpluggable memory region
        // Note that the state of the region is "unplugged", despite the block state
        // being generated at random. This should be fine as we just want to fuzz the
        // device logic and the plug/unplug operations in the vm object are idempotent
        // and will not fail.
        vm.register_hotpluggable_memory_region(
            anonymous(
                &[(GuestAddress(virtio_mem_addr), mib_to_bytes(total_size_mib))],
                false,
                huge_page_config,
            )
            .expect("Cannot initialize hotpluggable memory")
            .pop()
            .unwrap(),
            mib_to_bytes(slot_size_mib),
        )
        .unwrap();

        let vm = Arc::new(vm);

        let irq = Arc::new(IrqTrigger::new());
        let mut vq = VirtQueue::new(GuestAddress(0), vm.guest_memory(), queue_size);

        let nb_blocks = total_size_mib / block_size_mib;
        let plugged_blocks = input.take_bitvec(nb_blocks)?;

        // use .from_state() to initialize with a random (but valid) state
        let mut device = VirtioMem::from_state(
            vm.clone(),
            vec![vq.create_queue()],
            virtio_mem_config {
                block_size: mib_to_bytes(block_size_mib) as u64,
                addr: virtio_mem_addr,
                region_size: mib_to_bytes(total_size_mib) as u64,
                plugged_size: mib_to_bytes(plugged_blocks.count_ones() * block_size_mib) as u64,
                requested_size: mib_to_bytes(requested_size_mib) as u64,
                usable_region_size: mib_to_bytes(usable_region_size_mib) as u64,
                ..Default::default()
            },
            mib_to_bytes(slot_size_mib),
            plugged_blocks,
        )
        .unwrap();

        device.set_acked_features(device.avail_features());
        device.activate(vm.guest_memory().clone(), irq).unwrap();

        // randomly process requests
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
    //! Each test contains a seed as a u8 array, which is written to a file in fuzzer/in/mem_hotplug
    //! at the end.
    use std::fs::OpenOptions;
    use std::io::Write;

    #[test]
    fn generate_input_seed() {
        #[rustfmt::skip]
        let plug_seed = [
            0xff, // queue size (will be rounded up to next multiple of two, e.g. 256)
            0x00, // no huge pages
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // start at 512GiB (0 offset)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // block size 2 MiB (0 offset)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // slot size 128 MiB (0 offset)
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // total size 256 MiB (1 offset)
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // requested size 256 MiB (256 offset)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // usable size 0 MiB (0 offset)

            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // empty plugged_blocks bitmap (128b)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // continued

            // do a plug

            // fill virt queue first time
            0x01, // byte used to determine how many descriptors to write to queue (+1 is added)

            // first descriptor header
            0x00, // byte used to determine index at which first descriptor will be placed
            0x00, 0x20, // address at which descriptor will be put in guest memory
            0x01, // descriptor flags (VIRTQ_DESC_F_NEXT)
            0x01, // index at which the next descriptor in the chain will be placed

            // first descriptor buffer (request header)
            0x18, 0x00, // length of buffer (24 bytes here)
            0x00, 0x00, // type = VIRTIO_MEM_REQ_PLUG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
            0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, // addr = 512GiB
            0x80, 0x00, // nb_blocks = 128
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding

            // second descriptor header (chained to first)
            0x01, // byte used to determine index at which second descriptor will be placed
            0x00, 0x21, // address at which descriptor will be put in guest memory
            0x02, // descriptor flags (VIRTQ_DESC_F_WRITE)
            0x00, // index at which the next descriptor in the chain will be placed

            // second descriptor buffer (request header)
            0x10, 0x00, // length of buffer (16 bytes here)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // empty buffer
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // empty buffer

        ];

        #[rustfmt::skip]
        let unplug_seed = [
            0xff, // queue size (will be rounded up to next multiple of two, e.g. 256)
            0x00, // no huge pages
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // start at 512GiB (0 offset)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // block size 2 MiB (0 offset)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // slot size 128 MiB (0 offset)
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // total size 256 MiB (1 offset)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // requested size 0 MiB (0 offset)
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // usable size 256 MiB (256 offset)

            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // full plugged_blocks bitmap (128b)
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // continued

            // do an unplug

            // fill virt queue first time
            0x01, // byte used to determine how many descriptors to write to queue (+1 is added)

            // first descriptor header
            0x00, // byte used to determine index at which first descriptor will be placed
            0x00, 0x20, // address at which descriptor will be put in guest memory
            0x01, // descriptor flags (VIRTQ_DESC_F_NEXT)
            0x01, // index at which the next descriptor in the chain will be placed

            // first descriptor buffer (request header)
            0x18, 0x00, // length of buffer (24 bytes here)
            0x01, 0x00, // type = VIRTIO_MEM_REQ_UNPLUG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
            0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, // addr = 512GiB
            0x80, 0x00, // nb_blocks = 128
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding

            // second descriptor header (chained to first)
            0x01, // byte used to determine index at which second descriptor will be placed
            0x00, 0x21, // address at which descriptor will be put in guest memory
            0x02, // descriptor flags (VIRTQ_DESC_F_WRITE)
            0x00, // index at which the next descriptor in the chain will be placed

            // second descriptor buffer (request header)
            0x10, 0x00, // length of buffer (16 bytes here)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // empty buffer
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // empty buffer
        ];

        let _ = std::fs::create_dir_all("in/mem_hotplug");
        let mut plug_seed_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open("in/mem_hotplug/plug_request.in")
            .unwrap();

        plug_seed_file.write_all(&plug_seed).unwrap();
        let mut unplug_seed_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open("in/mem_hotplug/unplug_request.in")
            .unwrap();

        unplug_seed_file.write_all(&unplug_seed).unwrap();
    }
}
