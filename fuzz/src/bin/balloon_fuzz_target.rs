// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
    //! Fuzzes the virtio-balloon device by placing random descriptors in its inflate, deflate,
    //! stats, free-page-hinting, and free-page-reporting queues.

    use std::sync::Arc;

    use fuzzer::check_hugepages_available;
    use fuzzer::virtio::{FuzzData, InsufficientData, fuzz_data_descriptor};
    use vmm::devices::virtio::balloon::Balloon;
    use vmm::devices::virtio::balloon::{DEFLATE_INDEX, INFLATE_INDEX, STATS_INDEX};
    use vmm::devices::virtio::device::VirtioDevice;
    use vmm::devices::virtio::test_utils::VirtQueue;
    use vmm::devices::virtio::transport::mmio::IrqTrigger;
    use vmm::vmm_config::machine_config::HugePageConfig;
    use vmm::vstate::memory::test_utils::into_region_ext;
    use vmm::vstate::memory::{GuestAddress, anonymous};

    pub fn target(mut input: &[u8]) -> Result<(), InsufficientData> {
        const MEMORY_64K: usize = 0x10000;
        const MEMORY_8M: usize = 0x800000;

        let input = &mut input;
        let _features = input.take_u64()?;
        let queue_size = (input.take_u8()? as u16).next_power_of_two();

        let [
            huge_pages,
            deflate_on_oom,
            stats_enabled,
            free_page_hinting,
            free_page_reporting,
            ..,
        ] = input.take_bools()?;

        let (huge_page_config, mem_size) = match huge_pages {
            true => {
                if !check_hugepages_available(MEMORY_8M) {
                    return Ok(());
                }
                (HugePageConfig::Hugetlbfs2M, MEMORY_8M)
            }
            false => (HugePageConfig::None, MEMORY_64K),
        };

        let stats_polling_interval_s: u16 = if stats_enabled { 1 } else { 0 };

        let mut device = Balloon::new(
            0,
            deflate_on_oom,
            stats_polling_interval_s,
            free_page_hinting,
            free_page_reporting,
        )
        .expect("Failed to create balloon device");

        let regions = anonymous(&[(GuestAddress(0), mem_size)], false, huge_page_config)
            .expect("Cannot initialize memory");
        let mem = into_region_ext(regions);
        let irq = Arc::new(IrqTrigger::new());

        // Create queues matching the device's queue count.
        // Queue layout: [inflate, deflate, stats?, hinting?, reporting?]
        let num_queues = device.num_queues();
        let mut vqs: Vec<VirtQueue> = (0..num_queues)
            .map(|i| VirtQueue::new(GuestAddress(0x1000 * i as u64), &mem, queue_size))
            .collect();

        for (i, vq) in vqs.iter().enumerate() {
            *device.queue_config_mut(i).unwrap() = vq.create_queue().config;
        }

        // Ack all available features to ensure all queue processing paths are reachable.
        // Feature negotiation failures would just disable queue handlers, reducing coverage.
        device.set_acked_features(device.avail_features());
        device.activate(mem.clone(), irq).unwrap();

        // Inflate queue gets u32-aligned readonly descriptors (PFNs).
        // Deflate queue gets generic descriptors.
        // Stats queue (if present) gets BalloonStat structs (10 bytes each).
        // Hinting/reporting queues get page range descriptors.
        while let Ok(()) =
            input.fill_virt_queue(&mut vqs[INFLATE_INDEX], fuzz_data_descriptor, false)
        {
            let _ = input.fill_virt_queue(&mut vqs[DEFLATE_INDEX], fuzz_data_descriptor, false);

            // Fill optional queues if present
            for vq in vqs.iter_mut().skip(STATS_INDEX) {
                let _ = input.fill_virt_queue(vq, fuzz_data_descriptor, false);
            }

            // Call each queue processor individually to prevent one queue's error
            // from blocking the others (process_virtio_queues returns early on InvalidAvailIdx)
            _ = device.process_virtio_queues();

            // Note: stats queue is timer-driven (process_stats_timer_event), not called
            // by process_virtio_queues. It's pub(crate) so we can't call it directly.
            // AFL++ will still exercise it indirectly if it finds paths that trigger the timer.
        }

        // Exercise config space read/write with fuzzed offsets and data.
        // These are guest-accessible via MMIO/PCI config space operations.
        let mut config_buf = [0u8; 12];
        device.read_config(0, &mut config_buf);
        device.read_config(4, &mut config_buf[..4]);
        // Write actual_pages field (offset 4, 4 bytes)
        device.write_config(4, &[0x10, 0x00, 0x00, 0x00]);
        // Out-of-bounds read/write to exercise error paths
        device.read_config(100, &mut config_buf);
        device.write_config(100, &[0xFF]);

        // Exercise update_size (changes num_pages in config space)
        _ = device.update_size(1);

        // Exercise getters
        _ = device.config();
        _ = device.num_pages();
        _ = device.size_mb();
        _ = device.deflate_on_oom();
        _ = device.stats_polling_interval_s();
        _ = device.latest_stats();
        _ = device.is_activated();

        Ok(())
    }
}

#[cfg(test)]
mod seed_gen {
    use std::fs::OpenOptions;
    use std::io::Write;

    fn write_seed(name: &str, data: &[u8]) {
        let _ = std::fs::create_dir_all("in/balloon");
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(format!("in/balloon/{name}"))
            .unwrap()
            .write_all(data)
            .unwrap();
    }

    /// Build an inflate descriptor: readonly, with u32 PFN payload (4-byte aligned).
    /// Includes used_event padding.
    fn inflate_desc(num_descs: u8, idx: u8, addr: u16, pfns: &[u32]) -> Vec<u8> {
        let mut v = vec![num_descs, idx];
        v.extend_from_slice(&addr.to_le_bytes());
        v.push(0x00); // flags: readonly (inflate reads PFNs from guest)
        v.push(0x00); // next
        let payload: Vec<u8> = pfns.iter().flat_map(|p| p.to_le_bytes()).collect();
        v.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        v.extend_from_slice(&payload);
        v.extend_from_slice(&[0x0, 0x0]); // used_event
        v
    }

    /// Build a generic descriptor with raw payload. Includes used_event padding.
    fn raw_desc(num_descs: u8, idx: u8, addr: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![num_descs, idx];
        v.extend_from_slice(&addr.to_le_bytes());
        v.push(flags);
        v.push(0x00); // next
        v.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        v.extend_from_slice(payload);
        v.extend_from_slice(&[0x0, 0x0]); // used_event
        v
    }

    fn init_header(stats: bool, hinting: bool, reporting: bool) -> Vec<u8> {
        let mut v = Vec::new();
        // features (ignored - harness acks all available features)
        v.extend_from_slice(&0u64.to_le_bytes());
        // queue_size: use 1 to minimize descriptor count issues
        // (num_descs = take_u8 % queue_size + 1, with size=1 always gives 1)
        v.push(0x00);
        let bools: u8 = 0x02 // deflate_on_oom=true
            | if stats { 0x04 } else { 0 }
            | if hinting { 0x08 } else { 0 }
            | if reporting { 0x10 } else { 0 };
        v.push(bools);
        v
    }

    /// Inflate with consecutive PFNs → process_inflate, compact_page_frame_numbers, discard_range
    #[test]
    fn generate_inflate_seed() {
        let mut seed = init_header(false, false, false);
        seed.extend_from_slice(&inflate_desc(1, 0, 0x2000, &[0, 1, 2, 3, 4, 5, 6, 7]));
        seed.extend_from_slice(&raw_desc(1, 0, 0x3000, 0x00, &[0u8; 8]));
        write_seed("inflate.in", &seed);
    }

    /// Stats queue → process_stats_queue, update_with_stat, BalloonStat parsing
    #[test]
    fn generate_stats_seed() {
        let mut seed = init_header(true, false, false);
        // Inflate: minimal single PFN
        seed.extend_from_slice(&inflate_desc(1, 0, 0x2000, &[0]));
        // Deflate: minimal
        seed.extend_from_slice(&raw_desc(1, 0, 0x3000, 0x00, &[0u8; 4]));
        // Stats (index 2): BalloonStat = 10 bytes packed (u16 tag + u64 val)
        // Cover all 16 known tags (0-15) plus an unknown tag (99)
        let mut stats_payload = Vec::new();
        for tag in 0u16..=15 {
            stats_payload.extend_from_slice(&tag.to_le_bytes());
            stats_payload.extend_from_slice(&1024u64.to_le_bytes());
        }
        // Unknown tag to exercise the default/error branch
        stats_payload.extend_from_slice(&99u16.to_le_bytes());
        stats_payload.extend_from_slice(&0u64.to_le_bytes());
        seed.extend_from_slice(&raw_desc(1, 0, 0x4000, 0x02, &stats_payload));
        write_seed("stats.in", &seed);
    }

    /// Free page reporting → process_free_page_reporting_queue, discard_range
    #[test]
    fn generate_reporting_seed() {
        let mut seed = init_header(false, false, true);
        seed.extend_from_slice(&inflate_desc(1, 0, 0x2000, &[0]));
        seed.extend_from_slice(&raw_desc(1, 0, 0x3000, 0x00, &[0u8; 4]));
        // Reporting (index 2): descriptor addr+len defines range to discard
        seed.extend_from_slice(&raw_desc(1, 0, 0x4000, 0x00, &[0u8; 64]));
        write_seed("reporting.in", &seed);
    }

    /// Free page hinting → process_free_page_hinting_queue, cmd parsing
    #[test]
    fn generate_hinting_seed() {
        let mut seed = init_header(false, true, false);
        seed.extend_from_slice(&inflate_desc(1, 0, 0x2000, &[0]));
        seed.extend_from_slice(&raw_desc(1, 0, 0x3000, 0x00, &[0u8; 4]));
        // Hinting (index 2): 4-byte command descriptor (FREE_PAGE_HINT_STOP=0)
        seed.extend_from_slice(&raw_desc(1, 0, 0x4000, 0x00, &0u32.to_le_bytes()));
        write_seed("hinting.in", &seed);
    }

    /// All features → exercises all queue processing paths in one invocation
    #[test]
    fn generate_all_features_seed() {
        let mut seed = init_header(true, true, true);
        seed.extend_from_slice(&inflate_desc(1, 0, 0x2000, &[0, 1, 2, 3]));
        seed.extend_from_slice(&raw_desc(1, 0, 0x3000, 0x00, &[0u8; 4]));
        // Stats (index 2)
        let mut stats = Vec::new();
        stats.extend_from_slice(&4u16.to_le_bytes());
        stats.extend_from_slice(&1024u64.to_le_bytes());
        seed.extend_from_slice(&raw_desc(1, 0, 0x4000, 0x02, &stats));
        // Hinting (index 3): STOP command
        seed.extend_from_slice(&raw_desc(1, 0, 0x5000, 0x00, &0u32.to_le_bytes()));
        // Reporting (index 4)
        seed.extend_from_slice(&raw_desc(1, 0, 0x6000, 0x00, &[0u8; 32]));
        write_seed("all_features.in", &seed);
    }
}
