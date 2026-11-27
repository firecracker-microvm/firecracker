// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fuzz target for threaded, multiqueue virtio-block.
//!
//! The device runs one worker thread per queue, on the sync or the io_uring file engine. The fuzz
//! input takes the device options shared with the block target, then the queue count, the engine,
//! which queues the driver enables, and then a sequence of driver and VMM actions: filling and
//! notifying queues, kicks, dirty-page commits, reset and re-activation, disk updates, saves and
//! save-restore round trips. The workers keep running between actions, as in production; the
//! target pauses them with `prepare_save()`, which returns only once each has drained, before it
//! writes guest memory and before it saves the device, so it never writes guest memory while a
//! worker is reading it.
//!
//! The drive has no rate limiter, and the target runs no VMM event loop: in threaded mode the
//! device's only VMM-thread events are its activation and its rate limiter's refill timer, so
//! without a limiter the loop has nothing to handle. The rate limiter is out of this target's
//! scope.

#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;

use fuzzer::*;

#[cfg(feature = "afl_fuzz")]
afl_main!(fuzzing::target);

#[cfg(feature = "stdin_fuzz")]
stdin_main!(fuzzing::target);

pub mod fuzzing {
    use std::fs::File;
    use std::num::NonZeroU16;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use fuzzer::block::{DeviceOptions, GuestMemoryError, guest_memory, new_device};
    use fuzzer::virtio::{FuzzData, InsufficientData, fuzz_data_descriptor};
    use vmm::devices::virtio::block::persist::BlockConstructorArgs;
    use vmm::devices::virtio::block::virtio::VirtioBlock;
    use vmm::devices::virtio::block::virtio::device::FileEngineType;
    use vmm::devices::virtio::device::VirtioDevice;
    use vmm::devices::virtio::queue::QueueConfig;
    use vmm::devices::virtio::test_utils::VirtQueue;
    use vmm::devices::virtio::transport::mmio::IrqTrigger;
    use vmm::snapshot::Persist;
    use vmm::vstate::memory::{GuestAddress, GuestMemoryMmap};
    use vmm::vstate::vm::MAX_SUPPORTED_KVM_VCPUS;

    const MEMORY_SIZE: usize = 0x80000;
    // hugetlbfs backs guest memory in 2 MiB pages, so the guest gets one whole page. The layout
    // below fits in MEMORY_SIZE, so it fits here too.
    const MEMORY_HUGETLBFS_SIZE: usize = 0x200000;
    // Descriptor buffers start below 0x10000 (u16 address) and are at most 0xffff bytes long, so
    // they always end below 0x20000. Placing every queue above that keeps device writes (reads
    // from disk, GET_ID) from landing on any queue's rings.
    const QUEUES_BASE: u64 = 0x20000;
    // A 256-entry split queue needs about 6.6 KiB, so 8 KiB per queue is enough. 32 queues end at
    // 0x60000, inside MEMORY_SIZE.
    const QUEUE_STRIDE: u64 = 0x2000;
    // Firecracker rejects more queues than vCPUs, and caps vCPUs at MAX_SUPPORTED_KVM_VCPUS.
    const MAX_QUEUES: u8 = MAX_SUPPORTED_KVM_VCPUS as u8;
    const _: () = assert!(MAX_SUPPORTED_KVM_VCPUS <= u8::MAX as u16);
    const SECTOR_SIZE: u64 = 512;
    // Pauses, disk updates and dirty-page commits wait for every worker to reply, so inputs with
    // thousands of ops run for seconds and AFL++ reports them as hangs. Cap the sequence to keep
    // inputs fast.
    const MAX_OPS: usize = 256;
    // After a reset, activate() waits for a worker to use a request queued before the
    // re-activation. A malformed chain is never used, so cap the total wait per input well below
    // AFL++'s 2 s timeout.
    const MAX_PREFILL_WAIT: Duration = Duration::from_millis(100);
    // A restore spawns a worker (and on the io_uring engine a ring) per queue and joins the old
    // ones: 256 restores of 32 queues take over a second, so cap them separately.
    const MAX_RESTORES: usize = 8;
    #[derive(Debug)]
    enum Op {
        Fill(usize),
        Notify(usize),
        Kick,
        CommitDirty,
        ResetAndReactivate,
        UpdateDiskImage(u64),
        Save,
        SaveAndRestore,
    }

    impl Op {
        fn take<'a>(
            input: &mut impl FuzzData<'a>,
            num_queues: usize,
        ) -> Result<Op, InsufficientData> {
            Ok(match input.take_u8()? % 8 {
                0 => Op::Fill(input.take_u8()? as usize % num_queues),
                1 => Op::Notify(input.take_u8()? as usize % num_queues),
                2 => Op::Kick,
                3 => Op::CommitDirty,
                4 => Op::ResetAndReactivate,
                5 => Op::UpdateDiskImage(take_disk_len(input)?),
                6 => Op::Save,
                _ => Op::SaveAndRestore,
            })
        }
    }

    /// Saves the device and returns one restored from that state, as on snapshot restore
    /// (device_manager/persist.rs): restore, spawn the workers, and re-activate if the device was
    /// active. The queues come back from the state, so the driver's rings carry over. A started
    /// worker only waits for queue events, so, as Vmm::resume_vm does, kick the restored device to
    /// process requests the driver queued and notified before the save.
    fn save_and_restore(block: &VirtioBlock, mem: &GuestMemoryMmap) -> VirtioBlock {
        // As on snapshot creation: save, then commit the dirty pages.
        let state = block.save();
        block.commit_dirty();
        let mut restored =
            VirtioBlock::restore(BlockConstructorArgs { mem: mem.clone() }, &state).unwrap();
        restored.spawn_worker(Arc::new(vec![])).unwrap();
        if state.virtio_state.activated {
            restored
                .activate(mem.clone(), Arc::new(IrqTrigger::new()))
                .unwrap();
            restored.kick();
        }
        restored
    }

    fn take_disk_len<'a>(input: &mut impl FuzzData<'a>) -> Result<u64, InsufficientData> {
        Ok((input.take_u8()? as u64 + 1) * SECTOR_SIZE)
    }

    /// Swaps in a fresh backing file of `len` bytes, returning the file the device now uses.
    ///
    /// The device and every worker (which answer synchronously) open their own fds on the path
    /// during the call. The drive's config keeps the path, which the device opens again when it
    /// is restored, so the device's current file must stay open. On failure the device keeps its
    /// old path and file.
    fn update_disk(block: &mut VirtioBlock, backing: File, len: u64) -> File {
        let (f, path) = fuzzer::make_memfd("block_mq_update");
        f.set_len(len).unwrap();
        match block.update_disk_image(path) {
            Ok(()) => f,
            Err(_) => backing,
        }
    }

    /// The driver's queues, queue `idx` at `QUEUES_BASE + idx * QUEUE_STRIDE`, with fresh rings.
    fn create_queues(
        mem: &GuestMemoryMmap,
        num_queues: usize,
        queue_size: u16,
    ) -> Vec<VirtQueue<'_>> {
        (0..num_queues)
            .map(|idx| {
                let start = GuestAddress(QUEUES_BASE + QUEUE_STRIDE * idx as u64);
                VirtQueue::new(start, mem, queue_size)
            })
            .collect()
    }

    /// Resets the device and, if it reset, re-creates the driver's rings and re-activates it
    /// with the queues the input selects next. Returns false if the input ran out.
    fn reset_and_reactivate<'a, 'm>(
        block: &mut VirtioBlock,
        input: &mut impl FuzzData<'a>,
        vqs: &mut Vec<VirtQueue<'m>>,
        ready: &mut Vec<bool>,
        features: u64,
        mem: &'m GuestMemoryMmap,
        queue_size: u16,
        scratch: &GuestMemoryMmap,
        wait_left: &mut Duration,
    ) -> bool {
        if !block.reset() {
            return true;
        }
        let Ok(new_ready) = take_ready(input, vqs.len()) else {
            return false;
        };
        *ready = new_ready;
        // The driver re-creates its rings after a reset.
        *vqs = create_queues(mem, vqs.len(), queue_size);
        let Ok(notified) = prefill_and_notify(block, input, vqs, ready, scratch) else {
            return false;
        };
        activate(
            block,
            vqs,
            ready,
            features,
            mem,
            notified.map(|idx| (idx, wait_left)),
        );
        true
    }

    /// Before re-activation, the driver can queue a request on one queue, picked by the input, and
    /// notify it. The worker then picks it up through its queue event when it starts, not through
    /// a kick. Returns the notified queue, if any.
    fn prefill_and_notify<'a>(
        block: &VirtioBlock,
        input: &mut impl FuzzData<'a>,
        vqs: &mut [VirtQueue],
        ready: &[bool],
        scratch: &GuestMemoryMmap,
    ) -> Result<Option<usize>, InsufficientData> {
        let prefill = input.take_u8()?;
        if prefill & 1 == 0 {
            return Ok(None);
        }
        let idx = usize::from(prefill >> 1) % vqs.len();
        // The workers hold no queue until activation, so the driver can write it unpaused.
        if !fill_queue(input, vqs, ready, idx, scratch)? {
            return Ok(None);
        }
        let _ = block.queue_event(idx).unwrap().write(1);
        Ok(Some(idx))
    }

    /// Fills queue `idx` from the input, or, when the driver couldn't fill it (the queue isn't
    /// ready, or the device hasn't used every entry yet), consumes the same bytes into a queue in
    /// `scratch`. Either way the rest of the input parses the same, whatever the workers did.
    /// Returns whether the queue was filled.
    fn fill_queue<'a>(
        input: &mut impl FuzzData<'a>,
        vqs: &mut [VirtQueue],
        ready: &[bool],
        idx: usize,
        scratch: &GuestMemoryMmap,
    ) -> Result<bool, InsufficientData> {
        // A paused worker consumes nothing, so filling again before it has used every entry could
        // move avail.idx more than a queue size past the device's next index. The worker unwraps
        // that InvalidAvailIdx by design; the block target never reaches it because it processes
        // the queue after every fill. used.idx is the device's count: only the device writes it.
        if ready[idx] && vqs[idx].avail.idx.get() == vqs[idx].used.idx.get() {
            // Queues are out of reach of descriptor buffers, so no overwrite guard.
            input.fill_virt_queue(&mut vqs[idx], fuzz_data_descriptor, false)?;
            return Ok(true);
        }
        let mut skipped = VirtQueue::new(GuestAddress(0), scratch, vqs[idx].size());
        input.fill_virt_queue(&mut skipped, fuzz_data_descriptor, false)?;
        Ok(false)
    }

    /// Enables the queues selected by `ready`, acks `features` and activates the device. If
    /// `wait` names a queue, waits, within the remaining budget, for its worker to use the queued
    /// entries.
    fn activate(
        block: &mut VirtioBlock,
        vqs: &[VirtQueue],
        ready: &[bool],
        features: u64,
        mem: &GuestMemoryMmap,
        wait: Option<(usize, &mut Duration)>,
    ) {
        for (idx, vq) in vqs.iter().enumerate() {
            if ready[idx] {
                // Keep the device's max_size: the driver can't change it, and the device rejects
                // restoring a queue whose max_size isn't its own.
                let config = block.queue_config_mut(idx).unwrap();
                *config = QueueConfig {
                    max_size: config.max_size,
                    ..vq.create_queue().config
                };
            }
        }
        block.set_acked_features(block.avail_features() & features);
        block
            .activate(mem.clone(), Arc::new(IrqTrigger::new()))
            .unwrap();
        if let Some((idx, wait_left)) = wait {
            // Every valid request completes quickly; the budget bounds a malformed chain, which
            // the worker never uses.
            let start = Instant::now();
            let deadline = start + *wait_left;
            while vqs[idx].used.idx.get() != vqs[idx].avail.idx.get() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_micros(100));
            }
            *wait_left = wait_left.saturating_sub(start.elapsed());
        }
        // The workers start running.
    }

    /// Pauses the workers if they may be running. A pause returns once each worker has drained.
    fn pause(block: &mut VirtioBlock, paused: &mut bool) {
        if !*paused {
            block.prepare_save();
            *paused = true;
        }
    }

    fn take_ready<'a>(
        input: &mut impl FuzzData<'a>,
        num_queues: usize,
    ) -> Result<Vec<bool>, InsufficientData> {
        Ok(input.take_bitvec(num_queues)?.into_iter().collect())
    }

    pub fn target(mut data: &[u8]) -> Result<(), InsufficientData> {
        // glibc gives each thread its own malloc arena, reserving up to 64 MiB of address space
        // apiece, so a few dozen workers exhaust AFL's 512 MiB memory limit. One arena keeps that
        // limit meaningful.
        // SAFETY: mallopt only adjusts allocator tuning.
        unsafe { libc::mallopt(libc::M_ARENA_MAX, 1) };

        let input = &mut data;
        let options = DeviceOptions::take(input)?;
        let features = options.features;
        let queue_size = options.queue_size;
        let queue_count = input.take_u8()?;
        let [async_engine, teardown_running, track_dirty_pages, ..] = input.take_bools()?;
        let num_queues = (queue_count % MAX_QUEUES + 1) as usize;
        // Each worker then owns an io_uring. Pausing a worker drains its ring, so every
        // submitted request has completed by the time prepare_save() returns.
        let file_engine_type = match async_engine {
            true => FileEngineType::Async,
            false => FileEngineType::Sync,
        };
        // DeviceOptions turns discard off for a read-only drive; the io_uring engine doesn't
        // support it either.
        let options = DeviceOptions {
            discard: options.discard && !async_engine,
            ..options
        };
        let mut ready = take_ready(input, num_queues)?;
        let mut prefill_wait_left = MAX_PREFILL_WAIT;
        let mut restores_left = MAX_RESTORES;

        let mem = match guest_memory(
            options.huge_pages,
            MEMORY_SIZE,
            MEMORY_HUGETLBFS_SIZE,
            track_dirty_pages,
        ) {
            Ok(mem) => mem,
            // Exit gracefully if we don't have enough hugepages, as otherwise the fuzz target
            // would fail with SIGBUS.
            Err(GuestMemoryError::NotEnoughHugepages) => return Ok(()),
            Err(err) => panic!("Cannot initialize memory: {err:?}"),
        };
        // Where a fill the driver couldn't make goes; see fill_queue().
        let scratch = guest_memory(false, MEMORY_SIZE, 0, false).unwrap();

        let (mut block, mut backing) = new_device(
            &options,
            NonZeroU16::new(num_queues as u16),
            None,
            file_engine_type,
        );
        // No seccomp filter: an empty program is not installed.
        block.spawn_worker(Arc::new(vec![])).unwrap();

        let mut vqs = create_queues(&mem, num_queues, queue_size);

        activate(&mut block, &vqs, &ready, features, &mem, None);
        let mut paused = false;

        for _ in 0..MAX_OPS {
            let Ok(op) = Op::take(input, num_queues) else {
                break;
            };
            let more = match op {
                Op::Fill(idx) => {
                    // The device must not read the ring while the driver writes it.
                    pause(&mut block, &mut paused);
                    // A fill only fails when the input runs out, so there is no next op.
                    fill_queue(input, &mut vqs, &ready, idx, &scratch).is_ok()
                }
                Op::Notify(idx) => {
                    // Running workers handle it through their queue event; paused ones once
                    // resumed.
                    let _ = block.queue_event(idx).unwrap().write(1);
                    true
                }
                Op::Kick => {
                    // Paused workers resume and process their queues. Running ones take the
                    // worker's other kick path, which only processes the queue again. Either way
                    // the kick is only sent: it doesn't wait for the workers.
                    block.kick();
                    paused = false;
                    true
                }
                Op::CommitDirty => {
                    block.commit_dirty();
                    true
                }
                Op::UpdateDiskImage(len) => {
                    backing = update_disk(&mut block, backing, len);
                    true
                }
                Op::Save => {
                    // As on snapshot creation, save with the workers paused.
                    pause(&mut block, &mut paused);
                    let _ = block.save();
                    true
                }
                Op::SaveAndRestore => {
                    if restores_left > 0 {
                        restores_left -= 1;
                        pause(&mut block, &mut paused);
                        block = save_and_restore(&block, &mem);
                        // A restored, active device starts its data path again.
                        paused = false;
                    }
                    true
                }
                Op::ResetAndReactivate => {
                    // The re-activated device starts its data path again.
                    paused = false;
                    reset_and_reactivate(
                        &mut block,
                        input,
                        &mut vqs,
                        &mut ready,
                        features,
                        &mem,
                        queue_size,
                        &scratch,
                        &mut prefill_wait_left,
                    )
                }
            };
            if !more {
                break;
            }
        }

        // Tear the device down with its workers running or paused, as the input picks. As
        // Vmm::drop, commit the dirty pages before dropping the device.
        if teardown_running {
            block.kick();
        } else {
            pause(&mut block, &mut paused);
        }
        block.commit_dirty();
        drop(block);
        drop(backing);

        Ok(())
    }
}

#[cfg(test)]
mod seed_gen {
    //! Module used for generating the binary input seeds
    //!
    //! Each test builds a seed and saves it to a file in /in/block_mq.
    use fuzzer::block::seed::{
        Request, push_device_options, push_fill, push_write_fill, save_seed,
    };

    const OP_FILL: u8 = 0;
    const OP_NOTIFY: u8 = 1;
    const OP_KICK: u8 = 2;
    const OP_COMMIT_DIRTY: u8 = 3;
    const OP_RESET_AND_REACTIVATE: u8 = 4;
    const OP_UPDATE_DISK_IMAGE: u8 = 5;
    const OP_SAVE: u8 = 6;
    const OP_SAVE_AND_RESTORE: u8 = 7;

    /// `mq` flag bits (see [`push_header`]).
    const MQ_IO_URING: u8 = 0x1;
    const MQ_TEARDOWN_RUNNING: u8 = 0x2;
    const MQ_DIRTY_TRACKING: u8 = 0x4;

    /// `device` flag bits (see [`push_device_options`]).
    const DEVICE_HUGETLBFS: u8 = 0x8;
    const DEVICE_DISCARD: u8 = 0x10;

    /// VIRTIO_BLK_F_MQ
    const F_MQ: u64 = 1 << 12;
    /// VIRTIO_BLK_F_DISCARD
    const F_DISCARD: u64 = 1 << 13;

    /// Appends the input header: the device options shared with the block target (`features`, a
    /// queue size of 256, the `device` flag byte), then this target's `queue_count` byte, its `mq`
    /// flag byte and the `ready` bitmap of the queues the driver enables.
    ///
    /// `mq` bits: 0 io_uring, 1 teardown running, 2 dirty tracking.
    fn push_header(
        seed: &mut Vec<u8>,
        features: u64,
        device: u8,
        queue_count: u8,
        mq: u8,
        ready: u8,
    ) {
        push_device_options(seed, features, device);
        seed.push(queue_count); // num_queues: queue_count % 32 + 1
        seed.push(mq);
        seed.push(ready);
    }

    /// Saves a seed with a write on each of two queues, one of them notified (the kick processes
    /// both), on a device configured by the `device` and `mq` flag bytes, followed by the ops in
    /// `tail`.
    fn save_two_queue_seed(name: &str, device: u8, mq: u8, tail: &[u8]) {
        let mut seed = Vec::new();
        // 1 % 32 + 1 = 2 queues, both ready
        push_header(&mut seed, F_MQ, device, 0x1, mq, 0b11);

        seed.extend_from_slice(&[OP_FILL, 0x0]);
        push_write_fill(&mut seed, &[0x0100]);
        seed.extend_from_slice(&[OP_FILL, 0x1]);
        push_write_fill(&mut seed, &[0x1000]);
        seed.extend_from_slice(&[OP_NOTIFY, 0x1]);
        seed.push(OP_KICK);
        seed.extend_from_slice(tail);

        save_seed("block_mq", name, &seed);
    }

    /// Saves a seed with one fill of a single queue with `reqs`, then a kick, on a device with
    /// `features` and configured by the `device` flag byte.
    fn save_one_queue_seed(name: &str, features: u64, device: u8, reqs: &[(u16, Request)]) {
        let mut seed = Vec::new();
        push_header(&mut seed, features, device, 0x0, 0x0, 0b1);
        seed.extend_from_slice(&[OP_FILL, 0x0]);
        push_fill(&mut seed, reqs);
        seed.push(OP_KICK);
        save_seed("block_mq", name, &seed);
    }

    #[test]
    fn generate_input_seed() {
        // writeback, read-write, non-root, no discard, sync engine
        save_two_queue_seed("two_queue_writes", 0x0, 0x0, &[]);
    }

    #[test]
    fn generate_dirty_tracking_input_seed() {
        // as above, with dirty page tracking, then a dirty-page commit
        save_two_queue_seed(
            "two_queue_writes_dirty",
            0x0,
            MQ_DIRTY_TRACKING,
            &[OP_COMMIT_DIRTY],
        );
    }

    #[test]
    fn generate_async_input_seed() {
        // as the sync seed, on the io_uring engine
        save_two_queue_seed("two_queue_writes_async", 0x0, MQ_IO_URING, &[]);
    }

    #[test]
    fn generate_hugetlbfs_input_seed() {
        // as the sync seed, with guest memory backed by hugetlbfs
        save_two_queue_seed("two_queue_writes_hugetlbfs", DEVICE_HUGETLBFS, 0x0, &[]);
    }

    #[test]
    fn generate_teardown_running_input_seed() {
        // as the sync seed, torn down with the workers running rather than paused
        save_two_queue_seed(
            "two_queue_writes_teardown_running",
            0x0,
            MQ_TEARDOWN_RUNNING,
            &[],
        );
    }

    #[test]
    fn generate_update_disk_input_seed() {
        // as the sync seed, then a disk update to 8 sectors and another write on queue 0, on the
        // new disk
        let mut tail = vec![OP_UPDATE_DISK_IMAGE, 0x7, OP_FILL, 0x0];
        push_write_fill(&mut tail, &[0x2000]);
        tail.push(OP_KICK);
        save_two_queue_seed("two_queue_writes_update_disk", 0x0, 0x0, &tail);
    }

    #[test]
    fn generate_save_input_seed() {
        // as the sync seed, then a save, which pauses the workers, and another write on queue 0
        // that a kick resumes them to process
        let mut tail = vec![OP_SAVE, OP_FILL, 0x0];
        push_write_fill(&mut tail, &[0x2000]);
        tail.push(OP_KICK);
        save_two_queue_seed("two_queue_writes_save", 0x0, 0x0, &tail);
    }

    #[test]
    fn generate_restore_input_seed() {
        // as the sync seed, then a save-restore round trip and another write on queue 0
        let mut tail = vec![OP_SAVE_AND_RESTORE, OP_FILL, 0x0];
        push_write_fill(&mut tail, &[0x2000]);
        tail.push(OP_KICK);
        save_two_queue_seed("two_queue_writes_restore", 0x0, 0x0, &tail);
    }

    #[test]
    fn generate_four_queue_input_seed() {
        // 3 % 32 + 1 = 4 queues, all ready, a write on each, then a kick
        let mut seed = Vec::new();
        push_header(&mut seed, F_MQ, 0x0, 0x3, 0x0, 0b1111);
        for (idx, base) in [0x0100u16, 0x1000, 0x2000, 0x3000].into_iter().enumerate() {
            seed.extend_from_slice(&[OP_FILL, u8::try_from(idx).unwrap()]);
            push_write_fill(&mut seed, &[base]);
        }
        seed.push(OP_KICK);

        save_seed("block_mq", "four_queue_writes", &seed);
    }

    #[test]
    fn generate_not_ready_input_seed() {
        // 2 queues, only queue 0 ready. The fill of queue 1 goes to the scratch queue (the driver
        // can't fill a queue it hasn't enabled), and its notification reaches a worker whose queue
        // isn't ready.
        let mut seed = Vec::new();
        push_header(&mut seed, F_MQ, 0x0, 0x1, 0x0, 0b01);
        seed.extend_from_slice(&[OP_FILL, 0x0]);
        push_write_fill(&mut seed, &[0x0100]);
        seed.extend_from_slice(&[OP_FILL, 0x1]);
        push_write_fill(&mut seed, &[0x1000]);
        seed.extend_from_slice(&[OP_NOTIFY, 0x1, OP_KICK]);

        save_seed("block_mq", "two_queue_one_not_ready", &seed);
    }

    #[test]
    fn generate_read_input_seed() {
        // A write and then a read of the same sector in one fill of queue 0.
        save_one_queue_seed(
            "one_queue_write_read",
            F_MQ,
            0x0,
            &[(0x0100, Request::Write), (0x1000, Request::Read)],
        );
    }

    #[test]
    fn generate_get_id_input_seed() {
        // writeback, read-write, non-root, no discard
        save_one_queue_seed("one_queue_get_id", F_MQ, 0x0, &[(0x0100, Request::GetId)]);
    }

    #[test]
    fn generate_discard_input_seed() {
        // discard enabled and acked. A write, then a discard of the same sector.
        save_one_queue_seed(
            "one_queue_write_discard",
            F_MQ | F_DISCARD,
            DEVICE_DISCARD,
            &[(0x0100, Request::Write), (0x1000, Request::Discard)],
        );
    }

    #[test]
    fn generate_reset_prefill_input_seed() {
        let mut seed = Vec::new();
        // 2 queues, both ready
        push_header(&mut seed, F_MQ, 0x0, 0x1, 0x0, 0b11);

        // A reset, then a write queued and notified on queue 1 before re-activation, which its
        // worker processes through the queue event once it starts.
        seed.push(OP_RESET_AND_REACTIVATE);
        seed.push(0b11); // both queues ready again
        seed.push(0x3); // prefill queue 1 % 2 = 1
        push_write_fill(&mut seed, &[0x1000]);

        save_seed("block_mq", "two_queue_reset_prefill", &seed);
    }
}
