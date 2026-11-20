// Copyright 2026 VPSnet. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::os::unix::fs::{FileExt, OpenOptionsExt};

use utils::time::MockClock;
use vmm_sys_util::tempfile::TempFile;

use super::direct::DirectIo;
use super::tests::{check_clean_mem, check_dirty_mem, create_mem};
use super::*;
use crate::devices::virtio::block::virtio::request::{
    RequestHeader, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_OUT,
};
use crate::devices::virtio::block::virtio::test_utils::{
    default_block, direct_io_test_file, set_queue, set_rate_limiter,
    simulate_async_completion_event, simulate_queue_event,
};
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
use crate::rate_limiter::RateLimiter;
use crate::vstate::memory::Bytes;

fn next_completion(engine: &mut FileEngine, mem: &GuestMemoryMmap) -> u32 {
    let FileEngine::Async(engine) = engine else {
        unreachable!()
    };
    engine.drain(false).unwrap();
    engine.pop(mem).unwrap().unwrap().result().unwrap()
}

fn completed(engine: &mut FileEngine, mem: &GuestMemoryMmap, result: FileEngineOk) -> u32 {
    match result {
        FileEngineOk::Submitted => next_completion(engine, mem),
        FileEngineOk::Executed(done) => done.count,
    }
}

#[test]
fn test_direct_geometry() {
    let geometry = DirectIo::new(4096, 512, 1536).unwrap();
    assert!(geometry.aligned_span(512, 1024));
    assert!(!geometry.aligned_buffer(512));
    assert!(geometry.aligned_buffer(4096));
    DirectIo::new(0, 512, 4096).unwrap_err();
    DirectIo::new(4096, 0, 4096).unwrap_err();
    DirectIo::new(8192, 512, 4096).unwrap_err();
    DirectIo::new(512, 4096, 4608).unwrap_err();
    geometry.check_range(u64::MAX - 511, 512).unwrap_err();
}

#[test]
fn test_rmw_preserves_neighbors_and_waits_for_prior_write() {
    for ty in [FileEngineType::Sync, FileEngineType::Async] {
        let file = TempFile::new().unwrap().into_file();
        file.write_all_at(&[0x55; 8192], 0).unwrap();
        let mut engine =
            FileEngine::new(file, ty, Some(DirectIo::new(4096, 4096, 8192).unwrap())).unwrap();
        let mem = create_mem();
        mem.write_slice(&[0x33; 4096], GuestAddress(0)).unwrap();
        let first = engine
            .write(0, &mem, GuestAddress(0), 4096, PendingRequest::default())
            .unwrap();

        // Straddles two host blocks while modifying only two guest sectors.
        let src = GuestAddress(4097);
        mem.write_slice(&[0xa5; 1024], src).unwrap();
        let patch = engine
            .write(3584, &mem, src, 1024, PendingRequest::default())
            .unwrap();
        assert_eq!(completed(&mut engine, &mem, patch), 1024);
        assert_eq!(completed(&mut engine, &mem, first), 4096);
        let mut bytes = [0; 8192];
        engine.file().read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes[..3584], &[0x33; 3584]);
        assert_eq!(&bytes[3584..4608], &[0xa5; 1024]);
        assert_eq!(&bytes[4608..], &[0x55; 3584]);

        // A truncated backing cannot supply the second block to preserve.
        engine.file().set_len(4096).unwrap();
        engine
            .write(3584, &mem, src, 1024, PendingRequest::default())
            .unwrap_err();
        let mut first_block = [0; 4096];
        engine.file().read_exact_at(&mut first_block, 0).unwrap();
        assert_eq!(first_block, bytes[..4096]);
    }
}

#[test]
fn test_direct_short_read_marks_and_reports_only_delivered_prefix() {
    for ty in [FileEngineType::Sync, FileEngineType::Async] {
        for offset in [0, 512] {
            // Admit an 8K guest disk, then truncate its backing to inject a short host read.
            let file = TempFile::new().unwrap().into_file();
            file.write_all_at(&[0x42; 4096], 0).unwrap();
            let mut engine =
                FileEngine::new(file, ty, Some(DirectIo::new(4096, 4096, 8192).unwrap())).unwrap();
            let mem = create_mem();
            let result = engine
                .read(
                    offset,
                    &mem,
                    GuestAddress(0),
                    8192 - u32::try_from(offset).unwrap(),
                    PendingRequest::default(),
                )
                .unwrap();
            let len = completed(&mut engine, &mem, result);
            assert_eq!(u64::from(len), 4096 - offset);
            check_dirty_mem(&mem, GuestAddress(0), len);
            check_clean_mem(&mem, GuestAddress(4096), 4096);
            let mut copy = vec![0; len as usize];
            mem.read_slice(&mut copy, GuestAddress(0)).unwrap();
            assert!(copy.iter().all(|byte| *byte == 0x42));
        }
    }
}

#[test]
fn test_direct_staged_read_short_completion() {
    let file = TempFile::new().unwrap().into_file();
    file.write_all_at(&[0xbf; 1024], 0).unwrap();
    let mut engine = FileEngine::new(
        file,
        FileEngineType::Async,
        Some(DirectIo::new(4096, 512, 8192).unwrap()),
    )
    .unwrap();
    let mem = create_mem();
    let result = engine
        .read(0, &mem, GuestAddress(3), 4608, PendingRequest::default())
        .unwrap();
    assert!(matches!(result, FileEngineOk::Submitted));
    assert_eq!(next_completion(&mut engine, &mem), 1024);
    check_clean_mem(&mem, GuestAddress(4096), 4096);
    check_dirty_mem(&mem, GuestAddress(3), 1024);
    let mut copy = [0; 1024];
    mem.read_slice(&mut copy, GuestAddress(3)).unwrap();
    assert_eq!(copy, [0xbf; 1024]);
}

#[test]
fn test_direct_disk_and_ordered_flush() {
    let Some(backing) = direct_io_test_file() else {
        return;
    };
    for ty in [FileEngineType::Sync, FileEngineType::Async] {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_DIRECT)
            .open(backing.as_path())
            .unwrap();
        let mut engine = FileEngine::from_direct_file(fd, ty, 4096).unwrap();
        let mem = create_mem();
        mem.write_slice(&[0x81; 4096], GuestAddress(1)).unwrap();
        let write = engine
            .write(0, &mem, GuestAddress(1), 4096, PendingRequest::default())
            .unwrap();
        let flush = engine.flush(PendingRequest::default()).unwrap();
        // The direct fsync completes after the staged fixed-file write.
        assert_eq!(completed(&mut engine, &mem, write), 4096);
        assert_eq!(completed(&mut engine, &mem, flush), 0);
        let mem = create_mem();
        let read = engine
            .read(0, &mem, GuestAddress(1), 4096, PendingRequest::default())
            .unwrap();
        assert_eq!(completed(&mut engine, &mem, read), 4096);
        let mut bytes = [0; 4096];
        mem.read_slice(&mut bytes, GuestAddress(1)).unwrap();
        assert_eq!(bytes, [0x81; 4096]);
    }
}

#[test]
fn test_staged_writes_charge_ops_once() {
    let mut block = default_block(FileEngineType::Async);
    let file = TempFile::new().unwrap().into_file();
    file.set_len(4096).unwrap();
    block.resources_mut()[0].disk.file_engine = FileEngine::new(
        file,
        FileEngineType::Async,
        Some(DirectIo::new(4096, 512, 4096).unwrap()),
    )
    .unwrap();

    let mem = default_mem();
    let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
    set_queue(&mut block, 0, vq.create_queue());
    let clock = MockClock::new();
    set_rate_limiter(
        &mut block,
        RateLimiter::new_mocked(0, 0, 0, 2, 0, 100, &clock),
    );
    block.activate(mem.clone(), default_interrupt()).unwrap();

    for i in 0..2u16 {
        let head = i * 3;
        let header = 0x1000 + u64::from(i) * 32;
        let status = 0x3000 + u64::from(i);
        let data = 0x4001 + u64::from(i) * 512;
        vq.dtable[usize::from(head)].set(header, 16, VIRTQ_DESC_F_NEXT, head + 1);
        vq.dtable[usize::from(head + 1)].set(data, 512, VIRTQ_DESC_F_NEXT, head + 2);
        vq.dtable[usize::from(head + 2)].set(status, 1, VIRTQ_DESC_F_WRITE, 0);
        mem.write_obj(
            RequestHeader::new(VIRTIO_BLK_T_OUT, u64::from(i)),
            GuestAddress(header),
        )
        .unwrap();
        mem.write_obj(0xffu8, GuestAddress(status)).unwrap();
        vq.avail.ring[usize::from(i)].set(head);
    }
    vq.avail.idx.set(2);
    simulate_queue_event(&mut block, Some(false));
    assert_eq!(block.lock_rate_limiter().ops().unwrap().budget(), 1);
    simulate_async_completion_event(&mut block, true);
    simulate_async_completion_event(&mut block, true);
    assert_eq!(vq.used.idx.get(), 2);
    assert_eq!(block.lock_rate_limiter().ops().unwrap().budget(), 0);
    assert!(!block.lock_rate_limiter().is_blocked());
    for status in [0x3000, 0x3001] {
        assert_eq!(
            u32::from(mem.read_obj::<u8>(GuestAddress(status)).unwrap()),
            VIRTIO_BLK_S_OK
        );
    }
}

#[test]
fn test_direct_read_error_and_reset_dirty_tracking() {
    let backing = TempFile::new().unwrap();
    backing.as_file().set_len(4096).unwrap();
    for ty in [FileEngineType::Sync, FileEngineType::Async] {
        // Write-only fd forces a negative read on the zero-copy path. A kernel direct
        // read error cannot certify that none of its destination was modified.
        let fd = OpenOptions::new()
            .write(true)
            .open(backing.as_path())
            .unwrap();
        let mut engine =
            FileEngine::new(fd, ty, Some(DirectIo::new(4096, 512, 8192).unwrap())).unwrap();
        let mem = create_mem();
        let result = engine.read(0, &mem, GuestAddress(0), 8192, PendingRequest::default());
        if let FileEngine::Async(engine) = &mut engine {
            assert!(matches!(result, Ok(FileEngineOk::Submitted)));
            engine.drain(false).unwrap();
            engine.pop(&mem).unwrap().unwrap().result().unwrap_err();
        } else {
            result.unwrap_err();
        }
        check_dirty_mem(&mem, GuestAddress(0), 8192);
    }
    let mem = create_mem();
    let mut engine = FileEngine::new(
        backing.into_file(),
        FileEngineType::Async,
        Some(DirectIo::new(4096, 512, 8192).unwrap()),
    )
    .unwrap();
    engine
        .read(0, &mem, GuestAddress(0), 8192, PendingRequest::default())
        .unwrap();
    // A reset consumes this short CQE without normal guest completion.
    engine.drain(true).unwrap();
    check_dirty_mem(&mem, GuestAddress(0), 4096);
    check_clean_mem(&mem, GuestAddress(4096), 4096);
}

#[test]
fn test_direct_multi_window_transfer() {
    use crate::test_utils::single_region_mem_dirty_tracking;
    const SIZE: usize = 3 * super::direct::BUFFER_SIZE;
    const LEN: usize = 2 * super::direct::BUFFER_SIZE + 512;
    let payload: Vec<u8> = (0..LEN).map(|i| u8::try_from(i % 251).unwrap()).collect();
    for ty in [FileEngineType::Sync, FileEngineType::Async] {
        let file = TempFile::new().unwrap().into_file();
        file.write_all_at(&vec![0xee; SIZE], 0).unwrap();
        let mut engine = FileEngine::new(
            file,
            ty,
            Some(DirectIo::new(4096, 4096, SIZE as u64).unwrap()),
        )
        .unwrap();
        let mem = single_region_mem_dirty_tracking(SIZE);
        mem.write_slice(&payload, GuestAddress(1)).unwrap();
        let n = u32::try_from(LEN).unwrap();
        let result = engine
            .write(512, &mem, GuestAddress(1), n, PendingRequest::default())
            .unwrap();
        assert_eq!(completed(&mut engine, &mem, result), n);
        let mut bytes = vec![0; SIZE];
        engine.file().read_exact_at(&mut bytes, 0).unwrap();
        assert!(bytes[..512].iter().all(|b| *b == 0xee));
        assert_eq!(&bytes[512..512 + LEN], &payload);
        assert!(bytes[512 + LEN..].iter().all(|b| *b == 0xee));

        // Stop in the second window. The returned prefix and dirty bitmap track only
        // the guest data read before the short host transfer.
        let truncated = super::direct::BUFFER_SIZE + 4096;
        engine.file().set_len(truncated as u64).unwrap();
        let mem = single_region_mem_dirty_tracking(SIZE);
        let result = engine
            .read(512, &mem, GuestAddress(0), n, PendingRequest::default())
            .unwrap();
        let copied = completed(&mut engine, &mem, result) as usize;
        assert_eq!(copied, truncated - 512);
        let mut guest = vec![0; copied];
        mem.read_slice(&mut guest, GuestAddress(0)).unwrap();
        assert_eq!(guest, payload[..copied]);
        check_dirty_mem(&mem, GuestAddress(0), u32::try_from(copied).unwrap());
        check_clean_mem(&mem, GuestAddress(truncated as u64), 4096);
    }
}
