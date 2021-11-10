// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::{fs::FileExt, io::AsRawFd};
use vm_memory::{Bytes, MmapRegion, VolatileMemory};

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use utils::kernel_version::KernelVersion;
use utils::skip_if_kernel_lt_5_10;
use utils::tempfile::TempFile;

mod test_utils;
use crate::test_utils::drive_submission_and_completion;

use io_uring::{operation::OpCode, operation::Operation, Error, IoUring, SQueueError};

const NUM_ENTRIES: u32 = 128;

#[test]
fn test_ring_new() {
    skip_if_kernel_lt_5_10!();

    // Invalid entries count: 0.
    assert!(matches!(
        IoUring::new(0),
        Err(Error::Setup(e)) if e.kind() == std::io::ErrorKind::InvalidInput
    ));

    // Valid entries count.
    assert!(IoUring::new(NUM_ENTRIES).is_ok());
}

#[test]
fn test_eventfd() {
    skip_if_kernel_lt_5_10!();
    // Test registration.
    {
        // Ok.
        let ring = IoUring::new(NUM_ENTRIES).unwrap();
        assert!(ring
            .register_eventfd(EventFd::new(0).unwrap().as_raw_fd())
            .is_ok());

        // Cannot register multiple eventfds.
        assert!(matches!(
            ring.register_eventfd(EventFd::new(0).unwrap().as_raw_fd()),
            Err(Error::RegisterEventfd(e)) if e.kind() == std::io::ErrorKind::Other
        ));
    }
    // Test that events get delivered.
    {
        let file = TempFile::new().unwrap().into_file();
        let mut ring = IoUring::new(NUM_ENTRIES).unwrap();
        let user_data: u8 = 71;
        let buf = [0; 4];

        let eventfd = EventFd::new(0).unwrap();
        let epoll = Epoll::new().unwrap();
        epoll
            .ctl(
                ControlOperation::Add,
                eventfd.as_raw_fd(),
                EpollEvent::new(EventSet::IN, 0),
            )
            .unwrap();
        let mut ready_events = vec![EpollEvent::default(); 1];
        ring.register_file(&file).unwrap();
        ring.register_eventfd(eventfd.as_raw_fd()).unwrap();

        ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
            .unwrap();
        ring.submit().unwrap();

        assert_eq!(epoll.wait(500, &mut ready_events[..]).unwrap(), 1);
        assert_eq!(ready_events[0].event_set(), EventSet::IN);
    }
}

#[test]
fn test_ring_push() {
    skip_if_kernel_lt_5_10!();

    let file = TempFile::new().unwrap().into_file();
    let mut ring = IoUring::new(NUM_ENTRIES).unwrap();
    let user_data: u8 = 71;
    let buf = [0; 4];

    // Forgot to register file.
    assert!(matches!(
        ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, 71)),
        Err((Error::NoRegisteredFds, 71))
    ));
    assert_eq!(ring.pending_sqes().unwrap(), 0);

    // Now register file.
    ring.register_file(&file).unwrap();

    // Invalid fd.
    assert!(matches!(
        ring.push(Operation::read(1, buf.as_ptr() as usize, 4, 0, user_data)),
        Err((Error::InvalidFixedFd(1), 71))
    ));
    assert_eq!(ring.pending_sqes().unwrap(), 0);

    // Valid fd.
    assert!(ring
        .push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
        .is_ok());

    assert_eq!(ring.pending_sqes().unwrap(), 1);

    // Full Queue.
    for _ in 1..(NUM_ENTRIES) {
        assert!(ring
            .push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
            .is_ok());
    }

    assert_eq!(ring.pending_sqes().unwrap(), NUM_ENTRIES);

    assert!(matches!(
        ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data)),
        Err((Error::SQueue(SQueueError::FullQueue), 71))
    ));

    assert_eq!(ring.pending_sqes().unwrap(), NUM_ENTRIES);

    // We didn't get to submit so pop() should return None.
    assert!(ring.pop::<u8>().unwrap().is_none());
}

#[test]
fn test_ring_submit() {
    skip_if_kernel_lt_5_10!();

    let file = TempFile::new().unwrap().into_file();
    let mut ring = IoUring::new(NUM_ENTRIES).unwrap();
    let user_data: u8 = 71;
    let buf = [0; 4];

    ring.register_file(&file).unwrap();

    // Return 0 if we didn't push any sqes.
    assert_eq!(ring.submit().unwrap(), 0);

    // Now push an sqe.
    ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
        .unwrap();
    assert_eq!(ring.submit().unwrap(), 1);
    // Now push & submit some more.
    ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
        .unwrap();
    ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
        .unwrap();
    assert_eq!(ring.submit().unwrap(), 2);
}

#[test]
fn test_submit_and_wait_all() {
    skip_if_kernel_lt_5_10!();

    let file = TempFile::new().unwrap().into_file();
    let mut ring = IoUring::new(NUM_ENTRIES).unwrap();
    let user_data: u8 = 71;
    let buf = [0; 4];

    ring.register_file(&file).unwrap();

    // Return 0 if we didn't push any sqes.
    assert_eq!(ring.submit_and_wait_all().unwrap(), 0);

    // Now push an sqe.
    ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
        .unwrap();
    assert_eq!(ring.pending_sqes().unwrap(), 1);

    // A correct waiting period yields the completed entries.
    assert_eq!(ring.submit_and_wait_all().unwrap(), 1);
    assert_eq!(ring.pop::<u8>().unwrap().unwrap().user_data(), user_data);
    assert_eq!(ring.pending_sqes().unwrap(), 0);

    // Now push, submit & wait for some more entries.
    ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, 72))
        .unwrap();
    ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, 73))
        .unwrap();
    ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, 74))
        .unwrap();
    ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, 75))
        .unwrap();
    assert_eq!(ring.pending_sqes().unwrap(), 4);
    assert_eq!(ring.submit_and_wait_all().unwrap(), 4);
    assert_eq!(ring.pending_sqes().unwrap(), 0);

    assert!(ring.pop::<u8>().unwrap().is_some());
    assert!(ring.pop::<u8>().unwrap().is_some());
    assert!(ring.pop::<u8>().unwrap().is_some());
    assert!(ring.pop::<u8>().unwrap().is_some());
    assert!(ring.pop::<u8>().unwrap().is_none());
}

#[test]
fn test_write() {
    skip_if_kernel_lt_5_10!();

    // Test that writing the sorted values 1-100 into a file works correctly.

    const NUM_BYTES: usize = 100;
    // Setup.
    let file = TempFile::new().unwrap().into_file();
    let mut ring = IoUring::new(10).unwrap();
    ring.register_file(&file).unwrap();

    // Create & init a memory mapping for storing the write buffers.
    let mem_region: MmapRegion = MmapRegion::build(
        None,
        NUM_BYTES as usize,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
    )
    .unwrap();

    let expected_result: Vec<u8> = (0..(NUM_BYTES as u8)).collect();

    for i in 0..NUM_BYTES {
        mem_region
            .as_volatile_slice()
            .write_obj(i as u8, i as usize)
            .unwrap();
    }

    // Init the file with all zeros.
    file.write_all_at(&[0; NUM_BYTES], 0).unwrap();

    // Perform the IO.
    drive_submission_and_completion(&mut ring, &mem_region, OpCode::Write, NUM_BYTES);

    // Verify the result.
    let mut buf = [0u8; NUM_BYTES];
    file.read_exact_at(&mut buf, 0).unwrap();
    assert_eq!(buf, &expected_result[..]);
}

#[test]
fn test_read() {
    skip_if_kernel_lt_5_10!();

    // Test that reading the sorted values 1-100 from a file works correctly.

    const NUM_BYTES: usize = 100;
    // Setup.
    let file = TempFile::new().unwrap().into_file();
    let mut ring = IoUring::new(10).unwrap();
    ring.register_file(&file).unwrap();

    // Create & init a memory mapping for storing the read buffers.
    let mem_region: MmapRegion = MmapRegion::build(
        None,
        NUM_BYTES as usize,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
    )
    .unwrap();

    // Init the file with 1-100.
    let init_contents: Vec<u8> = (0..(NUM_BYTES as u8)).collect();
    file.write_all_at(&init_contents, 0).unwrap();

    // Perform the IO.
    drive_submission_and_completion(&mut ring, &mem_region, OpCode::Read, NUM_BYTES);

    let mut buf = [0; NUM_BYTES];
    mem_region
        .as_volatile_slice()
        .read_slice(&mut buf, 0)
        .unwrap();
    // Verify the result.
    assert_eq!(buf, &init_contents[..]);
}
