// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::undocumented_unsafe_blocks)]

use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::thread;
use std::time::Duration;

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use utils::tempfile::TempFile;
use vm_memory::VolatileMemory;
use vmm::vstate::memory::{Bytes, MmapRegion};

mod test_utils {
    use vm_memory::VolatileMemory;
    use vmm::io_uring::operation::{OpCode, Operation};
    use vmm::io_uring::{IoUring, IoUringError, SQueueError};
    use vmm::vstate::memory::MmapRegion;

    fn drain_cqueue(ring: &mut IoUring<usize>) {
        while let Some(entry) = ring.pop().unwrap() {
            entry.result().unwrap();
        }
    }

    pub fn drive_submission_and_completion(
        ring: &mut IoUring<usize>,
        mem_region: &MmapRegion,
        opcode: OpCode,
        num_bytes: usize,
    ) {
        for i in 0..num_bytes {
            loop {
                let operation = match opcode {
                    OpCode::Read => Operation::read(
                        0,
                        mem_region
                            .as_volatile_slice()
                            .subslice(i, 1)
                            .unwrap()
                            .ptr_guard_mut()
                            .as_ptr() as usize,
                        1,
                        i as u64,
                        i,
                    ),
                    OpCode::Write => Operation::write(
                        0,
                        mem_region
                            .as_volatile_slice()
                            .subslice(i, 1)
                            .unwrap()
                            .ptr_guard_mut()
                            .as_ptr() as usize,
                        1,
                        i as u64,
                        i,
                    ),
                    _ => panic!("Only supports read and write."),
                };

                match ring.push(operation) {
                    Ok(()) => break,
                    Err((IoUringError::SQueue(SQueueError::FullQueue), _)) => {
                        // Stop and wait.
                        ring.submit_and_wait_all().unwrap();
                        drain_cqueue(ring);

                        // Retry this OP
                    }
                    Err(_) => panic!("Unexpected error."),
                }
            }
        }

        ring.submit_and_wait_all().unwrap();
        drain_cqueue(ring);
        assert_eq!(ring.pending_sqes().unwrap(), 0);
    }
}
use vmm::io_uring::operation::{OpCode, Operation};
use vmm::io_uring::restriction::Restriction;
use vmm::io_uring::{IoUring, IoUringError, SQueueError};

use crate::test_utils::drive_submission_and_completion;

const NUM_ENTRIES: u32 = 128;

#[test]
fn test_ring_new() {
    // Invalid entries count: 0.
    assert!(matches!(
        IoUring::<u8>::new(0, vec![], vec![], None),
        Err(IoUringError::Setup(err)) if err.kind() == std::io::ErrorKind::InvalidInput
    ));
    // Try to register too many files.
    let dummy_file = TempFile::new().unwrap().into_file();
    assert!(matches!(
        IoUring::<u8>::new(10, vec![&dummy_file; 40000usize], vec![], None), // Max is 32768.
        Err(IoUringError::RegisterFileLimitExceeded)
    ));
}

#[test]
fn test_eventfd() {
    // Test that events get delivered.
    let eventfd = EventFd::new(0).unwrap();

    let file = TempFile::new().unwrap().into_file();
    let mut ring =
        IoUring::new(NUM_ENTRIES, vec![&file], vec![], Some(eventfd.as_raw_fd())).unwrap();
    let user_data: u8 = 71;
    let buf = [0; 4];
    let epoll = Epoll::new().unwrap();
    let mut ready_event = EpollEvent::default();

    epoll
        .ctl(
            ControlOperation::Add,
            eventfd.as_raw_fd(),
            EpollEvent::new(EventSet::IN, 0),
        )
        .unwrap();

    ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
        .unwrap();
    ring.submit().unwrap();

    assert_eq!(
        epoll
            .wait(500, std::slice::from_mut(&mut ready_event))
            .unwrap(),
        1
    );
    assert_eq!(ready_event.event_set(), EventSet::IN);
}

#[test]
fn test_restrictions() {
    // Check that only the allowlisted opcodes are permitted.
    {
        let file = TempFile::new().unwrap().into_file();
        let mut ring = IoUring::new(
            NUM_ENTRIES,
            vec![&file],
            vec![
                Restriction::RequireFixedFds,
                Restriction::AllowOpCode(OpCode::Read),
            ],
            None,
        )
        .unwrap();
        let buf = [0; 4];

        // Read operations are allowed.

        ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, 71))
            .unwrap();
        assert_eq!(ring.submit_and_wait_all().unwrap(), 1);
        ring.pop().unwrap().unwrap().result().unwrap();

        // Other operations are not allowed.

        ring.push(Operation::write(0, buf.as_ptr() as usize, 4, 0, 71))
            .unwrap();
        assert_eq!(ring.submit_and_wait_all().unwrap(), 1);
        ring.pop().unwrap().unwrap().result().unwrap_err();
    }
}

#[test]
fn test_ring_push() {
    // Forgot to register file.
    {
        let buf = [0; 4];
        let mut ring = IoUring::new(NUM_ENTRIES, vec![], vec![], None).unwrap();

        assert!(matches!(
            ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, 71)),
            Err((IoUringError::NoRegisteredFds, 71))
        ));
        assert_eq!(ring.pending_sqes().unwrap(), 0);
    }

    // Now register file.
    {
        let file = TempFile::new().unwrap().into_file();
        let mut ring = IoUring::new(NUM_ENTRIES, vec![&file], vec![], None).unwrap();
        let user_data: u8 = 71;
        let buf = [0; 4];

        // Invalid fd.
        assert!(matches!(
            ring.push(Operation::read(1, buf.as_ptr() as usize, 4, 0, user_data)),
            Err((IoUringError::InvalidFixedFd(1), 71))
        ));
        assert_eq!(ring.pending_sqes().unwrap(), 0);
        assert_eq!(ring.num_ops(), 0);

        // Valid fd.
        ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
            .unwrap();

        assert_eq!(ring.pending_sqes().unwrap(), 1);
        assert_eq!(ring.num_ops(), 1);

        // Full Queue.
        for _ in 1..(NUM_ENTRIES) {
            ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
                .unwrap();
        }

        assert_eq!(ring.pending_sqes().unwrap(), NUM_ENTRIES);
        assert_eq!(ring.num_ops(), NUM_ENTRIES);

        assert!(matches!(
            ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data)),
            Err((IoUringError::SQueue(SQueueError::FullQueue), 71))
        ));

        assert_eq!(ring.pending_sqes().unwrap(), NUM_ENTRIES);
        assert_eq!(ring.num_ops(), NUM_ENTRIES);

        // We didn't get to submit so pop() should return None.
        assert!(ring.pop().unwrap().is_none());
        assert_eq!(ring.num_ops(), NUM_ENTRIES);

        // Full Ring.
        ring.submit().unwrap();
        // Wait for the io_uring ops to reach the CQ
        thread::sleep(Duration::from_millis(150));
        for _ in 0..NUM_ENTRIES {
            ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
                .unwrap();
        }
        ring.submit().unwrap();
        // Wait for the io_uring ops to reach the CQ
        thread::sleep(Duration::from_millis(150));
        assert_eq!(ring.num_ops(), NUM_ENTRIES * 2);
        // The CQ should be full now
        assert!(matches!(
            ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data)),
            Err((IoUringError::FullCQueue, 71))
        ));

        // Check if there are NUM_ENTRIES * 2 cqes
        let mut num_cqes = 0;
        while let Ok(Some(_entry)) = ring.pop() {
            num_cqes += 1;
        }
        assert_eq!(num_cqes, NUM_ENTRIES * 2);
        assert_eq!(ring.num_ops(), 0);
    }
}

#[test]
fn test_ring_submit() {
    {
        let file = TempFile::new().unwrap().into_file();
        let mut ring = IoUring::new(NUM_ENTRIES, vec![&file], vec![], None).unwrap();
        let user_data: u8 = 71;
        let buf = [0; 4];

        // Return 0 if we didn't push any sqes.
        assert_eq!(ring.submit().unwrap(), 0);
        assert_eq!(ring.num_ops(), 0);

        // Now push an sqe.
        ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
            .unwrap();

        assert_eq!(ring.num_ops(), 1);
        assert_eq!(ring.submit().unwrap(), 1);
        // Now push & submit some more.
        ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
            .unwrap();
        ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
            .unwrap();

        assert_eq!(ring.num_ops(), 3);
        assert_eq!(ring.submit().unwrap(), 2);
    }
}

#[test]
fn test_submit_and_wait_all() {
    let file = TempFile::new().unwrap().into_file();
    let mut ring = IoUring::new(NUM_ENTRIES, vec![&file], vec![], None).unwrap();
    let user_data: u8 = 71;
    let buf = [0; 4];

    // Return 0 if we didn't push any sqes.
    assert_eq!(ring.submit_and_wait_all().unwrap(), 0);

    // Now push an sqe.
    ring.push(Operation::read(0, buf.as_ptr() as usize, 4, 0, user_data))
        .unwrap();
    assert_eq!(ring.pending_sqes().unwrap(), 1);
    assert_eq!(ring.num_ops(), 1);

    // A correct waiting period yields the completed entries.
    assert_eq!(ring.submit_and_wait_all().unwrap(), 1);
    assert_eq!(ring.pop().unwrap().unwrap().user_data(), user_data);
    assert_eq!(ring.pending_sqes().unwrap(), 0);
    assert_eq!(ring.num_ops(), 0);

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
    assert_eq!(ring.num_ops(), 4);
    assert_eq!(ring.submit_and_wait_all().unwrap(), 4);
    assert_eq!(ring.pending_sqes().unwrap(), 0);
    assert_eq!(ring.num_ops(), 4);
    assert!(ring.pop().unwrap().is_some());
    assert!(ring.pop().unwrap().is_some());
    assert!(ring.pop().unwrap().is_some());
    assert!(ring.pop().unwrap().is_some());
    assert!(ring.pop().unwrap().is_none());
    assert_eq!(ring.num_ops(), 0);
}

#[test]
fn test_write() {
    // Test that writing the sorted values 1-100 into a file works correctly.

    const NUM_BYTES: usize = 100;
    // Setup.
    let file = TempFile::new().unwrap().into_file();
    let mut ring = IoUring::new(NUM_ENTRIES, vec![&file], vec![], None).unwrap();

    // Create & init a memory mapping for storing the write buffers.
    let mem_region: MmapRegion = MmapRegion::build(
        None,
        NUM_BYTES,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
    )
    .unwrap();

    let expected_result: Vec<u8> = (0..(NUM_BYTES as u8)).collect();

    for i in 0..NUM_BYTES {
        mem_region
            .as_volatile_slice()
            .write_obj(i as u8, i)
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
    // Test that reading the sorted values 1-100 from a file works correctly.

    const NUM_BYTES: usize = 100;
    // Setup.
    let file = TempFile::new().unwrap().into_file();
    let mut ring = IoUring::new(NUM_ENTRIES, vec![&file], vec![], None).unwrap();

    // Create & init a memory mapping for storing the read buffers.
    let mem_region: MmapRegion = MmapRegion::build(
        None,
        NUM_BYTES,
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
