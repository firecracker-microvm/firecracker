// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use io_uring::{operation::OpCode, operation::Operation, Error, IoUring, SQueueError};
use vm_memory::{MmapRegion, VolatileMemory};

fn drain_cqueue(ring: &mut IoUring) {
    while let Some(entry) = ring.pop::<usize>().unwrap() {
        assert!(entry.result().is_ok());
    }
}

pub fn drive_submission_and_completion(
    ring: &mut IoUring,
    mem_region: &MmapRegion,
    opcode: OpCode,
    num_bytes: usize,
) {
    let mut left_at: isize = -1;
    loop {
        for i in ((left_at + 1) as usize)..num_bytes {
            left_at = i as isize;

            let operation = match opcode {
                OpCode::Read => Operation::read(
                    0,
                    mem_region
                        .as_volatile_slice()
                        .subslice(i as usize, 1)
                        .unwrap()
                        .as_ptr() as usize,
                    1,
                    i as u64,
                    i,
                ),
                OpCode::Write => Operation::write(
                    0,
                    mem_region
                        .as_volatile_slice()
                        .subslice(i as usize, 1)
                        .unwrap()
                        .as_ptr() as usize,
                    1,
                    i as u64,
                    i,
                ),
                _ => panic!("Only supports read and write."),
            };

            match ring.push(operation) {
                Ok(()) => {}
                Err(err_tuple) if matches!(err_tuple.0, Error::SQueue(SQueueError::FullQueue)) => {
                    // Stop and wait.
                    ring.submit_and_wait_all().unwrap();
                    drain_cqueue(ring);

                    // Decrement the left_at because we need to retry this op.
                    left_at -= 1;
                    break;
                }
                Err(_) => panic!("Unexpected error."),
            }
        }

        if left_at == ((num_bytes - 1) as isize) {
            break;
        }
    }

    ring.submit_and_wait_all().unwrap();
    drain_cqueue(ring);
    assert_eq!(ring.pending_sqes().unwrap(), 0);
}
