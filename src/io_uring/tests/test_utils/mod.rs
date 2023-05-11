// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use io_uring::operation::{OpCode, Operation};
use io_uring::{Error, IoUring, SQueueError};
use utils::vm_memory::{MmapRegion, VolatileMemory};

fn drain_cqueue(ring: &mut IoUring) {
    while let Some(entry) = unsafe { ring.pop::<usize>().unwrap() } {
        assert!(entry.result().is_ok());
    }
}

pub fn drive_submission_and_completion(
    ring: &mut IoUring,
    mem_region: &MmapRegion,
    opcode: OpCode,
    num_bytes: usize,
) {
    let mut left_at: usize = 0;
    loop {
        // left_at is only increased if the iteration succeeds, if the iteration fails it will be
        // retried
        for i in left_at..num_bytes {
            let operation = match opcode {
                OpCode::Read => Operation::read(
                    0,
                    mem_region
                        .as_volatile_slice()
                        .subslice(i, 1)
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
                        .subslice(i, 1)
                        .unwrap()
                        .as_ptr() as usize,
                    1,
                    i as u64,
                    i,
                ),
                _ => panic!("Only supports read and write."),
            };

            match unsafe { ring.push(operation) } {
                Ok(()) => {}
                Err(err_tuple) if matches!(err_tuple.0, Error::SQueue(SQueueError::FullQueue)) => {
                    // Stop and wait.
                    ring.submit_and_wait_all().unwrap();
                    drain_cqueue(ring);

                    // Do not increment the left_at because we need to retry this op.
                    break;
                }
                Err(_) => panic!("Unexpected error."),
            }

            // Increment the left_at since this iteration was successful
            left_at = i;
        }

        if left_at == (num_bytes - 1) {
            break;
        }
    }

    ring.submit_and_wait_all().unwrap();
    drain_cqueue(ring);
    assert_eq!(ring.pending_sqes().unwrap(), 0);
}
