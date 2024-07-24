// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![warn(missing_docs)]

#[allow(clippy::undocumented_unsafe_blocks)]
mod bindings;
pub mod operation;
mod probe;
mod queue;
pub mod restriction;

use std::collections::HashSet;
use std::fmt::Debug;
use std::fs::File;
use std::io::Error as IOError;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use bindings::io_uring_params;
use operation::{Cqe, FixedFd, OpCode, Operation};
use probe::{ProbeWrapper, PROBE_LEN};
pub use queue::completion::CQueueError;
use queue::completion::CompletionQueue;
pub use queue::submission::SQueueError;
use queue::submission::SubmissionQueue;
use restriction::Restriction;
use utils::syscall::SyscallReturnCode;

// IO_uring operations that we require to be supported by the host kernel.
const REQUIRED_OPS: [OpCode; 2] = [OpCode::Read, OpCode::Write];
// Taken from linux/fs/io_uring.c
const IORING_MAX_FIXED_FILES: usize = 1 << 15;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// IoUring Error.
pub enum IoUringError {
    /// Error originating in the completion queue: {0}
    CQueue(CQueueError),
    /// Could not enable the ring: {0}
    Enable(IOError),
    /// A FamStructWrapper operation has failed: {0}
    Fam(utils::fam::Error),
    /// The number of ops in the ring is >= CQ::count
    FullCQueue,
    /// Fd was not registered: {0}
    InvalidFixedFd(FixedFd),
    /// There are no registered fds.
    NoRegisteredFds,
    /// Error probing the io_uring subsystem: {0}
    Probe(IOError),
    /// Could not register eventfd: {0}
    RegisterEventfd(IOError),
    /// Could not register file: {0}
    RegisterFile(IOError),
    /// Attempted to register too many files.
    RegisterFileLimitExceeded,
    /// Could not register restrictions: {0}
    RegisterRestrictions(IOError),
    /// Error calling io_uring_setup: {0}
    Setup(IOError),
    /// Error originating in the submission queue: {0}
    SQueue(SQueueError),
    /// Required feature is not supported on the host kernel: {0}
    UnsupportedFeature(&'static str),
    /// Required operation is not supported on the host kernel: {0}
    UnsupportedOperation(&'static str),
}

impl IoUringError {
    /// Return true if this error is caused by a full submission or completion queue.
    pub fn is_throttling_err(&self) -> bool {
        matches!(
            self,
            Self::FullCQueue | Self::SQueue(SQueueError::FullQueue)
        )
    }
}

/// Main object representing an io_uring instance.
#[derive(Debug)]
pub struct IoUring<T> {
    registered_fds_count: u32,
    squeue: SubmissionQueue,
    cqueue: CompletionQueue,
    // Make sure the fd is declared after the queues, so that it isn't dropped before them.
    // If we drop the queues after the File, the associated kernel mem will never be freed.
    // The correct cleanup order is munmap(rings) -> close(fd).
    // We don't need to manually drop the fields in order,since Rust has a well defined drop order.
    fd: File,

    // The total number of ops. These includes the ops on the submission queue, the in-flight ops
    // and the ops that are in the CQ, but haven't been popped yet.
    num_ops: u32,
    slab: slab::Slab<T>,
}

impl<T: Debug> IoUring<T> {
    /// Create a new instance.
    ///
    /// # Arguments
    ///
    /// * `num_entries` - Requested number of entries in the ring. Will be rounded up to the
    /// nearest power of two.
    /// * `files` - Files to be registered for IO.
    /// * `restrictions` - Vector of [`Restriction`](restriction/enum.Restriction.html)s
    /// * `eventfd` - Optional eventfd for receiving completion notifications.
    pub fn new(
        num_entries: u32,
        files: Vec<&File>,
        restrictions: Vec<Restriction>,
        eventfd: Option<RawFd>,
    ) -> Result<Self, IoUringError> {
        let mut params = io_uring_params {
            // Create the ring as disabled, so that we may register restrictions.
            flags: bindings::IORING_SETUP_R_DISABLED,

            ..Default::default()
        };

        // SAFETY: Safe because values are valid and we check the return value.
        let fd = SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_io_uring_setup,
                num_entries,
                &mut params as *mut io_uring_params,
            )
        })
        .into_result()
        .map_err(IoUringError::Setup)?;
        // Safe to unwrap because the fd is valid.
        let fd = RawFd::try_from(fd).unwrap();

        // SAFETY: Safe because the fd is valid and because this struct owns the fd.
        let file = unsafe { File::from_raw_fd(fd) };

        Self::check_features(params)?;

        let squeue = SubmissionQueue::new(fd, &params).map_err(IoUringError::SQueue)?;
        let cqueue = CompletionQueue::new(fd, &params).map_err(IoUringError::CQueue)?;
        let slab =
            slab::Slab::with_capacity(params.sq_entries as usize + params.cq_entries as usize);

        let mut instance = Self {
            squeue,
            cqueue,
            fd: file,
            registered_fds_count: 0,
            num_ops: 0,
            slab,
        };

        instance.check_operations()?;

        if let Some(eventfd) = eventfd {
            instance.register_eventfd(eventfd)?;
        }

        instance.register_restrictions(restrictions)?;

        instance.register_files(files)?;

        instance.enable()?;

        Ok(instance)
    }

    /// Push an [`Operation`](operation/struct.Operation.html) onto the submission queue.
    pub fn push(&mut self, op: Operation<T>) -> Result<(), (IoUringError, T)> {
        // validate that we actually did register fds
        let fd = op.fd();
        match self.registered_fds_count {
            0 => Err((IoUringError::NoRegisteredFds, op.user_data)),
            len if fd >= len => Err((IoUringError::InvalidFixedFd(fd), op.user_data)),
            _ => {
                if self.num_ops >= self.cqueue.count() {
                    return Err((IoUringError::FullCQueue, op.user_data));
                }
                self.squeue
                    .push(op.into_sqe(&mut self.slab))
                    .map(|res| {
                        // This is safe since self.num_ops < IORING_MAX_CQ_ENTRIES (65536)
                        self.num_ops += 1;
                        res
                    })
                    .map_err(|(sqe_err, user_data_key)| -> (IoUringError, T) {
                        (
                            IoUringError::SQueue(sqe_err),
                            // We don't use slab.try_remove here for 2 reasons:
                            // 1. user_data was inserted in slab with step `op.into_sqe` just
                            //    before the push op so the user_data key should be valid and if
                            //    key is valid then `slab.remove()` will not fail.
                            // 2. If we use `slab.try_remove()` we'll have to find a way to return
                            //    a default value for the generic type T which is difficult because
                            //    it expands to more crates which don't make it easy to define a
                            //    default/clone type for type T.
                            // So believing that `slab.remove` won't fail we don't use
                            // the `slab.try_remove` method.
                            #[allow(clippy::cast_possible_truncation)]
                            self.slab.remove(user_data_key as usize),
                        )
                    })
            }
        }
    }

    /// Pop a completed entry off the completion queue. Returns `Ok(None)` if there are no entries.
    /// The type `T` must be the same as the `user_data` type used for `push`-ing the operation.
    pub fn pop(&mut self) -> Result<Option<Cqe<T>>, IoUringError> {
        self.cqueue
            .pop(&mut self.slab)
            .map(|maybe_cqe| {
                maybe_cqe.map(|cqe| {
                    // This is safe since the pop-ed CQEs have been previously pushed. However
                    // we use a saturating_sub for extra safety.
                    self.num_ops = self.num_ops.saturating_sub(1);
                    cqe
                })
            })
            .map_err(IoUringError::CQueue)
    }

    fn do_submit(&mut self, min_complete: u32) -> Result<u32, IoUringError> {
        self.squeue
            .submit(min_complete)
            .map_err(IoUringError::SQueue)
    }

    /// Submit all operations but don't wait for any completions.
    pub fn submit(&mut self) -> Result<u32, IoUringError> {
        self.do_submit(0)
    }

    /// Submit all operations and wait for their completion.
    pub fn submit_and_wait_all(&mut self) -> Result<u32, IoUringError> {
        self.do_submit(self.num_ops)
    }

    /// Return the number of operations currently on the submission queue.
    pub fn pending_sqes(&self) -> Result<u32, IoUringError> {
        self.squeue.pending().map_err(IoUringError::SQueue)
    }

    /// A total of the number of ops in the submission and completion queues, as well as the
    /// in-flight ops.
    pub fn num_ops(&self) -> u32 {
        self.num_ops
    }

    fn enable(&mut self) -> Result<(), IoUringError> {
        // SAFETY: Safe because values are valid and we check the return value.
        SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd.as_raw_fd(),
                bindings::IORING_REGISTER_ENABLE_RINGS,
                std::ptr::null::<libc::c_void>(),
                0,
            )
        })
        .into_empty_result()
        .map_err(IoUringError::Enable)
    }

    fn register_files(&mut self, files: Vec<&File>) -> Result<(), IoUringError> {
        if files.is_empty() {
            // No-op.
            return Ok(());
        }

        if (self.registered_fds_count as usize).saturating_add(files.len()) > IORING_MAX_FIXED_FILES
        {
            return Err(IoUringError::RegisterFileLimitExceeded);
        }

        // SAFETY: Safe because values are valid and we check the return value.
        SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd.as_raw_fd(),
                bindings::IORING_REGISTER_FILES,
                files
                    .iter()
                    .map(|f| f.as_raw_fd())
                    .collect::<Vec<_>>()
                    .as_mut_slice()
                    .as_mut_ptr() as *const _,
                files.len(),
            )
        })
        .into_empty_result()
        .map_err(IoUringError::RegisterFile)?;

        // Safe to truncate since files.len() < IORING_MAX_FIXED_FILES
        self.registered_fds_count += u32::try_from(files.len()).unwrap();
        Ok(())
    }

    fn register_eventfd(&self, fd: RawFd) -> Result<(), IoUringError> {
        // SAFETY: Safe because values are valid and we check the return value.
        SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd.as_raw_fd(),
                bindings::IORING_REGISTER_EVENTFD,
                (&fd) as *const _,
                1,
            )
        })
        .into_empty_result()
        .map_err(IoUringError::RegisterEventfd)
    }

    fn register_restrictions(&self, restrictions: Vec<Restriction>) -> Result<(), IoUringError> {
        if restrictions.is_empty() {
            // No-op.
            return Ok(());
        }
        // SAFETY: Safe because values are valid and we check the return value.
        SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd.as_raw_fd(),
                bindings::IORING_REGISTER_RESTRICTIONS,
                restrictions
                    .iter()
                    .map(bindings::io_uring_restriction::from)
                    .collect::<Vec<_>>()
                    .as_mut_slice()
                    .as_mut_ptr(),
                restrictions.len(),
            )
        })
        .into_empty_result()
        .map_err(IoUringError::RegisterRestrictions)
    }

    fn check_features(params: io_uring_params) -> Result<(), IoUringError> {
        // We require that the host kernel will never drop completed entries due to an (unlikely)
        // overflow in the completion queue.
        // This feature is supported for kernels greater than 5.7.
        // An alternative fix would be to keep an internal counter that tracks the number of
        // submitted entries that haven't been completed and makes sure it doesn't exceed
        // (2 * num_entries).
        if (params.features & bindings::IORING_FEAT_NODROP) == 0 {
            return Err(IoUringError::UnsupportedFeature("IORING_FEAT_NODROP"));
        }

        Ok(())
    }

    fn check_operations(&self) -> Result<(), IoUringError> {
        let mut probes = ProbeWrapper::new(PROBE_LEN).map_err(IoUringError::Fam)?;

        // SAFETY: Safe because values are valid and we check the return value.
        SyscallReturnCode(unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd.as_raw_fd(),
                bindings::IORING_REGISTER_PROBE,
                probes.as_mut_fam_struct_ptr(),
                PROBE_LEN,
            )
        })
        .into_empty_result()
        .map_err(IoUringError::Probe)?;

        let supported_opcodes: HashSet<u8> = probes
            .as_slice()
            .iter()
            .filter(|op| ((u32::from(op.flags)) & bindings::IO_URING_OP_SUPPORTED) != 0)
            .map(|op| op.op)
            .collect();

        for opcode in REQUIRED_OPS.iter() {
            if !supported_opcodes.contains(&(*opcode as u8)) {
                return Err(IoUringError::UnsupportedOperation((*opcode).into()));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    use std::os::unix::fs::FileExt;

    use proptest::prelude::*;
    use proptest::strategy::Strategy;
    use proptest::test_runner::{Config, TestRunner};
    use utils::syscall::SyscallReturnCode;
    use utils::tempfile::TempFile;
    use vm_memory::VolatileMemory;

    /// -------------------------------------
    /// BEGIN PROPERTY BASED TESTING
    use super::*;
    use crate::vstate::memory::{Bytes, MmapRegion};

    fn drain_cqueue(ring: &mut IoUring<u32>) {
        while let Some(entry) = ring.pop().unwrap() {
            entry.result().unwrap();

            // Assert that there were no partial writes.
            let count = entry.result().unwrap();
            let user_data = entry.user_data();
            assert_eq!(count, user_data);
        }
    }

    fn setup_mem_region(len: usize) -> MmapRegion {
        const PROT: i32 = libc::PROT_READ | libc::PROT_WRITE;
        const FLAGS: i32 = libc::MAP_ANONYMOUS | libc::MAP_PRIVATE;

        let ptr = unsafe { libc::mmap(std::ptr::null_mut(), len, PROT, FLAGS, -1, 0) };

        if (ptr as isize) < 0 {
            panic!("Mmap failed with {}", std::io::Error::last_os_error());
        }

        unsafe {
            // Use the raw version because we want to unmap memory ourselves.
            MmapRegion::build_raw(ptr.cast::<u8>(), len, PROT, FLAGS).unwrap()
        }
    }

    fn free_mem_region(region: MmapRegion) {
        unsafe { libc::munmap(region.as_ptr().cast::<libc::c_void>(), region.len()) };
    }

    fn read_entire_mem_region(region: &MmapRegion) -> Vec<u8> {
        let mut result = vec![0u8; region.len()];
        let count = region.as_volatile_slice().read(&mut result[..], 0).unwrap();
        assert_eq!(count, region.len());
        result
    }

    #[allow(clippy::let_with_type_underscore)]
    fn arbitrary_rw_operation(file_len: u32) -> impl Strategy<Value = Operation<u32>> {
        (
            // OpCode: 0 -> Write, 1 -> Read.
            0..2,
            // Length of the operation.
            0u32..file_len,
        )
            .prop_flat_map(move |(op, len)| {
                (
                    // op
                    Just(op),
                    // len
                    Just(len),
                    // offset
                    (0u32..(file_len - len)),
                    // mem region offset
                    (0u32..(file_len - len)),
                )
            })
            .prop_map(move |(op, len, off, mem_off)| {
                // We actually use an offset instead of an address, because we later need to modify
                // the memory region on which the operation is performed, based on the opcode.
                let mut operation = match op {
                    0 => Operation::write(0, mem_off as usize, len, off.into(), len),
                    _ => Operation::read(0, mem_off as usize, len, off.into(), len),
                };

                // Make sure the operations are executed in-order, so that they are equivalent to
                // their sync counterparts.
                operation.set_linked();
                operation
            })
    }

    #[test]
    fn proptest_read_write_correctness() {
        // Performs a sequence of random read and write operations on two files, with sync and
        // async IO, respectively.
        // Verifies that the files are identical afterwards and that the read operations returned
        // the same values.

        const FILE_LEN: u32 = 1024;
        // The number of arbitrary operations in a testrun.
        const OPS_COUNT: usize = 2000;
        const RING_SIZE: u32 = 128;

        // Allocate and init memory for holding the data that will be written into the file.
        let write_mem_region = setup_mem_region(FILE_LEN as usize);

        let sync_read_mem_region = setup_mem_region(FILE_LEN as usize);

        let async_read_mem_region = setup_mem_region(FILE_LEN as usize);

        // Init the write buffers with 0,1,2,...
        for i in 0..FILE_LEN {
            write_mem_region
                .as_volatile_slice()
                .write_obj(u8::try_from(i % u32::from(u8::MAX)).unwrap(), i as usize)
                .unwrap();
        }

        // Create two files and init their contents to zeros.
        let init_contents = [0u8; FILE_LEN as usize];
        let file_async = TempFile::new().unwrap().into_file();
        file_async.write_all_at(&init_contents, 0).unwrap();

        let file_sync = TempFile::new().unwrap().into_file();
        file_sync.write_all_at(&init_contents, 0).unwrap();

        // Create a custom test runner since we had to add some state buildup to the test.
        // (Referring to the above initializations).
        let mut runner = TestRunner::new(Config {
            #[cfg(target_arch = "x86_64")]
            cases: 1000, // Should run for about a minute.
            // Lower the cases on ARM since they take longer and cause coverage test timeouts.
            #[cfg(target_arch = "aarch64")]
            cases: 500,
            ..Config::default()
        });

        runner
            .run(
                &proptest::collection::vec(arbitrary_rw_operation(FILE_LEN), OPS_COUNT),
                |set| {
                    let mut ring =
                        IoUring::new(RING_SIZE, vec![&file_async], vec![], None).unwrap();

                    for mut operation in set {
                        // Perform the sync op.
                        let count = match operation.opcode {
                            OpCode::Write => u32::try_from(
                                SyscallReturnCode(unsafe {
                                    libc::pwrite(
                                        file_sync.as_raw_fd(),
                                        write_mem_region.as_ptr().add(operation.addr.unwrap())
                                            as *const libc::c_void,
                                        operation.len.unwrap() as usize,
                                        i64::try_from(operation.offset.unwrap()).unwrap(),
                                    )
                                })
                                .into_result()
                                .unwrap(),
                            )
                            .unwrap(),
                            OpCode::Read => u32::try_from(
                                SyscallReturnCode(unsafe {
                                    libc::pread(
                                        file_sync.as_raw_fd(),
                                        sync_read_mem_region
                                            .as_ptr()
                                            .add(operation.addr.unwrap())
                                            .cast::<libc::c_void>(),
                                        operation.len.unwrap() as usize,
                                        i64::try_from(operation.offset.unwrap()).unwrap(),
                                    )
                                })
                                .into_result()
                                .unwrap(),
                            )
                            .unwrap(),
                            _ => unreachable!(),
                        };

                        if count < operation.len.unwrap() {
                            panic!("Synchronous partial operation: {:?}", operation);
                        }

                        // Perform the async op.

                        // Modify the operation address based on the opcode.
                        match operation.opcode {
                            OpCode::Write => {
                                operation.addr = Some(unsafe {
                                    write_mem_region.as_ptr().add(operation.addr.unwrap()) as usize
                                })
                            }
                            OpCode::Read => {
                                operation.addr = Some(unsafe {
                                    async_read_mem_region.as_ptr().add(operation.addr.unwrap())
                                        as usize
                                })
                            }
                            _ => unreachable!(),
                        };

                        // If the ring is full, submit and wait.
                        if ring.pending_sqes().unwrap() == RING_SIZE {
                            ring.submit_and_wait_all().unwrap();
                            drain_cqueue(&mut ring);
                        }
                        ring.push(operation).unwrap();
                    }

                    // Submit any left async ops and wait.
                    ring.submit_and_wait_all().unwrap();
                    drain_cqueue(&mut ring);

                    // Get the write result for async IO.
                    let mut async_result = [0u8; FILE_LEN as usize];
                    file_async.read_exact_at(&mut async_result, 0).unwrap();

                    // Get the write result for sync IO.
                    let mut sync_result = [0u8; FILE_LEN as usize];
                    file_sync.read_exact_at(&mut sync_result, 0).unwrap();

                    // Now compare the write results.
                    assert_eq!(sync_result, async_result);

                    // Now compare the read results for sync and async IO.
                    assert_eq!(
                        read_entire_mem_region(&sync_read_mem_region),
                        read_entire_mem_region(&async_read_mem_region)
                    );

                    Ok(())
                },
            )
            .unwrap();

        // Clean up the memory.
        free_mem_region(write_mem_region);
        free_mem_region(sync_read_mem_region);
        free_mem_region(async_read_mem_region);
    }
}
