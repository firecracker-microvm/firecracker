// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::device::BlockResources;
use super::io::{BlockIoError, FileEngine, async_io};
use super::metrics::BlockDeviceMetrics;
use super::{FinishedRequest, IoErr, ProcessingResult, Request, VirtioBlockError};
use crate::devices::virtio::device::ActiveState;
use crate::devices::virtio::queue::InvalidAvailIdx;
use crate::devices::virtio::transport::VirtioInterruptType;
use crate::logger::{IncMetric, error};
use crate::rate_limiter::RateLimiter;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Runtime state and processing logic for an active block device.
#[derive(Debug)]
pub(crate) struct BlockWorker {
    pub(crate) resources: BlockResources,
    pub(crate) active_state: ActiveState,
    pub(crate) rate_limiter: Arc<Mutex<RateLimiter>>,
    pub(crate) is_blocked: Arc<AtomicBool>,
    pub(crate) metrics: Arc<BlockDeviceMetrics>,
}

pub(crate) enum FlushMode {
    Drain,
    DrainAndFlush,
}

macro_rules! unwrap_async_file_engine_or_return {
    ($file_engine: expr) => {
        match $file_engine {
            FileEngine::Async(engine) => engine,
            FileEngine::Sync(_) => {
                error!("The block device doesn't use an async IO engine");
                return;
            }
        }
    };
}

impl BlockWorker {
    /// Process a single event in the Virtio queue.
    ///
    /// This function is called by the event manager when the guest notifies us
    /// about new buffers in the queue.
    pub(crate) fn process_queue_event(&mut self) {
        self.metrics.queue_event_count.inc();
        if let Err(err) = self.resources.queue_evts[0].read() {
            error!("Failed to get queue event: {:?}", err);
            self.metrics.event_fails.inc();
        } else if self.is_blocked.load(Ordering::Relaxed) {
            self.metrics.rate_limiter_throttled_events.inc();
        } else if self.resources.is_io_engine_throttled {
            self.metrics.io_engine_throttled_events.inc();
        } else {
            self.process_virtio_queues().unwrap()
        }
    }

    /// Process device virtio queue(s).
    pub(crate) fn process_virtio_queues(&mut self) -> Result<(), InvalidAvailIdx> {
        self.process_queue(0)
    }

    /// Device specific function for peaking inside a queue and processing descriptors.
    fn process_queue(&mut self, queue_index: usize) -> Result<(), InvalidAvailIdx> {
        let rate_limiter = &self.rate_limiter;
        let queue = &mut self.resources.queues[queue_index];
        let mut used_any = false;

        while let Some(head) = queue.pop_or_enable_notification()? {
            self.metrics.remaining_reqs_count.add(queue.len().into());
            let processing_result =
                match Request::parse(&head, &self.active_state.mem, self.resources.disk.nsectors) {
                    Ok(request) => {
                        let is_rate_limited = {
                            let mut rate_limiter = rate_limiter
                                .lock()
                                .expect("Poisoned block rate limiter lock");
                            request.rate_limit(&mut rate_limiter)
                        };
                        if is_rate_limited {
                            // Stop processing the queue and return this descriptor chain to the
                            // avail ring, for later processing.
                            queue.undo_pop();
                            self.metrics.rate_limiter_throttled_events.inc();
                            break;
                        }

                        request.process(
                            &mut self.resources.disk,
                            head.index,
                            &self.active_state.mem,
                            &self.metrics,
                        )
                    }
                    Err(err) => {
                        error!("Failed to parse available descriptor chain: {:?}", err);
                        self.metrics.execute_fails.inc();
                        ProcessingResult::Executed(FinishedRequest {
                            num_bytes_to_mem: 0,
                            desc_idx: head.index,
                        })
                    }
                };

            match processing_result {
                ProcessingResult::Submitted => {}
                ProcessingResult::Throttled => {
                    queue.undo_pop();
                    self.resources.is_io_engine_throttled = true;
                    break;
                }
                ProcessingResult::Executed(finished) => {
                    used_any = true;
                    queue
                        .add_used(head.index, finished.num_bytes_to_mem)
                        .unwrap_or_else(|err| {
                            error!(
                                "Failed to add available descriptor head {}: {}",
                                head.index, err
                            )
                        });
                }
            }
        }
        queue.advance_used_ring_idx();

        if used_any && queue.prepare_kick() {
            self.active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|_| {
                    self.metrics.event_fails.inc();
                });
        }

        if let FileEngine::Async(ref mut engine) = self.resources.disk.file_engine
            && let Err(err) = engine.kick_submission_queue()
        {
            error!("BlockError submitting pending block requests: {:?}", err);
        }

        if !used_any {
            self.metrics.no_avail_buffer.inc();
        }

        Ok(())
    }

    fn process_async_completion_queue(&mut self) {
        let engine = unwrap_async_file_engine_or_return!(&mut self.resources.disk.file_engine);
        let queue = &mut self.resources.queues[0];

        loop {
            match engine.pop(&self.active_state.mem) {
                Err(error) => {
                    error!("Failed to read completed io_uring entry: {:?}", error);
                    break;
                }
                Ok(None) => break,
                Ok(Some(cqe)) => {
                    let res = cqe.result();
                    let user_data = cqe.user_data();

                    let (pending, res) = match res {
                        Ok(count) => (user_data, Ok(count)),
                        Err(error) => (
                            user_data,
                            Err(IoErr::FileEngine(BlockIoError::Async(
                                async_io::AsyncIoError::IO(error),
                            ))),
                        ),
                    };
                    let finished = pending.finish(&self.active_state.mem, res, &self.metrics);
                    queue
                        .add_used(finished.desc_idx, finished.num_bytes_to_mem)
                        .unwrap_or_else(|err| {
                            error!(
                                "Failed to add available descriptor head {}: {}",
                                finished.desc_idx, err
                            )
                        });
                }
            }
        }
        queue.advance_used_ring_idx();

        if queue.prepare_kick() {
            self.active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|_| {
                    self.metrics.event_fails.inc();
                });
        }
    }

    pub(crate) fn process_async_completion_event(&mut self) {
        let engine = unwrap_async_file_engine_or_return!(&mut self.resources.disk.file_engine);

        if let Err(err) = engine.completion_evt().read() {
            error!("Failed to get async completion event: {:?}", err);
        } else {
            self.process_async_completion_queue();

            if self.resources.is_io_engine_throttled {
                self.resources.is_io_engine_throttled = false;
                self.process_queue(0).unwrap()
            }
        }
    }

    pub(crate) fn drain_and_flush(&mut self, discard: bool) {
        if let Err(err) = self.resources.disk.file_engine.drain_and_flush(discard) {
            error!("Failed to drain ops and flush block data: {:?}", err);
        }
    }

    pub(crate) fn drain(&mut self, discard: bool) {
        if let Err(err) = self.resources.disk.file_engine.drain(discard) {
            error!("Failed to drain ops: {:?}", err);
        }
    }

    pub(crate) fn reset(&mut self) -> bool {
        if let Err(err) = self.resources.disk.file_engine.drain(true) {
            error!("Failed to reset block IO engine: {:?}", err);
            return false;
        }
        self.resources.is_io_engine_throttled = false;
        true
    }

    /// Prepare device for being snapshotted.
    pub(crate) fn prepare_save(&mut self) {
        self.drain_and_flush(false);
        if matches!(&self.resources.disk.file_engine, FileEngine::Async(_)) {
            self.process_async_completion_queue();
        }
    }

    /// Update the backing file and return the new sector count.
    pub fn update_disk_image(
        &mut self,
        disk_image_path: String,
        read_only: bool,
    ) -> Result<u64, VirtioBlockError> {
        self.resources.disk.update(disk_image_path, read_only)?;
        Ok(self.resources.disk.nsectors)
    }
}
