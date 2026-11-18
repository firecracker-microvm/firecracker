// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::AsRawFd;
use std::sync::Arc;

use vmm_sys_util::epoll::EventSet;

use super::device::BlockResources;
use super::io::{BlockIoError, FileEngine, async_io};
use super::metrics::BlockDeviceMetrics;
use super::{FinishedRequest, IoErr, ProcessingResult, Request, VirtioBlockError};
use crate::devices::virtio::device::ActiveState;
use crate::devices::virtio::queue::InvalidAvailIdx;
use crate::devices::virtio::transport::VirtioInterruptType;
use crate::devices::virtio::worker::{QueueGroupWorker, WorkerEvent};
use crate::logger::{IncMetric, error, warn};
use crate::rate_limiter::SharedRateLimiter;

/// Runtime state and processing logic for one queue of an active block device.
///
/// There is one worker per virtqueue. It runs either inline on the VMM thread or on a thread of its
/// own through the shared [`QueueGroupWorker`] lifecycle; the data path is identical either way.
#[derive(Debug)]
pub(crate) struct BlockWorker {
    pub(crate) resources: BlockResources,
    pub(crate) active_state: ActiveState,
    /// Shared by every queue of the device, so that a configured limit stays a per-device limit.
    /// Its blocked state is checked lock-free on every queue event.
    pub(crate) rate_limiter: SharedRateLimiter,
    pub(crate) discard_supported: bool,
    pub(crate) metrics: Arc<BlockDeviceMetrics>,
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
    const PROCESS_QUEUE: u32 = 0;
    const PROCESS_ASYNC_COMPLETION: u32 = 1;

    /// Process a single event in the Virtio queue.
    ///
    /// This function is called by the event manager when the guest notifies us
    /// about new buffers in the queue.
    pub(crate) fn process_queue_event(&mut self) {
        self.metrics.queue_event_count.inc();
        if let Err(err) = self.resources.queue_evt.read() {
            error!("Failed to get queue event: {:?}", err);
            self.metrics.event_fails.inc();
        } else if self.rate_limiter.is_blocked() {
            self.metrics.rate_limiter_throttled_events.inc();
        } else if self.resources.is_io_engine_throttled {
            self.metrics.io_engine_throttled_events.inc();
        } else {
            self.process_queue().unwrap()
        }
    }

    /// Device specific function for peaking inside a queue and processing descriptors.
    pub(super) fn process_queue(&mut self) -> Result<(), InvalidAvailIdx> {
        if !self.resources.queue.config.ready {
            return Ok(());
        }

        let rate_limiter = &self.rate_limiter;
        let queue = &mut self.resources.queue;
        let mut used_any = false;

        while let Some(head) = queue.pop_or_enable_notification()? {
            self.metrics.remaining_reqs_count.add(queue.len().into());
            let processing_result =
                match Request::parse(&head, &self.active_state.mem, self.resources.disk.nsectors) {
                    Ok(request) => {
                        let is_rate_limited = rate_limiter
                            .lock_if_limited()
                            .is_some_and(|mut rate_limiter| request.rate_limit(&mut rate_limiter));
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
                            self.discard_supported,
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
                .trigger(VirtioInterruptType::Queue(self.resources.queue_idx))
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
        if !self.resources.queue.config.ready {
            return;
        }

        let engine = unwrap_async_file_engine_or_return!(&mut self.resources.disk.file_engine);
        let queue = &mut self.resources.queue;

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
                .trigger(VirtioInterruptType::Queue(self.resources.queue_idx))
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
                self.process_queue().unwrap()
            }
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

impl QueueGroupWorker for BlockWorker {
    type Resources = BlockResources;

    fn events(&self) -> Vec<WorkerEvent> {
        // The rate limiter timerfd is deliberately absent: the limiter is shared by every queue of
        // the device, so its timer stays on the VMM event loop, which kicks the workers when the
        // limiter unblocks. Workers only read its lock-free blocked flag.
        let mut events = vec![WorkerEvent {
            fd: self.resources.queue_evt.as_raw_fd(),
            token: Self::PROCESS_QUEUE,
            events: EventSet::IN,
        }];
        if let FileEngine::Async(ref engine) = self.resources.disk.file_engine {
            events.push(WorkerEvent {
                fd: engine.completion_evt().as_raw_fd(),
                token: Self::PROCESS_ASYNC_COMPLETION,
                events: EventSet::IN,
            });
        }
        events
    }

    fn process(&mut self, token: u32) {
        match token {
            Self::PROCESS_QUEUE => self.process_queue_event(),
            Self::PROCESS_ASYNC_COMPLETION => self.process_async_completion_event(),
            other => warn!("Block worker received an unexpected epoll token {other}"),
        }
    }

    /// Completes the queue's pending I/O. The device flushes the backing file once every queue did
    /// (see `VirtioBlock::prepare_save`).
    fn prepare_save(&mut self) {
        // Drain errors are broken invariants.
        if let Err(err) = self.resources.disk.file_engine.drain(false) {
            panic!("Failed to drain block IO engine while quiescing: {err:?}");
        }
        if matches!(&self.resources.disk.file_engine, FileEngine::Async(_)) {
            self.process_async_completion_queue();
        }
    }

    fn kick(&mut self) {
        self.process_queue()
            .unwrap_or_else(|err| error!("Failed to kick block worker queue: {:?}", err));
    }

    fn commit_dirty(&self) {
        self.resources.queue.commit_dirty();
    }

    fn into_resources(mut self) -> BlockResources {
        self.resources.reset();
        self.resources
    }

    /// Completes in-flight I/O while the worker still holds the guest memory it targets, then
    /// commits the used ring pages written since the VMM's last commit. The device flushes once
    /// every queue is back (see `Drop for VirtioBlock`).
    fn shutdown(mut self) -> BlockResources {
        if let Err(err) = self.resources.disk.file_engine.drain(true) {
            error!("Failed to drain block IO engine on finish: {:?}", err);
        }
        self.resources.queue.commit_dirty();
        self.resources
    }
}
