// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use event_manager::{EventOps, Events, MutEventSubscriber, SubscriberOps};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use super::device::BlockResources;
use super::io::{BlockIoError, FileEngine, async_io};
use super::metrics::BlockDeviceMetrics;
use super::{FinishedRequest, IoErr, ProcessingResult, Request, VirtioBlockError};
use crate::EventManager;
use crate::devices::virtio::device::ActiveState;
use crate::devices::virtio::persist::QueueState;
use crate::devices::virtio::queue::{InvalidAvailIdx, QueueError};
use crate::devices::virtio::transport::VirtioInterruptType;
use crate::logger::{IncMetric, error, warn};
use crate::rate_limiter::RateLimiter;
use crate::seccomp::{BpfProgram, apply_filter};
use crate::snapshot::Persist;

/// Runtime state and processing logic for an active block device.
#[derive(Debug)]
pub(crate) struct BlockWorker {
    pub(crate) resources: BlockResources,
    pub(crate) active_state: ActiveState,
    pub(crate) rate_limiter: Arc<Mutex<RateLimiter>>,
    pub(crate) is_blocked: Arc<AtomicBool>,
    pub(crate) discard_supported: bool,
    pub(crate) metrics: Arc<BlockDeviceMetrics>,
}

/// Worker state and control channel side (recv ctl msg)
#[derive(Debug)]
struct ThreadedWorker {
    state: WorkerState,
    control_evt: EventFd,
    from_vmm: Receiver<ControlMsg>,
    to_vmm: Sender<ControlResponse>,
}

/// Data-path ownership state of the worker thread.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum WorkerState {
    Parked,
    Running(BlockWorker),
    Paused(BlockWorker),
    Finished,
}

#[allow(clippy::large_enum_variant)]
enum ControlMsg {
    Start(BlockWorker),
    UpdateDiskImage { path: String, read_only: bool },
    Reset,
    Pause,
    GetQueueState,
    MarkQueueMemoryDirty,
    Kick { resume: bool },
    Finish(FlushMode),
}

#[allow(clippy::large_enum_variant)]
enum ControlResponse {
    DiskUpdated(Result<u64, VirtioBlockError>), // returns nsectors on success
    Reset(BlockResources),
    Paused,
    QueueState(QueueState),
    QueueMemoryDirty(Result<(), QueueError>),
    InvalidState(String),
}

/// VMM-side handle for controlling and joining a block worker thread.
#[derive(Debug)]
pub(crate) struct WorkerHandle {
    to_worker: Sender<ControlMsg>,
    from_worker: Receiver<ControlResponse>,
    control_evt: EventFd,
    join: JoinHandle<()>,
    queue_evt: EventFd,
}

/// Determines how pending I/O is handled during worker teardown.
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

impl ControlResponse {
    fn name(&self) -> &'static str {
        match self {
            Self::DiskUpdated(_) => "disk update",
            Self::Reset(_) => "reset",
            Self::Paused => "pause",
            Self::QueueState(_) => "queue state",
            Self::QueueMemoryDirty(_) => "queue memory dirty",
            Self::InvalidState(_) => "invalid state",
        }
    }
}

impl BlockWorker {
    /// Process a single event in the Virtio queue.
    ///
    /// This function is called by the event manager when the guest notifies us
    /// about new buffers in the queue.
    pub(crate) fn process_queue_event(&mut self) {
        self.metrics.queue_event_count.inc();
        if let Err(err) = self.resources.queue_evt.read() {
            error!("Failed to get queue event: {:?}", err);
            self.metrics.event_fails.inc();
        } else if self.is_blocked.load(Ordering::Relaxed) {
            self.metrics.rate_limiter_throttled_events.inc();
        } else if self.resources.is_io_engine_throttled {
            self.metrics.io_engine_throttled_events.inc();
        } else {
            self.process_queue().unwrap()
        }
    }

    /// Device specific function for peaking inside a queue and processing descriptors.
    pub(super) fn process_queue(&mut self) -> Result<(), InvalidAvailIdx> {
        let rate_limiter = &self.rate_limiter;
        let queue = &mut self.resources.queue;
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

    /// Prepare device for being snapshotted.
    pub(crate) fn prepare_save(&mut self) {
        // Fsync errors are non-fatal; other drain errors are broken invariants.
        match self.resources.disk.file_engine.drain_and_flush(false) {
            Ok(()) => {}
            Err(BlockIoError::Async(async_io::AsyncIoError::SyncAll(err))) => {
                error!("Failed to flush block data for snapshot: {:?}", err);
            }
            Err(BlockIoError::Sync(err)) => {
                error!("Failed to flush block data for snapshot: {:?}", err);
            }
            Err(err) => panic!("Failed to drain block IO engine for snapshot: {err:?}"),
        }
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

impl WorkerHandle {
    /// Spawn a parked block worker thread.
    pub(crate) fn spawn(
        seccomp_filter: Arc<BpfProgram>,
        queue_evt: EventFd,
        name: String,
    ) -> Result<Self, std::io::Error> {
        // handle writes and worker reads the control eventfd
        let control_evt = EventFd::new(libc::EFD_NONBLOCK)?;
        let handle_evt = control_evt.try_clone()?;

        let (to_worker, from_vmm) = channel::<ControlMsg>();
        let (to_vmm, from_worker) = channel::<ControlResponse>();

        let join = thread::Builder::new().name(name).spawn(move || {
            // Create epoll before applying the filter, which does not allow epoll_create1.
            let event_manager =
                EventManager::new().expect("Failed to create block worker EventManager");

            if let Err(err) = apply_filter(&seccomp_filter) {
                panic!("Failed to apply seccomp filter on block worker: {err}");
            }

            run_worker_loop(event_manager, control_evt, from_vmm, to_vmm);
        })?;

        Ok(Self {
            to_worker,
            from_worker,
            control_evt: handle_evt,
            join,
            queue_evt,
        })
    }

    pub(crate) fn queue_event(&self) -> &EventFd {
        &self.queue_evt
    }

    /// Send a control request to the worker thread.
    ///
    /// Channels and control eventfd failures are invariants if broken, state cannot be recovered.
    fn request(&self, msg: ControlMsg) {
        self.to_worker
            .send(msg)
            .expect("Failed to send request to block worker");
        self.control_evt
            .write(1)
            .expect("Failed to notify block worker");
    }

    /// Transfer data-path resources to the worker thread and start processing.
    pub(crate) fn start(&self, worker: BlockWorker) {
        self.request(ControlMsg::Start(worker));
    }

    /// Stop processing and return the data-path resources to the VMM thread.
    /// The caller must reset the returned resources before reuse.
    pub(crate) fn reset(&self) -> BlockResources {
        self.request(ControlMsg::Reset);
        match self
            .from_worker
            .recv()
            .expect("Failed to receive block worker reset response")
        {
            ControlResponse::Reset(resources) => resources,
            ControlResponse::InvalidState(err) => panic!("Block worker rejected reset: {err}"),
            response => panic!(
                "Unexpected {} response to block worker reset",
                response.name()
            ),
        }
    }

    /// Replace the worker's backing file and return its new sector count.
    pub(crate) fn update_disk_image(
        &self,
        disk_image_path: String,
        read_only: bool,
    ) -> Result<u64, VirtioBlockError> {
        let msg = ControlMsg::UpdateDiskImage {
            path: disk_image_path,
            read_only,
        };
        self.request(msg);
        match self
            .from_worker
            .recv()
            .expect("Failed to receive block worker disk update response")
        {
            ControlResponse::DiskUpdated(result) => result,
            ControlResponse::InvalidState(err) => {
                panic!("Block worker rejected disk update: {err}")
            }
            response => panic!(
                "Unexpected {} response to block worker disk update",
                response.name()
            ),
        }
    }

    /// Pause data-path processing after completing pending I/O.
    pub(crate) fn pause(&self) {
        self.request(ControlMsg::Pause);
        match self
            .from_worker
            .recv()
            .expect("Failed to receive block worker pause response")
        {
            ControlResponse::Paused => {}
            ControlResponse::InvalidState(err) => panic!("Block worker rejected pause: {err}"),
            response => panic!(
                "Unexpected {} response to block worker pause",
                response.name()
            ),
        }
    }

    /// Read queue state from a paused worker.
    pub(crate) fn get_queue_state(&self) -> QueueState {
        self.request(ControlMsg::GetQueueState);
        match self
            .from_worker
            .recv()
            .expect("Failed to receive block worker queue state response")
        {
            ControlResponse::QueueState(state) => state,
            ControlResponse::InvalidState(err) => {
                panic!("Block worker rejected queue state request: {err}")
            }
            response => panic!(
                "Unexpected {} response to block worker queue state",
                response.name()
            ),
        }
    }

    /// Mark the worker-owned virtqueue memory dirty after a snapshot.
    pub(crate) fn mark_queue_memory_dirty(&self) -> Result<(), QueueError> {
        self.request(ControlMsg::MarkQueueMemoryDirty);
        match self
            .from_worker
            .recv()
            .expect("Failed to receive block worker queue memory dirty response")
        {
            ControlResponse::QueueMemoryDirty(result) => result,
            ControlResponse::InvalidState(err) => {
                panic!("Block worker rejected queue memory dirty request: {err}")
            }
            response => panic!(
                "Unexpected {} response to block worker queue memory dirty",
                response.name()
            ),
        }
    }

    /// Resume a paused worker and process pending queue entries.
    pub(crate) fn kick(&self, resume: bool) {
        self.request(ControlMsg::Kick { resume });
    }

    /// Stop the worker and wait for its thread to exit.
    pub(crate) fn finish(self, flush_mode: FlushMode) {
        if let Err(err) = self.to_worker.send(ControlMsg::Finish(flush_mode)) {
            error!("Block worker receiver already dropped: {:?}", err);
        }

        if let Err(err) = self.control_evt.write(1) {
            error!("Block worker control event is closed: {:?}", err);
        }

        self.join.join().unwrap_or_else(|err| {
            error!("Block worker thread panicked during teardown: {:?}", err);
        });
    }
}

impl ThreadedWorker {
    const PROCESS_QUEUE: u32 = 0;
    const PROCESS_ASYNC_COMPLETION: u32 = 1;
    const PROCESS_CONTROL: u32 = 2;

    fn register_control_event(&self, ops: &mut EventOps) {
        ops.add(Events::with_data(
            &self.control_evt,
            Self::PROCESS_CONTROL,
            EventSet::IN,
        ))
        .expect("Failed to register block worker control event");
    }

    fn register_runtime_events(resources: &BlockResources, ops: &mut EventOps) {
        ops.add(Events::with_data(
            &resources.queue_evt,
            Self::PROCESS_QUEUE,
            EventSet::IN,
        ))
        .expect("Failed to register queue event");
        if let FileEngine::Async(ref engine) = resources.disk.file_engine {
            ops.add(Events::with_data(
                engine.completion_evt(),
                Self::PROCESS_ASYNC_COMPLETION,
                EventSet::IN,
            ))
            .expect("Failed to register IO engine completion event");
        }
    }

    fn unregister_runtime_events(resources: &BlockResources, ops: &mut EventOps) {
        ops.remove(Events::with_data(
            &resources.queue_evt,
            Self::PROCESS_QUEUE,
            EventSet::IN,
        ))
        .expect("Failed to unregister queue event");
        if let FileEngine::Async(ref engine) = resources.disk.file_engine {
            ops.remove(Events::with_data(
                engine.completion_evt(),
                Self::PROCESS_ASYNC_COMPLETION,
                EventSet::IN,
            ))
            .expect("Failed to unregister IO engine completion event");
        }
    }

    fn process_control_event(&mut self, ops: &mut EventOps) {
        if let Err(err) = self.control_evt.read() {
            if let WorkerState::Running(worker) | WorkerState::Paused(worker) = &self.state {
                worker.metrics.event_fails.inc();
            }
            panic!("Failed to consume block worker control event: {err:?}");
        }

        while let Ok(msg) = self.from_vmm.try_recv() {
            match msg {
                ControlMsg::Start(worker) => self.start_worker(worker, ops),
                ControlMsg::UpdateDiskImage { path, read_only } => {
                    self.update_disk_image(path, read_only)
                }
                ControlMsg::Pause => self.pause_worker(ops),
                ControlMsg::GetQueueState => self.send_queue_state(),
                ControlMsg::MarkQueueMemoryDirty => self.mark_queue_memory_dirty(),
                ControlMsg::Kick { resume } => self.kick_worker(resume, ops),
                ControlMsg::Reset => self.reset_worker(ops),
                ControlMsg::Finish(flush_mode) => self.finish_worker(flush_mode, ops),
            }

            if self.is_finished() {
                break;
            }
        }
    }

    fn start_worker(&mut self, worker: BlockWorker, ops: &mut EventOps) {
        if !matches!(self.state, WorkerState::Parked) {
            warn!("Start requested while block worker is not parked");
            return;
        }

        Self::register_runtime_events(&worker.resources, ops);
        self.state = WorkerState::Running(worker);
    }

    /// Reply to the VMM. The handle outlives every request, so a closed channel is a
    /// broken invariant.
    fn reply(&self, response: ControlResponse) {
        self.to_vmm
            .send(response)
            .expect("Failed to send block worker response");
    }

    fn update_disk_image(&mut self, path: String, read_only: bool) {
        let result = match &mut self.state {
            WorkerState::Running(worker) | WorkerState::Paused(worker) => {
                worker.update_disk_image(path, read_only)
            }
            WorkerState::Parked => {
                warn!("Disk image update requested while block worker is parked");
                Err(VirtioBlockError::WorkerControl(
                    "disk update requested while worker is parked".to_string(),
                ))
            }
            WorkerState::Finished => {
                warn!("Disk image update requested after block worker finished");
                Err(VirtioBlockError::WorkerControl(
                    "disk update requested after worker finished".to_string(),
                ))
            }
        };

        self.reply(ControlResponse::DiskUpdated(result));
    }

    fn reset_worker(&mut self, ops: &mut EventOps) {
        let response = match std::mem::replace(&mut self.state, WorkerState::Parked) {
            WorkerState::Running(worker) => {
                Self::unregister_runtime_events(&worker.resources, ops);
                ControlResponse::Reset(worker.resources)
            }
            WorkerState::Paused(worker) => ControlResponse::Reset(worker.resources),
            state => {
                self.state = state;
                ControlResponse::InvalidState(
                    "reset requested while block worker is not active".to_string(),
                )
            }
        };

        self.reply(response);
    }

    fn pause_worker(&mut self, ops: &mut EventOps) {
        let response = match std::mem::replace(&mut self.state, WorkerState::Parked) {
            WorkerState::Running(mut worker) => {
                Self::unregister_runtime_events(&worker.resources, ops);
                worker.prepare_save();
                self.state = WorkerState::Paused(worker);
                ControlResponse::Paused
            }
            WorkerState::Paused(worker) => {
                self.state = WorkerState::Paused(worker);
                ControlResponse::Paused
            }
            state => {
                self.state = state;
                ControlResponse::InvalidState(
                    "pause requested while block worker is not active".to_string(),
                )
            }
        };

        self.reply(response);
    }

    fn send_queue_state(&self) {
        let response = match &self.state {
            WorkerState::Paused(worker) => {
                ControlResponse::QueueState(worker.resources.queue.save())
            }
            _ => ControlResponse::InvalidState(
                "queue state requested while block worker is not paused".to_string(),
            ),
        };

        self.reply(response);
    }

    fn mark_queue_memory_dirty(&mut self) {
        let result = if let WorkerState::Paused(worker) = &mut self.state {
            let mem = worker.active_state.mem.clone();
            worker.resources.queue.initialize(&mem)
        } else {
            warn!("Queue memory dirty requested while block worker is not paused");
            Err(QueueError::NotReady)
        };

        self.reply(ControlResponse::QueueMemoryDirty(result));
    }

    fn kick_worker(&mut self, resume: bool, ops: &mut EventOps) {
        match std::mem::replace(&mut self.state, WorkerState::Parked) {
            WorkerState::Paused(worker) if resume => {
                Self::register_runtime_events(&worker.resources, ops);
                self.state = WorkerState::Running(worker);
            }
            WorkerState::Paused(worker) => {
                self.state = WorkerState::Paused(worker);
                return;
            }
            WorkerState::Running(worker) => {
                self.state = WorkerState::Running(worker);
            }
            state => {
                warn!("Kick requested while block worker is not active");
                self.state = state;
                return;
            }
        }

        // process directly instead of going through epoll
        if let WorkerState::Running(worker) = &mut self.state {
            worker
                .process_queue()
                .unwrap_or_else(|err| error!("Failed to kick block worker queue: {:?}", err));
        }
    }

    fn finish_worker(&mut self, flush_mode: FlushMode, ops: &mut EventOps) {
        match std::mem::replace(&mut self.state, WorkerState::Finished) {
            WorkerState::Running(mut worker) => {
                Self::unregister_runtime_events(&worker.resources, ops);
                Self::flush_worker(&mut worker, flush_mode);
            }
            WorkerState::Paused(mut worker) => Self::flush_worker(&mut worker, flush_mode),
            WorkerState::Parked | WorkerState::Finished => {}
        }
    }

    fn flush_worker(worker: &mut BlockWorker, flush_mode: FlushMode) {
        match flush_mode {
            FlushMode::Drain => worker.drain(true),
            FlushMode::DrainAndFlush => worker.drain_and_flush(true),
        }
        worker.resources.is_io_engine_throttled = false;
    }

    fn is_finished(&self) -> bool {
        matches!(self.state, WorkerState::Finished)
    }
}

fn run_worker_loop(
    mut event_manager: EventManager,
    control_evt: EventFd,
    from_vmm: Receiver<ControlMsg>,
    to_vmm: Sender<ControlResponse>,
) {
    let worker = Arc::new(Mutex::new(ThreadedWorker {
        state: WorkerState::Parked,
        control_evt,
        from_vmm,
        to_vmm,
    }));
    let subscriber: Arc<Mutex<dyn MutEventSubscriber>> = worker.clone();
    event_manager.add_subscriber(subscriber);

    loop {
        if let Err(err) = event_manager.run() {
            error!("Block worker event loop error: {:?}", err);
        }
        if worker
            .lock()
            .expect("Poisoned block worker lock")
            .is_finished()
        {
            break;
        }
    }
}

impl MutEventSubscriber for ThreadedWorker {
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let source = event.data();
        let event_set = event.event_set();

        if !EventSet::IN.contains(event_set) {
            warn!(
                "Block worker received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if let WorkerState::Running(worker) = &mut self.state {
            match source {
                Self::PROCESS_QUEUE => worker.process_queue_event(),
                Self::PROCESS_ASYNC_COMPLETION => worker.process_async_completion_event(),
                Self::PROCESS_CONTROL => self.process_control_event(ops),
                _ => warn!("Block: Spurious event received: {:?}", source),
            }
        } else {
            match source {
                Self::PROCESS_CONTROL => self.process_control_event(ops),
                _ => warn!(
                    "Block: The device worker is not yet activated. Spurious event received: {:?}",
                    source
                ),
            }
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        self.register_control_event(ops);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RECV_TIMEOUT_SEC;
    use crate::devices::virtio::block::virtio::device::{BlockState, FileEngineType};
    use crate::devices::virtio::block::virtio::request::{
        VIRTIO_BLK_ID_BYTES, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_GET_ID,
    };
    use crate::devices::virtio::block::virtio::test_utils::{
        default_block, read_blk_req_descriptors, set_queue,
    };
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::vstate::memory::{Bytes, GuestAddress};

    #[test]
    fn test_control_msg_batch() {
        let mut block = default_block(FileEngineType::Sync);
        let BlockState::Configuring(resources, _) =
            std::mem::replace(&mut block.state, BlockState::Placeholder)
        else {
            unreachable!()
        };
        let expected_queue_state = resources.queue.save();
        let queue_evt = resources.queue_evt.try_clone().unwrap();
        let worker = BlockWorker {
            resources,
            active_state: ActiveState {
                mem: default_mem(),
                interrupt: default_interrupt(),
            },
            rate_limiter: block.rate_limiter.clone(),
            is_blocked: block.lock_rate_limiter().clone_blocked_flag(),
            discard_supported: false,
            metrics: block.metrics.clone(),
        };
        let handle = WorkerHandle::spawn(Arc::new(vec![]), queue_evt, "fc_test".into()).unwrap();

        handle.to_worker.send(ControlMsg::Start(worker)).unwrap();
        handle.to_worker.send(ControlMsg::Pause).unwrap();
        handle.to_worker.send(ControlMsg::GetQueueState).unwrap();
        handle.control_evt.write(1).unwrap();

        assert!(matches!(
            handle.from_worker.recv_timeout(RECV_TIMEOUT_SEC).unwrap(),
            ControlResponse::Paused
        ));
        match handle.from_worker.recv_timeout(RECV_TIMEOUT_SEC).unwrap() {
            ControlResponse::QueueState(queue_state) => {
                assert_eq!(queue_state, expected_queue_state);
            }
            response => panic!("Unexpected {} response", response.name()),
        }

        handle.finish(FlushMode::Drain);
    }

    #[test]
    fn test_kick_while_paused() {
        let mut block = default_block(FileEngineType::Sync);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        let BlockState::Configuring(mut resources, _) =
            std::mem::replace(&mut block.state, BlockState::Placeholder)
        else {
            unreachable!()
        };
        resources.queue.initialize(&mem).unwrap();
        let queue_evt = resources.queue_evt.try_clone().unwrap();
        let worker = BlockWorker {
            resources,
            active_state: ActiveState {
                mem: mem.clone(),
                interrupt: default_interrupt(),
            },
            rate_limiter: block.rate_limiter.clone(),
            is_blocked: block.lock_rate_limiter().clone_blocked_flag(),
            discard_supported: false,
            metrics: block.metrics.clone(),
        };
        let handle = WorkerHandle::spawn(Arc::new(vec![]), queue_evt, "fc_test".into()).unwrap();

        let pause = || {
            handle.to_worker.send(ControlMsg::Pause).unwrap();
            handle.control_evt.write(1).unwrap();
            assert!(matches!(
                handle.from_worker.recv_timeout(RECV_TIMEOUT_SEC).unwrap(),
                ControlResponse::Paused
            ));
        };
        let queue_state = || {
            handle.to_worker.send(ControlMsg::GetQueueState).unwrap();
            handle.control_evt.write(1).unwrap();
            match handle.from_worker.recv_timeout(RECV_TIMEOUT_SEC).unwrap() {
                ControlResponse::QueueState(state) => state,
                response => panic!("Unexpected {} response", response.name()),
            }
        };

        handle.start(worker);
        pause();
        let paused_queue_state = queue_state();

        read_blk_req_descriptors(&vq);
        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());
        vq.dtable[1].len.set(VIRTIO_BLK_ID_BYTES);
        mem.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, request_type_addr)
            .unwrap();

        handle.kick(false);
        assert_eq!(queue_state(), paused_queue_state);
        assert_eq!(vq.used.idx.get(), 0);

        handle.kick(true);
        pause();
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, VIRTIO_BLK_ID_BYTES + 1);
        assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);

        handle.finish(FlushMode::Drain);
    }

    #[test]
    fn test_parked_disk_update() {
        let worker = WorkerHandle::spawn(
            Arc::new(vec![]),
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            "fc_test".into(),
        )
        .unwrap();

        worker
            .to_worker
            .send(ControlMsg::UpdateDiskImage {
                path: String::new(),
                read_only: false,
            })
            .unwrap();
        worker.control_evt.write(1).unwrap();
        match worker.from_worker.recv_timeout(RECV_TIMEOUT_SEC).unwrap() {
            ControlResponse::DiskUpdated(Err(VirtioBlockError::WorkerControl(err))) => {
                assert!(err.contains("worker is parked"), "unexpected error: {err}");
            }
            response => panic!("Unexpected {} response", response.name()),
        }

        worker.finish(FlushMode::Drain);
    }
}
