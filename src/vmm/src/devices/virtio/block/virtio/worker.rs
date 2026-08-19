// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use event_manager::{EventOps, Events, MutEventSubscriber, SubscriberOps};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use super::device::BlockResources;
use super::io::{BlockIoError, FileEngine, async_io};
use super::metrics::BlockDeviceMetrics;
use super::{FinishedRequest, IoErr, ProcessingResult, Request, VirtioBlockError};
use crate::EventManager;
use crate::devices::virtio::device::ActiveState;
use crate::devices::virtio::queue::InvalidAvailIdx;
use crate::devices::virtio::transport::VirtioInterruptType;
use crate::logger::{IncMetric, error, warn};
use crate::rate_limiter::RateLimiter;

/// Runtime state and processing logic for an active block device.
#[derive(Debug)]
pub(crate) struct BlockWorker {
    pub(crate) resources: BlockResources,
    pub(crate) active_state: ActiveState,
    pub(crate) rate_limiter: Arc<Mutex<RateLimiter>>,
    pub(crate) is_blocked: Arc<AtomicBool>,
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
    Finished,
}

#[allow(clippy::large_enum_variant)]
enum ControlMsg {
    Start(BlockWorker),
    UpdateDiskImage { path: String, read_only: bool },
    Kick,
    Reset,
    Finish(FlushMode),
}

#[allow(clippy::large_enum_variant)]
enum ControlResponse {
    DiskUpdated(Result<u64, VirtioBlockError>), // returns nsectors on success
    Reset(Option<BlockResources>),
}

/// VMM-side handle for controlling and joining a block worker thread.
#[derive(Debug)]
pub(crate) struct WorkerHandle {
    to_worker: Sender<ControlMsg>,
    from_worker: Receiver<ControlResponse>,
    control_evt: EventFd,
    join: JoinHandle<()>,
    queue_evts: Vec<EventFd>,
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

impl WorkerHandle {
    /// Spawn a parked block worker thread.
    pub(crate) fn spawn(queue_evts: Vec<EventFd>, name: String) -> Result<Self, std::io::Error> {
        // handle writes and worker reads the control eventfd
        let control_evt = EventFd::new(libc::EFD_NONBLOCK)?;
        let handle_evt = control_evt.try_clone()?;

        let (to_worker, from_vmm) = channel::<ControlMsg>();
        let (to_vmm, from_worker) = channel::<ControlResponse>();

        let join = thread::Builder::new().name(name).spawn(move || {
            let event_manager =
                EventManager::new().expect("Failed to create block worker EventManager");
            run_worker_loop(event_manager, control_evt, from_vmm, to_vmm);
        })?;

        Ok(Self {
            to_worker,
            from_worker,
            control_evt: handle_evt,
            join,
            queue_evts,
        })
    }

    pub(crate) fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    /// Transfer data-path resources to the worker thread and start processing.
    pub(crate) fn start(&self, worker: BlockWorker) {
        if let Err(err) = self.to_worker.send(ControlMsg::Start(worker)) {
            error!("Failed to send block worker start message: {:?}", err);
            return;
        }

        if let Err(err) = self.control_evt.write(1) {
            error!("Failed to notify block worker: {:?}", err);
        }
    }

    /// Stop processing and return the data-path resources to the VMM thread.
    pub(crate) fn reset(&self) -> Option<BlockResources> {
        if let Err(err) = self.to_worker.send(ControlMsg::Reset) {
            error!(
                "Block worker receiver already dropped during reset: {:?}",
                err
            );
            return None;
        }

        if let Err(err) = self.control_evt.write(1) {
            error!(
                "Block worker control event is closed during reset: {:?}",
                err
            );
            return None;
        }

        loop {
            match self.from_worker.recv() {
                Ok(ControlResponse::Reset(resources)) => return resources,
                Ok(ControlResponse::DiskUpdated(_)) => {
                    warn!("Ignoring disk update response while waiting for reset");
                }
                Err(err) => {
                    error!("Block worker failed to acknowledge reset: {:?}", err);
                    return None;
                }
            }
        }
    }

    /// Replace the worker's backing file and return its new sector count.
    pub(crate) fn update_disk_image(
        &self,
        disk_image_path: String,
        read_only: bool,
    ) -> Result<u64, VirtioBlockError> {
        if let Err(err) = self.to_worker.send(ControlMsg::UpdateDiskImage {
            path: disk_image_path,
            read_only,
        }) {
            error!("Failed to send block worker disk update: {:?}", err);
            return Err(VirtioBlockError::WorkerControl(format!(
                "failed to send disk update: {err}"
            )));
        }

        if let Err(err) = self.control_evt.write(1) {
            error!("Failed to notify block worker of disk update: {:?}", err);
            return Err(VirtioBlockError::WorkerControl(format!(
                "failed to notify worker of disk update: {err}"
            )));
        }

        loop {
            match self.from_worker.recv() {
                Ok(ControlResponse::DiskUpdated(result)) => return result,
                Ok(ControlResponse::Reset(_)) => {
                    warn!("Ignoring reset response while waiting for disk update");
                }
                Err(err) => {
                    error!("Block worker failed to acknowledge disk update: {:?}", err);
                    return Err(VirtioBlockError::WorkerControl(format!(
                        "failed to receive disk update response: {err}"
                    )));
                }
            }
        }
    }

    pub(crate) fn kick(&self) {
        if let Err(err) = self.to_worker.send(ControlMsg::Kick) {
            error!("Failed to send block worker kick: {:?}", err);
            return;
        }

        if let Err(err) = self.control_evt.write(1) {
            error!("Failed to notify block worker of kick: {:?}", err);
        }
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
        if let Err(err) = ops.add(Events::with_data(
            &self.control_evt,
            Self::PROCESS_CONTROL,
            EventSet::IN,
        )) {
            error!("Failed to register block worker control event: {}", err);
        }
    }

    fn register_runtime_events(resources: &BlockResources, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &resources.queue_evts[0],
            Self::PROCESS_QUEUE,
            EventSet::IN,
        )) {
            error!("Failed to register queue event: {}", err);
        }
        if let FileEngine::Async(ref engine) = resources.disk.file_engine
            && let Err(err) = ops.add(Events::with_data(
                engine.completion_evt(),
                Self::PROCESS_ASYNC_COMPLETION,
                EventSet::IN,
            ))
        {
            error!("Failed to register IO engine completion event: {}", err);
        }
    }

    fn unregister_runtime_events(resources: &BlockResources, ops: &mut EventOps) {
        if let Err(err) = ops.remove(Events::with_data(
            &resources.queue_evts[0],
            Self::PROCESS_QUEUE,
            EventSet::IN,
        )) {
            error!("Failed to unregister queue event: {}", err);
        }
        if let FileEngine::Async(ref engine) = resources.disk.file_engine
            && let Err(err) = ops.remove(Events::with_data(
                engine.completion_evt(),
                Self::PROCESS_ASYNC_COMPLETION,
                EventSet::IN,
            ))
        {
            error!("Failed to unregister IO engine completion event: {}", err);
        }
    }

    fn process_control_event(&mut self, ops: &mut EventOps) {
        if let Err(err) = self.control_evt.read() {
            error!("Failed to consume block worker control event: {:?}", err);
            if let WorkerState::Running(worker) = &self.state {
                worker.metrics.event_fails.inc();
            }
            return;
        }

        while let Ok(msg) = self.from_vmm.try_recv() {
            match msg {
                ControlMsg::Start(worker) => self.start_worker(worker, ops),
                ControlMsg::UpdateDiskImage { path, read_only } => {
                    self.update_disk_image(path, read_only)
                }
                ControlMsg::Kick => self.kick_worker(),
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

    fn update_disk_image(&mut self, path: String, read_only: bool) {
        let result = match &mut self.state {
            WorkerState::Running(worker) => worker.update_disk_image(path, read_only),
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

        if let Err(err) = self.to_vmm.send(ControlResponse::DiskUpdated(result)) {
            error!(
                "Failed to send block worker disk update response: {:?}",
                err
            );
        }
    }

    fn kick_worker(&mut self) {
        match std::mem::replace(&mut self.state, WorkerState::Parked) {
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
                .process_virtio_queues()
                .unwrap_or_else(|err| error!("Failed to kick block worker queue: {:?}", err));
        }
    }

    fn reset_worker(&mut self, ops: &mut EventOps) {
        let resources = match std::mem::replace(&mut self.state, WorkerState::Parked) {
            WorkerState::Running(mut worker) => {
                Self::unregister_runtime_events(&worker.resources, ops);
                if worker.reset() {
                    Some(worker.resources)
                } else {
                    Self::register_runtime_events(&worker.resources, ops);
                    self.state = WorkerState::Running(worker);
                    None
                }
            }
            WorkerState::Parked => {
                warn!("Reset requested while block worker is parked");
                None
            }
            WorkerState::Finished => {
                self.state = WorkerState::Finished;
                None
            }
        };

        if let Err(err) = self.to_vmm.send(ControlResponse::Reset(resources)) {
            error!("Failed to send block worker reset response: {:?}", err);
        }
    }

    fn finish_worker(&mut self, flush_mode: FlushMode, ops: &mut EventOps) {
        if let WorkerState::Running(mut worker) =
            std::mem::replace(&mut self.state, WorkerState::Finished)
        {
            Self::unregister_runtime_events(&worker.resources, ops);
            match flush_mode {
                FlushMode::Drain => worker.drain(true),
                FlushMode::DrainAndFlush => worker.drain_and_flush(true),
            }
            worker.resources.is_io_engine_throttled = false;
        }
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
