// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cmp;
use std::io;
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::result;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use sys_util::EventFd;

use memory_model::GuestMemory;

use crate::{DeviceEventT, EpollHandler, Error as DeviceError};

use super::super::{
    ActivateError, ActivateResult, EpollConfigConstructor, Queue, VirtioDevice, TYPE_FS,
    VIRTIO_MMIO_INT_VRING,
};
use super::filesystem::{FuseBackend, Request};

use super::error::ExecuteError;

const CONFIG_TAG_SIZE: usize = 36;
const CONFIG_NUM_QUEUES_SIZE: usize = 4;
const CONFIG_SPACE_SIZE: usize = CONFIG_TAG_SIZE + CONFIG_NUM_QUEUES_SIZE;

// New descriptors are pending on the virtio queue.
const HIGH_AVAIL_EVENT: DeviceEventT = 0;
// New descriptors are pending on the virtio queue.
const QUEUE_AVAIL_EVENT: DeviceEventT = 1;

const QUEUE_SIZE: u16 = 256;
const NUM_REQUEST_QUEUES: usize = 1;
const NUM_HIPRIO_QUEUES: usize = 1;
const NUM_QUEUES: usize = NUM_HIPRIO_QUEUES + NUM_REQUEST_QUEUES;
const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

pub struct EpollConfig {
    q_avail_token: u64,
    h_token: u64,
    epoll_raw_fd: RawFd,
    sender: mpsc::Sender<Box<EpollHandler>>,
}

impl EpollConfigConstructor for EpollConfig {
    fn new(first_token: u64, epoll_raw_fd: RawFd, sender: mpsc::Sender<Box<EpollHandler>>) -> Self {
        EpollConfig {
            q_avail_token: first_token + u64::from(QUEUE_AVAIL_EVENT),
            h_token: first_token + u64::from(HIGH_AVAIL_EVENT),
            epoll_raw_fd,
            sender,
        }
    }
}

struct VtfsEpollHandler {
    mem: GuestMemory,
    fs: FuseBackend,
    hiprio_queue_evt: EventFd,
    request_queue_evt: EventFd,
    hiprio_queue: Queue,
    request_queue: Queue,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
}

impl VtfsEpollHandler {
    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            // METRICS.block.event_fails.inc();
            DeviceError::FailedSignalingUsedQueue(e)
        })
    }

    fn process_queue(&mut self, queue_index: DeviceEventT) -> bool {
        let queue = match queue_index {
            HIGH_AVAIL_EVENT => &mut self.hiprio_queue,
            QUEUE_AVAIL_EVENT => &mut self.request_queue,
            _ => {
                return false;
            }
        };

        let mut used_any = false;
        while let Some(head) = queue.pop(&self.mem) {
            let len: u32;
            match Request::parse(&head, &self.mem) {
                Ok(request) => {
                    len = request.execute(&mut self.fs).unwrap_or_else(|e| match e {
                        ExecuteError::InvalidMethod => {
                            // TODO: Metrics
                            request.send_err(libc::ENOSYS)
                        }
                        ExecuteError::IllegalParameter => {
                            // TODO: Metrics
                            request.send_err(libc::EINVAL)
                        }
                        ExecuteError::MemoryError => {
                            // TODO: Metrics
                            request.send_err(libc::EINVAL)
                        }
                        ExecuteError::UnknownHandle => {
                            // TODO: Metrics
                            request.send_err(libc::ENOENT)
                        }
                        ExecuteError::OSError(eno) => {
                            // TODO: Metrics
                            request.send_err(eno)
                        }
                        ExecuteError::UnknownError => {
                            // TODO: Metrics
                            request.send_err(libc::ENOSYS)
                        }
                    });
                }
                Err(_e) => {
                    len = 0;
                }
            }
            queue.add_used(&self.mem, head.index, len);
            used_any = true;
        }
        used_any
    }
}

impl EpollHandler for VtfsEpollHandler {
    fn handle_event(
        &mut self,
        device_event: DeviceEventT,
        _evset: epoll::Events,
    ) -> result::Result<(), DeviceError> {
        match device_event {
            QUEUE_AVAIL_EVENT => {
                if let Err(e) = self.request_queue_evt.read() {
                    Err(DeviceError::FailedReadingQueue {
                        event_type: "queue event",
                        underlying: e,
                    })
                } else if self.process_queue(QUEUE_AVAIL_EVENT) {
                    self.signal_used_queue()
                } else {
                    // While limiter is blocked, don't process any more requests.
                    Ok(())
                }
            }
            HIGH_AVAIL_EVENT => {
                if let Err(e) = self.hiprio_queue_evt.read() {
                    Err(DeviceError::FailedReadingQueue {
                        event_type: "queue event",
                        underlying: e,
                    })
                } else if self.process_queue(HIGH_AVAIL_EVENT) {
                    self.signal_used_queue()
                } else {
                    // While limiter is blocked, don't process any more requests.
                    Ok(())
                }
            }
            unknown => Err(DeviceError::UnknownEvent {
                device: "vtfs",
                event: unknown,
            }),
        }
    }
}

pub struct Vtfs {
    fs_path: PathBuf,
    avail_features: u64,
    acked_features: u64,
    config_space: Vec<u8>,
    epoll_config: EpollConfig,
}

impl Vtfs {
    /// Create a new virtio block device that operates on the given file.
    pub fn new(fs_tag: &str, fs_path: PathBuf, epoll_config: EpollConfig) -> io::Result<Vtfs> {
        let mut c = Vec::with_capacity(CONFIG_SPACE_SIZE);
        // for i in fs_tag.as_bytes().clone_from_slice(src: &[T]) {
        //     c.push(i)
        // }
        c.extend_from_slice(fs_tag.as_bytes());
        for _ in c.len()..CONFIG_TAG_SIZE {
            c.push(0u8)
        }
        c.extend_from_slice(&(NUM_REQUEST_QUEUES as u32).to_le_bytes());

        Ok(Vtfs {
            fs_path: fs_path,
            avail_features: 0u64,
            acked_features: 0u64,
            config_space: c,
            epoll_config,
        })
    }
}

impl VirtioDevice for Vtfs {
    fn device_type(&self) -> u32 {
        TYPE_FS
    }

    /// The maximum size of each queue that this device supports.
    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    /// Reads this device configuration space at `offset`.
    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            error!(
                "vtfs: virtio-fs received invalid read request of {} bytes at offset {}",
                data.len(),
                offset
            );
            // METRICS.block.cfg_fails.inc();
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&self.config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    /// Writes to this device configuration space at `offset`.
    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        error!("Failed to write config space")
    }

    /// Activates this device for real usage.
    fn activate(
        &mut self,
        mem: GuestMemory,
        interrupt_evt: EventFd,
        status: Arc<AtomicUsize>,
        mut queues: Vec<Queue>,
        mut queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != NUM_QUEUES || queue_evts.len() != NUM_QUEUES {
            return Err(ActivateError::BadActivate);
        }

        // TODO: check fs_path ?
        let fs_path = self.fs_path.to_str().ok_or(ActivateError::BadActivate)?;
        if let Some(fffs) = FuseBackend::new(fs_path) {
            let hiprio_queue = queues.remove(0);
            let request_queue = queues.remove(0);

            let hiprio_queue_evt = queue_evts.remove(0);
            let request_queue_evt = queue_evts.remove(0);

            let hiprio_queue_evt_raw_fd = hiprio_queue_evt.as_raw_fd();
            let request_queue_evt_raw_fd = request_queue_evt.as_raw_fd();

            let handler = VtfsEpollHandler {
                mem,
                fs: fffs,
                hiprio_queue_evt,
                request_queue_evt,
                hiprio_queue,
                request_queue,
                interrupt_status: status,
                interrupt_evt,
            };

            self.epoll_config
                .sender
                .send(Box::new(handler))
                .expect("Failed to send through the channel");

            epoll::ctl(
                self.epoll_config.epoll_raw_fd,
                epoll::ControlOptions::EPOLL_CTL_ADD,
                hiprio_queue_evt_raw_fd,
                epoll::Event::new(epoll::Events::EPOLLIN, self.epoll_config.h_token),
            )
            .map_err(|e| {
                // METRICS.block.activate_fails.inc();
                ActivateError::EpollCtl(e)
            })?;

            //TODO: barrier needed here by any chance?
            epoll::ctl(
                self.epoll_config.epoll_raw_fd,
                epoll::ControlOptions::EPOLL_CTL_ADD,
                request_queue_evt_raw_fd,
                epoll::Event::new(epoll::Events::EPOLLIN, self.epoll_config.q_avail_token),
            )
            .map_err(|e| {
                // METRICS.block.activate_fails.inc();
                ActivateError::EpollCtl(e)
            })?;

            return Ok(());
        }
        Err(ActivateError::BadActivate)
    }
}
