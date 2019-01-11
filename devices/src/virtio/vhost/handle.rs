// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::super::EpollHandlerPayload;
use super::INTERRUPT_STATUS_USED_RING;

use sys_util::EventFd;
use vhost_backend::Vhost;
use DeviceEventT;
use EpollHandler;

use super::super::super::Error as DeviceErr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

/// Event for injecting IRQ into guest.
pub const VHOST_IRQ_AVAILABLE: DeviceEventT = 0;
/// Event for stopping the vhost device.
pub const KILL_EVENT: DeviceEventT = 1;
// VHOST_IRQ_AVAILABLE and KILL_EVENT. KILL_EVENT is unused yet.
pub const VHOST_EVENTS_COUNT: usize = 2;

pub struct VhostEpollHandler<T: Vhost> {
    vhost_dev: T,
    interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    queue_evt: EventFd,
}

impl<T: Vhost> VhostEpollHandler<T> {
    /// Construct a new, empty event handler for vhost-based devices.
    ///
    /// # Arguments
    /// * `vhost_dev` - the vhost-based device info
    /// * `interrupt_status` - semaphore before triggering interrupt event
    /// * `interrupt_evt` EventFd for signaling an MMIO interrupt that the guest
    ///                   driver is listening to
    /// * `queue_evt` - EventFd used by the handle to monitor queue events
    pub fn new(
        vhost_dev: T,
        interrupt_status: Arc<AtomicUsize>,
        interrupt_evt: EventFd,
        queue_evt: EventFd,
    ) -> VhostEpollHandler<T> {
        VhostEpollHandler {
            vhost_dev,
            interrupt_status,
            interrupt_evt,
            queue_evt,
        }
    }

    fn signal_used_queue(&self) -> std::result::Result<(), DeviceErr> {
        self.interrupt_status
            .fetch_or(INTERRUPT_STATUS_USED_RING as usize, Ordering::SeqCst);
        if let Some(e) = self.interrupt_evt.write(1) {
            Err(DeviceErr::FailedSignalingUsedQueue(e))
        } else {
            Ok(())
        }
    }

    pub fn get_queue_evt(&self) -> RawFd {
        return self.queue_evt.as_raw_fd();
    }

    pub fn get_device(&self) -> &T {
        return &self.vhost_dev;
    }
}

impl<T: Vhost> EpollHandler for VhostEpollHandler<T>
where
    T: std::marker::Send,
{
    fn handle_event(
        &mut self,
        device_event: DeviceEventT,
        _: u32,
        _: EpollHandlerPayload,
    ) -> std::result::Result<(), DeviceErr> {
        match device_event {
            VHOST_IRQ_AVAILABLE => {
                if let Err(e) = self.queue_evt.read() {
                    error!("failed reading queue EventFd: {:?}", e);
                    Err(DeviceErr::FailedReadingQueue {
                        event_type: "EventFd",
                        underlying: e,
                    })
                } else {
                    self.signal_used_queue()
                }
            }
            KILL_EVENT => {
                //TODO: call API for device removal here
                info!("vhost device removed");
                Ok(())
            }
            other => Err(DeviceErr::UnknownEvent {
                device: "VhostEpollHandler",
                event: other,
            }),
        }
    }
}

pub struct VhostEpollConfig {
    queue_evt_token: u64,
    kill_token: u64,
    epoll_raw_fd: RawFd,
    sender: mpsc::Sender<Box<EpollHandler>>,
}

impl VhostEpollConfig {
    pub fn new(
        first_token: u64,
        epoll_raw_fd: RawFd,
        sender: mpsc::Sender<Box<EpollHandler>>,
    ) -> Self {
        VhostEpollConfig {
            queue_evt_token: first_token,
            kill_token: first_token + 1,
            epoll_raw_fd,
            sender,
        }
    }
    pub fn get_sender(&self) -> mpsc::Sender<Box<EpollHandler>> {
        self.sender.clone()
    }

    pub fn get_raw_epoll_fd(&self) -> RawFd {
        self.epoll_raw_fd
    }

    pub fn get_kill_token(&self) -> u64 {
        self.kill_token
    }

    pub fn get_queue_evt_token(&self) -> u64 {
        self.queue_evt_token
    }
}
