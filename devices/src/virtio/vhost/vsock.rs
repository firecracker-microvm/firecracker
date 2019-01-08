// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use super::super::{ActivateError, ActivateResult, Queue, VirtioDevice};
use super::handle::*;
use super::*;

use memory_model::GuestMemory;
use sys_util::EventFd;
use vhost_backend::Vhost;
use vhost_backend::Vsock as VhostVsockFd;

use byteorder::{ByteOrder, LittleEndian};
use epoll;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

const QUEUE_SIZE: u16 = 256;
const NUM_QUEUES: usize = 3;
const QUEUE_SIZES: &'static [u16] = &[QUEUE_SIZE; NUM_QUEUES];

impl std::convert::From<super::Error> for ActivateError {
    fn from(error: super::Error) -> Self {
        ActivateError::BadVhostActivate(error)
    }
}

pub struct Vsock {
    vsock_fd: Option<VhostVsockFd>,
    cid: u64,
    avail_features: u64,
    acked_features: u64,
    config_space: Vec<u8>,
    epoll_config: VhostEpollConfig,
    interrupt: Option<EventFd>,
}

impl Vsock {
    /// Create a new virtio-vsock device with the given VM cid.
    pub fn new(cid: u64, mem: &GuestMemory, epoll_config: VhostEpollConfig) -> Result<Vsock> {
        let fd = VhostVsockFd::new(mem).map_err(Error::VhostOpen)?;
        let avail_features = fd.get_features().map_err(Error::VhostGetFeatures)?;

        Ok(Vsock {
            vsock_fd: Some(fd),
            cid,
            avail_features,
            acked_features: 0,
            config_space: Vec::new(),
            epoll_config,
            interrupt: Some(EventFd::new().map_err(Error::VhostIrqCreate)?),
        })
    }
}

impl VirtioDevice for Vsock {
    fn device_type(&self) -> u32 {
        TYPE_VSOCK
    }

    fn queue_max_sizes(&self) -> &[u16] {
        QUEUE_SIZES
    }

    fn features(&self, page: u32) -> u32 {
        match page {
            // Get the lower 32-bits of the features bitfield.
            0 => self.avail_features as u32,
            // Get the upper 32-bits of the features bitfield.
            1 => (self.avail_features >> 32) as u32,
            _ => {
                warn!(
                    "vsock: virtio-vsock got request for features page: {}",
                    page
                );
                0u32
            }
        }
    }

    fn ack_features(&mut self, page: u32, value: u32) {
        let mut v = match page {
            0 => value as u64,
            1 => (value as u64) << 32,
            _ => {
                warn!(
                    "vsock: virtio-vsock device cannot ack unknown feature page: {}",
                    page
                );
                0u64
            }
        };

        // Check if the guest is ACK'ing a feature that we didn't claim to have.
        let unrequested_features = v & !self.avail_features;
        if unrequested_features != 0 {
            warn!("vsock: virtio-vsock got unknown feature ack: {:x}", v);

            // Don't count these features as acked.
            v &= !unrequested_features;
        }
        self.acked_features |= v;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match offset {
            0 if data.len() == 8 => LittleEndian::write_u64(data, self.cid),
            0 if data.len() == 4 => LittleEndian::write_u32(data, (self.cid & 0xffffffff) as u32),
            4 if data.len() == 4 => {
                LittleEndian::write_u32(data, ((self.cid >> 32) & 0xffffffff) as u32)
            }
            _ => warn!(
                "vsock: virtio-vsock received invalid read request of {} bytes at offset {}",
                data.len(),
                offset
            ),
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_len = self.config_space.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        let (_, right) = self.config_space.split_at_mut(offset as usize);
        right.copy_from_slice(&data[..]);
    }

    fn activate(
        &mut self,
        _: GuestMemory,
        interrupt_evt: EventFd,
        interrupt_status: Arc<AtomicUsize>,
        queues: Vec<Queue>,
        queue_evts: Vec<EventFd>,
    ) -> ActivateResult {
        if queues.len() != NUM_QUEUES || queue_evts.len() != NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if let Some(vsock_fd) = self.vsock_fd.take() {
            if let Some(interrupt) = self.interrupt.take() {
                let cid = self.cid;

                // The third vq is an event-only vq that is not handled by the vhost
                // subsystem (but still needs to exist).  Split it off here.
                let vhost_queues = queues[..2].to_vec();

                // Preliminary setup for vhost net.
                vsock_fd.set_owner().map_err(Error::VhostSetOwner)?;

                vsock_fd
                    .set_features(self.acked_features)
                    .map_err(Error::VhostSetFeatures)?;

                vsock_fd.set_mem_table().map_err(Error::VhostSetMemTable)?;

                for (queue_index, ref queue) in vhost_queues.iter().enumerate() {
                    vsock_fd
                        .set_vring_num(queue_index, queue.get_max_size())
                        .map_err(Error::VhostSetVringNum)?;

                    vsock_fd
                        .set_vring_addr(
                            QUEUE_SIZES[queue_index],
                            queue.actual_size(),
                            queue_index,
                            0,
                            queue.desc_table,
                            queue.used_ring,
                            queue.avail_ring,
                            None,
                        )
                        .map_err(Error::VhostSetVringAddr)?;
                    vsock_fd
                        .set_vring_base(queue_index, 0)
                        .map_err(Error::VhostSetVringBase)?;
                    vsock_fd
                        .set_vring_call(queue_index, &interrupt)
                        .map_err(Error::VhostSetVringCall)?;
                    vsock_fd
                        .set_vring_kick(queue_index, &queue_evts[queue_index])
                        .map_err(Error::VhostSetVringKick)?;
                }

                let handler =
                    VhostEpollHandler::new(vsock_fd, interrupt_status, interrupt_evt, interrupt);

                // vsock specific ioctl setup for running device.
                handler
                    .get_device()
                    .set_guest_cid(cid)
                    .map_err(Error::VhostVsockSetCid)?;
                handler
                    .get_device()
                    .start()
                    .map_err(Error::VhostVsockStart)?;

                let queue_evt_raw_fd = handler.get_queue_evt();
                //channel should be open and working
                self.epoll_config
                    .get_sender()
                    .send(Box::new(handler))
                    .unwrap();

                epoll::ctl(
                    self.epoll_config.get_raw_epoll_fd(),
                    epoll::ControlOptions::EPOLL_CTL_ADD,
                    queue_evt_raw_fd,
                    epoll::Event::new(
                        epoll::Events::EPOLLIN,
                        self.epoll_config.get_queue_evt_token(),
                    ),
                )
                .map_err(ActivateError::EpollCtl)?;

                return Ok(());
            }
        }
        Err(ActivateError::BadActivate)
    }
}
