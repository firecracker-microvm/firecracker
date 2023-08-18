// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Portions Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use logger::error;
use thiserror::Error;
use utils::eventfd::EventFd;
use utils::vm_memory::{
    Address, Error as MmapError, GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion,
};
use vhost::vhost_user::message::*;
use vhost::vhost_user::{Master, VhostUserMaster};
use vhost::{Error as VhostError, VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};

use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::IrqTrigger;

/// vhost-user error.
#[derive(Error, Debug)]
pub enum VhostUserError {
    #[error("Invalid available address")]
    AvailAddress(GuestMemoryError),
    /// Failed to connect to UDS Unix stream.
    #[error("Failed to connect to UDS Unix stream: {0}")]
    Connect(#[from] std::io::Error),
    #[error("Invalid descriptor table address")]
    DescriptorTableAddress(GuestMemoryError),
    #[error("Get features failed: {0}")]
    VhostUserGetFeatures(VhostError),
    #[error("Get protocol features failed: {0}")]
    VhostUserGetProtocolFeatures(VhostError),
    #[error("Set owner failed: {0}")]
    VhostUserSetOwner(VhostError),
    #[error("Set features failed: {0}")]
    VhostUserSetFeatures(VhostError),
    #[error("Set protocol features failed: {0}")]
    VhostUserSetProtocolFeatures(VhostError),
    #[error("Set mem table failed: {0}")]
    VhostUserSetMemTable(VhostError),
    #[error("Set vring num failed: {0}")]
    VhostUserSetVringNum(VhostError),
    #[error("Set vring addr failed: {0}")]
    VhostUserSetVringAddr(VhostError),
    #[error("Set vring base failed: {0}")]
    VhostUserSetVringBase(VhostError),
    #[error("Set vring call failed: {0}")]
    VhostUserSetVringCall(VhostError),
    #[error("Set vring kick failed: {0}")]
    VhostUserSetVringKick(VhostError),
    #[error("Set vring enable failed: {0}")]
    VhostUserSetVringEnable(VhostError),
    #[error("Failed to read vhost eventfd: {0}")]
    VhostUserMemoryRegion(MmapError),
    #[error("Invalid used address")]
    UsedAddress(GuestMemoryError),
}
type Result<T> = std::result::Result<T, VhostUserError>;

/// vhost-user socket handle
#[derive(Clone)]
pub struct VhostUserHandle {
    pub vu: Master,
    pub acked_protocol_features: u64,
    pub socket_path: String,
}

impl std::fmt::Debug for VhostUserHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhostUserHandle")
            .field("acked_protocol_features", &self.acked_protocol_features)
            .field("socket_path", &self.socket_path)
            .finish()
    }
}

impl VhostUserHandle {
    /// Connect to the vhost-user backend socket.
    pub fn connect_vhost_user(socket_path: &str, num_queues: u64) -> Result<Self> {
        let stream = UnixStream::connect(socket_path).map_err(VhostUserError::Connect)?;

        Ok(Self {
            vu: Master::from_stream(stream, num_queues),
            acked_protocol_features: 0u64,
            socket_path: socket_path.to_string(),
        })
    }

    /// Negotiate virtio and protocol features with the backend.
    pub fn negotiate_features_vhost_user(
        &mut self,
        avail_features: u64,
        avail_protocol_features: VhostUserProtocolFeatures,
    ) -> Result<(u64, u64)> {
        // Set vhost-user owner.
        self.vu
            .set_owner()
            .map_err(VhostUserError::VhostUserSetOwner)?;

        // Get features from backend, do negotiation to get a feature collection which
        // both VMM and backend support.
        let backend_features = self
            .vu
            .get_features()
            .map_err(VhostUserError::VhostUserGetFeatures)?;
        let acked_features = avail_features & backend_features;

        let acked_protocol_features =
            if acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
                let backend_protocol_features = self
                    .vu
                    .get_protocol_features()
                    .map_err(VhostUserError::VhostUserGetProtocolFeatures)?;

                let acked_protocol_features = avail_protocol_features & backend_protocol_features;

                self.vu
                    .set_protocol_features(acked_protocol_features)
                    .map_err(VhostUserError::VhostUserSetProtocolFeatures)?;

                acked_protocol_features
            } else {
                VhostUserProtocolFeatures::empty()
            };

        if avail_protocol_features.contains(VhostUserProtocolFeatures::REPLY_ACK)
            && acked_protocol_features.contains(VhostUserProtocolFeatures::REPLY_ACK)
        {
            self.vu.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);
        }

        Ok((acked_features, acked_protocol_features.bits()))
    }

    /// Set vhost-user protocol features to the backend.
    pub fn set_protocol_features_vhost_user(
        &mut self,
        acked_features: u64,
        acked_protocol_features: u64,
    ) -> Result<()> {
        self.vu
            .set_owner()
            .map_err(VhostUserError::VhostUserSetOwner)?;
        self.vu
            .get_features()
            .map_err(VhostUserError::VhostUserGetFeatures)?;

        if acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
            if let Some(acked_protocol_features) =
                VhostUserProtocolFeatures::from_bits(acked_protocol_features)
            {
                self.vu
                    .set_protocol_features(acked_protocol_features)
                    .map_err(VhostUserError::VhostUserSetProtocolFeatures)?;

                if acked_protocol_features.contains(VhostUserProtocolFeatures::REPLY_ACK) {
                    self.vu.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);
                }
            }
        }

        Ok(())
    }

    /// Update guest memory table to the backend.
    fn update_mem_table(&mut self, mem: &GuestMemoryMmap) -> Result<()> {
        let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();

        for region in mem.iter() {
            let (mmap_handle, mmap_offset) = match region.file_offset() {
                Some(_file_offset) => (_file_offset.file().as_raw_fd(), _file_offset.start()),
                None => {
                    return Err(VhostUserError::VhostUserMemoryRegion(
                        MmapError::NoMemoryRegion,
                    ))
                }
            };

            let vhost_user_net_reg = VhostUserMemoryRegionInfo {
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.len(),
                userspace_addr: region.as_ptr() as u64,
                mmap_offset,
                mmap_handle,
            };
            regions.push(vhost_user_net_reg);
        }

        self.vu
            .set_mem_table(regions.as_slice())
            .map_err(VhostUserError::VhostUserSetMemTable)?;

        Ok(())
    }

    /// Set up vhost-user backend. This includes updating memory table,
    /// sending information about virtio rings and enabling them.
    pub fn setup_vhost_user(
        &mut self,
        mem: &GuestMemoryMmap,
        queues: Vec<(usize, &Queue, &EventFd)>,
        irq_trigger: &IrqTrigger,
        acked_features: u64,
    ) -> Result<()> {
        self.vu
            .set_features(acked_features)
            .map_err(VhostUserError::VhostUserSetFeatures)?;

        // Update acked features after they have been sent to the backend.
        // self.acked_features = acked_features;

        // Provide the memory table to the backend.
        self.update_mem_table(mem)?;

        // Send set_vring_num here, since it could tell backends, like SPDK,
        // how many virt queues to be handled, which backend required to know
        // at early stage.
        for (queue_index, queue, _) in queues.iter() {
            self.vu
                .set_vring_num(*queue_index, queue.actual_size())
                .map_err(VhostUserError::VhostUserSetVringNum)?;
        }

        let mut queue_indexes = Vec::new();

        for (queue_index, queue, queue_evt) in queues.iter() {
            let config_data = VringConfigData {
                queue_max_size: queue.get_max_size(),
                queue_size: queue.actual_size(),
                flags: 0u32,
                desc_table_addr: mem
                    .get_host_address(queue.desc_table)
                    .map_err(VhostUserError::DescriptorTableAddress)?
                    as u64,
                used_ring_addr: mem
                    .get_host_address(queue.used_ring)
                    .map_err(VhostUserError::UsedAddress)? as u64,
                avail_ring_addr: mem
                    .get_host_address(queue.avail_ring)
                    .map_err(VhostUserError::AvailAddress)? as u64,
                log_addr: None,
            };

            self.vu
                .set_vring_addr(*queue_index, &config_data)
                .map_err(VhostUserError::VhostUserSetVringAddr)?;
            self.vu
                .set_vring_base(*queue_index, queue.avail_idx(mem).0)
                .map_err(VhostUserError::VhostUserSetVringBase)?;

            // No matter the queue, we set irq_evt for signaling the guest that buffers were
            // consumed.
            self.vu
                .set_vring_call(*queue_index, &irq_trigger.irq_evt)
                .map_err(VhostUserError::VhostUserSetVringCall)?;

            self.vu
                .set_vring_kick(*queue_index, queue_evt)
                .map_err(VhostUserError::VhostUserSetVringKick)?;

            queue_indexes.push(*queue_index);
        }

        self.enable_vhost_user_vrings(queue_indexes.clone(), true)?;

        Ok(())
    }

    /// Enable virtio rings on the backend.
    fn enable_vhost_user_vrings(&mut self, queue_indexes: Vec<usize>, enable: bool) -> Result<()> {
        for queue_index in queue_indexes {
            self.vu
                .set_vring_enable(queue_index, enable)
                .map_err(VhostUserError::VhostUserSetVringEnable)?;
        }

        Ok(())
    }

    /// Return low-level vhost-user frontend handle.
    pub fn socket_handle(&mut self) -> &mut Master {
        &mut self.vu
    }
}
