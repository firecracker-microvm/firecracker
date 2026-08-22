// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Portions Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use utils::time::{ClockType, get_time_us};
use vhost::vhost_user::message::*;
use vhost::vhost_user::{Frontend, VhostUserFrontend};
use vhost::{Error as VhostError, VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vm_memory::{Address, GuestMemoryBackend, GuestMemoryError, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState};
use crate::devices::virtio::queue::{Queue, QueueError};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::devices::virtio::vhost_user_metrics::{
    VhostUserDeviceMetrics, VhostUserMetricsPerDevice,
};
use crate::logger::{IncMetric, StoreMetric, debug};
use crate::utils::u64_to_usize;
use crate::vstate::interrupts::InterruptError;
use crate::vstate::memory::GuestMemoryMmap;

/// vhost-user error.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VhostUserError {
    /// Invalid available address
    AvailAddress(GuestMemoryError),
    /// Failed to connect to UDS Unix stream: {0}
    Connect(#[from] std::io::Error),
    /// Invalid descriptor table address
    DescriptorTableAddress(GuestMemoryError),
    /// Get features failed: {0}
    VhostUserGetFeatures(VhostError),
    /// Get protocol features failed: {0}
    VhostUserGetProtocolFeatures(VhostError),
    /// Set owner failed: {0}
    VhostUserSetOwner(VhostError),
    /// Set features failed: {0}
    VhostUserSetFeatures(VhostError),
    /// Set protocol features failed: {0}
    VhostUserSetProtocolFeatures(VhostError),
    /// Set mem table failed: {0}
    VhostUserSetMemTable(VhostError),
    /// Set vring num failed: {0}
    VhostUserSetVringNum(VhostError),
    /// Set vring addr failed: {0}
    VhostUserSetVringAddr(VhostError),
    /// Set vring base failed: {0}
    VhostUserSetVringBase(VhostError),
    /// Set vring call failed: {0}
    VhostUserSetVringCall(VhostError),
    /// Set vring kick failed: {0}
    VhostUserSetVringKick(VhostError),
    /// Set vring enable failed: {0}
    VhostUserSetVringEnable(VhostError),
    /// Failed to read vhost eventfd: No memory region found
    VhostUserNoMemoryRegion,
    /// Invalid used address
    UsedAddress(GuestMemoryError),
}

// Trait with all methods we use from `Frontend` from vhost crate.
// It allows us to create a mock implementation of the `Frontend`
// to verify calls to the backend.
// All methods have default impl in order to simplify mock impls.
pub trait VhostUserHandleBackend: Sized {
    /// Constructor of `Frontend`
    fn from_stream(_sock: UnixStream, _max_queue_num: u64) -> Self {
        unimplemented!()
    }

    fn set_hdr_flags(&self, _flags: VhostUserHeaderFlag) {
        unimplemented!()
    }

    /// Get from the underlying vhost implementation the feature bitmask.
    fn get_features(&self) -> Result<u64, vhost::Error> {
        unimplemented!()
    }

    /// Enable features in the underlying vhost implementation using a bitmask.
    fn set_features(&self, _features: u64) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Set the current Frontend as an owner of the session.
    fn set_owner(&self) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Set the memory map regions on the slave so it can translate the vring
    /// addresses. In the ancillary data there is an array of file descriptors
    fn set_mem_table(&self, _regions: &[VhostUserMemoryRegionInfo]) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Set the size of the queue.
    fn set_vring_num(&self, _queue_index: usize, _num: u16) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Sets the addresses of the different aspects of the vring.
    fn set_vring_addr(
        &self,
        _queue_index: usize,
        _config_data: &VringConfigData,
    ) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Sets the base offset in the available vring.
    fn set_vring_base(&self, _queue_index: usize, _base: u16) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Set the event file descriptor to signal when buffers are used.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// will be used instead of waiting for the call.
    fn set_vring_call(&self, _queue_index: usize, _fd: &EventFd) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    /// Set the event file descriptor for adding buffers to the vring.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// should be used instead of waiting for a kick.
    fn set_vring_kick(&self, _queue_index: usize, _fd: &EventFd) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures, vhost::Error> {
        unimplemented!()
    }

    fn set_protocol_features(
        &mut self,
        _features: VhostUserProtocolFeatures,
    ) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    fn set_vring_enable(&mut self, _queue_index: usize, _enable: bool) -> Result<(), vhost::Error> {
        unimplemented!()
    }

    fn get_config(
        &mut self,
        _offset: u32,
        _size: u32,
        _flags: VhostUserConfigFlags,
        _buf: &[u8],
    ) -> Result<(VhostUserConfig, VhostUserConfigPayload), vhost::Error> {
        unimplemented!()
    }

    fn set_config(
        &mut self,
        _offset: u32,
        _flags: VhostUserConfigFlags,
        _buf: &[u8],
    ) -> Result<(), vhost::Error> {
        unimplemented!()
    }
}

impl VhostUserHandleBackend for Frontend {
    fn from_stream(sock: UnixStream, max_queue_num: u64) -> Self {
        Frontend::from_stream(sock, max_queue_num)
    }

    fn set_hdr_flags(&self, flags: VhostUserHeaderFlag) {
        self.set_hdr_flags(flags)
    }

    /// Get from the underlying vhost implementation the feature bitmask.
    fn get_features(&self) -> Result<u64, vhost::Error> {
        <Frontend as VhostBackend>::get_features(self)
    }

    /// Enable features in the underlying vhost implementation using a bitmask.
    fn set_features(&self, features: u64) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_features(self, features)
    }

    /// Set the current Frontend as an owner of the session.
    fn set_owner(&self) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_owner(self)
    }

    /// Set the memory map regions on the slave so it can translate the vring
    /// addresses. In the ancillary data there is an array of file descriptors
    fn set_mem_table(&self, regions: &[VhostUserMemoryRegionInfo]) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_mem_table(self, regions)
    }

    /// Set the size of the queue.
    fn set_vring_num(&self, queue_index: usize, num: u16) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_vring_num(self, queue_index, num)
    }

    /// Sets the addresses of the different aspects of the vring.
    fn set_vring_addr(
        &self,
        queue_index: usize,
        config_data: &VringConfigData,
    ) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_vring_addr(self, queue_index, config_data)
    }

    /// Sets the base offset in the available vring.
    fn set_vring_base(&self, queue_index: usize, base: u16) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_vring_base(self, queue_index, base)
    }

    /// Set the event file descriptor to signal when buffers are used.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// will be used instead of waiting for the call.
    fn set_vring_call(&self, queue_index: usize, fd: &EventFd) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_vring_call(self, queue_index, fd)
    }

    /// Set the event file descriptor for adding buffers to the vring.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD flag. This flag
    /// is set when there is no file descriptor in the ancillary data. This signals that polling
    /// should be used instead of waiting for a kick.
    fn set_vring_kick(&self, queue_index: usize, fd: &EventFd) -> Result<(), vhost::Error> {
        <Frontend as VhostBackend>::set_vring_kick(self, queue_index, fd)
    }

    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures, vhost::Error> {
        <Frontend as VhostUserFrontend>::get_protocol_features(self)
    }

    fn set_protocol_features(
        &mut self,
        features: VhostUserProtocolFeatures,
    ) -> Result<(), vhost::Error> {
        <Frontend as VhostUserFrontend>::set_protocol_features(self, features)
    }

    fn set_vring_enable(&mut self, queue_index: usize, enable: bool) -> Result<(), vhost::Error> {
        <Frontend as VhostUserFrontend>::set_vring_enable(self, queue_index, enable)
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
        buf: &[u8],
    ) -> Result<(VhostUserConfig, VhostUserConfigPayload), vhost::Error> {
        <Frontend as VhostUserFrontend>::get_config(self, offset, size, flags, buf)
    }

    fn set_config(
        &mut self,
        offset: u32,
        flags: VhostUserConfigFlags,
        buf: &[u8],
    ) -> Result<(), vhost::Error> {
        <Frontend as VhostUserFrontend>::set_config(self, offset, flags, buf)
    }
}

pub type VhostUserHandle = VhostUserHandleImpl<Frontend>;

/// vhost-user socket handle
#[derive(Clone)]
pub struct VhostUserHandleImpl<T: VhostUserHandleBackend> {
    pub vu: T,
    pub socket_path: String,
}

impl<T: VhostUserHandleBackend> std::fmt::Debug for VhostUserHandleImpl<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhostUserHandle")
            .field("socket_path", &self.socket_path)
            .finish()
    }
}

impl<T: VhostUserHandleBackend> VhostUserHandleImpl<T> {
    /// Connect to the vhost-user backend socket and mark self as an
    /// owner of the session.
    pub fn new(socket_path: &str, num_queues: u64) -> Result<Self, VhostUserError> {
        let stream = UnixStream::connect(socket_path).map_err(VhostUserError::Connect)?;

        let vu = T::from_stream(stream, num_queues);
        vu.set_owner().map_err(VhostUserError::VhostUserSetOwner)?;

        Ok(Self {
            vu,
            socket_path: socket_path.to_string(),
        })
    }

    /// Set vhost-user features to the backend.
    pub fn set_features(&self, features: u64) -> Result<(), VhostUserError> {
        self.vu
            .set_features(features)
            .map_err(VhostUserError::VhostUserSetFeatures)
    }

    /// Set vhost-user protocol features to the backend.
    pub fn set_protocol_features(
        &mut self,
        acked_features: u64,
        acked_protocol_features: u64,
    ) -> Result<(), VhostUserError> {
        if acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0
            && let Some(acked_protocol_features) =
                VhostUserProtocolFeatures::from_bits(acked_protocol_features)
        {
            self.vu
                .set_protocol_features(acked_protocol_features)
                .map_err(VhostUserError::VhostUserSetProtocolFeatures)?;

            if acked_protocol_features.contains(VhostUserProtocolFeatures::REPLY_ACK) {
                self.vu.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);
            }
        }

        Ok(())
    }

    /// Negotiate virtio and protocol features with the backend.
    pub fn negotiate_features(
        &mut self,
        avail_features: u64,
        avail_protocol_features: VhostUserProtocolFeatures,
    ) -> Result<(u64, u64), VhostUserError> {
        // Get features from backend, do negotiation to get a feature collection which
        // both VMM and backend support.
        let backend_features = self
            .vu
            .get_features()
            .map_err(VhostUserError::VhostUserGetFeatures)?;
        let acked_features = avail_features & backend_features;

        let acked_protocol_features =
            // If frontend can negotiate protocol features.
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

        if acked_protocol_features.contains(VhostUserProtocolFeatures::REPLY_ACK) {
            self.vu.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);
        }

        Ok((acked_features, acked_protocol_features.bits()))
    }

    /// Update guest memory table to the backend.
    fn update_mem_table(&self, mem: &GuestMemoryMmap) -> Result<(), VhostUserError> {
        let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();

        for region in mem.iter() {
            let (mmap_handle, mmap_offset) = match region.file_offset() {
                Some(_file_offset) => (_file_offset.file().as_raw_fd(), _file_offset.start()),
                None => {
                    return Err(VhostUserError::VhostUserNoMemoryRegion);
                }
            };

            let vhost_user_net_reg = VhostUserMemoryRegionInfo {
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.len(),
                userspace_addr: region.inner.as_ptr() as u64,
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
    pub fn setup_backend(
        &mut self,
        mem: &GuestMemoryMmap,
        queues: &[(usize, &Queue, &EventFd)],
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), VhostUserError> {
        // Provide the memory table to the backend.
        self.update_mem_table(mem)?;

        // Send set_vring_num here, since it could tell backends, like SPDK,
        // how many virt queues to be handled, which backend required to know
        // at early stage.
        for (queue_index, queue, _) in queues.iter() {
            self.vu
                .set_vring_num(*queue_index, queue.size)
                .map_err(VhostUserError::VhostUserSetVringNum)?;
        }

        for (queue_index, queue, queue_evt) in queues.iter() {
            let config_data = VringConfigData {
                queue_max_size: queue.max_size,
                queue_size: queue.size,
                flags: 0u32,
                desc_table_addr: mem
                    .get_host_address(queue.desc_table_address)
                    .map_err(VhostUserError::DescriptorTableAddress)?
                    as u64,
                used_ring_addr: mem
                    .get_host_address(queue.used_ring_address)
                    .map_err(VhostUserError::UsedAddress)? as u64,
                avail_ring_addr: mem
                    .get_host_address(queue.avail_ring_address)
                    .map_err(VhostUserError::AvailAddress)? as u64,
                log_addr: None,
            };

            self.vu
                .set_vring_addr(*queue_index, &config_data)
                .map_err(VhostUserError::VhostUserSetVringAddr)?;
            self.vu
                .set_vring_base(*queue_index, queue.avail_ring_idx_get())
                .map_err(VhostUserError::VhostUserSetVringBase)?;

            // No matter the queue, we set irq_evt for signaling the guest that buffers were
            // consumed.
            self.vu
                .set_vring_call(
                    *queue_index,
                    interrupt
                        .notifier(VirtioInterruptType::Queue(
                            (*queue_index).try_into().unwrap_or_else(|_| {
                                panic!("vhost-user: invalid queue index: {}", *queue_index)
                            }),
                        ))
                        .as_ref()
                        .unwrap(),
                )
                .map_err(VhostUserError::VhostUserSetVringCall)?;

            self.vu
                .set_vring_kick(*queue_index, queue_evt)
                .map_err(VhostUserError::VhostUserSetVringKick)?;

            self.vu
                .set_vring_enable(*queue_index, true)
                .map_err(VhostUserError::VhostUserSetVringEnable)?;
        }

        Ok(())
    }
}

/// Largest number of queues a vhost-user device can be given.
///
/// The binding constraint is the PCI notification region: a dword per queue
/// in a 4KiB capability, so 1024 queues. MSI-X is looser, one vector per
/// queue plus one for configuration out of the 2048 a device may have.
const MAX_QUEUES: u64 = 1024;

/// How a device type configures its vhost-user frontend.
///
/// Everything that varies by virtio device type is supplied here, so that
/// [`VhostUserDevice`] itself stays device-type agnostic.
#[derive(Debug)]
pub struct VhostUserDeviceSpec {
    /// Path of the backend's Unix socket.
    pub socket: String,
    /// Number of virtqueues to allocate.
    pub num_queues: u64,
    /// Size of each virtqueue.
    pub queue_size: u16,
    /// Virtio features to offer the backend, device-specific bits included.
    /// Whatever the backend acks is what the guest driver is then offered.
    pub avail_features: u64,
    /// Size of the config space to fetch from the backend, which has to return
    /// exactly this many bytes. So this is the device type's config space size
    /// and not an upper bound.
    pub config_space_size: u32,
    /// Whether the CONFIG protocol feature is mandatory. Frontends with no
    /// device-specific fallback for the config space require it.
    pub require_config: bool,
    /// Name to report this device's metrics under.
    pub metrics_name: String,
}

/// Error building a vhost-user frontend.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VhostUserDeviceError {
    /// A vhost-user device needs at least one queue, got {0}
    InvalidNumQueues(u64),
    /// Config space size must be between 1 and 4096 bytes, got {0}
    InvalidConfigSpaceSize(u32),
    /// A vhost-user device supports at most {1} queues, got {0}
    TooManyQueues(u64, u64),
    /// Queue size must be a power of two, got {0}
    InvalidQueueSize(u16),
    /// Backend returned {0} bytes of config space, expected {1}
    ShortConfigSpace(usize, u32),
    /// Backend did not negotiate the mandatory CONFIG protocol feature
    ConfigFeatureNotNegotiated,
    /// Vhost-user: {0}
    VhostUser(VhostUserError),
    /// Failed to get config space from the backend: {0}
    GetConfig(VhostError),
    /// Failed to create eventfd: {0}
    EventFd(std::io::Error),
    /// Failed to signal the guest driver: {0}
    Interrupt(InterruptError),
}

/// Device-type agnostic vhost-user frontend.
///
/// Owns the parts of a vhost-user frontend that do not depend on which virtio
/// device type is being implemented: the backend handle, the negotiated
/// features and config space, and the virtqueues. Device types embed this and
/// add their own state alongside it.
pub struct VhostUserDevice<T: VhostUserHandleBackend> {
    pub avail_features: u64,
    pub acked_features: u64,
    /// Config space fetched from the backend, empty if CONFIG was not acked.
    pub config_space: Vec<u8>,
    config_space_size: u32,
    pub activate_evt: EventFd,
    pub queues: Vec<Queue>,
    pub queue_evts: Vec<EventFd>,
    pub device_state: DeviceState,
    pub vu_handle: VhostUserHandleImpl<T>,
    pub vu_acked_protocol_features: u64,
    pub metrics: Arc<VhostUserDeviceMetrics>,
}

// Custom because `Debug` is not derivable through `vhost`'s `Frontend`.
impl<T: VhostUserHandleBackend> std::fmt::Debug for VhostUserDevice<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhostUserDevice")
            .field("avail_features", &self.avail_features)
            .field("acked_features", &self.acked_features)
            .field("config_space", &self.config_space)
            .field("config_space_size", &self.config_space_size)
            .field("activate_evt", &self.activate_evt)
            .field("queues", &self.queues)
            .field("queue_evts", &self.queue_evts)
            .field("device_state", &self.device_state)
            .field("vu_handle", &self.vu_handle)
            .field(
                "vu_acked_protocol_features",
                &self.vu_acked_protocol_features,
            )
            .field("metrics", &self.metrics)
            .finish()
    }
}

impl<T: VhostUserHandleBackend> VhostUserDevice<T> {
    /// Connect to the backend, negotiate features, fetch the config space and
    /// allocate the queues.
    pub fn new(spec: VhostUserDeviceSpec) -> Result<Self, VhostUserDeviceError> {
        // Device-specific minimums (virtio-fs wants a hiprio queue plus at
        // least one request queue, say) are the caller's business.
        if spec.num_queues == 0 {
            return Err(VhostUserDeviceError::InvalidNumQueues(spec.num_queues));
        }

        // One MSI-X vector per queue plus one for configuration, and the PCI
        // transport allows 2048 vectors per device. Rejecting this here turns
        // what would otherwise be an eventfd per queue followed by a failed
        // u16 conversion during activation into an error the caller sees.
        if spec.num_queues > MAX_QUEUES {
            return Err(VhostUserDeviceError::TooManyQueues(
                spec.num_queues,
                MAX_QUEUES,
            ));
        }

        // Virtio requires a power of two. Nothing else checks the size a
        // device is built with, only the smaller size a driver later selects,
        // so an unusable queue would otherwise surface as a guest that
        // silently refuses to probe the device.
        if !spec.queue_size.is_power_of_two() {
            return Err(VhostUserDeviceError::InvalidQueueSize(spec.queue_size));
        }

        // Both ends are rejected by the vhost crate, the lower one only once a
        // backend acks CONFIG. Checking here keeps that from depending on which
        // backend we are talking to, and avoids allocating the buffer first.
        if spec.config_space_size == 0 || spec.config_space_size > VHOST_USER_CONFIG_SIZE {
            return Err(VhostUserDeviceError::InvalidConfigSpaceSize(
                spec.config_space_size,
            ));
        }

        let start_time = get_time_us(ClockType::Monotonic);

        let mut vu_handle = VhostUserHandleImpl::<T>::new(&spec.socket, spec.num_queues)
            .map_err(VhostUserDeviceError::VhostUser)?;
        let (acked_features, vu_acked_protocol_features) = vu_handle
            .negotiate_features(spec.avail_features, VhostUserProtocolFeatures::CONFIG)
            .map_err(VhostUserDeviceError::VhostUser)?;

        let config_acked =
            vu_acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() != 0;
        if spec.require_config && !config_acked {
            return Err(VhostUserDeviceError::ConfigFeatureNotNegotiated);
        }

        let config_space = if config_acked {
            get_config_space(&mut vu_handle, spec.config_space_size)?
        } else {
            vec![]
        };

        let activate_evt =
            EventFd::new(libc::EFD_NONBLOCK).map_err(VhostUserDeviceError::EventFd)?;

        let num_queues = u64_to_usize(spec.num_queues);
        let queues = vec![Queue::new(spec.queue_size); num_queues];
        let queue_evts = (0..num_queues)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK).map_err(VhostUserDeviceError::EventFd))
            .collect::<Result<Vec<_>, _>>()?;

        // What the backend acked is what the guest driver may choose from.
        let avail_features = acked_features;
        let acked_features = acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let metrics = VhostUserMetricsPerDevice::alloc(spec.metrics_name);
        metrics
            .init_time_us
            .store(get_time_us(ClockType::Monotonic) - start_time);

        Ok(Self {
            avail_features,
            acked_features,
            config_space,
            config_space_size: spec.config_space_size,
            activate_evt,
            queues,
            queue_evts,
            device_state: DeviceState::Inactive,
            vu_handle,
            vu_acked_protocol_features,
            metrics,
        })
    }

    /// Set up the backend's vrings for the queues the guest marked ready.
    pub fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        assert!(!self.is_activated());

        // A driver only initialises the queues it intends to use, and how many
        // that is comes from the backend-owned config space rather than from
        // the configured queue count (virtio-fs scales its request queues to
        // the vCPU count, for example). Initializing a queue the guest never
        // configured returns NotReady and aborts activation, so only the ready
        // ones are set up here. Real vring indices are preserved, so queues 0
        // and 2 being ready maps to vrings 0 and 2 rather than 0 and 1.
        let ready: Vec<usize> = self
            .queues
            .iter()
            .enumerate()
            .filter(|(_, queue)| queue.ready)
            .map(|(i, _)| i)
            .collect();

        // Activating with nothing ready would otherwise set up no vrings at
        // all and report success.
        if ready.is_empty() {
            return Err(ActivateError::QueueMemoryError(QueueError::NotReady));
        }

        if ready.len() < self.queues.len() {
            // The queue count a driver uses comes from the backend-owned config
            // space, so being given more than it wants is normal rather than a
            // problem worth warning about.
            debug!(
                "vhost-user: setting up {} of {} configured vrings, the guest driver did not \
                 ready the rest",
                ready.len(),
                self.queues.len()
            );
        }

        for &i in &ready {
            self.queues[i]
                .initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

        let start_time = get_time_us(ClockType::Monotonic);
        let queue_refs: Vec<(usize, &Queue, &EventFd)> = ready
            .iter()
            .map(|&i| (i, &self.queues[i], &self.queue_evts[i]))
            .collect();

        // Set the features again, now they are negotiated with the guest
        // driver as well.
        self.vu_handle
            .set_features(self.acked_features)
            .and_then(|()| {
                self.vu_handle
                    .setup_backend(&mem, &queue_refs, interrupt.clone())
            })
            .map_err(|err| {
                self.metrics.activate_fails.inc();
                ActivateError::VhostUser(err)
            })?;

        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        self.metrics
            .activate_time_us
            .store(get_time_us(ClockType::Monotonic) - start_time);
        Ok(())
    }

    pub fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    pub fn socket_path(&self) -> &str {
        &self.vu_handle.socket_path
    }

    pub fn deactivate(&mut self) {
        self.device_state = DeviceState::Inactive;
    }

    /// Interrupt of the activated device.
    ///
    /// # Panics
    ///
    /// Panics if the device is not activated.
    pub fn interrupt(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .deref()
    }

    /// Re-read the config space from the backend and tell the guest driver it
    /// changed.
    ///
    /// # Panics
    ///
    /// Panics if the device is not activated.
    pub fn refresh_config(&mut self) -> Result<(), VhostUserDeviceError> {
        let start_time = get_time_us(ClockType::Monotonic);
        let interrupt = self
            .device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .clone();

        self.config_space = get_config_space(&mut self.vu_handle, self.config_space_size)?;

        interrupt
            .trigger(VirtioInterruptType::Config)
            .map_err(VhostUserDeviceError::Interrupt)?;

        self.metrics
            .config_change_time_us
            .store(get_time_us(ClockType::Monotonic) - start_time);

        Ok(())
    }
}

fn get_config_space<T: VhostUserHandleBackend>(
    vu_handle: &mut VhostUserHandleImpl<T>,
    size: u32,
) -> Result<Vec<u8>, VhostUserDeviceError> {
    let buffer = vec![0u8; u64_to_usize(u64::from(size))];
    let (_, config_space) = vu_handle
        .vu
        .get_config(0, size, VhostUserConfigFlags::WRITABLE, &buffer)
        .map_err(VhostUserDeviceError::GetConfig)?;

    // The vhost crate checks the size the reply declares, but not the length of
    // the payload that follows it, so a backend can declare the size we asked
    // for and send fewer bytes. Short of this check the guest would read
    // whatever the config space was not long enough to cover.
    if config_space.len() != u64_to_usize(u64::from(size)) {
        return Err(VhostUserDeviceError::ShortConfigSpace(
            config_space.len(),
            size,
        ));
    }

    Ok(config_space)
}
#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::fs::File;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::test_utils::default_interrupt;
    use crate::test_utils::create_tmp_socket;
    use crate::vstate::memory;
    use crate::vstate::memory::{GuestAddress, GuestRegionMmapExt};

    /// Backend that records the vring index of every per-vring call, so a test
    /// can tell an index-preserving setup from an index-compacting one.
    #[derive(Default)]
    pub(crate) struct VringCalls {
        pub num: Vec<usize>,
        pub addr: Vec<usize>,
        pub base: Vec<usize>,
        pub call: Vec<usize>,
        pub kick: Vec<usize>,
        pub enable: Vec<usize>,
    }

    pub(crate) struct MockRecorder {
        pub calls: std::cell::UnsafeCell<VringCalls>,
    }

    impl VhostUserHandleBackend for MockRecorder {
        fn from_stream(_sock: UnixStream, _max_queue_num: u64) -> Self {
            Self {
                calls: std::cell::UnsafeCell::new(VringCalls::default()),
            }
        }

        fn set_owner(&self) -> Result<(), vhost::Error> {
            Ok(())
        }

        fn set_hdr_flags(&self, _flags: VhostUserHeaderFlag) {}

        fn get_features(&self) -> Result<u64, vhost::Error> {
            Ok(0)
        }

        fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures, vhost::Error> {
            Ok(VhostUserProtocolFeatures::empty())
        }

        fn set_protocol_features(
            &mut self,
            _features: VhostUserProtocolFeatures,
        ) -> Result<(), vhost::Error> {
            Ok(())
        }

        fn set_features(&self, _features: u64) -> Result<(), vhost::Error> {
            Ok(())
        }

        fn set_mem_table(
            &self,
            _regions: &[VhostUserMemoryRegionInfo],
        ) -> Result<(), vhost::Error> {
            Ok(())
        }

        fn set_vring_num(&self, queue_index: usize, _num: u16) -> Result<(), vhost::Error> {
            unsafe { (*self.calls.get()).num.push(queue_index) };
            Ok(())
        }

        fn set_vring_addr(
            &self,
            queue_index: usize,
            _config_data: &VringConfigData,
        ) -> Result<(), vhost::Error> {
            unsafe { (*self.calls.get()).addr.push(queue_index) };
            Ok(())
        }

        fn set_vring_base(&self, queue_index: usize, _base: u16) -> Result<(), vhost::Error> {
            unsafe { (*self.calls.get()).base.push(queue_index) };
            Ok(())
        }

        fn set_vring_call(&self, queue_index: usize, _fd: &EventFd) -> Result<(), vhost::Error> {
            unsafe { (*self.calls.get()).call.push(queue_index) };
            Ok(())
        }

        fn set_vring_kick(&self, queue_index: usize, _fd: &EventFd) -> Result<(), vhost::Error> {
            unsafe { (*self.calls.get()).kick.push(queue_index) };
            Ok(())
        }

        fn set_vring_enable(
            &mut self,
            queue_index: usize,
            _enable: bool,
        ) -> Result<(), vhost::Error> {
            unsafe { (*self.calls.get()).enable.push(queue_index) };
            Ok(())
        }
    }

    fn recording_device(socket: String, num_queues: u64) -> VhostUserDevice<MockRecorder> {
        VhostUserDevice::<MockRecorder>::new(VhostUserDeviceSpec {
            socket,
            num_queues,
            queue_size: 128,
            avail_features: 0,
            config_space_size: 8,
            require_config: false,
            metrics_name: format!("test_generic_{num_queues}"),
        })
        .unwrap()
    }

    fn ready_queue(device: &mut VhostUserDevice<MockRecorder>, index: usize) {
        device.queues[index].ready = true;
        device.queues[index].size = device.queues[index].max_size;
    }

    fn test_mem() -> GuestMemoryMmap {
        let region_size = 0x10000;
        let file = TempFile::new().unwrap().into_file();
        file.set_len(region_size as u64).unwrap();
        create_mem(file, &[(GuestAddress(0x0), region_size)])
    }

    #[test]
    fn test_activate_preserves_vring_indices() {
        let (_tmp_dir, tmp_socket_path) = create_tmp_socket();
        let mut device = recording_device(tmp_socket_path, 3);

        // The guest readies vrings 0 and 2 and leaves 1 alone, which is what a
        // driver using fewer queues than were configured looks like.
        ready_queue(&mut device, 0);
        ready_queue(&mut device, 2);

        device.activate(test_mem(), default_interrupt()).unwrap();

        // Vring 2 has to be set up as vring 2, not renumbered to 1.
        let calls = unsafe { &*device.vu_handle.vu.calls.get() };
        assert_eq!(calls.num, vec![0, 2]);
        assert_eq!(calls.addr, vec![0, 2]);
        assert_eq!(calls.base, vec![0, 2]);
        assert_eq!(calls.call, vec![0, 2]);
        assert_eq!(calls.kick, vec![0, 2]);
        assert_eq!(calls.enable, vec![0, 2]);
    }

    #[test]
    fn test_activate_without_ready_queues() {
        let (_tmp_dir, tmp_socket_path) = create_tmp_socket();
        let mut device = recording_device(tmp_socket_path, 2);

        // Nothing ready has to fail rather than set up no vrings and report
        // success.
        assert!(matches!(
            device.activate(test_mem(), default_interrupt()),
            Err(ActivateError::QueueMemoryError(QueueError::NotReady))
        ));
        assert!(!device.is_activated());

        let calls = unsafe { &*device.vu_handle.vu.calls.get() };
        assert!(calls.num.is_empty());
    }

    #[test]
    fn test_new_rejects_invalid_spec() {
        let spec = |num_queues, config_space_size| VhostUserDeviceSpec {
            socket: "no-such-socket".to_string(),
            num_queues,
            queue_size: 128,
            avail_features: 0,
            config_space_size,
            require_config: false,
            metrics_name: "test_invalid_spec".to_string(),
        };

        // All three are rejected before the socket is touched, so the bogus
        // path above never gets in the way.
        assert!(matches!(
            VhostUserDevice::<MockRecorder>::new(spec(0, 8)),
            Err(VhostUserDeviceError::InvalidNumQueues(0))
        ));
        assert!(matches!(
            VhostUserDevice::<MockRecorder>::new(spec(1, 0)),
            Err(VhostUserDeviceError::InvalidConfigSpaceSize(0))
        ));
        assert!(matches!(
            VhostUserDevice::<MockRecorder>::new(spec(1, VHOST_USER_CONFIG_SIZE + 1)),
            Err(VhostUserDeviceError::InvalidConfigSpaceSize(_))
        ));
        assert!(matches!(
            VhostUserDevice::<MockRecorder>::new(spec(MAX_QUEUES + 1, 8)),
            Err(VhostUserDeviceError::TooManyQueues(_, MAX_QUEUES))
        ));

        let odd_queue_size = VhostUserDeviceSpec {
            queue_size: 100,
            ..spec(1, 8)
        };
        assert!(matches!(
            VhostUserDevice::<MockRecorder>::new(odd_queue_size),
            Err(VhostUserDeviceError::InvalidQueueSize(100))
        ));
    }

    #[test]
    fn test_new_rejects_short_config_space() {
        /// Backend that acks CONFIG and then under-fills the config space.
        struct MockShortConfig;

        impl VhostUserHandleBackend for MockShortConfig {
            fn from_stream(_sock: UnixStream, _max_queue_num: u64) -> Self {
                Self
            }

            fn set_owner(&self) -> Result<(), vhost::Error> {
                Ok(())
            }

            fn set_hdr_flags(&self, _flags: VhostUserHeaderFlag) {}

            fn get_features(&self) -> Result<u64, vhost::Error> {
                Ok(VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits())
            }

            fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures, vhost::Error> {
                Ok(VhostUserProtocolFeatures::CONFIG)
            }

            fn set_protocol_features(
                &mut self,
                _features: VhostUserProtocolFeatures,
            ) -> Result<(), vhost::Error> {
                Ok(())
            }

            fn get_config(
                &mut self,
                _offset: u32,
                _size: u32,
                _flags: VhostUserConfigFlags,
                _buf: &[u8],
            ) -> Result<(VhostUserConfig, VhostUserConfigPayload), vhost::Error> {
                // Asked for 8 bytes, answers with 3.
                Ok((VhostUserConfig::default(), vec![0x69, 0x69, 0x69]))
            }
        }

        let (_tmp_dir, tmp_socket_path) = create_tmp_socket();
        let result = VhostUserDevice::<MockShortConfig>::new(VhostUserDeviceSpec {
            socket: tmp_socket_path,
            num_queues: 1,
            queue_size: 128,
            avail_features: VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits(),
            config_space_size: 8,
            require_config: true,
            metrics_name: "test_short_config".to_string(),
        });

        // A guest reading the bytes the backend did not send would otherwise be
        // reading whatever the config space was too short to cover.
        assert!(matches!(
            result,
            Err(VhostUserDeviceError::ShortConfigSpace(3, 8))
        ));
    }

    pub(crate) fn create_mem(file: File, regions: &[(GuestAddress, usize)]) -> GuestMemoryMmap {
        GuestMemoryMmap::from_regions(
            memory::create(
                regions.iter().copied(),
                libc::MAP_PRIVATE,
                Some(file),
                false,
                libc::MADV_NORMAL,
            )
            .unwrap()
            .into_iter()
            .map(|region| GuestRegionMmapExt::dram_from_mmap_region(region, 0))
            .collect(),
        )
        .unwrap()
    }

    #[test]
    fn test_new() {
        struct MockFrontend {
            sock: UnixStream,
            max_queue_num: u64,
            is_owner: std::cell::UnsafeCell<bool>,
        }

        impl VhostUserHandleBackend for MockFrontend {
            fn from_stream(sock: UnixStream, max_queue_num: u64) -> Self {
                Self {
                    sock,
                    max_queue_num,
                    is_owner: std::cell::UnsafeCell::new(false),
                }
            }

            fn set_owner(&self) -> Result<(), vhost::Error> {
                unsafe { *self.is_owner.get() = true };
                Ok(())
            }
        }

        let max_queue_num = 69;

        let (_tmp_dir, tmp_socket_path) = create_tmp_socket();

        // Creation of the VhostUserHandleImpl correctly connects to the socket, sets the maximum
        // number of queues and sets itself as an owner of the session.
        let vuh =
            VhostUserHandleImpl::<MockFrontend>::new(&tmp_socket_path, max_queue_num).unwrap();
        assert_eq!(
            vuh.vu
                .sock
                .peer_addr()
                .unwrap()
                .as_pathname()
                .unwrap()
                .to_str()
                .unwrap(),
            &tmp_socket_path,
        );
        assert_eq!(vuh.vu.max_queue_num, max_queue_num);
        assert!(unsafe { *vuh.vu.is_owner.get() });
    }

    #[test]
    fn test_set_features() {
        struct MockFrontend {
            features: std::cell::UnsafeCell<u64>,
        }

        impl VhostUserHandleBackend for MockFrontend {
            fn set_features(&self, features: u64) -> Result<(), vhost::Error> {
                unsafe { *self.features.get() = features };
                Ok(())
            }
        }

        // VhostUserHandleImpl can correctly set backend features.
        let vuh = VhostUserHandleImpl {
            vu: MockFrontend { features: 0.into() },
            socket_path: "".to_string(),
        };
        vuh.set_features(0x69).unwrap();
        assert_eq!(unsafe { *vuh.vu.features.get() }, 0x69);
    }

    #[test]
    fn test_set_protocol_features() {
        struct MockFrontend {
            protocol_features: VhostUserProtocolFeatures,
            hdr_flags: std::cell::UnsafeCell<VhostUserHeaderFlag>,
        }

        impl VhostUserHandleBackend for MockFrontend {
            fn set_hdr_flags(&self, flags: VhostUserHeaderFlag) {
                unsafe { *self.hdr_flags.get() = flags };
            }

            fn set_protocol_features(
                &mut self,
                features: VhostUserProtocolFeatures,
            ) -> Result<(), vhost::Error> {
                self.protocol_features = features;
                Ok(())
            }
        }

        let mut vuh = VhostUserHandleImpl {
            vu: MockFrontend {
                protocol_features: VhostUserProtocolFeatures::empty(),
                hdr_flags: std::cell::UnsafeCell::new(VhostUserHeaderFlag::empty()),
            },
            socket_path: "".to_string(),
        };

        // No protocol features are set if acked_features do not have PROTOCOL_FEATURES bit
        let acked_features = 0;
        let acked_protocol_features = VhostUserProtocolFeatures::empty();
        vuh.set_protocol_features(acked_features, acked_protocol_features.bits())
            .unwrap();
        assert_eq!(vuh.vu.protocol_features, VhostUserProtocolFeatures::empty());
        assert_eq!(
            unsafe { &*vuh.vu.hdr_flags.get() }.bits(),
            VhostUserHeaderFlag::empty().bits()
        );

        // No protocol features are set if acked_features do not have PROTOCOL_FEATURES bit
        let acked_features = 0;
        let acked_protocol_features = VhostUserProtocolFeatures::all();
        vuh.set_protocol_features(acked_features, acked_protocol_features.bits())
            .unwrap();
        assert_eq!(vuh.vu.protocol_features, VhostUserProtocolFeatures::empty());
        assert_eq!(
            unsafe { &*vuh.vu.hdr_flags.get() }.bits(),
            VhostUserHeaderFlag::empty().bits()
        );

        // If not REPLY_ACK present, no header is set
        let acked_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let mut acked_protocol_features = VhostUserProtocolFeatures::all();
        acked_protocol_features.set(VhostUserProtocolFeatures::REPLY_ACK, false);
        vuh.set_protocol_features(acked_features, acked_protocol_features.bits())
            .unwrap();
        assert_eq!(vuh.vu.protocol_features, acked_protocol_features);
        assert_eq!(
            unsafe { &*vuh.vu.hdr_flags.get() }.bits(),
            VhostUserHeaderFlag::empty().bits()
        );

        // If REPLY_ACK present, header is set
        let acked_features = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let acked_protocol_features = VhostUserProtocolFeatures::all();
        vuh.set_protocol_features(acked_features, acked_protocol_features.bits())
            .unwrap();
        assert_eq!(vuh.vu.protocol_features, acked_protocol_features);
        assert_eq!(
            unsafe { &*vuh.vu.hdr_flags.get() }.bits(),
            VhostUserHeaderFlag::NEED_REPLY.bits()
        );
    }

    #[test]
    fn test_negotiate_features() {
        struct MockFrontend {
            features: u64,
            protocol_features: VhostUserProtocolFeatures,
            hdr_flags: std::cell::UnsafeCell<VhostUserHeaderFlag>,
        }

        impl VhostUserHandleBackend for MockFrontend {
            fn set_hdr_flags(&self, flags: VhostUserHeaderFlag) {
                unsafe { *self.hdr_flags.get() = flags };
            }

            fn get_features(&self) -> Result<u64, vhost::Error> {
                Ok(self.features)
            }

            fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures, vhost::Error> {
                Ok(self.protocol_features)
            }

            fn set_protocol_features(
                &mut self,
                features: VhostUserProtocolFeatures,
            ) -> Result<(), vhost::Error> {
                self.protocol_features = features;
                Ok(())
            }
        }

        let mut vuh = VhostUserHandleImpl {
            vu: MockFrontend {
                features: 0,
                protocol_features: VhostUserProtocolFeatures::empty(),
                hdr_flags: std::cell::UnsafeCell::new(VhostUserHeaderFlag::empty()),
            },
            socket_path: "".to_string(),
        };

        // If nothing is available, nothing is negotiated
        let avail_features = 0;
        let avail_protocol_features = VhostUserProtocolFeatures::empty();
        let (acked_features, acked_protocol_features) = vuh
            .negotiate_features(avail_features, avail_protocol_features)
            .unwrap();
        assert_eq!(acked_features, avail_features);
        assert_eq!(acked_protocol_features, avail_protocol_features.bits());
        assert_eq!(vuh.vu.protocol_features, VhostUserProtocolFeatures::empty());
        assert_eq!(
            unsafe { &*vuh.vu.hdr_flags.get() }.bits(),
            VhostUserHeaderFlag::empty().bits()
        );

        // If neither frontend avail_features nor backend avail_features contain PROTOCOL_FEATURES
        // bit, only features are negotiated
        let mut avail_features = VhostUserVirtioFeatures::all();
        avail_features.set(VhostUserVirtioFeatures::PROTOCOL_FEATURES, false);

        // Pretend backend has same features as frontend
        vuh.vu.features = avail_features.bits();

        let avail_protocol_features = VhostUserProtocolFeatures::empty();
        let (acked_features, acked_protocol_features) = vuh
            .negotiate_features(avail_features.bits(), avail_protocol_features)
            .unwrap();
        assert_eq!(acked_features, avail_features.bits());
        assert_eq!(acked_protocol_features, avail_protocol_features.bits());
        assert_eq!(vuh.vu.protocol_features, VhostUserProtocolFeatures::empty());
        assert_eq!(
            unsafe { &*vuh.vu.hdr_flags.get() }.bits(),
            VhostUserHeaderFlag::empty().bits()
        );

        // If PROTOCOL_FEATURES is negotiated, but REPLY_ACK is not, headers are not set
        let avail_features = VhostUserVirtioFeatures::all();
        // Pretend backend has same features as frontend
        vuh.vu.features = avail_features.bits();

        let mut avail_protocol_features = VhostUserProtocolFeatures::empty();
        avail_protocol_features.set(VhostUserProtocolFeatures::CONFIG, true);

        let mut backend_protocol_features = VhostUserProtocolFeatures::empty();
        backend_protocol_features.set(VhostUserProtocolFeatures::CONFIG, true);
        backend_protocol_features.set(VhostUserProtocolFeatures::PAGEFAULT, true);
        vuh.vu.protocol_features = backend_protocol_features;

        let (acked_features, acked_protocol_features) = vuh
            .negotiate_features(avail_features.bits(), avail_protocol_features)
            .unwrap();
        assert_eq!(acked_features, avail_features.bits());
        assert_eq!(acked_protocol_features, avail_protocol_features.bits());
        assert_eq!(vuh.vu.protocol_features, avail_protocol_features);
        assert_eq!(
            unsafe { &*vuh.vu.hdr_flags.get() }.bits(),
            VhostUserHeaderFlag::empty().bits()
        );

        // If PROTOCOL_FEATURES and REPLY_ACK are negotiated
        let avail_features = VhostUserVirtioFeatures::all();
        // Pretend backend has same features as frontend
        vuh.vu.features = avail_features.bits();

        let mut avail_protocol_features = VhostUserProtocolFeatures::empty();
        avail_protocol_features.set(VhostUserProtocolFeatures::REPLY_ACK, true);

        // Pretend backend has same features as frontend
        vuh.vu.protocol_features = avail_protocol_features;

        let (acked_features, acked_protocol_features) = vuh
            .negotiate_features(avail_features.bits(), avail_protocol_features)
            .unwrap();
        assert_eq!(acked_features, avail_features.bits());
        assert_eq!(acked_protocol_features, avail_protocol_features.bits());
        assert_eq!(vuh.vu.protocol_features, avail_protocol_features);
        assert_eq!(
            unsafe { &*vuh.vu.hdr_flags.get() }.bits(),
            VhostUserHeaderFlag::NEED_REPLY.bits(),
        );
    }

    #[test]
    fn test_update_mem_table() {
        struct MockFrontend {
            regions: std::cell::UnsafeCell<Vec<VhostUserMemoryRegionInfo>>,
        }

        impl VhostUserHandleBackend for MockFrontend {
            fn set_mem_table(
                &self,
                regions: &[VhostUserMemoryRegionInfo],
            ) -> Result<(), vhost::Error> {
                unsafe { (*self.regions.get()).extend_from_slice(regions) }
                Ok(())
            }
        }

        let vuh = VhostUserHandleImpl {
            vu: MockFrontend {
                regions: std::cell::UnsafeCell::new(vec![]),
            },
            socket_path: "".to_string(),
        };

        let region_size = 0x10000;
        let file = TempFile::new().unwrap().into_file();
        let file_size = 2 * region_size;
        file.set_len(file_size as u64).unwrap();
        let regions = vec![
            (GuestAddress(0x0), region_size),
            (GuestAddress(0x10000), region_size),
        ];

        let guest_memory = create_mem(file, &regions);

        vuh.update_mem_table(&guest_memory).unwrap();

        // VhostUserMemoryRegionInfo should be correctly set by the VhostUserHandleImpl
        let expected_regions = guest_memory
            .iter()
            .map(|region| VhostUserMemoryRegionInfo {
                guest_phys_addr: region.start_addr().raw_value(),
                memory_size: region.len(),
                userspace_addr: region.inner.as_ptr() as u64,
                mmap_offset: region.file_offset().unwrap().start(),
                mmap_handle: region.file_offset().unwrap().file().as_raw_fd(),
            })
            .collect::<Vec<_>>();

        for (region, expected) in (unsafe { &*vuh.vu.regions.get() })
            .iter()
            .zip(expected_regions)
        {
            // VhostUserMemoryRegionInfo does not implement Eq.
            assert_eq!(region.guest_phys_addr, expected.guest_phys_addr);
            assert_eq!(region.memory_size, expected.memory_size);
            assert_eq!(region.userspace_addr, expected.userspace_addr);
            assert_eq!(region.mmap_offset, expected.mmap_offset);
            assert_eq!(region.mmap_handle, expected.mmap_handle);
        }
    }

    #[test]
    fn test_setup_backend() {
        #[derive(Default)]
        struct VringData {
            index: usize,
            size: u16,
            config: VringConfigData,
            base: u16,
            call: i32,
            kick: i32,
            enable: bool,
        }

        struct MockFrontend {
            vrings: std::cell::UnsafeCell<Vec<VringData>>,
        }

        impl VhostUserHandleBackend for MockFrontend {
            fn set_mem_table(
                &self,
                _regions: &[VhostUserMemoryRegionInfo],
            ) -> Result<(), vhost::Error> {
                Ok(())
            }

            fn set_vring_num(&self, queue_index: usize, num: u16) -> Result<(), vhost::Error> {
                unsafe {
                    (*self.vrings.get()).push(VringData {
                        index: queue_index,
                        size: num,
                        ..Default::default()
                    })
                };
                Ok(())
            }

            fn set_vring_addr(
                &self,
                queue_index: usize,
                config_data: &VringConfigData,
            ) -> Result<(), vhost::Error> {
                unsafe { (&mut (*self.vrings.get()))[queue_index].config = *config_data };
                Ok(())
            }

            fn set_vring_base(&self, queue_index: usize, base: u16) -> Result<(), vhost::Error> {
                unsafe { (&mut (*self.vrings.get()))[queue_index].base = base };
                Ok(())
            }

            fn set_vring_call(&self, queue_index: usize, fd: &EventFd) -> Result<(), vhost::Error> {
                unsafe { (&mut (*self.vrings.get()))[queue_index].call = fd.as_raw_fd() };
                Ok(())
            }

            fn set_vring_kick(&self, queue_index: usize, fd: &EventFd) -> Result<(), vhost::Error> {
                unsafe { (&mut (*self.vrings.get()))[queue_index].kick = fd.as_raw_fd() };
                Ok(())
            }

            fn set_vring_enable(
                &mut self,
                queue_index: usize,
                enable: bool,
            ) -> Result<(), vhost::Error> {
                unsafe { &mut *self.vrings.get() }
                    .get_mut(queue_index)
                    .unwrap()
                    .enable = enable;
                Ok(())
            }
        }

        let mut vuh = VhostUserHandleImpl {
            vu: MockFrontend {
                vrings: std::cell::UnsafeCell::new(vec![]),
            },
            socket_path: "".to_string(),
        };

        let region_size = 0x10000;
        let file = TempFile::new().unwrap().into_file();
        file.set_len(region_size as u64).unwrap();
        let regions = vec![(GuestAddress(0x0), region_size)];

        let guest_memory = create_mem(file, &regions);

        let mut queue = Queue::new(128);
        queue.ready = true;
        queue.size = queue.max_size;
        queue.initialize(&guest_memory).unwrap();

        let event_fd = EventFd::new(0).unwrap();

        let queues = [(0, &queue, &event_fd)];

        let interrupt = default_interrupt();
        vuh.setup_backend(&guest_memory, &queues, interrupt.clone())
            .unwrap();

        // VhostUserHandleImpl should correctly send memory and queues information to
        // the backend.
        let expected_config = VringData {
            index: 0,
            size: 128,
            config: VringConfigData {
                queue_max_size: 128,
                queue_size: 128,
                flags: 0,
                desc_table_addr: guest_memory
                    .get_host_address(queue.desc_table_address)
                    .unwrap() as u64,
                used_ring_addr: guest_memory
                    .get_host_address(queue.used_ring_address)
                    .unwrap() as u64,
                avail_ring_addr: guest_memory
                    .get_host_address(queue.avail_ring_address)
                    .unwrap() as u64,
                log_addr: None,
            },
            base: queue.avail_ring_idx_get(),
            call: interrupt
                .notifier(VirtioInterruptType::Queue(0u16))
                .as_ref()
                .unwrap()
                .as_raw_fd(),
            kick: event_fd.as_raw_fd(),
            enable: true,
        };

        let result = unsafe { &*vuh.vu.vrings.get() };
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].index, expected_config.index);
        assert_eq!(result[0].size, expected_config.size);

        // VringConfigData does not implement Eq.
        assert_eq!(
            result[0].config.queue_max_size,
            expected_config.config.queue_max_size
        );
        assert_eq!(
            result[0].config.queue_size,
            expected_config.config.queue_size
        );
        assert_eq!(result[0].config.flags, expected_config.config.flags);
        assert_eq!(
            result[0].config.desc_table_addr,
            expected_config.config.desc_table_addr
        );
        assert_eq!(
            result[0].config.used_ring_addr,
            expected_config.config.used_ring_addr
        );
        assert_eq!(
            result[0].config.avail_ring_addr,
            expected_config.config.avail_ring_addr
        );
        assert_eq!(result[0].config.log_addr, expected_config.config.log_addr);

        assert_eq!(result[0].base, expected_config.base);
        assert_eq!(result[0].call, expected_config.call);
        assert_eq!(result[0].kick, expected_config.kick);
        assert_eq!(result[0].enable, expected_config.enable);
    }
}
