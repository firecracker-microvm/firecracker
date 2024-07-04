// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Portions Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use log::error;
use utils::eventfd::EventFd;
use utils::u64_to_usize;
use vhost::vhost_user::message::*;
use vhost::vhost_user::Frontend;

use super::{VhostUserBlockError, NUM_QUEUES, QUEUE_SIZE};
use crate::devices::virtio::block::CacheType;
use crate::devices::virtio::device::{DeviceState, IrqTrigger, IrqType, VirtioDevice};
use crate::devices::virtio::gen::virtio_blk::{
    VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO, VIRTIO_F_VERSION_1,
};
use crate::devices::virtio::gen::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::vhost_user::{VhostUserHandleBackend, VhostUserHandleImpl};
use crate::devices::virtio::vhost_user_metrics::{
    VhostUserDeviceMetrics, VhostUserMetricsPerDevice,
};
use crate::devices::virtio::{ActivateError, TYPE_BLOCK};
use crate::logger::{log_dev_preview_warning, IncMetric, StoreMetric};
use crate::vmm_config::drive::BlockDeviceConfig;
use crate::vstate::memory::GuestMemoryMmap;

/// Block device config space size in bytes.
const BLOCK_CONFIG_SPACE_SIZE: u32 = 60;

const AVAILABLE_FEATURES: u64 = (1 << VIRTIO_F_VERSION_1)
    | (1 << VIRTIO_RING_F_EVENT_IDX)
    // vhost-user specific bit. Not defined in standart virtio spec.
    // Specifies ability of frontend to negotiate protocol features.
    | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    // We always try to negotiate readonly with the backend.
    // If the backend is configured as readonly, we will accept it.
    | (1 << VIRTIO_BLK_F_RO);

/// Use this structure to set up the Block Device before booting the kernel.
#[derive(Debug, PartialEq, Eq)]
pub struct VhostUserBlockConfig {
    /// Unique identifier of the drive.
    pub drive_id: String,
    /// Part-UUID. Represents the unique id of the boot partition of this device. It is
    /// optional and it will be used only if the `is_root_device` field is true.
    pub partuuid: Option<String>,
    /// If set to true, it makes the current device the root block device.
    /// Setting this flag to true will mount the block device in the
    /// guest under /dev/vda unless the partuuid is present.
    pub is_root_device: bool,
    /// If set to true, the drive will ignore flush requests coming from
    /// the guest driver.
    pub cache_type: CacheType,

    /// Socket path of the vhost-user process
    pub socket: String,
}

impl TryFrom<&BlockDeviceConfig> for VhostUserBlockConfig {
    type Error = VhostUserBlockError;

    fn try_from(value: &BlockDeviceConfig) -> Result<Self, Self::Error> {
        if value.socket.is_some()
            && value.is_read_only.is_none()
            && value.path_on_host.is_none()
            && value.rate_limiter.is_none()
            && value.file_engine_type.is_none()
        {
            Ok(Self {
                drive_id: value.drive_id.clone(),
                partuuid: value.partuuid.clone(),
                is_root_device: value.is_root_device,
                cache_type: value.cache_type,

                socket: value.socket.as_ref().unwrap().clone(),
            })
        } else {
            Err(VhostUserBlockError::Config)
        }
    }
}

impl From<VhostUserBlockConfig> for BlockDeviceConfig {
    fn from(value: VhostUserBlockConfig) -> Self {
        Self {
            drive_id: value.drive_id,
            partuuid: value.partuuid,
            is_root_device: value.is_root_device,
            cache_type: value.cache_type,

            is_read_only: None,
            path_on_host: None,
            rate_limiter: None,
            file_engine_type: None,

            socket: Some(value.socket),
        }
    }
}

pub type VhostUserBlock = VhostUserBlockImpl<Frontend>;

/// vhost-user block device.
pub struct VhostUserBlockImpl<T: VhostUserHandleBackend> {
    // Virtio fields.
    pub avail_features: u64,
    pub acked_features: u64,
    pub config_space: Vec<u8>,
    pub activate_evt: EventFd,

    // Transport related fields.
    pub queues: Vec<Queue>,
    pub queue_evts: [EventFd; u64_to_usize(NUM_QUEUES)],
    pub device_state: DeviceState,
    pub irq_trigger: IrqTrigger,

    // Implementation specific fields.
    pub id: String,
    pub partuuid: Option<String>,
    pub cache_type: CacheType,
    pub root_device: bool,
    pub read_only: bool,

    // Vhost user protocol handle
    pub vu_handle: VhostUserHandleImpl<T>,
    pub vu_acked_protocol_features: u64,
    pub metrics: Arc<VhostUserDeviceMetrics>,
}

// Need custom implementation because otherwise `Debug` is required for `vhost::Master`
impl<T: VhostUserHandleBackend> std::fmt::Debug for VhostUserBlockImpl<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhostUserBlockImpl")
            .field("avail_features", &self.avail_features)
            .field("acked_features", &self.acked_features)
            .field("config_space", &self.config_space)
            .field("activate_evt", &self.activate_evt)
            .field("queues", &self.queues)
            .field("queue_evts", &self.queue_evts)
            .field("device_state", &self.device_state)
            .field("irq_trigger", &self.irq_trigger)
            .field("id", &self.id)
            .field("partuuid", &self.partuuid)
            .field("cache_type", &self.cache_type)
            .field("root_device", &self.root_device)
            .field("read_only", &self.read_only)
            .field("vu_handle", &self.vu_handle)
            .field(
                "vu_acked_protocol_features",
                &self.vu_acked_protocol_features,
            )
            .field("metrics", &self.metrics)
            .finish()
    }
}

impl<T: VhostUserHandleBackend> VhostUserBlockImpl<T> {
    pub fn new(config: VhostUserBlockConfig) -> Result<Self, VhostUserBlockError> {
        log_dev_preview_warning("vhost-user-blk device", Option::None);
        let start_time = utils::time::get_time_us(utils::time::ClockType::Monotonic);
        let mut requested_features = AVAILABLE_FEATURES;

        if config.cache_type == CacheType::Writeback {
            requested_features |= 1 << VIRTIO_BLK_F_FLUSH;
        }

        let requested_protocol_features = VhostUserProtocolFeatures::CONFIG;

        let mut vu_handle = VhostUserHandleImpl::<T>::new(&config.socket, NUM_QUEUES)
            .map_err(VhostUserBlockError::VhostUser)?;
        let (acked_features, acked_protocol_features) = vu_handle
            .negotiate_features(requested_features, requested_protocol_features)
            .map_err(VhostUserBlockError::VhostUser)?;

        // Get config from backend if CONFIG is acked or use empty buffer.
        let config_space =
            if acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() != 0 {
                // This buffer is used for config size check in vhost crate.
                let buffer = [0u8; BLOCK_CONFIG_SPACE_SIZE as usize];
                let (_, new_config_space) = vu_handle
                    .vu
                    .get_config(
                        0,
                        BLOCK_CONFIG_SPACE_SIZE,
                        VhostUserConfigFlags::WRITABLE,
                        &buffer,
                    )
                    .map_err(VhostUserBlockError::Vhost)?;
                new_config_space
            } else {
                vec![]
            };

        let activate_evt =
            EventFd::new(libc::EFD_NONBLOCK).map_err(VhostUserBlockError::EventFd)?;

        let queues = vec![Queue::new(QUEUE_SIZE)];
        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(VhostUserBlockError::EventFd)?;
            u64_to_usize(NUM_QUEUES)];
        let device_state = DeviceState::Inactive;
        let irq_trigger = IrqTrigger::new().map_err(VhostUserBlockError::IrqTrigger)?;

        // We negotiated features with backend. Now these acked_features
        // are available for guest driver to choose from.
        let avail_features = acked_features;
        let acked_features = acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let read_only = acked_features & (1 << VIRTIO_BLK_F_RO) != 0;
        let vhost_user_block_metrics_name = format!("block_{}", config.drive_id);

        let metrics = VhostUserMetricsPerDevice::alloc(vhost_user_block_metrics_name);
        let delta_us = utils::time::get_time_us(utils::time::ClockType::Monotonic) - start_time;
        metrics.init_time_us.store(delta_us);

        Ok(Self {
            avail_features,
            acked_features,
            config_space,
            activate_evt,

            queues,
            queue_evts,
            device_state,
            irq_trigger,

            id: config.drive_id,
            partuuid: config.partuuid,
            cache_type: config.cache_type,
            read_only,
            root_device: config.is_root_device,

            vu_handle,
            vu_acked_protocol_features: acked_protocol_features,
            metrics,
        })
    }

    /// Prepare device for being snapshotted.
    pub fn prepare_save(&mut self) {
        unimplemented!("VhostUserBlock does not support snapshotting yet");
    }

    pub fn config(&self) -> VhostUserBlockConfig {
        VhostUserBlockConfig {
            drive_id: self.id.clone(),
            partuuid: self.partuuid.clone(),
            is_root_device: self.root_device,
            cache_type: self.cache_type,
            socket: self.vu_handle.socket_path.clone(),
        }
    }

    pub fn config_update(&mut self) -> Result<(), VhostUserBlockError> {
        let start_time = utils::time::get_time_us(utils::time::ClockType::Monotonic);

        // This buffer is used for config size check in vhost crate.
        let buffer = [0u8; BLOCK_CONFIG_SPACE_SIZE as usize];
        let (_, new_config_space) = self
            .vu_handle
            .vu
            .get_config(
                0,
                BLOCK_CONFIG_SPACE_SIZE,
                VhostUserConfigFlags::WRITABLE,
                &buffer,
            )
            .map_err(VhostUserBlockError::Vhost)?;
        self.config_space = new_config_space;
        self.irq_trigger
            .trigger_irq(IrqType::Config)
            .map_err(VhostUserBlockError::IrqTrigger)?;

        let delta_us = utils::time::get_time_us(utils::time::ClockType::Monotonic) - start_time;
        self.metrics.config_change_time_us.store(delta_us);

        Ok(())
    }
}

impl<T: VhostUserHandleBackend + Send + 'static> VirtioDevice for VhostUserBlockImpl<T> {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_trigger(&self) -> &IrqTrigger {
        &self.irq_trigger
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if let Some(config_space_bytes) = self.config_space.as_slice().get(u64_to_usize(offset)..) {
            let len = config_space_bytes.len().min(data.len());
            data[..len].copy_from_slice(&config_space_bytes[..len]);
        } else {
            error!("Failed to read config space");
            self.metrics.cfg_fails.inc();
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // We do not advertise VIRTIO_BLK_F_CONFIG_WCE
        // that would allow configuring the "writeback" field.
        // Other block config fields are immutable.
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> Result<(), ActivateError> {
        let start_time = utils::time::get_time_us(utils::time::ClockType::Monotonic);
        // Setting features again, because now we negotiated them
        // with guest driver as well.
        self.vu_handle
            .set_features(self.acked_features)
            .and_then(|()| {
                self.vu_handle.setup_backend(
                    &mem,
                    &[(0, &self.queues[0], &self.queue_evts[0])],
                    &self.irq_trigger,
                )
            })
            .map_err(|err| {
                self.metrics.activate_fails.inc();
                ActivateError::VhostUser(err)
            })?;
        self.device_state = DeviceState::Activated(mem);
        let delta_us = utils::time::get_time_us(utils::time::ClockType::Monotonic) - start_time;
        self.metrics.activate_time_us.store(delta_us);
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::os::unix::net::UnixStream;
    use std::sync::atomic::Ordering;

    use utils::tempfile::TempFile;
    use vhost::{VhostUserMemoryRegionInfo, VringConfigData};

    use super::*;
    use crate::devices::virtio::block::virtio::device::FileEngineType;
    use crate::devices::virtio::mmio::VIRTIO_MMIO_INT_CONFIG;
    use crate::utilities::test_utils::create_tmp_socket;
    use crate::vstate::memory::{FileOffset, GuestAddress, GuestMemoryExtension};

    #[test]
    fn test_from_config() {
        let block_config = BlockDeviceConfig {
            drive_id: "".to_string(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: None,
            path_on_host: None,
            rate_limiter: None,
            file_engine_type: None,

            socket: Some("sock".to_string()),
        };
        VhostUserBlockConfig::try_from(&block_config).unwrap();

        let block_config = BlockDeviceConfig {
            drive_id: "".to_string(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(true),
            path_on_host: Some("path".to_string()),
            rate_limiter: None,
            file_engine_type: Some(FileEngineType::Sync),

            socket: None,
        };
        VhostUserBlockConfig::try_from(&block_config).unwrap_err();

        let block_config = BlockDeviceConfig {
            drive_id: "".to_string(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(true),
            path_on_host: Some("path".to_string()),
            rate_limiter: None,
            file_engine_type: Some(FileEngineType::Sync),

            socket: Some("sock".to_string()),
        };
        VhostUserBlockConfig::try_from(&block_config).unwrap_err();
    }

    #[test]
    fn test_new_no_features() {
        struct MockMaster {
            sock: UnixStream,
            max_queue_num: u64,
            is_owner: std::cell::UnsafeCell<bool>,
            features: u64,
            protocol_features: VhostUserProtocolFeatures,
            hdr_flags: std::cell::UnsafeCell<VhostUserHeaderFlag>,
        }

        impl VhostUserHandleBackend for MockMaster {
            fn from_stream(sock: UnixStream, max_queue_num: u64) -> Self {
                Self {
                    sock,
                    max_queue_num,
                    is_owner: std::cell::UnsafeCell::new(false),
                    features: 0,
                    protocol_features: VhostUserProtocolFeatures::empty(),
                    hdr_flags: std::cell::UnsafeCell::new(VhostUserHeaderFlag::empty()),
                }
            }

            fn set_owner(&self) -> Result<(), vhost::Error> {
                unsafe { *self.is_owner.get() = true };
                Ok(())
            }

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

        let (_tmp_dir, tmp_socket_path) = create_tmp_socket();

        let vhost_block_config = VhostUserBlockConfig {
            drive_id: "test_drive".to_string(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,
            socket: tmp_socket_path.clone(),
        };
        let vhost_block = VhostUserBlockImpl::<MockMaster>::new(vhost_block_config).unwrap();

        // If backend has no features, nothing should be negotiated and
        // no flags should be set.
        assert_eq!(
            vhost_block
                .vu_handle
                .vu
                .sock
                .peer_addr()
                .unwrap()
                .as_pathname()
                .unwrap()
                .to_str()
                .unwrap(),
            &tmp_socket_path,
        );
        assert_eq!(vhost_block.vu_handle.vu.max_queue_num, NUM_QUEUES);
        assert!(unsafe { *vhost_block.vu_handle.vu.is_owner.get() });
        assert_eq!(vhost_block.avail_features, 0);
        assert_eq!(vhost_block.acked_features, 0);
        assert_eq!(vhost_block.vu_acked_protocol_features, 0);
        assert_eq!(
            unsafe { &*vhost_block.vu_handle.vu.hdr_flags.get() }.bits(),
            VhostUserHeaderFlag::empty().bits()
        );
        assert!(!vhost_block.root_device);
        assert!(!vhost_block.read_only);
        assert_eq!(vhost_block.config_space, Vec::<u8>::new());
    }

    #[test]
    fn test_new_all_features() {
        struct MockMaster {
            sock: UnixStream,
            max_queue_num: u64,
            is_owner: std::cell::UnsafeCell<bool>,
            features: u64,
            protocol_features: VhostUserProtocolFeatures,
            hdr_flags: std::cell::UnsafeCell<VhostUserHeaderFlag>,
        }

        impl VhostUserHandleBackend for MockMaster {
            fn from_stream(sock: UnixStream, max_queue_num: u64) -> Self {
                Self {
                    sock,
                    max_queue_num,
                    is_owner: std::cell::UnsafeCell::new(false),
                    features: AVAILABLE_FEATURES | (1 << VIRTIO_BLK_F_FLUSH),

                    protocol_features: VhostUserProtocolFeatures::all(),
                    hdr_flags: std::cell::UnsafeCell::new(VhostUserHeaderFlag::empty()),
                }
            }

            fn set_owner(&self) -> Result<(), vhost::Error> {
                unsafe { *self.is_owner.get() = true };
                Ok(())
            }

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

            fn get_config(
                &mut self,
                _offset: u32,
                _size: u32,
                _flags: VhostUserConfigFlags,
                _buf: &[u8],
            ) -> Result<(VhostUserConfig, VhostUserConfigPayload), vhost::Error> {
                Ok((VhostUserConfig::default(), vec![0x69, 0x69, 0x69]))
            }
        }

        let (_tmp_dir, tmp_socket_path) = create_tmp_socket();

        let vhost_block_config = VhostUserBlockConfig {
            drive_id: "test_drive".to_string(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Writeback,
            socket: tmp_socket_path.clone(),
        };
        let mut vhost_block = VhostUserBlockImpl::<MockMaster>::new(vhost_block_config).unwrap();

        // If backend has all features, features offered by block device
        // should be negotiated and header flags should be set.
        assert_eq!(
            vhost_block
                .vu_handle
                .vu
                .sock
                .peer_addr()
                .unwrap()
                .as_pathname()
                .unwrap()
                .to_str()
                .unwrap(),
            &tmp_socket_path,
        );
        assert_eq!(vhost_block.vu_handle.vu.max_queue_num, NUM_QUEUES);
        assert!(unsafe { *vhost_block.vu_handle.vu.is_owner.get() });

        assert_eq!(
            vhost_block.avail_features,
            AVAILABLE_FEATURES | (1 << VIRTIO_BLK_F_FLUSH)
        );
        assert_eq!(
            vhost_block.acked_features,
            VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
        );
        assert_eq!(
            vhost_block.vu_acked_protocol_features,
            VhostUserProtocolFeatures::CONFIG.bits()
        );
        assert_eq!(
            unsafe { &*vhost_block.vu_handle.vu.hdr_flags.get() }.bits(),
            VhostUserHeaderFlag::empty().bits()
        );
        assert!(!vhost_block.root_device);
        assert!(!vhost_block.read_only);
        assert_eq!(vhost_block.config_space, vec![0x69, 0x69, 0x69]);

        // Test some `VirtioDevice` methods
        assert_eq!(
            vhost_block.avail_features(),
            AVAILABLE_FEATURES | (1 << VIRTIO_BLK_F_FLUSH)
        );
        assert_eq!(
            vhost_block.acked_features(),
            VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
        );

        // Valid read
        let mut read_config = vec![0, 0, 0];
        vhost_block.read_config(0, &mut read_config);
        assert_eq!(read_config, vec![0x69, 0x69, 0x69]);

        // Invalid offset
        let mut read_config = vec![0, 0, 0];
        vhost_block.read_config(0x69, &mut read_config);
        assert_eq!(read_config, vec![0, 0, 0]);

        // Writing to the config does nothing
        vhost_block.write_config(0x69, &[0]);
        assert_eq!(vhost_block.config_space, vec![0x69, 0x69, 0x69]);

        // Testing [`config_update`]
        vhost_block.config_space = vec![];
        vhost_block.config_update().unwrap();
        assert_eq!(vhost_block.config_space, vec![0x69, 0x69, 0x69]);
        assert_eq!(
            vhost_block.interrupt_status().load(Ordering::SeqCst),
            VIRTIO_MMIO_INT_CONFIG
        );
    }

    #[test]
    fn test_activate() {
        struct MockMaster {
            features_are_set: std::cell::UnsafeCell<bool>,
            memory_is_set: std::cell::UnsafeCell<bool>,
            vring_enabled: std::cell::UnsafeCell<bool>,
        }

        impl VhostUserHandleBackend for MockMaster {
            fn from_stream(_sock: UnixStream, _max_queue_num: u64) -> Self {
                Self {
                    features_are_set: std::cell::UnsafeCell::new(false),
                    memory_is_set: std::cell::UnsafeCell::new(false),
                    vring_enabled: std::cell::UnsafeCell::new(false),
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

            fn get_config(
                &mut self,
                _offset: u32,
                _size: u32,
                _flags: VhostUserConfigFlags,
                _buf: &[u8],
            ) -> Result<(VhostUserConfig, VhostUserConfigPayload), vhost::Error> {
                Ok((VhostUserConfig::default(), vec![]))
            }

            fn set_features(&self, _features: u64) -> Result<(), vhost::Error> {
                unsafe { (*self.features_are_set.get()) = true };
                Ok(())
            }

            fn set_mem_table(
                &self,
                _regions: &[VhostUserMemoryRegionInfo],
            ) -> Result<(), vhost::Error> {
                unsafe { (*self.memory_is_set.get()) = true };
                Ok(())
            }

            fn set_vring_num(&self, _queue_index: usize, _num: u16) -> Result<(), vhost::Error> {
                Ok(())
            }

            fn set_vring_addr(
                &self,
                _queue_index: usize,
                _config_data: &VringConfigData,
            ) -> Result<(), vhost::Error> {
                Ok(())
            }

            fn set_vring_base(&self, _queue_index: usize, _base: u16) -> Result<(), vhost::Error> {
                Ok(())
            }

            fn set_vring_call(
                &self,
                _queue_index: usize,
                _fd: &EventFd,
            ) -> Result<(), vhost::Error> {
                Ok(())
            }

            fn set_vring_kick(
                &self,
                _queue_index: usize,
                _fd: &EventFd,
            ) -> Result<(), vhost::Error> {
                Ok(())
            }

            fn set_vring_enable(
                &mut self,
                _queue_index: usize,
                _enable: bool,
            ) -> Result<(), vhost::Error> {
                unsafe { (*self.vring_enabled.get()) = true };
                Ok(())
            }
        }

        // Block creation
        let (_tmp_dir, tmp_socket_path) = create_tmp_socket();
        let vhost_block_config = VhostUserBlockConfig {
            drive_id: "test_drive".to_string(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Writeback,
            socket: tmp_socket_path,
        };
        let mut vhost_block = VhostUserBlockImpl::<MockMaster>::new(vhost_block_config).unwrap();

        // Memory creation
        let region_size = 0x10000;
        let file = TempFile::new().unwrap().into_file();
        file.set_len(region_size as u64).unwrap();
        let regions = vec![(
            FileOffset::new(file.try_clone().unwrap(), 0x0),
            GuestAddress(0x0),
            region_size,
        )];
        let guest_memory = GuestMemoryMmap::from_raw_regions_file(regions, false, false).unwrap();

        // During actiavion of the device features, memory and queues should be set and activated.
        vhost_block.activate(guest_memory).unwrap();
        assert!(unsafe { *vhost_block.vu_handle.vu.features_are_set.get() });
        assert!(unsafe { *vhost_block.vu_handle.vu.memory_is_set.get() });
        assert!(unsafe { *vhost_block.vu_handle.vu.vring_enabled.get() });
        assert!(vhost_block.is_activated());
    }
}
