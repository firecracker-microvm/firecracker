// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Portions Copyright 2019 Intel Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use vhost::vhost_user::Frontend;
use vhost::vhost_user::message::*;
use vmm_sys_util::eventfd::EventFd;

use super::{NUM_QUEUES, QUEUE_SIZE, VhostUserBlockError};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::block::CacheType;
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_blk::{VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::devices::virtio::vhost_user::{
    VhostUserDevice, VhostUserDeviceSpec, VhostUserHandleBackend,
};
use crate::logger::log_dev_preview_warning;
use crate::vmm_config::drive::BlockDeviceConfig;
use crate::vstate::memory::GuestMemoryMmap;
use crate::{MutEventSubscriber, impl_device_type};

/// Block device config space size in bytes.
const BLOCK_CONFIG_SPACE_SIZE: u32 = 60;

const AVAILABLE_FEATURES: u64 = (1 << VIRTIO_F_VERSION_1)
    | (1 << VIRTIO_RING_F_EVENT_IDX)
    // vhost-user specific bit. Not defined in standard virtio spec.
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
        if let (Some(socket), None, None, None, None, None, None) = (
            &value.socket,
            &value.is_read_only,
            &value.path_on_host,
            &value.rate_limiter,
            &value.file_engine_type,
            &value.blk_size,
            &value.topology,
        ) {
            Ok(Self {
                drive_id: value.drive_id.clone(),
                partuuid: value.partuuid.clone(),
                is_root_device: value.is_root_device,
                cache_type: value.cache_type,

                socket: socket.clone(),
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
            blk_size: None,
            topology: None,

            socket: Some(value.socket),
        }
    }
}

pub type VhostUserBlock = VhostUserBlockImpl<Frontend>;

/// vhost-user block device.
pub struct VhostUserBlockImpl<T: VhostUserHandleBackend> {
    // Everything that is not specific to block living in the generic frontend.
    pub vu_device: VhostUserDevice<T>,

    // Implementation specific fields.
    pub id: String,
    pub partuuid: Option<String>,
    pub cache_type: CacheType,
    pub root_device: bool,
    pub read_only: bool,
}

// Need custom implementation because otherwise `Debug` is required for `vhost::Master`
impl<T: VhostUserHandleBackend> std::fmt::Debug for VhostUserBlockImpl<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhostUserBlockImpl")
            .field("vu_device", &self.vu_device)
            .field("id", &self.id)
            .field("partuuid", &self.partuuid)
            .field("cache_type", &self.cache_type)
            .field("root_device", &self.root_device)
            .field("read_only", &self.read_only)
            .finish()
    }
}

impl<T: VhostUserHandleBackend> VhostUserBlockImpl<T> {
    pub fn new(config: VhostUserBlockConfig) -> Result<Self, VhostUserBlockError> {
        log_dev_preview_warning("vhost-user-blk device", Option::None);

        let mut avail_features = AVAILABLE_FEATURES;
        if config.cache_type == CacheType::Writeback {
            avail_features |= 1 << VIRTIO_BLK_F_FLUSH;
        }

        let vu_device = VhostUserDevice::<T>::new(VhostUserDeviceSpec {
            socket: config.socket,
            num_queues: NUM_QUEUES,
            queue_size: QUEUE_SIZE,
            avail_features,
            config_space_size: BLOCK_CONFIG_SPACE_SIZE,
            // A backend that does not implement CONFIG leaves the config space
            // empty, which the guest driver reads as a zero-capacity disk.
            require_config: false,
            metrics_name: format!("block_{}", config.drive_id),
        })?;

        // What the backend acked is what the guest driver gets offered, so this
        // is where a readonly backend shows up.
        let read_only = vu_device.avail_features & (1 << VIRTIO_BLK_F_RO) != 0;

        Ok(Self {
            vu_device,

            id: config.drive_id,
            partuuid: config.partuuid,
            cache_type: config.cache_type,
            read_only,
            root_device: config.is_root_device,
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
            socket: self.vu_device.socket_path().to_string(),
        }
    }

    pub fn config_update(&mut self) -> Result<(), VhostUserBlockError> {
        Ok(self.vu_device.refresh_config()?)
    }
}

impl<T: VhostUserHandleBackend + Send + 'static> VirtioDevice for VhostUserBlockImpl<T>
where
    VhostUserBlockImpl<T>: MutEventSubscriber,
{
    impl_device_type!(VirtioDeviceType::Block);

    fn id(&self) -> &str {
        &self.id
    }

    fn avail_features(&self) -> u64 {
        self.vu_device.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.vu_device.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.vu_device.acked_features = acked_features;
    }

    fn queues(&self) -> &[Queue] {
        &self.vu_device.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.vu_device.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.vu_device.queue_evts
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.vu_device.interrupt()
    }

    fn config_as_bytes(&self) -> &[u8] {
        self.vu_device.config_space.as_slice()
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // We do not advertise VIRTIO_BLK_F_CONFIG_WCE
        // that would allow configuring the "writeback" field.
        // Other block config fields are immutable.
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        self.vu_device.activate(mem, interrupt)
    }

    fn is_activated(&self) -> bool {
        self.vu_device.is_activated()
    }

    fn deactivate(&mut self) {
        self.vu_device.deactivate();
    }

    fn _reset(&mut self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::os::unix::net::UnixStream;
    use std::sync::atomic::Ordering;

    use event_manager::{EventOps, Events, MutEventSubscriber};
    use vhost::{VhostUserMemoryRegionInfo, VringConfigData};
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::block::virtio::device::FileEngineType;
    use crate::devices::virtio::device::{ActiveState, DeviceState};
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::devices::virtio::transport::mmio::VIRTIO_MMIO_INT_CONFIG;
    use crate::devices::virtio::vhost_user::tests::create_mem;
    use crate::test_utils::create_tmp_socket;
    use crate::vstate::memory::GuestAddress;

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
            blk_size: None,
            topology: None,

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
            blk_size: None,
            topology: None,

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
            blk_size: None,
            topology: None,

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

        impl MutEventSubscriber for VhostUserBlockImpl<MockMaster> {
            fn process(&mut self, _: Events, _: &mut EventOps) {}
            fn init(&mut self, _: &mut EventOps) {}
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
                .vu_device
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
        assert_eq!(vhost_block.vu_device.vu_handle.vu.max_queue_num, NUM_QUEUES);
        assert!(unsafe { *vhost_block.vu_device.vu_handle.vu.is_owner.get() });
        assert_eq!(vhost_block.vu_device.avail_features, 0);
        assert_eq!(vhost_block.vu_device.acked_features, 0);
        assert_eq!(vhost_block.vu_device.vu_acked_protocol_features, 0);
        assert_eq!(
            unsafe { &*vhost_block.vu_device.vu_handle.vu.hdr_flags.get() }.bits(),
            VhostUserHeaderFlag::empty().bits()
        );
        assert!(!vhost_block.root_device);
        assert!(!vhost_block.read_only);
        assert_eq!(vhost_block.vu_device.config_space, Vec::<u8>::new());
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
                size: u32,
                _flags: VhostUserConfigFlags,
                _buf: &[u8],
            ) -> Result<(VhostUserConfig, VhostUserConfigPayload), vhost::Error> {
                // The frontend requires the backend to answer with as many
                // bytes as were asked for.
                let mut config = vec![0x69, 0x69, 0x69];
                config.resize(size as usize, 0);
                Ok((VhostUserConfig::default(), config))
            }
        }

        impl MutEventSubscriber for VhostUserBlockImpl<MockMaster> {
            fn process(&mut self, _: Events, _: &mut EventOps) {}
            fn init(&mut self, _: &mut EventOps) {}
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
                .vu_device
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
        assert_eq!(vhost_block.vu_device.vu_handle.vu.max_queue_num, NUM_QUEUES);
        assert!(unsafe { *vhost_block.vu_device.vu_handle.vu.is_owner.get() });

        assert_eq!(
            vhost_block.vu_device.avail_features,
            AVAILABLE_FEATURES | (1 << VIRTIO_BLK_F_FLUSH)
        );
        assert_eq!(
            vhost_block.vu_device.acked_features,
            VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
        );
        assert_eq!(
            vhost_block.vu_device.vu_acked_protocol_features,
            VhostUserProtocolFeatures::CONFIG.bits()
        );
        assert_eq!(
            unsafe { &*vhost_block.vu_device.vu_handle.vu.hdr_flags.get() }.bits(),
            VhostUserHeaderFlag::empty().bits()
        );
        assert!(!vhost_block.root_device);
        assert!(vhost_block.read_only);
        assert_eq!(
            vhost_block.vu_device.config_space.len(),
            BLOCK_CONFIG_SPACE_SIZE as usize
        );
        assert_eq!(
            &vhost_block.vu_device.config_space[..3],
            &[0x69, 0x69, 0x69]
        );

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
        assert_eq!(
            vhost_block.vu_device.config_space.len(),
            BLOCK_CONFIG_SPACE_SIZE as usize
        );
        assert_eq!(
            &vhost_block.vu_device.config_space[..3],
            &[0x69, 0x69, 0x69]
        );

        // Testing [`config_update`]
        vhost_block.vu_device.device_state = DeviceState::Activated(ActiveState {
            mem: default_mem(),
            interrupt: default_interrupt(),
        });
        vhost_block.vu_device.config_space = vec![];
        vhost_block.config_update().unwrap();
        assert_eq!(
            vhost_block.vu_device.config_space.len(),
            BLOCK_CONFIG_SPACE_SIZE as usize
        );
        assert_eq!(
            &vhost_block.vu_device.config_space[..3],
            &[0x69, 0x69, 0x69]
        );
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

        impl MutEventSubscriber for VhostUserBlockImpl<MockMaster> {
            fn process(&mut self, _: Events, _: &mut EventOps) {}
            fn init(&mut self, _: &mut EventOps) {}
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
        let regions = vec![(GuestAddress(0x0), region_size)];
        let guest_memory = create_mem(file, &regions);
        let q = VirtQueue::new(GuestAddress(0), &guest_memory, 16);
        vhost_block.vu_device.queues[0] = q.create_queue();
        let interrupt = default_interrupt();

        // During actiavion of the device features, memory and queues should be set and activated.
        vhost_block.activate(guest_memory, interrupt).unwrap();
        assert!(unsafe { *vhost_block.vu_device.vu_handle.vu.features_are_set.get() });
        assert!(unsafe { *vhost_block.vu_device.vu_handle.vu.memory_is_set.get() });
        assert!(unsafe { *vhost_block.vu_device.vu_handle.vu.vring_enabled.get() });
        assert!(vhost_block.is_activated());
    }
}
