// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use vhost::vhost_user::Frontend;
use vhost::vhost_user::message::*;
use vmm_sys_util::eventfd::EventFd;

use super::{QUEUE_SIZE, VhostUserGenericError};
use crate::MutEventSubscriber;
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::{
    VIRTIO_F_ACCESS_PLATFORM, VIRTIO_F_ADMIN_VQ, VIRTIO_F_NOTIF_CONFIG_DATA,
    VIRTIO_F_NOTIFICATION_DATA, VIRTIO_F_RING_PACKED, VIRTIO_F_RING_RESET, VIRTIO_F_SR_IOV,
};
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::devices::virtio::vhost_user::{
    VhostUserDevice, VhostUserDeviceSpec, VhostUserHandleBackend,
};
use crate::logger::{IncMetric, log_dev_preview_warning};
use crate::utils::u64_to_usize;
use crate::vmm_config::vhost_user_device::VhostUserDeviceConfig;
use crate::vstate::memory::GuestMemoryMmap;

/// Size of the config space fetched from the backend when none is configured.
///
/// The protocol requires the backend to return exactly the number of bytes
/// requested, and only the device type knows how many that is, so whoever
/// configures the device can say. This default suits a backend that pads its
/// reply, and is large enough to cover the config space of the device types
/// most likely to be attached this way.
const DEFAULT_CONFIG_SPACE_SIZE: u32 = 256;

/// The value `VirtioDeviceType::VhostUserGeneric` uses, rejected as a
/// guest-visible device type so the two cannot be confused.
const VIRTIO_DEVICE_TYPE_SENTINEL: u8 = 0xFF;

/// Features the frontend cannot honour, whatever the backend offers.
///
/// Everything else is passed through: a frontend that knows nothing about the
/// device type has no basis for withholding that device type's features, and
/// dropping them would leave the guest unable to use the device as configured.
/// These particular bits change how the frontend itself has to drive the
/// queues or translate addresses, so offering them would promise the guest
/// something Firecracker does not do.
const WITHHELD_FEATURES: u64 = VhostUserVirtioFeatures::LOG_ALL.bits()
    | (1 << VIRTIO_F_ACCESS_PLATFORM)
    // The queues are split rings here; there is no packed ring support.
    | (1 << VIRTIO_F_RING_PACKED)
    // Notifications are ioeventfds, so the value the guest writes is
    // discarded and never reaches the backend.
    | (1 << VIRTIO_F_NOTIFICATION_DATA)
    | (1 << VIRTIO_F_NOTIF_CONFIG_DATA)
    // Neither transport implements per-queue reset or an admin queue.
    | (1 << VIRTIO_F_RING_RESET)
    | (1 << VIRTIO_F_ADMIN_VQ)
    | (1 << VIRTIO_F_SR_IOV);

const AVAILABLE_FEATURES: u64 = !WITHHELD_FEATURES;

// Protocol features are negotiated through this virtio bit, and the config
// space this device cannot work without is a protocol feature, so it has to
// survive whatever else is withheld.
const _: () = assert!(
    AVAILABLE_FEATURES & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0,
    "the vhost-user protocol feature bit must be offered"
);

pub type VhostUserGeneric = VhostUserGenericImpl<Frontend>;

/// Generic vhost-user frontend device.
///
/// Unlike per-device-type vhost-user frontends, this device knows nothing
/// about the specific virtio device type being implemented. The backend is
/// fully responsible for handling the configuration space. This allows using
/// device types Firecracker has no frontend for, e.g. virtio-fs or
/// virtio-scsi, without writing a dedicated frontend for each.
pub struct VhostUserGenericImpl<T: VhostUserHandleBackend> {
    // Everything that is not specific to this device lives in the shared
    // frontend, alongside the other vhost-user device types.
    pub vu_device: VhostUserDevice<T>,

    // Implementation specific fields.
    pub id: String,
    pub device_type_id: u8,
    pub config_space_size: u32,
}

// Need custom implementation because otherwise `Debug` is required for `vhost::Master`
impl<T: VhostUserHandleBackend> std::fmt::Debug for VhostUserGenericImpl<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhostUserGenericImpl")
            .field("vu_device", &self.vu_device)
            .field("id", &self.id)
            .field("device_type_id", &self.device_type_id)
            .field("config_space_size", &self.config_space_size)
            .finish()
    }
}

impl<T: VhostUserHandleBackend> VhostUserGenericImpl<T> {
    pub fn new(config: VhostUserDeviceConfig) -> Result<Self, VhostUserGenericError> {
        log_dev_preview_warning("generic vhost-user device", Option::None);

        // 0 means "no device" to the virtio-mmio driver, and 0xFF is the
        // value Firecracker uses internally to key this device type, so
        // accepting it would leave the guest-visible type and the host-side
        // one indistinguishable by value.
        if config.device_type == 0 || config.device_type == VIRTIO_DEVICE_TYPE_SENTINEL {
            return Err(VhostUserGenericError::InvalidDeviceType(config.device_type));
        }

        let config_space_size = config
            .config_space_size
            .unwrap_or(DEFAULT_CONFIG_SPACE_SIZE);

        let vu_device = VhostUserDevice::<T>::new(VhostUserDeviceSpec {
            socket: config.socket,
            num_queues: config.num_queues,
            queue_size: config.queue_size.unwrap_or(QUEUE_SIZE),
            avail_features: AVAILABLE_FEATURES,
            config_space_size,
            // The backend owns the whole config space and there is no
            // device-specific fallback, so unlike block this device cannot
            // work against a backend without CONFIG.
            require_config: true,
            metrics_name: format!("generic_{}", config.id),
        })?;

        Ok(Self {
            vu_device,

            id: config.id,
            device_type_id: config.device_type,
            config_space_size,
        })
    }
}

impl<T: VhostUserHandleBackend + Send + 'static> VirtioDevice for VhostUserGenericImpl<T>
where
    VhostUserGenericImpl<T>: MutEventSubscriber,
{
    fn const_device_type() -> VirtioDeviceType {
        VirtioDeviceType::VhostUserGeneric
    }

    fn device_type(&self) -> VirtioDeviceType {
        VirtioDeviceType::VhostUserGeneric
    }

    /// Returns the real virtio device type ID as seen by the guest.
    ///
    /// Overrides the default implementation because `device_type()` returns
    /// the host-side sentinel [`VirtioDeviceType::VhostUserGeneric`] while
    /// the guest must see the actual virtio spec device type ID provided by
    /// the user at configuration time.
    fn virtio_device_type_id(&self) -> u32 {
        u32::from(self.device_type_id)
    }

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

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if let Some(config_space_bytes) = self
            .vu_device
            .config_space
            .as_slice()
            .get(u64_to_usize(offset)..)
        {
            let len = config_space_bytes.len().min(data.len());
            data[..len].copy_from_slice(&config_space_bytes[..len]);
            // The caller's buffer is not zeroed for us, so anything the config
            // space does not cover has to be zeroed rather than left as
            // whatever the last access put there.
            data[len..].fill(0);
        } else {
            // Not logged: the guest chooses the offset and could otherwise
            // flood the log by reading past the end in a loop.
            self.vu_device.metrics.cfg_fails.inc();
            data.fill(0);
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        // Config space is owned entirely by the backend. Writes from the
        // guest driver are forwarded to the backend via the CONFIG protocol
        // feature in a future implementation.
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

    fn config_as_bytes(&self) -> &[u8] {
        self.vu_device.config_space.as_slice()
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

    use event_manager::{EventOps, Events, MutEventSubscriber};
    use vhost::{VhostUserMemoryRegionInfo, VringConfigData};
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt};
    use crate::devices::virtio::vhost_user::tests::create_mem;
    use crate::test_utils::create_tmp_socket;
    use crate::vstate::memory::GuestAddress;

    #[test]
    fn test_new_rejects_reserved_device_types() {
        /// The device type is checked before the socket is touched, so this
        /// never has to answer anything.
        struct MockUnused;
        impl VhostUserHandleBackend for MockUnused {}

        let config = |device_type| VhostUserDeviceConfig {
            device_type,
            ..default_config("no-such-socket".to_string())
        };

        // 0 reads as "no device" to the virtio-mmio driver.
        assert!(matches!(
            VhostUserGenericImpl::<MockUnused>::new(config(0)),
            Err(VhostUserGenericError::InvalidDeviceType(0))
        ));
        // 0xFF is the value Firecracker keys this device type by internally.
        assert!(matches!(
            VhostUserGenericImpl::<MockUnused>::new(config(0xFF)),
            Err(VhostUserGenericError::InvalidDeviceType(0xFF))
        ));
    }

    #[test]
    fn test_backend_features_reach_the_guest() {
        /// A device-specific bit. Bit 5 is `VIRTIO_BLK_F_RO` for a block
        /// device, but the frontend has no business knowing that.
        const DEVICE_SPECIFIC_BIT: u64 = 1 << 5;

        struct MockFeatures;

        impl VhostUserHandleBackend for MockFeatures {
            fn from_stream(_sock: UnixStream, _max_queue_num: u64) -> Self {
                Self
            }

            fn set_owner(&self) -> Result<(), vhost::Error> {
                Ok(())
            }

            fn set_hdr_flags(&self, _flags: VhostUserHeaderFlag) {}

            fn get_features(&self) -> Result<u64, vhost::Error> {
                Ok(DEVICE_SPECIFIC_BIT
                    | (1 << VIRTIO_F_RING_PACKED)
                    | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits())
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
                size: u32,
                _flags: VhostUserConfigFlags,
                _buf: &[u8],
            ) -> Result<(VhostUserConfig, VhostUserConfigPayload), vhost::Error> {
                Ok((VhostUserConfig::default(), vec![0; size as usize]))
            }
        }

        let (_tmp_dir, tmp_socket_path) = create_tmp_socket();
        let device =
            VhostUserGenericImpl::<MockFeatures>::new(default_config(tmp_socket_path)).unwrap();

        // The device type is the backend's business, so its features have to
        // reach the guest or the guest cannot use the device as configured.
        assert_ne!(device.vu_device.avail_features & DEVICE_SPECIFIC_BIT, 0);

        // Except the ones the frontend itself would have to implement.
        assert_eq!(
            device.vu_device.avail_features & (1 << VIRTIO_F_RING_PACKED),
            0
        );
    }

    #[test]
    fn test_configured_config_space_size_is_used() {
        /// Answers with as many bytes as were asked for, so the size the
        /// device ends up with is the size it requested.
        struct MockSized;

        impl VhostUserHandleBackend for MockSized {
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
                size: u32,
                _flags: VhostUserConfigFlags,
                _buf: &[u8],
            ) -> Result<(VhostUserConfig, VhostUserConfigPayload), vhost::Error> {
                Ok((VhostUserConfig::default(), vec![0; size as usize]))
            }
        }

        let (_tmp_dir, tmp_socket_path) = create_tmp_socket();
        let device = VhostUserGenericImpl::<MockSized>::new(VhostUserDeviceConfig {
            config_space_size: Some(44),
            ..default_config(tmp_socket_path)
        })
        .unwrap();

        // A device type whose config space is smaller than the default can be
        // served without the backend having to pad its reply.
        assert_eq!(device.config_space_size, 44);
        assert_eq!(device.vu_device.config_space.len(), 44);
    }

    fn default_config(socket: String) -> VhostUserDeviceConfig {
        VhostUserDeviceConfig {
            id: "test_device".to_string(),
            device_type: 26, // VIRTIO_ID_FS
            socket,
            num_queues: 2,
            queue_size: None,
            config_space_size: None,
        }
    }

    #[test]
    fn test_new_no_features() {
        struct MockMaster {
            _sock: UnixStream,
            _max_queue_num: u64,
            is_owner: std::cell::UnsafeCell<bool>,
            hdr_flags: std::cell::UnsafeCell<VhostUserHeaderFlag>,
        }

        impl VhostUserHandleBackend for MockMaster {
            fn from_stream(sock: UnixStream, max_queue_num: u64) -> Self {
                Self {
                    _sock: sock,
                    _max_queue_num: max_queue_num,
                    is_owner: std::cell::UnsafeCell::new(false),
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
                Ok(0)
            }

            fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures, vhost::Error> {
                Ok(VhostUserProtocolFeatures::empty())
            }

            fn set_protocol_features(
                &mut self,
                features: VhostUserProtocolFeatures,
            ) -> Result<(), vhost::Error> {
                let _ = features;
                Ok(())
            }
        }

        impl MutEventSubscriber for VhostUserGenericImpl<MockMaster> {
            fn process(&mut self, _: Events, _: &mut EventOps) {}
            fn init(&mut self, _: &mut EventOps) {}
        }

        let (_tmp_dir, tmp_socket_path) = create_tmp_socket();

        // Backend without CONFIG feature must return an error.
        let err =
            VhostUserGenericImpl::<MockMaster>::new(default_config(tmp_socket_path)).unwrap_err();
        assert!(matches!(
            err,
            VhostUserGenericError::ConfigFeatureNotNegotiated
        ));
    }

    #[test]
    fn test_new_all_features() {
        struct MockMaster {
            sock: UnixStream,
            max_queue_num: u64,
            is_owner: std::cell::UnsafeCell<bool>,
            protocol_features: VhostUserProtocolFeatures,
            hdr_flags: std::cell::UnsafeCell<VhostUserHeaderFlag>,
        }

        impl VhostUserHandleBackend for MockMaster {
            fn from_stream(sock: UnixStream, max_queue_num: u64) -> Self {
                Self {
                    sock,
                    max_queue_num,
                    is_owner: std::cell::UnsafeCell::new(false),
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
                Ok(AVAILABLE_FEATURES)
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
                let mut config = vec![0x01, 0x02, 0x03];
                config.resize(size as usize, 0);
                Ok((VhostUserConfig::default(), config))
            }
        }

        impl MutEventSubscriber for VhostUserGenericImpl<MockMaster> {
            fn process(&mut self, _: Events, _: &mut EventOps) {}
            fn init(&mut self, _: &mut EventOps) {}
        }

        let (_tmp_dir, tmp_socket_path) = create_tmp_socket();
        let device =
            VhostUserGenericImpl::<MockMaster>::new(default_config(tmp_socket_path.clone()))
                .unwrap();

        // Connected to the socket it was configured with, as the block
        // device's equivalent test checks.
        assert_eq!(
            device
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
        assert!(unsafe { *device.vu_device.vu_handle.vu.is_owner.get() });
        assert_eq!(device.vu_device.vu_handle.vu.max_queue_num, 2);
        assert_eq!(device.vu_device.avail_features, AVAILABLE_FEATURES);
        assert_eq!(
            device.vu_device.acked_features,
            VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
        );
        assert_eq!(
            device.vu_device.config_space.len(),
            DEFAULT_CONFIG_SPACE_SIZE as usize
        );
        assert_eq!(&device.vu_device.config_space[..3], &[0x01, 0x02, 0x03]);
        assert_eq!(device.device_type_id, 26);
        assert_eq!(device.vu_device.queues.len(), 2);
        assert_eq!(device.vu_device.queue_evts.len(), 2);

        // VirtioDevice trait methods
        assert_eq!(device.id(), "test_device");
        assert_eq!(device.device_type(), VirtioDeviceType::VhostUserGeneric);
        assert_eq!(device.virtio_device_type_id(), 26);

        // Valid read
        let mut buf = vec![0u8; 3];
        device.read_config(0, &mut buf);
        assert_eq!(buf, vec![0x01, 0x02, 0x03]);

        // Straddling the end zeroes the part the config space does not cover,
        // rather than leaving whatever the caller's buffer held.
        let mut buf = vec![0xAAu8; 3];
        device.read_config(u64::from(DEFAULT_CONFIG_SPACE_SIZE) - 1, &mut buf);
        assert_eq!(buf, vec![0, 0, 0]);

        // Wholly past the end zeroes all of it, and 0xFF is deliberately not
        // used as the offset here: it is still inside a 256 byte config space.
        let mut buf = vec![0xAAu8; 3];
        device.read_config(u64::from(DEFAULT_CONFIG_SPACE_SIZE), &mut buf);
        assert_eq!(buf, vec![0, 0, 0]);

        // Write is a no-op
        let mut device = device;
        device.write_config(0, &[0xFF]);
        assert_eq!(
            device.vu_device.config_space.len(),
            DEFAULT_CONFIG_SPACE_SIZE as usize
        );
        assert_eq!(&device.vu_device.config_space[..3], &[0x01, 0x02, 0x03]);
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
                // Must include PROTOCOL_FEATURES so that protocol feature
                // negotiation (including CONFIG) takes place.
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
                size: u32,
                _flags: VhostUserConfigFlags,
                _buf: &[u8],
            ) -> Result<(VhostUserConfig, VhostUserConfigPayload), vhost::Error> {
                Ok((VhostUserConfig::default(), vec![0; size as usize]))
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

        impl MutEventSubscriber for VhostUserGenericImpl<MockMaster> {
            fn process(&mut self, _: Events, _: &mut EventOps) {}
            fn init(&mut self, _: &mut EventOps) {}
        }

        let (_tmp_dir, tmp_socket_path) = create_tmp_socket();
        let mut device =
            VhostUserGenericImpl::<MockMaster>::new(default_config(tmp_socket_path)).unwrap();

        let region_size = 0x10000;
        let file = TempFile::new().unwrap().into_file();
        file.set_len(region_size as u64).unwrap();
        let regions = vec![(GuestAddress(0x0), region_size)];
        let guest_memory = create_mem(file, &regions);

        for q in device.vu_device.queues.iter_mut() {
            let vq = VirtQueue::new(GuestAddress(0), &guest_memory, 16);
            *q = vq.create_queue();
        }

        let interrupt = default_interrupt();
        device.activate(guest_memory, interrupt).unwrap();

        assert!(unsafe { *device.vu_device.vu_handle.vu.features_are_set.get() });
        assert!(unsafe { *device.vu_device.vu_handle.vu.memory_is_set.get() });
        assert!(unsafe { *device.vu_device.vu_handle.vu.vring_enabled.get() });
        assert!(device.is_activated());
    }

    #[test]
    fn test_new_rejects_zero_queues() {
        let mut config = default_config("/nonexistent.sock".to_string());
        config.num_queues = 0;

        // Rejected before any backend connection is attempted.
        let err = VhostUserGeneric::new(config).unwrap_err();
        assert!(matches!(err, VhostUserGenericError::InvalidNumQueues(0)));
    }

    #[test]
    fn test_activate_skips_unready_queues() {
        // Records the vring indices enabled on the backend during activation.
        struct MockMaster {
            enabled_queues: std::cell::UnsafeCell<Vec<usize>>,
        }

        impl VhostUserHandleBackend for MockMaster {
            fn from_stream(_sock: UnixStream, _max_queue_num: u64) -> Self {
                Self {
                    enabled_queues: std::cell::UnsafeCell::new(Vec::new()),
                }
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
                size: u32,
                _flags: VhostUserConfigFlags,
                _buf: &[u8],
            ) -> Result<(VhostUserConfig, VhostUserConfigPayload), vhost::Error> {
                Ok((VhostUserConfig::default(), vec![0; size as usize]))
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
                queue_index: usize,
                enable: bool,
            ) -> Result<(), vhost::Error> {
                if enable {
                    unsafe { (*self.enabled_queues.get()).push(queue_index) };
                }
                Ok(())
            }
        }

        impl MutEventSubscriber for VhostUserGenericImpl<MockMaster> {
            fn process(&mut self, _: Events, _: &mut EventOps) {}
            fn init(&mut self, _: &mut EventOps) {}
        }

        let (_tmp_dir, tmp_socket_path) = create_tmp_socket();
        let mut config = default_config(tmp_socket_path);
        config.num_queues = 3;
        let mut device = VhostUserGenericImpl::<MockMaster>::new(config).unwrap();

        let region_size = 0x10000;
        let file = TempFile::new().unwrap().into_file();
        file.set_len(region_size as u64).unwrap();
        let regions = vec![(GuestAddress(0x0), region_size)];
        let guest_memory = create_mem(file, &regions);

        // The guest initialises queues 0 and 2 but leaves queue 1 unready,
        // mirroring a driver that uses fewer queues than the frontend was
        // configured with, so the unready one has to be skipped rather than
        // initialized, which would abort activation with NotReady.
        for i in [0, 2] {
            let vq = VirtQueue::new(GuestAddress(0), &guest_memory, 16);
            device.vu_device.queues[i] = vq.create_queue();
        }
        assert!(!device.vu_device.queues[1].ready);

        let interrupt = default_interrupt();
        device.activate(guest_memory, interrupt).unwrap();

        // Only the ready queues are set up, at their real vring indices.
        let enabled = unsafe { (*device.vu_device.vu_handle.vu.enabled_queues.get()).clone() };
        assert_eq!(enabled, vec![0, 2]);
        assert!(device.is_activated());
    }
}
