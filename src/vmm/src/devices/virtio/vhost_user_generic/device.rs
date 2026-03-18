// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;
use std::sync::Arc;

use log::error;
use utils::time::{ClockType, get_time_us};
use vhost::vhost_user::Frontend;
use vhost::vhost_user::message::*;
use vmm_sys_util::eventfd::EventFd;

use super::{QUEUE_SIZE, VhostUserGenericError};
use crate::MutEventSubscriber;
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::Queue;
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::devices::virtio::vhost_user::{VhostUserHandleBackend, VhostUserHandleImpl};
use crate::devices::virtio::vhost_user_metrics::{
    VhostUserDeviceMetrics, VhostUserMetricsPerDevice,
};
use crate::logger::{IncMetric, StoreMetric, log_dev_preview_warning};
use crate::utils::u64_to_usize;
use crate::vmm_config::vhost_user_device::VhostUserDeviceConfig;
use crate::vstate::memory::GuestMemoryMmap;

/// Maximum config space size in bytes. Used as the upper bound when fetching
/// config space from the backend. The backend may return fewer bytes.
const MAX_CONFIG_SPACE_SIZE: u32 = 256;

const AVAILABLE_FEATURES: u64 = (1 << VIRTIO_F_VERSION_1)
    | (1 << VIRTIO_RING_F_EVENT_IDX)
    // vhost-user specific bit. Not defined in standard virtio spec.
    // Specifies ability of frontend to negotiate protocol features.
    | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

pub type VhostUserGeneric = VhostUserGenericImpl<Frontend>;

/// Generic vhost-user frontend device.
///
/// Unlike per-device-type vhost-user frontends, this device knows nothing
/// about the specific virtio device type being implemented. The backend is
/// fully responsible for handling the configuration space. This allows using
/// device types that Firecracker would never support natively (e.g. virtiofsd,
/// SPDK vhost-user-blk) without requiring a dedicated frontend for each.
pub struct VhostUserGenericImpl<T: VhostUserHandleBackend> {
    // Virtio fields.
    pub avail_features: u64,
    pub acked_features: u64,
    /// Config space fetched from the backend via the CONFIG protocol feature.
    pub config_space: Vec<u8>,
    pub activate_evt: EventFd,

    // Transport related fields.
    pub queues: Vec<Queue>,
    pub queue_evts: Vec<EventFd>,
    pub device_state: DeviceState,

    // Implementation specific fields.
    pub id: String,
    /// The raw virtio device type ID written to the MMIO device type register.
    /// Stored separately because VirtioDeviceType::VhostUserGeneric is used
    /// as the host-side map key while the guest must see the real device type.
    pub device_type_id: u32,

    // Vhost user protocol handle.
    pub vu_handle: VhostUserHandleImpl<T>,
    pub vu_acked_protocol_features: u64,
    pub metrics: Arc<VhostUserDeviceMetrics>,
}

// Need custom implementation because otherwise `Debug` is required for `vhost::Master`
impl<T: VhostUserHandleBackend> std::fmt::Debug for VhostUserGenericImpl<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VhostUserGenericImpl")
            .field("avail_features", &self.avail_features)
            .field("acked_features", &self.acked_features)
            .field("config_space", &self.config_space)
            .field("activate_evt", &self.activate_evt)
            .field("queues", &self.queues)
            .field("queue_evts", &self.queue_evts)
            .field("device_state", &self.device_state)
            .field("id", &self.id)
            .field("device_type_id", &self.device_type_id)
            .field("vu_handle", &self.vu_handle)
            .field(
                "vu_acked_protocol_features",
                &self.vu_acked_protocol_features,
            )
            .field("metrics", &self.metrics)
            .finish()
    }
}

impl<T: VhostUserHandleBackend> VhostUserGenericImpl<T> {
    pub fn new(config: VhostUserDeviceConfig) -> Result<Self, VhostUserGenericError> {
        log_dev_preview_warning("generic vhost-user device", Option::None);
        let start_time = get_time_us(ClockType::Monotonic);

        let requested_protocol_features = VhostUserProtocolFeatures::CONFIG;

        let mut vu_handle =
            VhostUserHandleImpl::<T>::new(&config.socket, config.num_queues)
                .map_err(VhostUserGenericError::VhostUser)?;
        let (acked_features, acked_protocol_features) = vu_handle
            .negotiate_features(AVAILABLE_FEATURES, requested_protocol_features)
            .map_err(VhostUserGenericError::VhostUser)?;

        // The CONFIG protocol feature is required: the backend is responsible
        // for the entire config space and we have no device-specific fallback.
        if acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
            return Err(VhostUserGenericError::ConfigFeatureNotNegotiated);
        }

        // Fetch the config space from the backend.
        let buffer = [0u8; MAX_CONFIG_SPACE_SIZE as usize];
        let (_, config_space) = vu_handle
            .vu
            .get_config(0, MAX_CONFIG_SPACE_SIZE, VhostUserConfigFlags::WRITABLE, &buffer)
            .map_err(VhostUserGenericError::Vhost)?;

        let activate_evt =
            EventFd::new(libc::EFD_NONBLOCK).map_err(VhostUserGenericError::EventFd)?;

        let num_queues = config.num_queues as usize;
        let queues = vec![Queue::new(config.queue_size.unwrap_or(QUEUE_SIZE)); num_queues];
        let queue_evts = (0..num_queues)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK).map_err(VhostUserGenericError::EventFd))
            .collect::<Result<Vec<_>, _>>()?;
        let device_state = DeviceState::Inactive;

        // We negotiated features with the backend. Now these acked_features
        // are available for the guest driver to choose from.
        let avail_features = acked_features;
        let acked_features = acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let metrics_name = format!("vhost_user_generic_{}", config.id);
        let metrics = VhostUserMetricsPerDevice::alloc(metrics_name);
        let delta_us = get_time_us(ClockType::Monotonic) - start_time;
        metrics.init_time_us.store(delta_us);

        Ok(Self {
            avail_features,
            acked_features,
            config_space,
            activate_evt,

            queues,
            queue_evts,
            device_state,

            id: config.id,
            device_type_id: u32::from(config.device_type),

            vu_handle,
            vu_acked_protocol_features: acked_protocol_features,
            metrics,
        })
    }

    /// Prepare device for being snapshotted.
    pub fn prepare_save(&mut self) {
        unimplemented!("VhostUserGeneric does not support snapshotting yet");
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
    fn mmio_device_type_id(&self) -> u32 {
        self.device_type_id
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
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

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .deref()
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
        // Config space is owned entirely by the backend. Writes from the
        // guest driver are forwarded to the backend via the CONFIG protocol
        // feature in a future implementation.
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

        let start_time = get_time_us(ClockType::Monotonic);

        let queue_refs: Vec<(usize, &Queue, &EventFd)> = self
            .queues
            .iter()
            .zip(self.queue_evts.iter())
            .enumerate()
            .map(|(i, (q, ev))| (i, q, ev))
            .collect();

        // Setting features again, because now we negotiated them
        // with the guest driver as well.
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
        let delta_us = get_time_us(ClockType::Monotonic) - start_time;
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

    use event_manager::{EventOps, Events, MutEventSubscriber};
    use vhost::{VhostUserMemoryRegionInfo, VringConfigData};
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::devices::virtio::vhost_user::tests::create_mem;
    use crate::test_utils::create_tmp_socket;
    use crate::vstate::memory::GuestAddress;

    fn default_config(socket: String) -> VhostUserDeviceConfig {
        VhostUserDeviceConfig {
            id: "test_device".to_string(),
            device_type: 26, // VIRTIO_ID_FS
            socket,
            num_queues: 2,
            queue_size: None,
        }
    }

    #[test]
    fn test_new_no_features() {
        struct MockMaster {
            sock: UnixStream,
            max_queue_num: u64,
            is_owner: std::cell::UnsafeCell<bool>,
            hdr_flags: std::cell::UnsafeCell<VhostUserHeaderFlag>,
        }

        impl VhostUserHandleBackend for MockMaster {
            fn from_stream(sock: UnixStream, max_queue_num: u64) -> Self {
                Self {
                    sock,
                    max_queue_num,
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

            fn get_protocol_features(
                &mut self,
            ) -> Result<VhostUserProtocolFeatures, vhost::Error> {
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
        let err = VhostUserGenericImpl::<MockMaster>::new(default_config(tmp_socket_path))
            .unwrap_err();
        assert!(matches!(err, VhostUserGenericError::ConfigFeatureNotNegotiated));
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

            fn get_protocol_features(
                &mut self,
            ) -> Result<VhostUserProtocolFeatures, vhost::Error> {
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
                Ok((VhostUserConfig::default(), vec![0x01, 0x02, 0x03]))
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

        assert!(unsafe { *device.vu_handle.vu.is_owner.get() });
        assert_eq!(device.vu_handle.vu.max_queue_num, 2);
        assert_eq!(device.avail_features, AVAILABLE_FEATURES);
        assert_eq!(
            device.acked_features,
            VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
        );
        assert_eq!(device.config_space, vec![0x01, 0x02, 0x03]);
        assert_eq!(device.device_type_id, 26);
        assert_eq!(device.queues.len(), 2);
        assert_eq!(device.queue_evts.len(), 2);

        // VirtioDevice trait methods
        assert_eq!(device.id(), "test_device");
        assert_eq!(device.device_type(), VirtioDeviceType::VhostUserGeneric);
        assert_eq!(device.mmio_device_type_id(), 26);

        // Valid read
        let mut buf = vec![0u8; 3];
        device.read_config(0, &mut buf);
        assert_eq!(buf, vec![0x01, 0x02, 0x03]);

        // Out-of-bounds offset returns zeroes
        let mut buf = vec![0u8; 3];
        device.read_config(0xFF, &mut buf);
        assert_eq!(buf, vec![0, 0, 0]);

        // Write is a no-op
        let mut device = device;
        device.write_config(0, &[0xFF]);
        assert_eq!(device.config_space, vec![0x01, 0x02, 0x03]);
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

            fn get_protocol_features(
                &mut self,
            ) -> Result<VhostUserProtocolFeatures, vhost::Error> {
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

            fn set_vring_base(
                &self,
                _queue_index: usize,
                _base: u16,
            ) -> Result<(), vhost::Error> {
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

        for q in device.queues.iter_mut() {
            let vq = VirtQueue::new(GuestAddress(0), &guest_memory, 16);
            *q = vq.create_queue();
        }

        let interrupt = default_interrupt();
        device.activate(guest_memory, interrupt).unwrap();

        assert!(unsafe { *device.vu_handle.vu.features_are_set.get() });
        assert!(unsafe { *device.vu_handle.vu.memory_is_set.get() });
        assert!(unsafe { *device.vu_handle.vu.vring_enabled.get() });
        assert!(device.is_activated());
    }
}
