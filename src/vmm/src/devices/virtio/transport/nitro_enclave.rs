// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclave transport for VirtIO devices passed to enclaves.
//!
//! This module implements the enclave device model where the parent VMM
//! provides virtio devices to an enclave through Nitro Enclave ioctls
//! (`NE_ADD_DEVICE`, `NE_SET_VRING_CALL`, `NE_SET_VRING_KICK`) and a shared
//! info page.
//!
//! The `NeTransport` wraps a `VirtioDevice` and bridges it to the enclave,
//! parallel to `MmioTransport` and `VirtioPciDevice`.

use std::fmt::Debug;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};

use event_manager::{EventOps, Events, MutEventSubscriber};
use vm_memory::{GuestAddress, GuestMemoryBackend, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

use super::pci::device_status;
use super::{VirtioInterrupt, VirtioInterruptType};
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_IOMMU_PLATFORM;
use crate::logger::{IncMetric, METRICS, debug, error, info, warn};
use crate::nitro_enclave::info_page::InfoPage;
use crate::nitro_enclave::ne_ioctl::{self, EnclaveFd, NeAddDevice};
use crate::vstate::interrupts::InterruptError;
use crate::vstate::memory::GuestMemoryMmap;

/// The feature bit a guest must ack for its DMA to be routed through an IOMMU,
/// which is how a confidential enclave reaches its DMB.
const IOMMU_PLATFORM_FEATURE: u64 = 1u64 << VIRTIO_F_IOMMU_PLATFORM;

/// Virtio device status bits indicating the guest driver has fully initialized
/// the device (`ACKNOWLEDGE | DRIVER | FEATURES_OK | DRIVER_OK`).
const VIRTIO_STATUS_DRIVER_OK: u8 = device_status::ACKNOWLEDGE
    | device_status::DRIVER
    | device_status::FEATURES_OK
    | device_status::DRIVER_OK;

/// Errors from Nitro Enclave transport operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum NeTransportError {
    /// Failed to create eventfd: {0}
    EventFd(std::io::Error),
    /// NE_ADD_DEVICE ioctl failed: {0}
    AddDevice(std::io::Error),
    /// NE_SET_VRING_CALL ioctl failed: {0}
    SetVringCall(std::io::Error),
    /// NE_SET_VRING_KICK ioctl failed: {0}
    SetVringKick(std::io::Error),
    /// NE_SET_INFO_EVENT_FD ioctl failed: {0}
    SetInfoEventFd(std::io::Error),
    /// Device reports {0} queues, exceeding NE_MAX_VQS (64)
    TooManyQueues(usize),
    /// Device config is {0} bytes, exceeding NE_DEVICE_CONFIG_MAX_SIZE (256)
    ConfigTooLarge(usize),
    /// NE_UPDATE_DEVICE_CONFIG ioctl failed: {0}
    UpdateDeviceConfig(std::io::Error),
}

/// VirtioInterrupt implementation for Nitro Enclave devices.
///
/// Writes to "call" eventfds, which the Nitro Enclave driver delivers as
/// MSI-X interrupts to the enclave guest.
#[derive(Debug)]
pub struct NeInterrupt {
    call_fds: Vec<EventFd>,
    status: Arc<AtomicU32>,
}

impl VirtioInterrupt for NeInterrupt {
    fn trigger(&self, int_type: VirtioInterruptType) -> Result<(), InterruptError> {
        match int_type {
            VirtioInterruptType::Queue(idx) => {
                // Like the MSI-X transport, treat an out-of-range queue index as
                // an error rather than silently dropping the interrupt.
                let fd = self
                    .call_fds
                    .get(idx as usize)
                    .ok_or(InterruptError::InvalidVectorIndex(idx as usize))?;
                fd.write(1).map_err(InterruptError::Io)?;
                METRICS.interrupts.triggers.inc();
            }
            VirtioInterruptType::Config => {
                // No-op: unlike the MSI-X transport (which fires a config
                // vector), the enclave has no config-change interrupt path.
                // Config changes are pushed to the enclave via
                // NE_UPDATE_DEVICE_CONFIG, driven synchronously from the API
                // path (PATCH /drives).
            }
        }
        Ok(())
    }

    fn status(&self) -> Arc<AtomicU32> {
        self.status.clone()
    }

    #[cfg(test)]
    fn has_pending_interrupt(&self, _interrupt_type: VirtioInterruptType) -> bool {
        false
    }

    #[cfg(test)]
    fn ack_interrupt(&self, _interrupt_type: VirtioInterruptType) {}
}

/// The DMA memory an enclave device reads/writes virtqueues from, and the mode
/// that choice implies.
///
/// In direct mode the device DMAs straight into the donated enclave RAM, which
/// the parent shares with the enclave. In confidential mode the enclave RAM is
/// isolated, so the device DMAs into a per-device DMB instead; the enclave
/// guest negotiates `VIRTIO_F_IOMMU_PLATFORM` to route its DMA there.
#[derive(Debug)]
pub enum DeviceDmaMemory {
    /// Direct mode: device DMAs into the donated enclave RAM (shared with parent).
    GuestMemory(GuestMemoryMmap),
    /// Confidential mode: device DMAs into a per-device DMB (a single CMA region
    /// at `GuestAddress(0)`, shared with the enclave).
    Dmb(GuestMemoryMmap),
}

impl DeviceDmaMemory {
    /// The guest memory the device reads/writes virtqueues from, in either mode.
    fn memory(&self) -> &GuestMemoryMmap {
        match self {
            DeviceDmaMemory::GuestMemory(mem) | DeviceDmaMemory::Dmb(mem) => mem,
        }
    }
}

/// Nitro Enclave transport wrapping a VirtioDevice for an enclave.
///
/// Unlike MMIO/PCI transports where KVM routes guest MMIO writes directly
/// to device eventfds via `register_ioevent`, this transport wires the
/// device's own `queue_events` fds to the Nitro Enclave driver via
/// `NE_SET_VRING_KICK`.
#[derive(Debug)]
pub struct NeTransport {
    device: Arc<Mutex<dyn VirtioDevice>>,
    dma_memory: DeviceDmaMemory,
    interrupt: Arc<NeInterrupt>,
    device_uid: u64,
    num_vqs: u32,
    info_page: Arc<InfoPage>,
    info_event_fd: EventFd,
    virtio_devid: VirtioDeviceType,
}

impl NeTransport {
    /// Create a new NE transport for the given device.
    pub fn new(
        device: Arc<Mutex<dyn VirtioDevice>>,
        dma_memory: DeviceDmaMemory,
        info_page: Arc<InfoPage>,
        virtio_devid: VirtioDeviceType,
        num_vqs: u32,
    ) -> Result<Self, NeTransportError> {
        let num_vqs_usize = num_vqs as usize;
        if num_vqs_usize > ne_ioctl::NE_MAX_VQS {
            return Err(NeTransportError::TooManyQueues(num_vqs_usize));
        }

        // The per-VQ "call" eventfds are owned by the interrupt; the parent
        // writes them and the NE driver delivers each as an MSI-X to the enclave.
        let mut call_fds = Vec::with_capacity(num_vqs_usize);
        for _ in 0..num_vqs {
            call_fds.push(EventFd::new(libc::EFD_NONBLOCK).map_err(NeTransportError::EventFd)?);
        }

        let interrupt = Arc::new(NeInterrupt {
            call_fds,
            status: Arc::new(AtomicU32::new(0)),
        });

        let info_event_fd = EventFd::new(libc::EFD_NONBLOCK).map_err(NeTransportError::EventFd)?;

        Ok(Self {
            device,
            dma_memory,
            interrupt,
            device_uid: 0,
            num_vqs,
            info_page,
            info_event_fd,
            virtio_devid,
        })
    }

    /// Register the device with the enclave via NE_ADD_DEVICE and wire eventfds.
    ///
    /// Must be called before `NE_START_ENCLAVE`.
    pub fn register_device(&mut self, enclave_fd: &EnclaveFd) -> Result<(), NeTransportError> {
        let mut req = NeAddDevice {
            device_type: self.virtio_devid as u32,
            num_vqs: self.num_vqs,
            ..Default::default()
        };

        let kick_fds: Vec<i32> = {
            let locked_device = self.device.lock().expect("Poisoned lock");

            // Populate device config from the wrapped device. The enclave config
            // region is fixed-size; fail rather than silently truncate.
            let config = locked_device.config_as_bytes();
            if config.len() > ne_ioctl::NE_DEVICE_CONFIG_MAX_SIZE {
                return Err(NeTransportError::ConfigTooLarge(config.len()));
            }
            req.device_config[..config.len()].copy_from_slice(config);
            req.config_size = u32::try_from(config.len()).expect("config_size overflow");

            // Populate device features (first 8 bytes of the 512-bit bitmap).
            // When DMA targets a DMB, advertise VIRTIO_F_IOMMU_PLATFORM so the
            // enclave guest routes its DMA there.
            let mut avail = locked_device.avail_features();
            if let DeviceDmaMemory::Dmb(_) = self.dma_memory {
                avail |= IOMMU_PLATFORM_FEATURE;
            }
            req.device_features[..8].copy_from_slice(&avail.to_le_bytes());

            (0..locked_device.num_queues())
                .map(|i| {
                    locked_device
                        .queue_event(i)
                        .expect("queue event must exist for each advertised queue")
                        .as_raw_fd()
                })
                .collect()
        };

        // If DMA targets a DMB, register it as a shared-memory backing range so
        // the enclave can place queue DMA in it. `shm_region` outlives the
        // NE_ADD_DEVICE ioctl below, since `req.shm_regions_ptr` aliases it.
        let shm_region = match &self.dma_memory {
            DeviceDmaMemory::Dmb(dmb) => {
                // The DMB is a single region at GuestAddress(0); register its
                // host mapping as the SHM backing range.
                let region = dmb
                    .find_region(GuestAddress(0))
                    .expect("DMB always has a region at GuestAddress(0)");
                Some(ne_ioctl::NeShmRegion {
                    shm_id: ne_ioctl::VIRTIO_SHMEM_ID_DMB,
                    reserved: [0; 7],
                    userspace_addr: region.as_ptr() as u64,
                    size: region.len(),
                })
            }
            DeviceDmaMemory::GuestMemory(_) => None,
        };
        if let Some(region) = &shm_region {
            // A pointer to the single region is a valid 1-element array pointer.
            req.num_shm_regions = 1;
            req.shm_regions_ptr = region as *const ne_ioctl::NeShmRegion as u64;
        }

        enclave_fd
            .add_device(&mut req)
            .map_err(NeTransportError::AddDevice)?;

        self.device_uid = req.device_uid;

        info!(
            "NE_ADD_DEVICE: devid={:?} uid={} num_vqs={} config_size={} \
             shm_regions={} info_event_vector={}",
            self.virtio_devid,
            self.device_uid,
            self.num_vqs,
            req.config_size,
            req.num_shm_regions,
            req.info_event_vector,
        );

        // Wire eventfds: KICK (enclave -> device backend) and CALL (parent -> enclave MSI-X).
        // `kick_fds`, `req.vq_info` and `call_fds` are all sized by `num_vqs`; an
        // index loop reads clearer here than zipping three slices.
        #[allow(clippy::needless_range_loop)]
        for i in 0..self.num_vqs as usize {
            let kick_fd = kick_fds[i];
            let vq_info = &req.vq_info[i];
            let call_fd = &self.interrupt.call_fds[i];

            enclave_fd
                .set_vring_kick(self.device_uid, vq_info.msix_entry, kick_fd)
                .map_err(NeTransportError::SetVringKick)?;

            enclave_fd
                .set_vring_call(
                    self.device_uid,
                    vq_info.bar4_doorbell_offset,
                    call_fd.as_raw_fd(),
                )
                .map_err(NeTransportError::SetVringCall)?;

            debug!(
                "  vq[{i}]: KICK fd={kick_fd} msix_entry={} CALL bar4_doorbell_offset={}",
                vq_info.msix_entry, vq_info.bar4_doorbell_offset,
            );
        }

        // Wire the info-event that triggers `activate_if_ready` (see `process`).
        // Every device gets a wired info-event; the vector is a mux VQ id and 0
        // is a valid value (there is no "absent" sentinel and no vector pool).
        enclave_fd
            .set_info_event_fd(req.info_event_vector, self.info_event_fd.as_raw_fd())
            .map_err(NeTransportError::SetInfoEventFd)?;

        Ok(())
    }

    /// Returns a reference to the inner virtio device.
    pub fn device(&self) -> &Arc<Mutex<dyn VirtioDevice>> {
        &self.device
    }

    /// Push the current device config space to the enclave mirror.
    pub(crate) fn update_device_config(
        &self,
        enclave_fd: &EnclaveFd,
    ) -> Result<(), NeTransportError> {
        let device = self.device.lock().expect("Poisoned lock");
        let config = device.config_as_bytes();

        enclave_fd
            .update_device_config(self.device_uid, 0, config)
            .map_err(NeTransportError::UpdateDeviceConfig)?;

        debug!(
            "pushed {}-byte config update for device uid={}",
            config.len(),
            self.device_uid
        );
        Ok(())
    }

    /// Activate the device if the enclave guest has signalled DRIVER_OK in the
    /// info-page mirror. Invoked on info-event fd readiness.
    fn activate_if_ready(&mut self) {
        // The info-event is fired by the untrusted enclave, which fully controls
        // the info page; a matching, valid device entry may not be published yet
        // (or ever). Treat a missing entry as "not ready" and wait, rather than
        // panicking the parent VMM event loop on enclave-controlled input.
        let Some(entry) = self.info_page.find_device_entry(self.device_uid) else {
            error!(
                "info-event for uid={} but no matching device entry yet; ignoring",
                self.device_uid
            );
            return;
        };
        let mirror = entry.mirror;

        // The guest driver must have fully initialized the device.
        // (copy out of the packed mirror struct before referencing)
        let device_status = mirror.common.device_status;
        if (device_status & VIRTIO_STATUS_DRIVER_OK) != VIRTIO_STATUS_DRIVER_OK {
            debug!(
                "device uid={} not yet DRIVER_OK (status={device_status:#04x})",
                self.device_uid
            );
            return;
        }

        let mut locked_device = self.device.lock().expect("Poisoned lock");

        let driver_features = mirror.driver_features;
        if matches!(self.dma_memory, DeviceDmaMemory::Dmb(_))
            && (driver_features & IOMMU_PLATFORM_FEATURE) == 0
        {
            error!(
                "Device uid={} did not negotiate VIRTIO_F_IOMMU_PLATFORM while its DMA \
                 targets a DMB; not activating (driver_features={driver_features:#x})",
                self.device_uid
            );
            return;
        }
        info!(
            "DRIVER_OK detected for device uid={}, activating",
            self.device_uid
        );

        // Set acked features from the mirror.
        let avail = locked_device.avail_features();
        locked_device.set_acked_features(driver_features & avail);

        // Configure each queue from the mirror. In the enclave model the guest's
        // negotiated queue config arrives via the info-page mirror rather than
        // trapped MMIO/PCI register writes, so the parent must copy size/addresses
        // into each queue's config here before `activate()`. This is the enclave
        // equivalent of the MMIO/PCI transports' queue-register write handlers;
        // the values are validated by `Queue::initialize()` inside `activate()`.
        let num_queues = locked_device.num_queues().min(self.num_vqs as usize);
        for (i, qm) in mirror.queue.iter().enumerate().take(num_queues) {
            let queue = locked_device
                .queue_config_mut(i)
                .expect("queue config must exist for each advertised queue");
            if qm.enable == 0 {
                // Leave the queue `ready = false`. All current enclave devices
                // have mandatory queues, so `activate()` -> `Queue::initialize()`
                // will fail cleanly with `NotReady` if the enclave left one
                // disabled. A device with genuinely optional queues would need
                // explicit handling here.
                continue;
            }
            queue.size = qm.size;
            queue.ready = true;
            queue.desc_table_address = GuestAddress(qm.desc);
            queue.avail_ring_address = GuestAddress(qm.driver);
            queue.used_ring_address = GuestAddress(qm.device);
        }

        // Activate the device.
        match locked_device.activate(self.dma_memory.memory().clone(), self.interrupt.clone()) {
            Ok(()) => {
                info!("Device uid={} activated successfully", self.device_uid);

                // Kick all queues in case the device sent any notifications to
                // us before we wired up the eventfds on our end. We must not
                // interrupt the guest here — only the device backend is poked.
                for i in 0..locked_device.num_queues() {
                    if let Some(evt) = locked_device.queue_event(i) {
                        let _ = evt.write(1);
                    }
                }
            }
            Err(e) => {
                error!("Failed to activate device uid={}: {e:?}", self.device_uid);
            }
        }
    }
}

impl MutEventSubscriber for NeTransport {
    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        if events.fd() == self.info_event_fd.as_raw_fd() {
            let _ = self.info_event_fd.read();
            if self.device.lock().expect("Poisoned lock").is_activated() {
                // The device is already activated; the info-event should not
                // fire again for it. Log and ignore.
                warn!(
                    "info-event fired for already-activated device uid={}",
                    self.device_uid
                );
                return;
            }
            self.activate_if_ready();
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        if let Err(e) = ops.add(Events::new(
            &self.info_event_fd,
            event_manager::EventSet::IN,
        )) {
            error!(
                "Failed to register info-event fd for device uid={}: {e}",
                self.device_uid
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::transport::mmio::tests::DummyDevice;
    use crate::nitro_enclave::info_page::{
        DEVICE_ENTRY_MIN_SIZE, TestPageBuilder, VirtioDeviceMirror, test_device_mirror,
    };
    use crate::test_utils::single_region_mem;

    // Two features the dummy device offers: a plain one, and IOMMU_PLATFORM.
    const PLAIN_FEATURE: u64 = 1;
    const IOMMU_FEATURE: u64 = IOMMU_PLATFORM_FEATURE;

    fn ne_transport_with(
        info_page: InfoPage,
        device_uid: u64,
        dma_memory: DeviceDmaMemory,
    ) -> NeTransport {
        let mut device = DummyDevice::new();
        // A real device never advertises IOMMU_PLATFORM itself: register_device
        // ORs it only into the copy sent to the enclave.
        device.set_avail_features(PLAIN_FEATURE);
        let mut transport = NeTransport::new(
            Arc::new(Mutex::new(device)),
            dma_memory,
            Arc::new(info_page),
            VirtioDeviceType::Rng,
            1,
        )
        .unwrap();
        transport.device_uid = device_uid;
        transport
    }

    fn ne_transport(info_page: InfoPage, device_uid: u64) -> NeTransport {
        let dma = DeviceDmaMemory::GuestMemory(single_region_mem(0x1000));
        ne_transport_with(info_page, device_uid, dma)
    }

    /// A mirror the guest driver has finished initialising, acking `driver_features`.
    fn driver_ok_mirror(device_uid: u64, driver_features: u64) -> VirtioDeviceMirror {
        let mut mirror = test_device_mirror(device_uid);
        mirror.common.device_status = VIRTIO_STATUS_DRIVER_OK;
        mirror.driver_features = driver_features;
        mirror
    }

    fn page_with(mirror: VirtioDeviceMirror) -> InfoPage {
        TestPageBuilder::new()
            .device_mirror(8192, DEVICE_ENTRY_MIN_SIZE, mirror)
            .build()
    }

    #[test]
    fn test_activate_if_ready_missing_mirror_no_panic() {
        // The info page has no device-config mirror at all. An enclave firing the
        // info-event without publishing a mirror must NOT panic the parent; the
        // device just stays un-activated.
        let page = TestPageBuilder::new().build();
        let mut transport = ne_transport(page, 7);
        transport.activate_if_ready();
        assert!(!transport.device.lock().unwrap().is_activated());
    }

    #[test]
    fn test_activate_if_ready_mismatched_uid_no_panic() {
        // A mirror exists, but for a different device_uid than this transport's.
        // find_device_entry returns None; the device must stay un-activated.
        let page = TestPageBuilder::new()
            .device_mirror(8192, DEVICE_ENTRY_MIN_SIZE, test_device_mirror(1))
            .build();
        let mut transport = ne_transport(page, 999);
        transport.activate_if_ready();
        assert!(!transport.device.lock().unwrap().is_activated());
    }

    #[test]
    fn test_activate_if_ready_dmb_requires_iommu_platform() {
        // Confidential mode: the device's DMA targets a DMB, but the guest driver
        // acked only a plain feature. Its DMA would not reach the DMB, so the
        // device must not activate -- and must not even get its acked features.
        let page = page_with(driver_ok_mirror(1, PLAIN_FEATURE));
        let dma = DeviceDmaMemory::Dmb(single_region_mem(0x1000));
        let mut transport = ne_transport_with(page, 1, dma);

        transport.activate_if_ready();

        let device = transport.device.lock().unwrap();
        assert!(!device.is_activated());
        assert_eq!(device.acked_features(), 0);
    }

    #[test]
    fn test_activate_if_ready_dmb_with_iommu_platform_proceeds() {
        // Same, but the driver acked VIRTIO_F_IOMMU_PLATFORM. The gate lets it
        // through, which is observable because set_acked_features runs after it.
        let page = page_with(driver_ok_mirror(1, PLAIN_FEATURE | IOMMU_FEATURE));
        let dma = DeviceDmaMemory::Dmb(single_region_mem(0x1000));
        let mut transport = ne_transport_with(page, 1, dma);

        transport.activate_if_ready();

        // The device does not offer the IOMMU bit, so it is masked out of the
        // acked set; reaching set_acked_features at all is what shows the gate
        // let this through.
        let device = transport.device.lock().unwrap();
        assert!(device.is_activated());
        assert_eq!(device.acked_features(), PLAIN_FEATURE);
    }

    #[test]
    fn test_activate_if_ready_direct_mode_ignores_iommu_platform() {
        // Direct mode: DMA targets the donated enclave RAM, so the gate does not
        // apply and the same driver_features that were rejected above proceed.
        let page = page_with(driver_ok_mirror(1, PLAIN_FEATURE));
        let dma = DeviceDmaMemory::GuestMemory(single_region_mem(0x1000));
        let mut transport = ne_transport_with(page, 1, dma);

        transport.activate_if_ready();

        let device = transport.device.lock().unwrap();
        assert!(device.is_activated());
        assert_eq!(device.acked_features(), PLAIN_FEATURE);
    }
}
