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
use vm_memory::GuestAddress;
use vmm_sys_util::eventfd::EventFd;

use super::pci::device_status;
use super::{VirtioInterrupt, VirtioInterruptType};
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_IOMMU_PLATFORM;
use crate::logger::{debug, error, info, warn};
use crate::nitro_enclave::dmb::Dmb;
use crate::nitro_enclave::info_page::InfoPage;
use crate::nitro_enclave::ne_ioctl::{self, EnclaveFd, NeAddDevice};
use crate::vstate::interrupts::InterruptError;
use crate::vstate::memory::GuestMemoryMmap;

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
            }
            VirtioInterruptType::Config => {
                // No-op: unlike the MSI-X transport (which fires a config
                // vector), the enclave has no config-change interrupt path.
                // Config changes are pushed to the enclave via the
                // NE_UPDATE_DEVICE_CONFIG ioctl, not the per-queue call fds.
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
    /// Confidential mode: device DMAs into a per-device DMB.
    Dmb(Dmb),
}

impl DeviceDmaMemory {
    /// The guest memory the device reads/writes virtqueues from, in either mode.
    fn memory(&self) -> &GuestMemoryMmap {
        match self {
            DeviceDmaMemory::GuestMemory(mem) => mem,
            DeviceDmaMemory::Dmb(dmb) => dmb.guest_memory(),
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
                avail |= 1u64 << VIRTIO_F_IOMMU_PLATFORM;
            }
            req.device_features[..8].copy_from_slice(&avail.to_le_bytes());

            locked_device
                .queue_events()
                .iter()
                .map(|fd| fd.as_raw_fd())
                .collect()
        };

        // If DMA targets a DMB, register it as a shared-memory backing range so
        // the enclave can place queue DMA in it. `shm_region` outlives the
        // NE_ADD_DEVICE ioctl below, since `req.shm_regions_ptr` aliases it.
        let shm_region = match &self.dma_memory {
            DeviceDmaMemory::Dmb(dmb) => Some(ne_ioctl::NeShmRegion {
                shm_id: ne_ioctl::VIRTIO_SHMEM_ID_DMB,
                reserved: [0; 7],
                userspace_addr: dmb.host_addr(),
                size: dmb.size(),
            }),
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

        // Wire eventfds: KICK (enclave → device backend) and CALL (parent → enclave MSI-X).
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

        info!(
            "DRIVER_OK detected for device uid={}, activating",
            self.device_uid
        );

        let mut locked_device = self.device.lock().expect("Poisoned lock");

        // Set acked features from the mirror.
        let driver_features = mirror.driver_features;
        let avail = locked_device.avail_features();
        locked_device.set_acked_features(driver_features & avail);

        // Configure each queue from the mirror. In the enclave model the guest's
        // negotiated queue config arrives via the info-page mirror rather than
        // trapped MMIO/PCI register writes, so the parent must copy size/addresses
        // into the `Queue` structs here before `activate()`. This is the enclave
        // equivalent of the MMIO/PCI transports' queue-register write handlers;
        // the values are validated by `Queue::initialize()` inside `activate()`.
        let queues = locked_device.queues_mut();
        for (i, queue) in queues.iter_mut().enumerate().take(self.num_vqs as usize) {
            let qm = &mirror.queue[i];
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
                for evt in locked_device.queue_events() {
                    let _ = evt.write(1);
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
        DEVICE_ENTRY_MIN_SIZE, TestPageBuilder, test_device_mirror,
    };
    use crate::test_utils::single_region_mem;

    fn ne_transport(info_page: InfoPage, device_uid: u64) -> NeTransport {
        let device = Arc::new(Mutex::new(DummyDevice::new()));
        let memory = single_region_mem(0x1000);
        let mut transport = NeTransport::new(
            device,
            DeviceDmaMemory::GuestMemory(memory),
            Arc::new(info_page),
            VirtioDeviceType::Rng,
            1,
        )
        .unwrap();
        transport.device_uid = device_uid;
        transport
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
}
