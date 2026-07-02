// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclave device manager.
//!
//! Manages Nitro Enclave transport devices, parallel to `MMIODeviceManager` and `PciDevices`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use event_manager::SubscriberOps;

use crate::EventManager;
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceId, VirtioDeviceType};
use crate::devices::virtio::transport::nitro_enclave::{
    DeviceDmaMemory, NeTransport, NeTransportError,
};
use crate::nitro_enclave::enclave_vm::{EnclaveVm, EnclaveVmError};
use crate::utils::{mib_to_bytes, u64_to_usize};

/// Errors from NE device manager operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum NeDeviceError {
    /// Failed to create NE transport: {0}
    Transport(#[from] NeTransportError),
    /// Failed to allocate DMB: {0}
    Dmb(#[from] EnclaveVmError),
}

/// Manages NE transport devices for enclaves.
#[derive(Debug, Default)]
pub struct NeDevices {
    devices: HashMap<VirtioDeviceId, Arc<Mutex<NeTransport>>>,
}

impl NeDevices {
    /// Attach a virtio device via the Nitro Enclave transport.
    ///
    /// This manager owns the attach orchestration (mirroring how
    /// `pci_mngr::attach_common` drives `register_notification_ioevent`):
    /// it constructs the transport, drives the host-side wiring via
    /// `NeTransport::register_device` (NE_ADD_DEVICE + eventfds), and registers
    /// the device backend and transport as event subscribers. The transport
    /// itself only owns the wiring primitive and post-DRIVER_OK activation.
    pub fn attach_ne_virtio_device(
        &mut self,
        device: Arc<Mutex<dyn VirtioDevice>>,
        enclave_vm: &EnclaveVm,
        dmb_size_mib: Option<u64>,
        event_manager: &mut EventManager,
    ) -> Result<(), NeDeviceError> {
        let (device_id, num_vqs) = {
            let locked = device.lock().expect("Poisoned lock");
            let num_vqs = u32::try_from(locked.queues().len()).expect("queue count exceeds u32");
            ((locked.device_type(), locked.id().to_string()), num_vqs)
        };

        // Installed by enclave_builder before any device is attached.
        let info_page = enclave_vm
            .info_page()
            .expect("info page must be installed before device attachment");

        // A DMB size selects confidential mode: allocate a per-device DMB and
        // use it as the device's DMA memory. No size selects direct mode: the
        // device uses the donated enclave RAM, which is accessible to the parent
        // only in that mode. The size is resolved and validated by the config
        // layer (bounded to at most 256 MiB), so it converts to bytes without
        // overflow.
        let dma_memory = match dmb_size_mib {
            Some(size_mib) => {
                let dmb = enclave_vm.create_dmb(mib_to_bytes(u64_to_usize(size_mib)))?;
                DeviceDmaMemory::Dmb(dmb)
            }
            None => {
                let memory = enclave_vm
                    .guest_memory()
                    .expect("direct mode keeps enclave guest memory for device DMA")
                    .clone();
                DeviceDmaMemory::GuestMemory(memory)
            }
        };

        let mut transport =
            NeTransport::new(device.clone(), dma_memory, info_page, device_id.0, num_vqs)?;

        // Wire the transport to the enclave: NE_ADD_DEVICE + eventfds.
        transport.register_device(enclave_vm.enclave_fd())?;

        // Register subscribers only after successful wiring.
        event_manager.add_subscriber(device);
        let transport = Arc::new(Mutex::new(transport));
        event_manager.add_subscriber(transport.clone());
        self.devices.insert(device_id, transport);
        Ok(())
    }

    pub(crate) fn get_device(
        &self,
        device_type: VirtioDeviceType,
        device_id: &str,
    ) -> Option<Arc<Mutex<dyn VirtioDevice>>> {
        self.devices
            .get(&(device_type, device_id.to_string()))
            .map(|transport| transport.lock().expect("Poisoned lock").device().clone())
    }

    pub(crate) fn contains_virtio_device(&self, device_id: &VirtioDeviceId) -> bool {
        self.devices.contains_key(device_id)
    }

    pub(crate) fn for_each_virtio_device(
        &self,
        mut f: impl FnMut(VirtioDeviceType, &dyn VirtioDevice),
    ) {
        for ((device_type, _), transport) in &self.devices {
            let device_arc = transport.lock().expect("Poisoned lock").device().clone();
            let device = device_arc.lock().expect("Poisoned lock");
            f(*device_type, &*device);
        }
    }

    pub(crate) fn for_each_virtio_device_mut(
        &self,
        mut f: impl FnMut(VirtioDeviceType, &mut dyn VirtioDevice),
    ) {
        for ((device_type, _), transport) in &self.devices {
            let device_arc = transport.lock().expect("Poisoned lock").device().clone();
            let mut device = device_arc.lock().expect("Poisoned lock");
            f(*device_type, &mut *device);
        }
    }
}
