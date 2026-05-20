// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nitro Enclave device manager.
//!
//! Manages Nitro Enclave transport devices, parallel to `MMIODeviceManager` and `PciDevices`.

use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use event_manager::{MutEventSubscriber, SubscriberOps};

use crate::EventManager;
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::transport::nitro_enclave::{NeTransport, NeTransportError};
use crate::nitro_enclave::enclave_vm::EnclaveVm;

/// Errors from NE device manager operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum NeDeviceError {
    /// Failed to create NE transport: {0}
    Transport(#[from] NeTransportError),
}

/// Manages NE transport devices for enclaves.
#[derive(Debug, Default)]
pub struct NeDevices {
    devices: Vec<Arc<Mutex<NeTransport>>>,
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
    pub fn attach_ne_virtio_device<T: 'static + VirtioDevice + MutEventSubscriber + Debug>(
        &mut self,
        device: Arc<Mutex<T>>,
        enclave_vm: &EnclaveVm,
        event_manager: &mut EventManager,
    ) -> Result<(), NeDeviceError> {
        let (virtio_devid, num_vqs) = {
            let locked = device.lock().expect("Poisoned lock");
            let num_vqs = u32::try_from(locked.queues().len()).expect("queue count exceeds u32");
            (locked.device_type(), num_vqs)
        };

        // Both are guaranteed present by enclave_builder: install_info_page()
        // and load_and_add_memory() both precede device attachment.
        let memory = enclave_vm
            .guest_memory()
            .expect("guest memory must be set before device attachment")
            .clone();
        let info_page = enclave_vm
            .info_page()
            .expect("info page must be installed before device attachment");

        let mut transport =
            NeTransport::new(device.clone(), memory, info_page, virtio_devid, num_vqs)?;

        // Wire the transport to the enclave: NE_ADD_DEVICE + eventfds.
        transport.register_device(enclave_vm.enclave_fd())?;

        // Register subscribers only after successful wiring.
        event_manager.add_subscriber(device);
        let transport = Arc::new(Mutex::new(transport));
        event_manager.add_subscriber(transport.clone());
        self.devices.push(transport);
        Ok(())
    }
}
