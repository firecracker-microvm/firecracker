// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
#![cfg(target_arch = "x86_64")]

use std::fmt;
use std::sync::{Arc, Mutex};

use devices;
use kvm_ioctls::VmFd;
use utils::eventfd::EventFd;

/// Errors corresponding to the `PortIODeviceManager`.
#[derive(Debug)]
pub enum Error {
    /// Cannot add legacy device to Bus.
    BusError(devices::BusError),
    /// Cannot create EventFd.
    EventFd(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            BusError(ref err) => write!(f, "Failed to add legacy device to Bus: {}", err),
            EventFd(ref err) => write!(f, "Failed to create EventFd: {}", err),
        }
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// The `PortIODeviceManager` is a wrapper that is used for registering legacy devices
/// on an I/O Bus. It currently manages the uart and i8042 devices.
/// The `LegacyDeviceManger` should be initialized only by using the constructor.
pub struct PortIODeviceManager {
    pub io_bus: devices::Bus,
    pub stdio_serial: Arc<Mutex<devices::legacy::Serial>>,
    pub i8042: Arc<Mutex<devices::legacy::I8042Device>>,

    pub com_evt_1_3: EventFd,
    pub com_evt_2_4: EventFd,
    pub kbd_evt: EventFd,
}

impl PortIODeviceManager {
    /// Create a new DeviceManager handling legacy devices (uart, i8042).
    pub fn new(
        serial: Arc<Mutex<devices::legacy::Serial>>,
        i8042_reset_evfd: EventFd,
    ) -> Result<Self> {
        let io_bus = devices::Bus::new();
        let com_evt_1_3 = serial
            .lock()
            .unwrap()
            .interrupt_evt()
            .try_clone()
            .map_err(Error::EventFd)?;
        let com_evt_2_4 = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let kbd_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?;

        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(
            i8042_reset_evfd,
            kbd_evt.try_clone().map_err(Error::EventFd)?,
        )));

        Ok(PortIODeviceManager {
            io_bus,
            stdio_serial: serial,
            i8042,
            com_evt_1_3,
            com_evt_2_4,
            kbd_evt,
        })
    }

    /// Register supported legacy devices.
    pub fn register_devices(&mut self, vm_fd: &VmFd) -> Result<()> {
        self.io_bus
            .insert(self.stdio_serial.clone(), 0x3f8, 0x8)
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_2_4.try_clone().map_err(Error::EventFd)?,
                ))),
                0x2f8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_1_3.try_clone().map_err(Error::EventFd)?,
                ))),
                0x3e8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_2_4.try_clone().map_err(Error::EventFd)?,
                ))),
                0x2e8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(self.i8042.clone(), 0x060, 0x5)
            .map_err(Error::BusError)?;

        vm_fd
            .register_irqfd(&self.com_evt_1_3, 4)
            .map_err(|e| Error::EventFd(std::io::Error::from_raw_os_error(e.errno())))?;
        vm_fd
            .register_irqfd(&self.com_evt_2_4, 3)
            .map_err(|e| Error::EventFd(std::io::Error::from_raw_os_error(e.errno())))?;
        vm_fd
            .register_irqfd(&self.kbd_evt, 1)
            .map_err(|e| Error::EventFd(std::io::Error::from_raw_os_error(e.errno())))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    #[test]
    fn test_register_legacy_devices() {
        let guest_mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), 0x1000)]).unwrap();
        let mut vm = crate::builder::setup_kvm_vm(&guest_mem, false).unwrap();
        crate::builder::setup_interrupt_controller(&mut vm).unwrap();
        let serial = devices::legacy::Serial::new_sink(EventFd::new(libc::EFD_NONBLOCK).unwrap());
        let mut ldm = PortIODeviceManager::new(
            Arc::new(Mutex::new(serial)),
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();
        assert!(ldm.register_devices(vm.fd()).is_ok());
    }

    #[test]
    fn test_debug_error() {
        assert_eq!(
            format!("{}", Error::BusError(devices::BusError::Overlap)),
            format!(
                "Failed to add legacy device to Bus: {}",
                devices::BusError::Overlap
            )
        );
        assert_eq!(
            format!("{}", Error::EventFd(std::io::Error::from_raw_os_error(1))),
            format!(
                "Failed to create EventFd: {}",
                std::io::Error::from_raw_os_error(1)
            )
        );
    }
}
