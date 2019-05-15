// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt;
use std::io::{self, stdout};
use std::sync::{Arc, Mutex};

use devices;
use sys_util::{EventFd, Terminal};

/// Errors corresponding to the `LegacyDeviceManager`.
#[derive(Debug)]
pub enum Error {
    /// Cannot add legacy device to Bus.
    BusError(devices::BusError),
    /// Cannot create EventFd.
    EventFd(io::Error),
    /// Cannot set mode for terminal.
    StdinHandle(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            BusError(ref err) => write!(f, "Failed to add legacy device to Bus: {}", err),
            EventFd(ref err) => write!(f, "Failed to create EventFd: {}", err),
            StdinHandle(ref err) => write!(f, "Failed to set mode for terminal: {}", err),
        }
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// The `LegacyDeviceManager` is a wrapper that is used for registering legacy devices
/// on an I/O Bus. It currently manages the uart and i8042 devices.
/// The `LegacyDeviceManger` should be initialized only by using the constructor.
pub struct LegacyDeviceManager {
    pub io_bus: devices::Bus,
    pub stdio_serial: Arc<Mutex<devices::legacy::Serial>>,
    pub i8042: Arc<Mutex<devices::legacy::I8042Device>>,

    pub com_evt_1_3: EventFd,
    pub com_evt_2_4: EventFd,
    pub kbd_evt: EventFd,
    pub stdin_handle: io::Stdin,
}

impl LegacyDeviceManager {
    /// Create a new DeviceManager handling legacy devices (uart, i8042).
    pub fn new() -> Result<Self> {
        let io_bus = devices::Bus::new();
        let com_evt_1_3 = EventFd::new().map_err(Error::EventFd)?;
        let com_evt_2_4 = EventFd::new().map_err(Error::EventFd)?;
        let kbd_evt = EventFd::new().map_err(Error::EventFd)?;
        let stdio_serial = Arc::new(Mutex::new(devices::legacy::Serial::new_out(
            com_evt_1_3.try_clone().map_err(Error::EventFd)?,
            Box::new(stdout()),
            None,
        )));

        // Create exit event for i8042
        let exit_evt = EventFd::new().map_err(Error::EventFd)?;
        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(
            exit_evt,
            kbd_evt.try_clone().unwrap(),
        )));

        Ok(LegacyDeviceManager {
            io_bus,
            stdio_serial,
            i8042,
            com_evt_1_3,
            com_evt_2_4,
            kbd_evt,
            stdin_handle: io::stdin(),
        })
    }

    #[cfg(target_arch = "x86_64")]
    /// Register supported legacy devices.
    pub fn register_devices(&mut self) -> Result<()> {
        self.io_bus
            .insert(self.stdio_serial.clone(), 0x3f8, 0x8)
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_2_4.try_clone().map_err(Error::EventFd)?,
                    None,
                ))),
                0x2f8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_1_3.try_clone().map_err(Error::EventFd)?,
                    None,
                ))),
                0x3e8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(
                Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                    self.com_evt_2_4.try_clone().map_err(Error::EventFd)?,
                    None,
                ))),
                0x2e8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.stdin_handle
            .lock()
            .set_raw_mode()
            .map_err(Error::StdinHandle)?;
        self.io_bus
            .insert(self.i8042.clone(), 0x060, 0x5)
            .map_err(Error::BusError)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_register_legacy_devices() {
        let ldm = LegacyDeviceManager::new();
        assert!(ldm.is_ok());
        assert!(&ldm.unwrap().register_devices().is_ok());
        // we need to reset the terminal otherwise stdin will remain in raw mode
        let stdin_handle = io::stdin();
        stdin_handle.lock().set_canon_mode().unwrap();
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
            format!("{}", Error::EventFd(io::Error::from_raw_os_error(1))),
            format!(
                "Failed to create EventFd: {}",
                io::Error::from_raw_os_error(1)
            )
        );
        assert_eq!(
            format!("{}", Error::StdinHandle(io::Error::from_raw_os_error(1))),
            format!(
                "Failed to set mode for terminal: {}",
                io::Error::from_raw_os_error(1)
            )
        );
    }
}
