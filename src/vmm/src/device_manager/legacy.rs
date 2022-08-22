// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
#![cfg(target_arch = "x86_64")]

use std::fmt;
use std::sync::{Arc, Mutex};

use acpi::{aml, Aml};
use devices::legacy::{EventFdTrigger, SerialDevice, SerialEventsWrapper};
use kvm_ioctls::VmFd;
use libc::EFD_NONBLOCK;
use logger::METRICS;
use utils::eventfd::EventFd;
use vm_superio::Serial;

use crate::resource_manager::ResourceManager;

/// Errors corresponding to the `PortIODeviceManager`.
#[derive(Debug, derive_more::From)]
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

fn create_serial(com_event: EventFdTrigger) -> Result<Arc<Mutex<SerialDevice>>> {
    let serial_device = Arc::new(Mutex::new(SerialDevice {
        serial: Serial::with_events(
            com_event.try_clone()?,
            SerialEventsWrapper {
                metrics: METRICS.uart.clone(),
                buffer_ready_event_fd: None,
            },
            Box::new(std::io::sink()),
        ),
        input: None,
    }));

    Ok(serial_device)
}

/// The `PortIODeviceManager` is a wrapper that is used for registering legacy devices
/// on an I/O Bus. It currently manages the uart and i8042 devices.
/// The `LegacyDeviceManger` should be initialized only by using the constructor.
pub struct PortIODeviceManager {
    pub io_bus: devices::Bus,
    pub stdio_serial: Arc<Mutex<SerialDevice>>,
    pub i8042: Arc<Mutex<devices::legacy::I8042Device>>,

    // Communication event on ports 1 & 3.
    pub com_evt_1_3: EventFdTrigger,
    // Communication event on ports 2 & 4.
    pub com_evt_2_4: EventFdTrigger,
    // Keyboard event.
    pub kbd_evt: EventFd,
}

impl PortIODeviceManager {
    /// Legacy serial port device addresses. See
    /// <https://tldp.org/HOWTO/Serial-HOWTO-10.html#ss10.1>.
    const SERIAL_PORT_ADDRESSES: [u64; 4] = [0x3f8, 0x2f8, 0x3e8, 0x2e8];
    /// Size of legacy serial ports.
    const SERIAL_PORT_SIZE: u64 = 0x8;
    /// i8042 keyboard data register address. See
    /// <https://elixir.bootlin.com/linux/latest/source/drivers/input/serio/i8042-io.h#L41>.
    const I8042_KDB_DATA_REGISTER_ADDRESS: u64 = 0x060;
    /// i8042 keyboard data register size.
    const I8042_KDB_DATA_REGISTER_SIZE: u64 = 0x5;

    /// Create a new DeviceManager handling legacy devices (uart, i8042).
    pub fn new(serial: Arc<Mutex<SerialDevice>>, i8042_reset_evfd: EventFd) -> Result<Self> {
        let io_bus = devices::Bus::new();
        let com_evt_1_3 = serial
            .lock()
            .expect("Poisoned lock")
            .serial
            .interrupt_evt()
            .try_clone()?;
        let com_evt_2_4 = EventFdTrigger::new(EventFd::new(EFD_NONBLOCK)?);
        let kbd_evt = EventFd::new(libc::EFD_NONBLOCK)?;

        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(
            i8042_reset_evfd,
            kbd_evt.try_clone()?,
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
        let serial_2_4 = create_serial(self.com_evt_2_4.try_clone()?)?;
        let serial_1_3 = create_serial(self.com_evt_1_3.try_clone()?)?;
        self.io_bus.insert(
            self.stdio_serial.clone(),
            Self::SERIAL_PORT_ADDRESSES[0],
            Self::SERIAL_PORT_SIZE,
        )?;
        self.io_bus.insert(
            serial_2_4.clone(),
            Self::SERIAL_PORT_ADDRESSES[1],
            Self::SERIAL_PORT_SIZE,
        )?;
        self.io_bus.insert(
            serial_1_3.clone(),
            Self::SERIAL_PORT_ADDRESSES[2],
            Self::SERIAL_PORT_SIZE,
        )?;
        self.io_bus.insert(
            serial_2_4,
            Self::SERIAL_PORT_ADDRESSES[3],
            Self::SERIAL_PORT_SIZE,
        )?;
        self.io_bus.insert(
            self.i8042.clone(),
            Self::I8042_KDB_DATA_REGISTER_ADDRESS,
            Self::I8042_KDB_DATA_REGISTER_SIZE,
        )?;

        vm_fd
            .register_irqfd(&self.com_evt_1_3, ResourceManager::serial_1_3_gsi())
            .map_err(|e| Error::EventFd(std::io::Error::from_raw_os_error(e.errno())))?;
        vm_fd
            .register_irqfd(&self.com_evt_2_4, ResourceManager::serial_2_4_gsi())
            .map_err(|e| Error::EventFd(std::io::Error::from_raw_os_error(e.errno())))?;
        vm_fd
            .register_irqfd(&self.kbd_evt, ResourceManager::i8042_gsi())
            .map_err(|e| Error::EventFd(std::io::Error::from_raw_os_error(e.errno())))?;
        Ok(())
    }
}

impl Aml for PortIODeviceManager {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) {
        /* COM1 */
        aml::Device::new(
            "_SB_.COM1".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0501")),
                &aml::Name::new("_UID".into(), &aml::ZERO),
                &aml::Name::new("_DDN".into(), &"COM1"),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![
                        &aml::Interrupt::new(
                            true,
                            true,
                            false,
                            false,
                            ResourceManager::serial_1_3_gsi(),
                        ),
                        &aml::Io::new(
                            PortIODeviceManager::SERIAL_PORT_ADDRESSES[0] as u16,
                            PortIODeviceManager::SERIAL_PORT_ADDRESSES[0] as u16,
                            1,
                            PortIODeviceManager::SERIAL_PORT_SIZE as u8,
                        ),
                    ]),
                ),
            ],
        )
        .append_aml_bytes(v);
        /* COM2 */
        aml::Device::new(
            "_SB_.COM2".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0501")),
                &aml::Name::new("_UID".into(), &aml::ONE),
                &aml::Name::new("_DDN".into(), &"COM2"),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![
                        &aml::Interrupt::new(
                            true,
                            true,
                            false,
                            false,
                            ResourceManager::serial_2_4_gsi(),
                        ),
                        &aml::Io::new(
                            PortIODeviceManager::SERIAL_PORT_ADDRESSES[1] as u16,
                            PortIODeviceManager::SERIAL_PORT_ADDRESSES[1] as u16,
                            1,
                            PortIODeviceManager::SERIAL_PORT_SIZE as u8,
                        ),
                    ]),
                ),
            ],
        )
        .append_aml_bytes(v);
        /* COM3 */
        aml::Device::new(
            "_SB_.COM3".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0501")),
                &aml::Name::new("_UID".into(), &2u8),
                &aml::Name::new("_DDN".into(), &"COM3"),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![
                        &aml::Interrupt::new(
                            true,
                            true,
                            false,
                            false,
                            ResourceManager::serial_1_3_gsi(),
                        ),
                        &aml::Io::new(
                            PortIODeviceManager::SERIAL_PORT_ADDRESSES[2] as u16,
                            PortIODeviceManager::SERIAL_PORT_ADDRESSES[2] as u16,
                            1,
                            PortIODeviceManager::SERIAL_PORT_SIZE as u8,
                        ),
                    ]),
                ),
            ],
        )
        .append_aml_bytes(v);
        /* COM4 */
        aml::Device::new(
            "_SB_.COM4".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0501")),
                &aml::Name::new("_UID".into(), &3u8),
                &aml::Name::new("_DDN".into(), &"COM4"),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![
                        &aml::Interrupt::new(
                            true,
                            true,
                            false,
                            false,
                            ResourceManager::serial_2_4_gsi(),
                        ),
                        &aml::Io::new(
                            PortIODeviceManager::SERIAL_PORT_ADDRESSES[3] as u16,
                            PortIODeviceManager::SERIAL_PORT_ADDRESSES[3] as u16,
                            1,
                            PortIODeviceManager::SERIAL_PORT_SIZE as u8,
                        ),
                    ]),
                ),
            ],
        )
        .append_aml_bytes(v);
        // i8042
        aml::Device::new(
            "_SB_.PS2_".into(),
            vec![
                &aml::Name::new("_HID".into(), &aml::EisaName::new("PNP0303")),
                &aml::Method::new("_STA".into(), 0, false, vec![&aml::Return::new(&0x0Fu8)]),
                &aml::Name::new(
                    "_CRS".into(),
                    &aml::ResourceTemplate::new(vec![
                        &aml::Io::new(
                            PortIODeviceManager::I8042_KDB_DATA_REGISTER_ADDRESS as u16,
                            PortIODeviceManager::I8042_KDB_DATA_REGISTER_ADDRESS as u16,
                            1u8,
                            1u8,
                        ),
                        /* Fake a command port so Linux stops complaining */
                        &aml::Io::new(0x0064, 0x0064, 1u8, 1u8),
                        &aml::Interrupt::new(
                            true,
                            true,
                            false,
                            false,
                            ResourceManager::i8042_gsi(),
                        ),
                    ]),
                ),
            ],
        )
        .append_aml_bytes(v);
    }
}

#[cfg(test)]
mod tests {
    use vm_memory::GuestAddress;

    use super::*;

    #[test]
    fn test_register_legacy_devices() {
        let guest_mem =
            vm_memory::test_utils::create_anon_guest_memory(&[(GuestAddress(0x0), 0x1000)], false)
                .unwrap();
        let mut vm = crate::builder::setup_kvm_vm(&guest_mem, false).unwrap();
        crate::builder::setup_interrupt_controller(&mut vm).unwrap();
        let mut ldm = PortIODeviceManager::new(
            create_serial(EventFdTrigger::new(EventFd::new(EFD_NONBLOCK).unwrap())).unwrap(),
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
