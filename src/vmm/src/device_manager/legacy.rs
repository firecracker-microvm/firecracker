// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
#![cfg(target_arch = "x86_64")]

use std::sync::{Arc, Mutex};

use acpi_tables::aml::AmlError;
use acpi_tables::{Aml, aml};

use crate::devices::legacy::{I8042Device, SerialDevice};
use crate::vstate::bus::BusError;
use crate::vstate::vm::KvmVm;

/// Errors corresponding to the `PortIODeviceManager`.
#[derive(Debug, derive_more::From, thiserror::Error, displaydoc::Display)]
pub enum LegacyDeviceError {
    /// Failed to add legacy device to Bus: {0}
    BusError(BusError),
    /// Failed to create EventFd: {0}
    EventFd(std::io::Error),
}

/// The `PortIODeviceManager` is a wrapper that is used for registering legacy devices
/// on an I/O Bus. It currently manages the uart and i8042 devices.
#[derive(Debug)]
pub struct PortIODeviceManager {
    // BusDevice::Serial
    pub stdio_serial: Arc<Mutex<SerialDevice>>,
    // BusDevice::I8042Device
    pub i8042: Arc<Mutex<I8042Device>>,
}

impl PortIODeviceManager {
    /// Serial port 1
    const COM1_GSI: u32 = 4;
    /// x86 global system interrupt for keyboard port.
    /// See <https://en.wikipedia.org/wiki/Interrupt_request_(PC_architecture)>.
    const KBD_EVT_GSI: u32 = 1;
    /// Legacy serial port device addresses. See
    /// <https://tldp.org/HOWTO/Serial-HOWTO-10.html#ss10.1>.
    const SERIAL_PORT_ADDRESS: u64 = 0x3f8;
    /// Size of legacy serial ports.
    const SERIAL_PORT_SIZE: u64 = 0x8;
    /// i8042 keyboard data register address. See
    /// <https://elixir.bootlin.com/linux/latest/source/drivers/input/serio/i8042-io.h#L41>.
    const I8042_KDB_DATA_REGISTER_ADDRESS: u64 = 0x060;
    /// i8042 keyboard data register size.
    const I8042_KDB_DATA_REGISTER_SIZE: u64 = 0x5;

    /// Register supported legacy devices.
    pub fn register_devices(&mut self, vm: &KvmVm) -> Result<(), LegacyDeviceError> {
        let io_bus = &vm.pio_bus;
        io_bus.insert(
            self.stdio_serial.clone(),
            Self::SERIAL_PORT_ADDRESS,
            Self::SERIAL_PORT_SIZE,
        )?;
        io_bus.insert(
            self.i8042.clone(),
            Self::I8042_KDB_DATA_REGISTER_ADDRESS,
            Self::I8042_KDB_DATA_REGISTER_SIZE,
        )?;

        vm.register_irq(
            self.stdio_serial
                .lock()
                .expect("Poisoned lock")
                .serial
                .interrupt_evt(),
            Self::COM1_GSI,
        )
        .map_err(|e| LegacyDeviceError::EventFd(std::io::Error::from_raw_os_error(e.errno())))?;

        vm.register_irq(
            &self.i8042.lock().expect("Poisoned lock").kbd_interrupt_evt,
            Self::KBD_EVT_GSI,
        )
        .map_err(|e| LegacyDeviceError::EventFd(std::io::Error::from_raw_os_error(e.errno())))?;

        Ok(())
    }

    pub(crate) fn append_aml_bytes(bytes: &mut Vec<u8>) -> Result<(), AmlError> {
        // Setup COM1
        aml::Device::new(
            "_SB_.COM1".try_into()?,
            vec![
                &aml::Name::new("_HID".try_into()?, &aml::EisaName::new("PNP0501")?)?,
                &aml::Name::new("_UID".try_into()?, &0u8)?,
                &aml::Name::new("_DDN".try_into()?, &"COM1")?,
                &aml::Name::new(
                    "_CRS".try_into().unwrap(),
                    &aml::ResourceTemplate::new(vec![
                        &aml::Interrupt::new(true, true, false, false, Self::COM1_GSI),
                        &aml::Io::new(
                            Self::SERIAL_PORT_ADDRESS.try_into().unwrap(),
                            Self::SERIAL_PORT_ADDRESS.try_into().unwrap(),
                            1,
                            Self::SERIAL_PORT_SIZE.try_into().unwrap(),
                        ),
                    ]),
                )?,
            ],
        )
        .append_aml_bytes(bytes)?;
        // Setup i8042
        aml::Device::new(
            "_SB_.PS2_".try_into()?,
            vec![
                &aml::Name::new("_HID".try_into()?, &aml::EisaName::new("PNP0303")?)?,
                &aml::Method::new(
                    "_STA".try_into()?,
                    0,
                    false,
                    vec![&aml::Return::new(&0x0fu8)],
                ),
                &aml::Name::new(
                    "_CRS".try_into()?,
                    &aml::ResourceTemplate::new(vec![
                        &aml::Io::new(
                            PortIODeviceManager::I8042_KDB_DATA_REGISTER_ADDRESS
                                .try_into()
                                .unwrap(),
                            PortIODeviceManager::I8042_KDB_DATA_REGISTER_ADDRESS
                                .try_into()
                                .unwrap(),
                            1u8,
                            1u8,
                        ),
                        // Fake a command port so Linux stops complaining
                        &aml::Io::new(0x0064, 0x0064, 1u8, 1u8),
                        &aml::Interrupt::new(true, true, false, false, Self::KBD_EVT_GSI),
                    ]),
                )?,
            ],
        )
        .append_aml_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use libc::EFD_NONBLOCK;
    use vm_superio::Serial;
    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::devices::legacy::serial::{SerialOut, SerialOutInner};
    use crate::devices::legacy::{EventFdTrigger, SerialEventsWrapper};
    use crate::vstate::vm::tests::setup_vm_with_memory;

    #[test]
    fn test_register_legacy_devices() {
        let (_, vm) = setup_vm_with_memory(0x1000);
        vm.setup_irqchip().unwrap();
        let mut ldm = PortIODeviceManager {
            stdio_serial: Arc::new(Mutex::new(SerialDevice {
                serial: Serial::with_events(
                    EventFdTrigger::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                    SerialEventsWrapper {
                        buffer_ready_event_fd: None,
                    },
                    SerialOut::new(SerialOutInner::Sink, None),
                ),
                input: None,
            })),
            i8042: Arc::new(Mutex::new(
                I8042Device::new(EventFd::new(libc::EFD_NONBLOCK).unwrap()).unwrap(),
            )),
        };
        ldm.register_devices(&vm).unwrap();
    }
}
