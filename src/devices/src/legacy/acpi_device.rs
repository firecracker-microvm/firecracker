// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Copyright © 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

// Code adapted from Cloud Hypervisor:
// https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/devices/src/legacy/gpio_pl061.rs

// Copyright 2022 Arm Limited (or its affiliates). All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! ARM PrimeCell General Purpose Input/Output(PL061)
//!
//! This module implements an ARM PrimeCell General Purpose Input/Output(PL061) to support gracefully poweroff microvm from external.
//!

use crate::bus::BusDevice;
use logger::warn;
use std::result;
use std::{fmt, io};
use utils::eventfd::EventFd;

#[derive(Debug)]
pub enum Error {
    AcpiDeviceInterruptFailure(io::Error),
    AcpiDeviceShutdownFirecrackerFailure(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::AcpiDeviceInterruptFailure(ref e) => {
                write!(f, "Could not trigger Acpi Device interrupt: {}.", e)
            }
            Error::AcpiDeviceShutdownFirecrackerFailure(ref e) => {
                write!(f, "Could not shutdown Firecracker from Acpi Device: {}.", e)
            }
        }
    }
}

type Result<T> = result::Result<T, Error>;

// AcpiDevice should emulate two ACPI registers required for a gracefull shutdown (using fixed hardware method):
// X_PM1a_EVT_BLK (4 bytes) and X_PM1a_CNT_BLK (2 bytes)
// https://uefi.org/specs/ACPI/6.4/05_ACPI_Software_Programming_Model/ACPI_Software_Programming_Model.html#fadt-format

// To keep the implementation simple, both registers were implemented in the same
// AcpiDevice; the bits of these two registers are saved into data field of the AcpiDevice
// structure (in the least significant 6 bytes of the u64 variable) as it follows:

// -------------------------------------------------------------------------------------------------------------------------------------------
// |                                                    data field of the AcpiDevice struct                                                  |
// -------------------------------------------------------------------------------------------------------------------------------------------
// | 0 ... 7       8        9 ... 19       24      25 ... 31 | 32  ...  41      42          43          44         45       46 47 | 48 .. 64 |
// -------------------------------------------------------------------------------------------------------------------------------------------
// |                        X_PM1a_EVT_BLK                   |                                  X_PM1a_CNT_BLK                    | NOT USED |
// -------------------------------------------------------------------------------------------------------------------------------------------
// | 0 ... 7       8        9 ... 19       24      25 ... 31 |  0  ...   9      10          11          12         13       14 15 | NOT USED |
// -------------------------------------------------------------------------------------------------------------------------------------------
// |           PWRBTN_STS              PWRBTN_EN             |               SLP_TYPx    SLP_TYPx    SLP_TYPx    SLP_EN           | NOT USED |
// -------------------------------------------------------------------------------------------------------------------------------------------

// To trigger a shutdown, PWRBTN_STS and PWRBTN_EN (in X_PM1a_EVT_BLK) needs to be written as
// ones and the interrupt should be raised. When guest goes to soft-off state, SLP_EN is written
// as one and SLP_TYPx is written with the value from the _S5 object from the DSDT table (in
// fact, when guest goes into power state x, then the value from the _Sx object is written into
// SLP_TYPx bits located into X_PM1a_CNT_BLK)

pub struct AcpiDevice {
    /// Data Register
    data: u64,
    /// Interrupt to be triggered for OSPM to read ACPI registers
    interrupt: EventFd,
    /// CPU reset eventfd. We will set this event to stop Firecracker.
    reset_evt: EventFd,
}

impl AcpiDevice {
    /// Constructs a device that holds ACPI registers.
    pub fn new(interrupt: EventFd, reset_evt: EventFd) -> Self {
        Self {
            data: 0,
            interrupt,
            reset_evt,
        }
    }

    pub fn send_acpi_shutdown_signal(&mut self) -> Result<()> {
        const PWRBTN_STS_OFFSET: u64 = 8;
        const PWRBTN_EN: u64 = 24;

        // Set bits according to the spec in order to trigger the shutdown
        // https://uefi.org/specs/ACPI/6.4/04_ACPI_Hardware_Specification/ACPI_Hardware_Specification.html#pm1-event-grouping
        self.data = self.data | (1 << PWRBTN_STS_OFFSET) | (1 << PWRBTN_EN);

        // Make OSPM read ACPI registers and generate the ACPI event by setting the interrupt on ACPI Device
        self.interrupt
            .write(1)
            .map_err(Error::AcpiDeviceInterruptFailure)
    }

    fn shutdown_vmm(&mut self) -> Result<()> {
        self.reset_evt
            .write(1)
            .map_err(Error::AcpiDeviceShutdownFirecrackerFailure)
    }
}

impl BusDevice for AcpiDevice {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        const SLP_EN_OFFSET: u64 = 45;

        if offset < 6 {
            let mut value = self.data;

            // SLP_EN is a write only bit; reading from it will always return 0 according to the spec:
            // https://uefi.org/specs/ACPI/6.4/04_ACPI_Hardware_Specification/ACPI_Hardware_Specification.html#pm1-control-registers-fixed-hardware-feature-control-bits
            value = value & (!(1 << SLP_EN_OFFSET));

            // get each byte from value considering Little Endian representation
            let value_bytes = value.to_le_bytes();

            // write first <data.len()> bytes to data (least significant <data.len()> bytes of value)
            data.clone_from_slice(&value_bytes[(offset as usize)..(offset as usize) + data.len()]);
        } else {
            warn!("Invalid AcpiDevice read: offset {}", offset);
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        const SLP_TYPX_OFFSET: u64 = 42;
        const SOFT_OFF_STATE_VALUE: u64 = 5;
        const SLP_EN_OFFSET: u64 = 45;

        if offset < 6 {
            // add padding bytes to data such that we get 8 bytes that can be transformed in u64
            let mut data_with_padding = [0u8; 8];
            data_with_padding[(offset as usize)..(offset as usize) + data.len()]
                .clone_from_slice(&data);

            // save data as u64 considering Little Endian representation
            self.data = u64::from_le_bytes(data_with_padding);

            // check for soft-off state according to the spec:
            // https://uefi.org/specs/ACPI/6.4/04_ACPI_Hardware_Specification/ACPI_Hardware_Specification.html#pm1-control-registers-fixed-hardware-feature-control-bits
            let soft_off_state_bits =
                (1 << SLP_EN_OFFSET) | (SOFT_OFF_STATE_VALUE << SLP_TYPX_OFFSET);

            // check if required bits for the soft-off state are written as ones (the other bits
            // in the AcpiDevice can have any value)
            if (self.data & soft_off_state_bits) == soft_off_state_bits {
                if self.shutdown_vmm().is_err() {
                    warn!("AcpiDevice could not shutdown Firecracker");
                }
            }
        } else {
            warn!("Invalid AcpiDevice write: offset {}", offset);
        }
    }
}
