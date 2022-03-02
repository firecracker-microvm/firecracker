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
    BadWriteOffset(u64),
    GpioInterruptDisabled,
    GpioInterruptFailure(io::Error),
    GpioTriggerKeyFailure(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BadWriteOffset(offset) => write!(f, "Bad Write Offset: {}", offset),
            Error::GpioInterruptDisabled => write!(f, "GPIO interrupt disabled by guest driver.",),
            Error::GpioInterruptFailure(ref e) => {
                write!(f, "Could not trigger GPIO interrupt: {}.", e)
            }
            Error::GpioTriggerKeyFailure(key) => {
                write!(f, "Invalid GPIO Input key triggerd: {}.", key)
            }
        }
    }
}

type Result<T> = result::Result<T, Error>;

pub struct GpioDevice {
    // Data Register
    data: u32,
    // GPIO irq_field
    interrupt: EventFd,
}

impl GpioDevice {
    /// Constructs an GPIO device.
    pub fn new(interrupt: EventFd) -> Self {
        Self { data: 0, interrupt }
    }

    pub fn send_acpi_shutdown_signal(&mut self) -> Result<()> {
        self.data = self.data | 256 | 16777216;

        self.interrupt
            .write(9)
            .map_err(Error::GpioInterruptFailure)?;
        Ok(())
    }
}

impl BusDevice for GpioDevice {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        let mut value;

        if data.len() <= 4 {
            value = self.data;

            println!("READ FROM GPIO! {} : {}", offset, value);

            value = value >> (8 * offset);

            for i in 0..(data.len()) {
                data[i] = (value % 256) as u8;
                value = value >> 8;
            }
        } else {
            warn!(
                "Invalid GPIO read: offset {}, data length {}",
                offset,
                data.len()
            );
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() > 4 {
            warn!(
                "Invalid GPIO write: offset {}, data length {}",
                offset,
                data.len()
            );
        } else {
            let mut value: u32 = data[data.len() - 1].into();

            for i in 1..data.len() {
                value = (value << 8) + (data[data.len() - 1 - i] as u32)
            }

            value = value << (offset * 8);
            self.data = value;

            println!("WRITE FROM GPIO! {} : {}", offset, value);
        }
    }
}
