// Copyright 2020 ARM Limited. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! ARM PrimeCell General Purpose Input/Output(PL061)
//!
//! This module implements an ARM PrimeCell General Purpose Input/Output(PL061) to support gracefully poweroff microvm from external.
//!

use std::fmt;
use std::result;

use crate::bus::BusDevice;
use kvm_ioctls::VmFd;
use utils::byte_order;
use logger::{Metric, METRICS};

use crate::chrono::Duration;
use crate::timer::Timer;
use std::sync::mpsc::channel;

const OFS_DATA: u64 = 0x400; // Data Register
const GPIODIR: u64 = 0x400; // Direction Register
const GPIOIS: u64 = 0x404; // Interrupt Sense Register
const GPIOIBE: u64 = 0x408; // Interrupt Both Edges Register
const GPIOIEV: u64 = 0x40c; // Interrupt Event Register
const GPIOIE: u64 = 0x410; // Interrupt Mask Register
const GPIORIE: u64 = 0x414; // Raw Interrupt Status Register
const GPIOMIS: u64 = 0x418; // Masked Interrupt Status Register
const GPIOIC: u64 = 0x41c; // Interrupt Clear Register
const GPIOAFSEL: u64 = 0x420; // Mode Control Select Register
                              // From 0x424 to 0xFDC => reserved space.
                              // From 0xFE0 to 0xFFC => Peripheral and PrimeCell Identification Registers which are Read Only registers.
                              // Thses registers can conceptually be treated as a 32-bit register, and PartNumber[11:0] is used to identify the peripheral.
                              // We are putting the expected values (look at 'Reset value' column from above mentioned document) in an array.
const GPIO_ID: [u8; 8] = [0x61, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];
// ID Margins
const GPIO_ID_LOW: u64 = 0xfe0;
const GPIO_ID_HIGH: u64 = 0x1000;

const N_GPIOS: u32 = 8;

#[derive(Debug)]
pub enum Error {
    BadWriteOffset(u64),
    GPIOInterruptDisabled,
    GPIOInterruptFailure(kvm_ioctls::Error),
    GPIOTriggerKeyFailure(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BadWriteOffset(offset) => write!(f, "Bad Write Offset: {}", offset),
            Error::GPIOInterruptDisabled => write!(f, "GPIO interrupt disabled by guest driver.",),
            Error::GPIOInterruptFailure(ref e) => {
                write!(f, "Could not trigger GPIO interrupt: {}.", e)
            }
            Error::GPIOTriggerKeyFailure(key) => {
                write!(f, "Invalid GPIO Input key triggerd: {}.", key)
            }
        }
    }
}

type Result<T> = result::Result<T, Error>;

/// A GPIO device following the PL061 specification.
pub struct GPIO {
    // Data Register
    data: u32,
    old_in_data: u32,
    // Direction Register
    dir: u32,
    // Interrupt Sense Register
    isense: u32,
    // Interrupt Both Edges Register
    ibe: u32,
    // Interrupt Event Register
    iev: u32,
    // Interrupt Mask Register
    im: u32,
    // Raw Interrupt Status Register
    istate: u32,
    // Mode Control Select Register
    afsel: u32,
    // GPIO irq_field
    gpio_irq: u32,
}

impl GPIO {
    /// Constructs an PL061 GPIO device.
    pub fn new(gpio_irq: u32) -> GPIO {
        GPIO {
            data: 0,
            old_in_data: 0,
            dir: 0,
            isense: 0,
            ibe: 0,
            iev: 0,
            im: 0,
            istate: 0,
            afsel: 0,
            gpio_irq,
        }
    }

    fn pl061_internal_update(&mut self) {
        // FIXME:
        //  Missing Output Interrupt Emulation.

        // Input Edging Interrupt Emulation.
        let changed = ((self.old_in_data ^ self.data) & !self.dir) as u32;
        if changed > 0 {
            self.old_in_data = self.data;
            for i in 0..N_GPIOS {
                let mask = (1 << i) as u32;
                if (changed & mask) > 0 {
                    // Bits set high in GPIOIS(Interrupt sense register) configure the corresponding
                    // pins to detect levels, otherwise, detect edges.
                    if (self.isense & mask) == 0 {
                        if (self.ibe & mask) > 0 {
                            // Bits set high in GPIOIBE(Interrupt both-edges register) configure the corresponding
                            // pins to detect both falling and rising edges.
                            // Clearing a bit configures the pin to be controlled by GPIOIEV.
                            self.istate |= mask;
                        } else {
                            // Bits set to high in GPIOIEV(Interrupt event register) configure the
                            // corresponding pin to detect rising edges, otherwise, detect falling edges.
                            self.istate |= !(self.data ^ self.iev) & mask;
                        }
                    }
                }
            }
        }

        // Input Level Interrupt Emulation.
        self.istate |= !(self.data ^ self.iev) & self.isense;
    }

    fn handle_write(&mut self, offset: u64, val: u32) -> Result<()> {
        if offset < OFS_DATA {
            // In order to write to data register, the corresponding bits in the mask, resulting
            // from the offsite[9:2], must be HIGH. otherwise the bit values remain unchanged.
            let mask = (offset >> 2) as u32 & self.dir;
            self.data = (self.data & !mask) | (val & mask);
        } else {
            match offset {
                GPIODIR => {
                    /* Direction Register */
                    self.dir = val & 0xff;
                }
                GPIOIS => {
                    /* Interrupt Sense Register */
                    self.isense = val & 0xff;
                }
                GPIOIBE => {
                    /* Interrupt Both Edges Register */
                    self.ibe = val & 0xff;
                }
                GPIOIEV => {
                    /* Interrupt Event Register */
                    self.iev = val & 0xff;
                }
                GPIOIE => {
                    /* Interrupt Mask Register */
                    self.im = val & 0xff;
                }
                GPIOIC => {
                    /* Interrupt Clear Register */
                    self.istate &= !val;
                }
                GPIOAFSEL => {
                    /* Mode Control Select Register */
                    self.afsel = val & 0xff;
                }
                o => {
                    return Err(Error::BadWriteOffset(o));
                }
            }
        }
        Ok(())
    }

    pub fn trigger_key(&mut self, key: u32, vm: &VmFd) -> Result<()> {
        let mask = (1 << key) as u32;
        if (!self.dir & mask) > 0 {
            // emulate key event
            // By default, Input Pin is configured to detect both rising and falling edges.
            // So reverse the input pin data to generate a pulse.
            self.data |= !(self.data & mask) & mask;
            self.pl061_internal_update();

            match self.trigger_gpio_interrupt(vm) {
                Ok(_) | Err(Error::GPIOInterruptDisabled) => return Ok(()),
                Err(e) => return Err(e),
            }
        }

        return Err(Error::GPIOTriggerKeyFailure(key));
    }

    fn trigger_gpio_interrupt(&self, vm: &VmFd) -> Result<()> {
        // Bits set to high in GPIOIE(Interrupt mask register) allow the corresponding pins to
        // trigger their individual interrupts and then the combined GPIOINTR line.
        if (self.istate & self.im) == 0 {
            warn!("Failed to trigger GPIO input interrupt (disabled by guest OS)");
            return Err(Error::GPIOInterruptDisabled);
        }

        // Sets the irq level to 1
        vm.set_irq_line(self.gpio_irq, true)
            .map_err(Error::GPIOInterruptFailure)?;

        // The outbound irq line is raised for 100ms before dropped again, in order to
        // emulate high level signal.
        let timer = Timer::new();
        let (tx, rx) = channel();
        let _guard = timer.schedule_with_delay(Duration::milliseconds(100), move || {
            let _ignored = tx.send(());
        });
        rx.recv().unwrap();

        // Sets the irq level to 0
        vm.set_irq_line(self.gpio_irq, false)
            .map_err(Error::GPIOInterruptFailure)
    }
}

impl BusDevice for GPIO {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        let value;
        let mut read_ok = true;

        if offset < GPIO_ID_HIGH && offset >= GPIO_ID_LOW {
            let index = ((offset - GPIO_ID_LOW) >> 2) as usize;
            value = u32::from(GPIO_ID[index]);
        } else if offset < OFS_DATA {
            value = self.data & ((offset >> 2) as u32)
        } else {
            value = match offset {
                GPIODIR => self.dir,
                GPIOIS => self.isense,
                GPIOIBE => self.ibe,
                GPIOIEV => self.iev,
                GPIOIE => self.im,
                GPIORIE => self.istate,
                GPIOMIS => self.istate & self.im,
                GPIOAFSEL => self.afsel,
                _ => {
                    read_ok = false;
                    0
                }
            };
        }

        if read_ok && data.len() <= 4 {
            byte_order::write_le_u32(data, value);
        } else {
            warn!(
                "Invalid GPIO PL061 read: offset {}, data length {}",
                offset,
                data.len()
            );
            METRICS.gpio.error_count.inc();
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() <= 4 {
            let value = byte_order::read_le_u32(&data[..]);
            if let Err(e) = self.handle_write(offset, value) {
                warn!("Failed to write to GPIO PL061 device: {}", e);
                METRICS.gpio.error_count.inc();
            }
        } else {
            warn!(
                "Invalid GPIO PL061 write: offset {}, data length {}",
                offset,
                data.len()
            );
            METRICS.gpio.error_count.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gpio_read_write_and_event() {
        let irq = 0x01000044 as u32;
        let mut gpio = GPIO::new(irq);
        let mut data = [0; 4];

        // Read and write to the GPIODIR register.
        // Set pin 0 output pin.
        byte_order::write_le_u32(&mut data, 1);
        gpio.write(GPIODIR, &mut data);
        gpio.read(GPIODIR, &mut data);
        let v = byte_order::read_le_u32(&data[..]);
        assert_eq!(v, 1);

        // Read and write to the GPIODATA register.
        byte_order::write_le_u32(&mut data, 1);
        // Set pin 0 high.
        let offset = 0x00000004 as u32;
        gpio.write(offset, &mut data);
        gpio.read(offset, &mut data);
        let v = byte_order::read_le_u32(&data[..]);
        assert_eq!(v, 1);

        // Read and write to the GPIOIS register.
        // Configure pin 0 detecting level interrupt.
        byte_order::write_le_u32(&mut data, 1);
        gpio.write(GPIOIS, &mut data);
        gpio.read(GPIOIS, &mut data);
        let v = byte_order::read_le_u32(&data[..]);
        assert_eq!(v, 1);

        // Read and write to the GPIOIBE register.
        // Configure pin 1 detecting both falling and rising edges.
        byte_order::write_le_u32(&mut data, 2);
        gpio.write(GPIOIBE, &mut data);
        gpio.read(GPIOIBE, &mut data);
        let v = byte_order::read_le_u32(&data[..]);
        assert_eq!(v, 2);

        // Read and write to the GPIOIEV register.
        // Configure pin 2 detecting both falling and rising edges.
        byte_order::write_le_u32(&mut data, 4);
        gpio.write(GPIOIEV, &mut data);
        gpio.read(GPIOIEV, &mut data);
        let v = byte_order::read_le_u32(&data[..]);
        assert_eq!(v, 4);

        // Read and write to the GPIOIE register.
        // Configure pin 0...2 capable of triggering their individual interrupts
        // and then the combined GPIOINTR line.
        byte_order::write_le_u32(&mut data, 7);
        gpio.write(GPIOIE, &mut data);
        gpio.read(GPIOIE, &mut data);
        let v = byte_order::read_le_u32(&data[..]);
        assert_eq!(v, 7);

        let mask = 0x00000002 as u32;
        // emulate an rising pulse in pin 1.
        gpio.data |= !(gpio.data & mask) & mask;
        self.pl061_internal_update();
        // The interrupt line on pin 1 should be on.
        // Read the GPIOMIS register.
        gpio.read(GPIOMIS, &mut data);
        let v = byte_order::read_le_u32(&data[..]);
        assert_eq!(v, 2);

        // Read and Write to the GPIOIC register.
        // clear interrupt in pin 1.
        byte_order::write_le_u32(&mut data, 2);
        gpio.write(GPIOIC, &mut data);
        gpio.read(GPIOIC, &mut data);
        let v = byte_order::read_le_u32(&data[..]);
        assert_eq!(v, 2);

        // Attempts to write beyond the writable space.
        byte_order::write_le_u32(&mut data, 0);
        let no_errors_before = METRICS.gpio.error_count.count();
        gpio.write(GPIO_ID_LOW, &mut data);
        let no_errors_after = METRICS.gpio.error_count.count();
        assert_eq!(no_errors_after - no_errors_before, 1);

        let mut data = [0; 4];
        gpio.read(GPIO_ID_LOW, &mut data);
        let index = GPIO_ID_LOW + 3;
        assert_eq!(data[0], GPIO_ID[((index - GPIO_ID_LOW) >> 2) as usize]);
    }
}


