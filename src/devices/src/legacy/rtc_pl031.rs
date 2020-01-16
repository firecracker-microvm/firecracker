// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! ARM PL031 Real Time Clock
//!
//! This module implements a PL031 Real Time Clock (RTC) that provides to provides long time base counter.
//! This is achieved by generating an interrupt signal after counting for a programmed number of cycles of
//! a real-time clock input.
//!

extern crate utils;

use std::fmt;
use std::time::Instant;
use std::{io, result};

use crate::BusDevice;
use logger::{Metric, METRICS};
use utils::byte_order;
use utils::eventfd::EventFd;
//use bus::Error;

// As you can see in https://static.docs.arm.com/ddi0224/c/real_time_clock_pl031_r1p3_technical_reference_manual_DDI0224C.pdf
// at section 3.2 Summary of RTC registers, the total size occupied by this device is 0x000 -> 0xFFC + 4 = 0x1000.
// From 0x0 to 0x1C we have following registers:
const RTCDR: u64 = 0x0; // Data Register.
const RTCMR: u64 = 0x4; // Match Register.
const RTCLR: u64 = 0x8; // Load Regiser.
const RTCCR: u64 = 0xc; // Control Register.
const RTCIMSC: u64 = 0x10; // Interrupt Mask Set or Clear Register.
const RTCRIS: u64 = 0x14; // Raw Interrupt Status.
const RTCMIS: u64 = 0x18; // Masked Interrupt Status.
const RTCICR: u64 = 0x1c; // Interrupt Clear Register.
                          // From 0x020 to 0xFDC => reserved space.
                          // From 0xFE0 to 0x1000 => Peripheral and PrimeCell Identification Registers which are Read Only registers.
                          // AMBA standard devices have CIDs (Cell IDs) and PIDs (Peripheral IDs). The linux kernel will look for these in order to assert the identity
                          // of these devices (i.e look at the `amba_device_try_add` function).
                          // We are putting the expected values (look at 'Reset value' column from above mentioned document) in an array.
const PL031_ID: [u8; 8] = [0x31, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];
// We are only interested in the margins.
const AMBA_ID_LOW: u64 = 0xFE0;
const AMBA_ID_HIGH: u64 = 0x1000;

#[derive(Debug)]
pub enum Error {
    BadWriteOffset(u64),
    InterruptFailure(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BadWriteOffset(offset) => write!(f, "Bad Write Offset: {}", offset),
            Error::InterruptFailure(e) => write!(f, "Failed to trigger interrupt: {}", e),
        }
    }
}
type Result<T> = result::Result<T, Error>;

/// A RTC device following the PL031 specification..
pub struct RTC {
    previous_now: Instant,
    tick_offset: i64,
    // This is used for implementing the RTC alarm. However, in Firecracker we do not need it.
    match_value: u32,
    // Writes to this register load an update value into the RTC.
    load: u32,
    imsc: u32,
    ris: u32,
    interrupt_evt: EventFd,
}

impl RTC {
    /// Constructs an AMBA PL031 RTC device.
    pub fn new(interrupt_evt: EventFd) -> RTC {
        RTC {
            // This is used only for duration measuring purposes.
            previous_now: Instant::now(),
            tick_offset: utils::time::get_time(utils::time::ClockType::Real) as i64,
            match_value: 0,
            load: 0,
            imsc: 0,
            ris: 0,
            interrupt_evt,
        }
    }

    fn trigger_interrupt(&mut self) -> Result<()> {
        self.interrupt_evt.write(1).map_err(Error::InterruptFailure)
    }

    fn get_time(&self) -> u32 {
        let ts = (self.tick_offset as i128)
            + (Instant::now().duration_since(self.previous_now).as_nanos() as i128);
        (ts / utils::time::NANOS_PER_SECOND as i128) as u32
    }

    fn handle_write(&mut self, offset: u64, val: u32) -> Result<()> {
        match offset {
            RTCMR => {
                // The MR register is used for implementing the RTC alarm. A real time clock alarm is
                // a feature that can be used to allow a computer to 'wake up' after shut down to execute
                // tasks every day or on a certain day. It can sometimes be found in the 'Power Management'
                // section of a motherboard's BIOS setup. This is functionality that extends beyond
                // Firecracker intended use. However, we increment a metric just in case.
                self.match_value = val;
                METRICS.rtc.missed_write_count.inc();
            }
            RTCLR => {
                self.load = val;
                self.previous_now = Instant::now();
                // If the unwrap fails, then the internal value of the clock has been corrupted and
                // we want to terminate the execution of the process.
                self.tick_offset = utils::time::seconds_to_nanoseconds(i64::from(val)).unwrap();
            }
            RTCIMSC => {
                self.imsc = val & 1;
                self.trigger_interrupt()?;
            }
            RTCICR => {
                // As per above mentioned doc, the interrupt is cleared by writing any data value to
                // the Interrupt Clear Register.
                self.ris = 0;
                self.trigger_interrupt()?;
            }
            RTCCR => (), // ignore attempts to turn off the timer.
            o => {
                return Err(Error::BadWriteOffset(o));
            }
        }
        Ok(())
    }
}

impl BusDevice for RTC {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        let v;
        let mut read_ok = true;

        if offset < AMBA_ID_HIGH && offset >= AMBA_ID_LOW {
            let index = ((offset - AMBA_ID_LOW) >> 2) as usize;
            v = u32::from(PL031_ID[index]);
        } else {
            v = match offset {
                RTCDR => self.get_time(),
                RTCMR => {
                    METRICS.rtc.missed_read_count.inc();
                    // Even though we are not implementing RTC alarm we return the last value
                    self.match_value
                }
                RTCLR => self.load,
                RTCCR => 1, // RTC is always enabled.
                RTCIMSC => self.imsc,
                RTCRIS => self.ris,
                RTCMIS => self.ris & self.imsc,
                _ => {
                    read_ok = false;
                    0
                }
            };
        }
        if read_ok && data.len() <= 4 {
            byte_order::write_le_u32(data, v);
        } else {
            warn!(
                "Invalid RTC PL031 read: offset {}, data length {}",
                offset,
                data.len()
            );
            METRICS.rtc.error_count.inc();
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() <= 4 {
            let v = byte_order::read_le_u32(&data[..]);
            if let Err(e) = self.handle_write(offset, v) {
                warn!("Failed to write to RTC PL031 device: {}", e);
                METRICS.rtc.error_count.inc();
            }
        } else {
            warn!(
                "Invalid RTC PL031 write: offset {}, data length {}",
                offset,
                data.len()
            );
            METRICS.rtc.error_count.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtc_read_write_and_event() {
        let mut rtc = RTC::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());
        let mut data = [0; 4];

        // Read and write to the MR register.
        byte_order::write_le_u32(&mut data, 123);
        rtc.write(RTCMR, &mut data);
        rtc.read(RTCMR, &mut data);
        let v = byte_order::read_le_u32(&data[..]);
        assert_eq!(v, 123);

        // Read and write to the LR register.
        let v = utils::time::get_time(utils::time::ClockType::Real);
        byte_order::write_le_u32(&mut data, (v / utils::time::NANOS_PER_SECOND) as u32);
        let previous_now_before = rtc.previous_now;
        rtc.write(RTCLR, &mut data);

        assert!(rtc.previous_now > previous_now_before);

        rtc.read(RTCLR, &mut data);
        let v_read = byte_order::read_le_u32(&data[..]);
        assert_eq!((v / utils::time::NANOS_PER_SECOND) as u32, v_read);

        // Read and write to IMSC register.
        // Test with non zero value.
        let non_zero = 1;
        byte_order::write_le_u32(&mut data, non_zero);
        rtc.write(RTCIMSC, &mut data);
        // The interrupt line should be on.
        assert!(rtc.interrupt_evt.read().unwrap() == 1);
        rtc.read(RTCIMSC, &mut data);
        let v = byte_order::read_le_u32(&data[..]);
        assert_eq!(non_zero & 1, v);

        // Now test with 0.
        byte_order::write_le_u32(&mut data, 0);
        rtc.write(RTCIMSC, &mut data);
        rtc.read(RTCIMSC, &mut data);
        let v = byte_order::read_le_u32(&data[..]);
        assert_eq!(0, v);

        // Read and write to the ICR register.
        byte_order::write_le_u32(&mut data, 1);
        rtc.write(RTCICR, &mut data);
        // The interrupt line should be on.
        assert!(rtc.interrupt_evt.read().unwrap() > 1);
        let v_before = byte_order::read_le_u32(&data[..]);
        let no_errors_before = METRICS.rtc.error_count.count();

        rtc.read(RTCICR, &mut data);
        let no_errors_after = METRICS.rtc.error_count.count();
        let v = byte_order::read_le_u32(&data[..]);
        // ICR is a  write only register. Data received should stay equal to data sent.
        assert_eq!(v, v_before);
        assert_eq!(no_errors_after - no_errors_before, 1);

        // Attempts to turn off the RTC should not go through.
        byte_order::write_le_u32(&mut data, 0);
        rtc.write(RTCCR, &mut data);
        rtc.read(RTCCR, &mut data);
        let v = byte_order::read_le_u32(&data[..]);
        assert_eq!(v, 1);

        // Attempts to write beyond the writable space. Using here the space used to read
        // the CID and PID from.
        byte_order::write_le_u32(&mut data, 0);
        let no_errors_before = METRICS.rtc.error_count.count();
        rtc.write(AMBA_ID_LOW, &mut data);
        let no_errors_after = METRICS.rtc.error_count.count();
        assert_eq!(no_errors_after - no_errors_before, 1);
        // However, reading from the AMBA_ID_LOW should succeed upon read.

        let mut data = [0; 4];
        rtc.read(AMBA_ID_LOW, &mut data);
        let index = AMBA_ID_LOW + 3;
        assert_eq!(data[0], PL031_ID[((index - AMBA_ID_LOW) >> 2) as usize]);
    }
}
