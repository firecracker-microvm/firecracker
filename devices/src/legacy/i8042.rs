// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use logger::{Metric, METRICS};
use std::fmt;
use std::num::Wrapping;
use std::{io, result};
use sys_util::EventFd;

use BusDevice;

#[derive(Debug)]
pub enum Error {
    CloneCpuResetEvt(io::Error),
    KbdInterruptDisabled,
    KbdInterruptFailure(io::Error),
    InternalBufferFull,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::CloneCpuResetEvt(io_err) => write!(
                f,
                "Could not clone CPU reset eventfd: {}.",
                io_err.to_string()
            ),
            Error::KbdInterruptDisabled => {
                write!(f, "Keyboard interrupt disabled by guest driver.",)
            }
            Error::KbdInterruptFailure(io_err) => write!(
                f,
                "Could not trigger keyboard interrupt: {}.",
                io_err.to_string()
            ),
            Error::InternalBufferFull => write!(f, "i8042 internal buffer full."),
        }
    }
}

type Result<T> = result::Result<T, Error>;

/// Offset of the status port (port 0x64)
const OFS_STATUS: u64 = 4;

/// Offset of the data port (port 0x60)
const OFS_DATA: u64 = 0;

/// i8042 commands
/// These values are written by the guest driver to port 0x64.
const CMD_READ_CTR: u8 = 0x20; // Read control register
const CMD_WRITE_CTR: u8 = 0x60; // Write control register
const CMD_READ_OUTP: u8 = 0xD0; // Read output port
const CMD_WRITE_OUTP: u8 = 0xD1; // Write output port
const CMD_RESET_CPU: u8 = 0xFE; // Reset CPU

/// i8042 status register bits
const SB_OUT_DATA_AVAIL: u8 = 1; // Data available at port 0x60
const SB_I8042_CMD_DATA: u8 = 1 << 3; // i8042 expecting command parameter at port 0x60
const SB_KBD_ENABLED: u8 = 1 << 4; // 1 = kbd enabled, 0 = kbd locked

/// i8042 control register bits
const CB_KBD_INT: u8 = 1 << 0; // kbd interrupt enabled
const CB_POST_OK: u8 = 1 << 2; // POST ok (should always be 1)

/// Key scan codes
const KEY_CTRL: u16 = 0x0014;
const KEY_ALT: u16 = 0x0011;
const KEY_DEL: u16 = 0xE071;

/// Internal i8042 buffer size, in bytes
const BUF_SIZE: usize = 16;

/// A i8042 PS/2 controller that emulates just enough to shutdown the machine.
pub struct I8042Device {
    /// CPU reset eventfd. We will set this event when the guest issues CMD_RESET_CPU.
    reset_evt: EventFd,

    /// Keyboard interrupt event (IRQ 1).
    kbd_interrupt_evt: EventFd,

    /// The i8042 status register.
    status: u8,

    /// The i8042 control register.
    control: u8,

    /// The i8042 output port.
    outp: u8,

    /// The last command sent to port 0x64.
    cmd: u8,

    /// The internal i8042 data buffer.
    buf: [u8; BUF_SIZE],
    bhead: Wrapping<usize>,
    btail: Wrapping<usize>,
}

impl I8042Device {
    /// Constructs an i8042 device that will signal the given event when the guest requests it.
    pub fn new(reset_evt: EventFd, kbd_interrupt_evt: EventFd) -> I8042Device {
        I8042Device {
            reset_evt,
            kbd_interrupt_evt,
            control: CB_POST_OK | CB_KBD_INT,
            cmd: 0,
            outp: 0,
            status: SB_KBD_ENABLED,
            buf: [0; BUF_SIZE],
            bhead: Wrapping(0),
            btail: Wrapping(0),
        }
    }

    /// Returns a clone of the CPU reset event fd
    pub fn get_reset_evt_clone(&self) -> Result<EventFd> {
        self.reset_evt.try_clone().map_err(Error::CloneCpuResetEvt)
    }

    pub fn trigger_kbd_interrupt(&self) -> Result<()> {
        if (self.control & CB_KBD_INT) == 0 {
            return Err(Error::KbdInterruptDisabled);
        }
        self.kbd_interrupt_evt
            .write(1)
            .map_err(Error::KbdInterruptFailure)
    }

    pub fn trigger_key(&mut self, key: u16) -> Result<()> {
        if key & 0xff00 != 0 {
            // Check if there is enough room in the buffer, before pushing an extended (2-byte) key.
            if BUF_SIZE - self.buf_len() < 2 {
                return Err(Error::InternalBufferFull);
            }
            self.push_byte((key >> 8) as u8)?;
        }
        self.push_byte((key & 0xff) as u8)?;

        match self.trigger_kbd_interrupt() {
            Ok(_) | Err(Error::KbdInterruptDisabled) => {
                warn!("Failed to trigger i8042 kbd interrupt (disabled by guest OS)");
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    #[inline]
    pub fn trigger_ctrl_alt_del(&mut self) -> Result<()> {
        // The CTRL+ALT+DEL sequence is 4 bytes in total (1 extended key + 2 normal keys).
        // Fail if we don't have room for the whole sequence.
        if BUF_SIZE - self.buf_len() < 4 {
            return Err(Error::InternalBufferFull);
        }
        self.trigger_key(KEY_CTRL)?;
        self.trigger_key(KEY_ALT)?;
        self.trigger_key(KEY_DEL)?;
        Ok(())
    }

    #[inline]
    fn push_byte(&mut self, byte: u8) -> Result<()> {
        self.status |= SB_OUT_DATA_AVAIL;
        if self.buf_len() == BUF_SIZE {
            return Err(Error::InternalBufferFull);
        }
        self.buf[self.btail.0 % BUF_SIZE] = byte;
        self.btail += Wrapping(1usize);
        Ok(())
    }

    #[inline]
    fn pop_byte(&mut self) -> Option<u8> {
        if self.buf_len() == 0 {
            return None;
        }
        let res = self.buf[self.bhead.0 % BUF_SIZE];
        self.bhead += Wrapping(1usize);
        if self.buf_len() == 0 {
            self.status &= !SB_OUT_DATA_AVAIL;
        }
        Some(res)
    }

    #[inline]
    fn flush_buf(&mut self) {
        self.bhead = Wrapping(0usize);
        self.btail = Wrapping(0usize);
        self.status &= !SB_OUT_DATA_AVAIL;
    }

    #[inline]
    fn buf_len(&self) -> usize {
        (self.btail - self.bhead).0
    }
}

impl BusDevice for I8042Device {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        // All our ports are byte-wide. We don't know how to handle any wider data.
        if data.len() != 1 {
            METRICS.i8042.missed_read_count.inc();
            return;
        }

        let mut read_ok = true;

        match offset {
            OFS_STATUS => data[0] = self.status,
            OFS_DATA => {
                // The guest wants to read a byte from port 0x60. For the 8042, that means the top
                // byte in the internal buffer. If the buffer is empty, the guest will get a 0.
                data[0] = self.pop_byte().unwrap_or(0);

                // Check if we still have data in the internal buffer. If so, we need to trigger
                // another interrupt, to let the guest know they need to issue another read from
                // port 0x60.
                if (self.status & SB_OUT_DATA_AVAIL) != 0 {
                    if let Err(Error::KbdInterruptFailure(err)) = self.trigger_kbd_interrupt() {
                        warn!("Failed to trigger i8042 kbd interrupt {:?}", err);
                    }
                }
            }
            _ => read_ok = false,
        }
        if read_ok {
            METRICS.i8042.read_count.add(data.len());
        } else {
            METRICS.i8042.missed_read_count.inc();
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        // All our ports are byte-wide. We don't know how to handle any wider data.
        if data.len() != 1 {
            METRICS.i8042.missed_write_count.inc();
            return;
        }

        let mut write_ok = true;

        match offset {
            OFS_STATUS if data[0] == CMD_RESET_CPU => {
                // The guest wants to assert the CPU reset line. We handle that by triggering
                // our exit event fd. Meaning Firecracker will be exiting as soon as the VMM
                // thread wakes up to handle this event.
                if let Err(e) = self.reset_evt.write(1) {
                    error!("Failed to trigger i8042 reset event: {:?}", e);
                    METRICS.i8042.error_count.inc();
                }
                METRICS.i8042.reset_count.inc();
            }
            OFS_STATUS if data[0] == CMD_READ_CTR => {
                // The guest wants to read the control register.
                // Let's make sure only the control register will be available for reading from
                // the data port, for the next inb(0x60).
                self.flush_buf();
                let control = self.control;
                // Buffer is empty, push() will always succeed.
                self.push_byte(control).unwrap();
            }
            OFS_STATUS if data[0] == CMD_WRITE_CTR => {
                // The guest wants to write the control register. This is a two-step command:
                // 1. port 0x64 < CMD_WRITE_CTR
                // 2. port 0x60 < <control reg value>
                // Make sure we'll be expecting the control reg value on port 0x60 for the next
                // write.
                self.flush_buf();
                self.status |= SB_I8042_CMD_DATA;
                self.cmd = data[0];
            }
            OFS_STATUS if data[0] == CMD_READ_OUTP => {
                // The guest wants to read the output port (for lack of a better name - this is
                // just another register on the 8042, that happens to also have its bits connected
                // to some output pins of the 8042).
                self.flush_buf();
                let outp = self.outp;
                // Buffer is empty, push() will always succeed.
                self.push_byte(outp).unwrap();
            }
            OFS_STATUS if data[0] == CMD_WRITE_OUTP => {
                // Similar to writing the control register, this is a two-step command.
                // I.e. write CMD_WRITE_OUTP at port 0x64, then write the actual out port value
                // to port 0x60.
                self.status |= SB_I8042_CMD_DATA;
                self.cmd = data[0];
            }
            OFS_DATA if (self.status & SB_I8042_CMD_DATA) != 0 => {
                // The guest is writing to port 0x60. This byte can either be:
                // 1. the payload byte of a CMD_WRITE_CTR or CMD_WRITE_OUTP command, in which case
                //    the status reg bit SB_I8042_CMD_DATA will be set, or
                // 2. a direct command sent to the keyboard
                // This match arm handles the first option (when the SB_I8042_CMD_DATA bit is set).
                match self.cmd {
                    CMD_WRITE_CTR => self.control = data[0],
                    CMD_WRITE_OUTP => self.outp = data[0],
                    _ => (),
                }
                self.status &= !SB_I8042_CMD_DATA;
            }
            OFS_DATA => {
                // The guest is sending a command straight to the keyboard (so this byte is not
                // addressed to the 8042, but to the keyboard). Since we're emulating a pretty
                // dumb keyboard, we can get away with blindly ack-in anything (byte 0xFA).
                // Something along the lines of "Yeah, uhm-uhm, yeah, okay, honey, that's great."
                self.flush_buf();
                // Buffer is empty, push() will always succeed.
                self.push_byte(0xFA).unwrap();
                if let Err(Error::KbdInterruptFailure(err)) = self.trigger_kbd_interrupt() {
                    warn!("Failed to trigger i8042 kbd interrupt {:?}", err);
                }
            }
            _ => {
                write_ok = false;
            }
        }

        if write_ok {
            METRICS.i8042.write_count.inc();
        } else {
            METRICS.i8042.missed_write_count.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_i8042_read_write_and_event() {
        let mut i8042 = I8042Device::new(EventFd::new().unwrap(), EventFd::new().unwrap());
        let reset_evt = i8042.get_reset_evt_clone().unwrap();

        // Check if reading in a 2-length array doesn't have side effects.
        let mut data = [1, 2];
        i8042.read(0, &mut data);
        assert_eq!(data, [1, 2]);
        i8042.read(1, &mut data);
        assert_eq!(data, [1, 2]);

        // Check if reset works.
        // Write 1 to the reset event fd, so that read doesn't block in case the event fd
        // counter doesn't change (for 0 it blocks).
        assert!(reset_evt.write(1).is_ok());
        let mut data = [CMD_RESET_CPU];
        i8042.write(OFS_STATUS, &mut data);
        assert_eq!(reset_evt.read().unwrap(), 2);

        // Check if reading with offset 1 doesn't have side effects.
        i8042.read(1, &mut data);
        assert_eq!(data[0], CMD_RESET_CPU);

        // Check invalid `write`s.
        let before = METRICS.i8042.missed_write_count.count();
        // offset != 0.
        i8042.write(1, &mut data);
        // data != CMD_RESET_CPU
        data[0] = CMD_RESET_CPU + 1;
        i8042.write(1, &mut data);
        // data.len() != 1
        let mut data = [CMD_RESET_CPU; 2];
        i8042.write(1, &mut data);
        assert_eq!(METRICS.i8042.missed_write_count.count(), before + 3);
    }

    #[test]
    fn test_i8042_commands() {
        let mut i8042 = I8042Device::new(EventFd::new().unwrap(), EventFd::new().unwrap());
        let mut data = [1];

        // Test reading/writing the control register.
        data[0] = CMD_WRITE_CTR;
        i8042.write(OFS_STATUS, &data);
        assert_ne!(i8042.status & SB_I8042_CMD_DATA, 0);
        data[0] = 0x52;
        i8042.write(OFS_DATA, &data);
        data[0] = CMD_READ_CTR;
        i8042.write(OFS_STATUS, &data);
        assert_ne!(i8042.status & SB_OUT_DATA_AVAIL, 0);
        i8042.read(OFS_DATA, &mut data);
        assert_eq!(data[0], 0x52);

        // Test reading/writing the output port.
        data[0] = CMD_WRITE_OUTP;
        i8042.write(OFS_STATUS, &data);
        assert_ne!(i8042.status & SB_I8042_CMD_DATA, 0);
        data[0] = 0x52;
        i8042.write(OFS_DATA, &data);
        data[0] = CMD_READ_OUTP;
        i8042.write(OFS_STATUS, &data);
        assert_ne!(i8042.status & SB_OUT_DATA_AVAIL, 0);
        i8042.read(OFS_DATA, &mut data);
        assert_eq!(data[0], 0x52);

        // Test kbd commands.
        data[0] = 0x52;
        i8042.write(OFS_DATA, &data);
        assert_ne!(i8042.status & SB_OUT_DATA_AVAIL, 0);
        i8042.read(OFS_DATA, &mut data);
        assert_eq!(data[0], 0xFA);
    }

    #[test]
    fn test_i8042_buffer() {
        let mut i8042 = I8042Device::new(EventFd::new().unwrap(), EventFd::new().unwrap());

        // Test push/pop.
        i8042.push_byte(52).unwrap();
        assert_ne!(i8042.status & SB_OUT_DATA_AVAIL, 0);
        assert_eq!(i8042.pop_byte().unwrap(), 52);
        assert_eq!(i8042.status & SB_OUT_DATA_AVAIL, 0);

        // Test empty buffer pop.
        assert!(i8042.pop_byte().is_none());

        // Test buffer full.
        for i in 0..BUF_SIZE {
            i8042.push_byte(i as u8).unwrap();
            assert_eq!(i8042.buf_len(), i + 1);
        }
        match i8042.push_byte(0) {
            Err(Error::InternalBufferFull) => (),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_i8042_kbd() {
        let mut i8042 = I8042Device::new(EventFd::new().unwrap(), EventFd::new().unwrap());

        fn expect_key(i8042: &mut I8042Device, key: u16) {
            let mut data = [1];

            // The interrupt line should be on.
            i8042.trigger_kbd_interrupt().unwrap();
            assert!(i8042.kbd_interrupt_evt.read().unwrap() > 1);

            // The "data available" flag should be on.
            i8042.read(OFS_STATUS, &mut data);

            let mut key_byte: u8;
            if key & 0xFF00 != 0 {
                // For extended keys, we should be able to read the MSB first.
                key_byte = ((key & 0xFF00) >> 8) as u8;
                i8042.read(OFS_DATA, &mut data);
                assert_eq!(data[0], key_byte);

                // And then do the same for the LSB.

                // The interrupt line should be on.
                i8042.trigger_kbd_interrupt().unwrap();
                assert!(i8042.kbd_interrupt_evt.read().unwrap() > 1);
                // The "data available" flag should be on.
                i8042.read(OFS_STATUS, &mut data);
            }
            key_byte = (key & 0xFF) as u8;
            i8042.read(OFS_DATA, &mut data);
            assert_eq!(data[0], key_byte);
        }

        // Test key trigger.
        i8042.trigger_key(KEY_CTRL).unwrap();
        expect_key(&mut i8042, KEY_CTRL);

        // Test extended key trigger.
        i8042.trigger_key(KEY_DEL).unwrap();
        expect_key(&mut i8042, KEY_DEL);

        // Test CTRL+ALT+DEL trigger.
        i8042.trigger_ctrl_alt_del().unwrap();
        expect_key(&mut i8042, KEY_CTRL);
        expect_key(&mut i8042, KEY_ALT);
        expect_key(&mut i8042, KEY_DEL);

        // Almost fill up the buffer, so we can test trigger failures.
        for _i in 0..BUF_SIZE - 1 {
            i8042.push_byte(1).unwrap();
        }

        // Test extended key trigger failure.
        assert_eq!(i8042.buf_len(), BUF_SIZE - 1);
        match i8042.trigger_key(KEY_DEL) {
            Err(Error::InternalBufferFull) => (),
            _ => assert!(false),
        }

        // Test ctrl+alt+del trigger failure.
        i8042.pop_byte().unwrap();
        i8042.pop_byte().unwrap();
        assert_eq!(i8042.buf_len(), BUF_SIZE - 3);
        match i8042.trigger_ctrl_alt_del() {
            Err(Error::InternalBufferFull) => (),
            _ => assert!(false),
        }

        // Test kbd interrupt disable.
        let mut data = [1];
        data[0] = CMD_WRITE_CTR;
        i8042.write(OFS_STATUS, &data);
        data[0] = i8042.control & !CB_KBD_INT;
        i8042.write(OFS_DATA, &data);
        i8042.trigger_key(KEY_CTRL).unwrap();
        match i8042.trigger_kbd_interrupt() {
            Err(Error::KbdInterruptDisabled) => (),
            _ => assert!(false),
        }
    }
}
