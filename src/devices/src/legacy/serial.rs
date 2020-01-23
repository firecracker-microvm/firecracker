// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::VecDeque;
use std::io;
use std::os::unix::io::AsRawFd;

use logger::{Metric, METRICS};
use polly::epoll::{EpollEvent, EventSet};
use polly::event_manager::Subscriber;
use utils::eventfd::EventFd;

use crate::bus::BusDevice;

const LOOP_SIZE: usize = 0x40;

const DATA: u8 = 0;
const IER: u8 = 1;
const IIR: u8 = 2;
const LCR: u8 = 3;
const MCR: u8 = 4;
const LSR: u8 = 5;
const MSR: u8 = 6;
const SCR: u8 = 7;

const DLAB_LOW: u8 = 0;
const DLAB_HIGH: u8 = 1;

const IER_RECV_BIT: u8 = 0x1;
const IER_THR_BIT: u8 = 0x2;
const IER_FIFO_BITS: u8 = 0x0f;

const IIR_FIFO_BITS: u8 = 0xc0;
const IIR_NONE_BIT: u8 = 0x1;
const IIR_THR_BIT: u8 = 0x2;
const IIR_RECV_BIT: u8 = 0x4;

const LCR_DLAB_BIT: u8 = 0x80;

const LSR_DATA_BIT: u8 = 0x1;
const LSR_EMPTY_BIT: u8 = 0x20;
const LSR_IDLE_BIT: u8 = 0x40;

const MCR_LOOP_BIT: u8 = 0x10;

const DEFAULT_INTERRUPT_IDENTIFICATION: u8 = IIR_NONE_BIT; // no pending interrupt
const DEFAULT_LINE_STATUS: u8 = LSR_EMPTY_BIT | LSR_IDLE_BIT; // THR empty and line is idle
const DEFAULT_LINE_CONTROL: u8 = 0x3; // 8-bits per character
const DEFAULT_MODEM_CONTROL: u8 = 0x8; // Auxiliary output 2
const DEFAULT_MODEM_STATUS: u8 = 0x20 | 0x10 | 0x80; // data ready, clear to send, carrier detect
const DEFAULT_BAUD_DIVISOR: u16 = 12; // 9600 bps

// Cannot use multiple types as bounds for a trait object, so we define our own trait
// which is a composition of the desired bounds. In this case, io::Read and AsRawFd.
// Run `rustc --explain E0225` for more details.
/// Trait that composes the `std::io::Read` and `std::os::unix::io::AsRawFd` traits.
pub trait ReadableFd: io::Read + AsRawFd {}

/// Emulates serial COM ports commonly seen on x86 I/O ports 0x3f8/0x2f8/0x3e8/0x2e8.
///
/// This can optionally write the guest's output to a Write trait object. To send input to the
/// guest, use `raw_input`.
pub struct Serial {
    interrupt_enable: u8,
    interrupt_identification: u8,
    interrupt_evt: EventFd,
    line_control: u8,
    line_status: u8,
    modem_control: u8,
    modem_status: u8,
    scratch: u8,
    baud_divisor: u16,
    in_buffer: VecDeque<u8>,
    out: Option<Box<dyn io::Write + Send>>,
    input: Option<Box<dyn ReadableFd + Send>>,
}

impl Serial {
    fn new(
        interrupt_evt: EventFd,
        out: Option<Box<dyn io::Write + Send>>,
        input: Option<Box<dyn ReadableFd + Send>>,
    ) -> Serial {
        Serial {
            interrupt_enable: 0,
            interrupt_identification: DEFAULT_INTERRUPT_IDENTIFICATION,
            interrupt_evt,
            line_control: DEFAULT_LINE_CONTROL,
            line_status: DEFAULT_LINE_STATUS,
            modem_control: DEFAULT_MODEM_CONTROL,
            modem_status: DEFAULT_MODEM_STATUS,
            scratch: 0,
            baud_divisor: DEFAULT_BAUD_DIVISOR,
            in_buffer: VecDeque::new(),
            out,
            input,
        }
    }

    /// Constructs a Serial port ready for input and output.
    pub fn new_in_out(
        interrupt_evt: EventFd,
        input: Box<dyn ReadableFd + Send>,
        out: Box<dyn io::Write + Send>,
    ) -> Serial {
        Self::new(interrupt_evt, Some(out), Some(input))
    }

    /// Constructs a Serial port ready for output but with no input.
    pub fn new_out(interrupt_evt: EventFd, out: Box<dyn io::Write + Send>) -> Serial {
        Self::new(interrupt_evt, Some(out), None)
    }

    /// Constructs a Serial port with no connected input or output.
    pub fn new_sink(interrupt_evt: EventFd) -> Serial {
        Self::new(interrupt_evt, None, None)
    }

    /// Provides a reference to the interrupt event fd.
    pub fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    fn is_dlab_set(&self) -> bool {
        (self.line_control & LCR_DLAB_BIT) != 0
    }

    fn is_recv_intr_enabled(&self) -> bool {
        (self.interrupt_enable & IER_RECV_BIT) != 0
    }

    fn is_thr_intr_enabled(&self) -> bool {
        (self.interrupt_enable & IER_THR_BIT) != 0
    }

    fn is_loop(&self) -> bool {
        (self.modem_control & MCR_LOOP_BIT) != 0
    }

    fn add_intr_bit(&mut self, bit: u8) {
        self.interrupt_identification &= !IIR_NONE_BIT;
        self.interrupt_identification |= bit;
    }

    fn del_intr_bit(&mut self, bit: u8) {
        self.interrupt_identification &= !bit;
        if self.interrupt_identification == 0x0 {
            self.interrupt_identification = IIR_NONE_BIT;
        }
    }

    fn thr_empty(&mut self) -> io::Result<()> {
        if self.is_thr_intr_enabled() {
            self.add_intr_bit(IIR_THR_BIT);
            self.trigger_interrupt()?
        }
        Ok(())
    }

    fn recv_data(&mut self) -> io::Result<()> {
        if self.is_recv_intr_enabled() {
            self.add_intr_bit(IIR_RECV_BIT);
            self.trigger_interrupt()?
        }
        self.line_status |= LSR_DATA_BIT;
        Ok(())
    }

    fn trigger_interrupt(&mut self) -> io::Result<()> {
        self.interrupt_evt.write(1)
    }

    fn iir_reset(&mut self) {
        self.interrupt_identification = DEFAULT_INTERRUPT_IDENTIFICATION;
    }

    // Handles a write request from the driver.
    fn handle_write(&mut self, offset: u8, value: u8) -> io::Result<()> {
        match offset as u8 {
            DLAB_LOW if self.is_dlab_set() => {
                self.baud_divisor = (self.baud_divisor & 0xff00) | u16::from(value)
            }
            DLAB_HIGH if self.is_dlab_set() => {
                self.baud_divisor = (self.baud_divisor & 0x00ff) | (u16::from(value) << 8)
            }
            DATA => {
                if self.is_loop() {
                    if self.in_buffer.len() < LOOP_SIZE {
                        self.in_buffer.push_back(value);
                        self.recv_data()?;
                    }
                } else {
                    if let Some(out) = self.out.as_mut() {
                        out.write_all(&[value])?;
                        METRICS.uart.write_count.inc();
                        out.flush()?;
                        METRICS.uart.flush_count.inc();
                    }
                    self.thr_empty()?;
                }
            }
            IER => self.interrupt_enable = value & IER_FIFO_BITS,
            LCR => self.line_control = value,
            MCR => self.modem_control = value,
            SCR => self.scratch = value,
            _ => {}
        }
        Ok(())
    }

    // Handles a read request from the driver.
    fn handle_read(&mut self, offset: u8) -> u8 {
        match offset as u8 {
            DLAB_LOW if self.is_dlab_set() => self.baud_divisor as u8,
            DLAB_HIGH if self.is_dlab_set() => (self.baud_divisor >> 8) as u8,
            DATA => {
                self.del_intr_bit(IIR_RECV_BIT);
                if self.in_buffer.len() <= 1 {
                    self.line_status &= !LSR_DATA_BIT;
                }
                METRICS.uart.read_count.inc();
                self.in_buffer.pop_front().unwrap_or_default()
            }
            IER => self.interrupt_enable,
            IIR => {
                let v = self.interrupt_identification | IIR_FIFO_BITS;
                self.iir_reset();
                v
            }
            LCR => self.line_control,
            MCR => self.modem_control,
            LSR => self.line_status,
            MSR => self.modem_status,
            SCR => self.scratch,
            _ => 0,
        }
    }

    fn raw_input(&mut self, data: &[u8]) -> io::Result<()> {
        if !self.is_loop() {
            self.in_buffer.extend(data);
            self.recv_data()?;
        }
        Ok(())
    }
}

impl BusDevice for Serial {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            METRICS.uart.missed_read_count.inc();
            return;
        }

        data[0] = self.handle_read(offset as u8);
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            METRICS.uart.missed_write_count.inc();
            return;
        }
        if let Err(e) = self.handle_write(offset as u8, data[0]) {
            error!("Failed the write to serial: {}", e);
            METRICS.uart.error_count.inc();
        }
    }
}

impl Subscriber for Serial {
    /// Handle a read event (EPOLLIN) on the serial input fd.
    fn process(&mut self, event: EpollEvent) {
        let source = event.fd();
        let event_set = event.event_set();

        // TODO: also check for errors. Pending high level discussions on how we want
        // to handle errors in devices.
        let supported_events = EventSet::IN;
        if !supported_events.contains(event_set) {
            warn!(
                "Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if let Some(input) = self.input.as_mut() {
            if input.as_raw_fd() == source {
                let mut out = [0u8; 32];
                match input.read(&mut out[..]) {
                    Ok(count) => {
                        self.raw_input(&out[..count])
                            .unwrap_or_else(|e| warn!("Serial error on input: {}", e));
                    }
                    Err(e) => {
                        warn!("error while reading stdin: {:?}", e);
                    }
                }
            }
        }
        error!("Spurious Serial input event!");
    }

    /// Initial registration of pollable objects.
    /// If serial input is present, register the serial input FD as readable.
    fn interest_list(&self) -> Vec<EpollEvent> {
        match &self.input {
            Some(input) => vec![EpollEvent::new(EventSet::IN, input.as_raw_fd() as u64)],
            None => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::io::Write;
    use std::os::unix::io::RawFd;
    use std::sync::{Arc, Mutex};

    use polly::event_manager::EventManager;

    struct SharedBufferInternal {
        read_buf: Vec<u8>,
        write_buf: Vec<u8>,
        evfd: EventFd,
    }

    #[derive(Clone)]
    struct SharedBuffer {
        internal: Arc<Mutex<SharedBufferInternal>>,
    }

    impl SharedBuffer {
        fn new() -> SharedBuffer {
            SharedBuffer {
                internal: Arc::new(Mutex::new(SharedBufferInternal {
                    read_buf: Vec::new(),
                    write_buf: Vec::new(),
                    evfd: EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                })),
            }
        }
    }
    impl io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.internal.lock().unwrap().write_buf.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.internal.lock().unwrap().write_buf.flush()
        }
    }
    impl io::Read for SharedBuffer {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.internal.lock().unwrap().read_buf.as_slice().read(buf)
        }
    }
    impl AsRawFd for SharedBuffer {
        fn as_raw_fd(&self) -> RawFd {
            self.internal.lock().unwrap().evfd.as_raw_fd()
        }
    }
    impl ReadableFd for SharedBuffer {}

    static RAW_INPUT_BUF: [u8; 3] = [b'a', b'b', b'c'];

    #[test]
    fn test_event_handling_no_in() {
        let intr_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new_out(intr_evt, Box::new(serial_out.clone()));
        // A serial without in does not have any events in the list.
        assert!(serial.interest_list().is_empty());
        // Even though there is no in, process should not panic. Call it to validate this.
        serial.process(EpollEvent::new(EventSet::IN, 0));
    }

    #[test]
    fn test_event_handling_with_in() {
        let intr_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let serial_in_out = SharedBuffer::new();

        let mut serial = Serial::new_in_out(
            intr_evt.try_clone().unwrap(),
            Box::new(serial_in_out.clone()),
            Box::new(serial_in_out.clone()),
        );
        // Check that the interest list contains the EPOLL_IN event.
        assert_eq!(serial.interest_list().len(), 1);

        // Process an invalid event type does not panic.
        let invalid_event = EpollEvent::new(EventSet::OUT, intr_evt.as_raw_fd() as u64);
        serial.process(invalid_event);

        // Process an event with a `RawFd` that does not correspond to `intr_evt` does not panic.
        let invalid_event = EpollEvent::new(EventSet::IN, 0);
        serial.process(invalid_event);
    }

    #[test]
    fn test_serial_output() {
        let intr_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new_out(intr_evt, Box::new(serial_out.clone()));

        // Invalid write of multiple chars at once.
        serial.write(u64::from(DATA), &[b'x', b'y']);
        // Valid one char at a time writes.
        RAW_INPUT_BUF
            .iter()
            .for_each(|&c| serial.write(u64::from(DATA), &[c]));
        assert_eq!(
            serial_out.internal.lock().unwrap().write_buf.as_slice(),
            &RAW_INPUT_BUF
        );
    }

    #[test]
    fn test_serial_raw_input() {
        let intr_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let serial_out = SharedBuffer::new();

        let mut serial = Serial::new_out(intr_evt.try_clone().unwrap(), Box::new(serial_out));

        // Write 1 to the interrupt event fd, so that read doesn't block in case the event fd
        // counter doesn't change (for 0 it blocks).
        assert!(intr_evt.write(1).is_ok());
        serial.write(u64::from(IER), &[IER_RECV_BIT]);
        serial.raw_input(&RAW_INPUT_BUF).unwrap();

        // Verify the serial raised an interrupt.
        assert_eq!(intr_evt.read().unwrap(), 2);

        // Check if reading in a 2-length array doesn't have side effects.
        let mut data = [0u8, 0u8];
        serial.read(u64::from(DATA), &mut data[..]);
        assert_eq!(data, [0u8, 0u8]);

        let mut data = [0u8];
        serial.read(u64::from(LSR), &mut data[..]);
        assert_ne!(data[0] & LSR_DATA_BIT, 0);

        // Verify reading the previously inputted buffer.
        RAW_INPUT_BUF.iter().for_each(|&c| {
            serial.read(u64::from(DATA), &mut data[..]);
            assert_eq!(data[0], c);
        });

        // Check if reading from the largest u8 offset returns 0.
        serial.read(0xff, &mut data[..]);
        assert_eq!(data[0], 0);
    }

    #[test]
    fn test_serial_input() {
        let intr_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let serial_in_out = SharedBuffer::new();

        let mut serial = Serial::new_in_out(
            intr_evt.try_clone().unwrap(),
            Box::new(serial_in_out.clone()),
            Box::new(serial_in_out.clone()),
        );

        // Write 1 to the interrupt event fd, so that read doesn't block in case the event fd
        // counter doesn't change (for 0 it blocks).
        assert!(intr_evt.write(1).is_ok());
        serial.write(u64::from(IER), &[IER_RECV_BIT]);

        // Prepare the input buffer.
        {
            let mut guard = serial_in_out.internal.lock().unwrap();
            guard.read_buf.write_all(&RAW_INPUT_BUF).unwrap();
            guard.evfd.write(1).unwrap();
        }

        let mut evmgr = EventManager::new().unwrap();
        let serial_wrap = Arc::new(Mutex::new(serial));
        evmgr.add_subscriber(serial_wrap.clone()).unwrap();

        // Run the event handler which should drive serial input.
        // There should be one event reported (which should have also handled serial input).
        assert_eq!(evmgr.run_with_timeout(50).unwrap(), 1);

        // Verify the serial raised an interrupt.
        assert_eq!(intr_evt.read().unwrap(), 2);

        let mut serial = serial_wrap.lock().unwrap();
        let mut data = [0u8];
        serial.read(u64::from(LSR), &mut data[..]);
        assert_ne!(data[0] & LSR_DATA_BIT, 0);

        // Verify reading the previously inputted buffer.
        RAW_INPUT_BUF.iter().for_each(|&c| {
            serial.read(u64::from(DATA), &mut data[..]);
            assert_eq!(data[0], c);
        });
    }

    #[test]
    fn test_serial_thr() {
        let intr_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let mut serial = Serial::new_sink(intr_evt.try_clone().unwrap());

        // write 1 to the interrupt event fd, so that read doesn't block in case the event fd
        // counter doesn't change (for 0 it blocks)
        assert!(intr_evt.write(1).is_ok());
        serial.write(u64::from(IER), &[IER_THR_BIT]);
        serial.write(u64::from(DATA), &[b'a']);

        assert_eq!(intr_evt.read().unwrap(), 2);
        let mut data = [0u8];
        serial.read(u64::from(IER), &mut data[..]);
        assert_eq!(data[0] & IER_FIFO_BITS, IER_THR_BIT);
        serial.read(u64::from(IIR), &mut data[..]);
        assert_ne!(data[0] & IIR_THR_BIT, 0);
    }

    #[test]
    fn test_serial_dlab() {
        let mut serial = Serial::new_sink(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        serial.write(u64::from(LCR), &[LCR_DLAB_BIT as u8]);
        serial.write(u64::from(DLAB_LOW), &[0x12 as u8]);
        serial.write(u64::from(DLAB_HIGH), &[0x34 as u8]);

        let mut data = [0u8];
        serial.read(u64::from(LCR), &mut data[..]);
        assert_eq!(data[0], LCR_DLAB_BIT as u8);
        serial.read(u64::from(DLAB_LOW), &mut data[..]);
        assert_eq!(data[0], 0x12);
        serial.read(u64::from(DLAB_HIGH), &mut data[..]);
        assert_eq!(data[0], 0x34);
    }

    #[test]
    fn test_serial_modem() {
        let mut serial = Serial::new_sink(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        serial.write(u64::from(MCR), &[MCR_LOOP_BIT as u8]);
        serial.write(u64::from(DATA), &[b'a']);
        serial.write(u64::from(DATA), &[b'b']);
        serial.write(u64::from(DATA), &[b'c']);

        let mut data = [0u8];
        serial.read(u64::from(MSR), &mut data[..]);
        assert_eq!(data[0], DEFAULT_MODEM_STATUS as u8);
        serial.read(u64::from(MCR), &mut data[..]);
        assert_eq!(data[0], MCR_LOOP_BIT as u8);
        serial.read(u64::from(DATA), &mut data[..]);
        assert_eq!(data[0], b'a');
        serial.read(u64::from(DATA), &mut data[..]);
        assert_eq!(data[0], b'b');
        serial.read(u64::from(DATA), &mut data[..]);
        assert_eq!(data[0], b'c');
    }

    #[test]
    fn test_serial_scratch() {
        let mut serial = Serial::new_sink(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        serial.write(u64::from(SCR), &[0x12 as u8]);

        let mut data = [0u8];
        serial.read(u64::from(SCR), &mut data[..]);
        assert_eq!(data[0], 0x12 as u8);
    }

    #[test]
    fn test_serial_data_len() {
        const LEN: usize = 1;
        let mut serial = Serial::new_sink(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        let missed_writes_before = METRICS.uart.missed_write_count.count();
        // Trying to write data of length different than the one that we initialized the device with
        // should increase the `missed_write_count` metric.
        serial.write(u64::from(DATA), &[b'x', b'x']);
        let missed_writes_after = METRICS.uart.missed_write_count.count();
        assert_eq!(missed_writes_before, missed_writes_after - 1);

        let data = [b'x'; LEN];
        serial.write(u64::from(DATA), &data);
        // When we write data that has the length used to initialize the device, the `missed_write_count`
        // metric stays the same.
        assert_eq!(missed_writes_before, missed_writes_after - 1);
    }
}
