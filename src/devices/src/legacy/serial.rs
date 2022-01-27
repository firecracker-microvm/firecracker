// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use crate::legacy::EventFdTrigger;
use crate::BusDevice;
use logger::SerialDeviceMetrics;
use std::io;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::result;
use std::sync::Arc;
use vm_superio::serial::Error as SerialError;
use vm_superio::serial::SerialEvents;
use vm_superio::Serial;
use vm_superio::Trigger;

use event_manager::{EventOps, Events, MutEventSubscriber};
use logger::{error, warn, IncMetric};
use std::os::unix::io::RawFd;
use utils::epoll::EventSet;

// Cannot use multiple types as bounds for a trait object, so we define our own trait
// which is a composition of the desired bounds. In this case, io::Read and AsRawFd.
// Run `rustc --explain E0225` for more details.
/// Trait that composes the `std::io::Read` and `std::os::unix::io::AsRawFd` traits.
pub trait ReadableFd: io::Read + AsRawFd {}

// Received Data Available interrupt - for letting the driver know that
// there is some pending data to be processed.
pub const IER_RDA_BIT: u8 = 0b0000_0001;
// Received Data Available interrupt offset
pub const IER_RDA_OFFSET: u8 = 1;

#[derive(Debug)]
pub enum RawIOError {
    Serial(SerialError<io::Error>),
}

pub trait RawIOHandler {
    /// Send raw input to this emulated device.
    fn raw_input(&mut self, _data: &[u8]) -> result::Result<(), RawIOError>;
}

impl<EV: SerialEvents, W: Write> RawIOHandler for Serial<EventFdTrigger, EV, W> {
    // This is not used for anything and is basically just a dummy implementation for `raw_input`.
    fn raw_input(&mut self, data: &[u8]) -> result::Result<(), RawIOError> {
        // Fail fast if the serial is serviced with more data than it can buffer.
        if data.len() > self.fifo_capacity() {
            return Err(RawIOError::Serial(SerialError::FullFifo));
        }

        // Before enqueuing bytes we first check if there is enough free space
        // in the FIFO.
        if self.fifo_capacity() >= data.len() {
            self.enqueue_raw_bytes(data).map_err(RawIOError::Serial)?;
        }
        Ok(())
    }
}

pub struct SerialEventsWrapper {
    pub metrics: Arc<SerialDeviceMetrics>,
    pub buffer_ready_event_fd: Option<EventFdTrigger>,
}

impl SerialEvents for SerialEventsWrapper {
    fn buffer_read(&self) {
        self.metrics.read_count.inc();
    }

    fn out_byte(&self) {
        self.metrics.write_count.inc();
    }

    fn tx_lost_byte(&self) {
        self.metrics.missed_write_count.inc();
    }

    fn in_buffer_empty(&self) {
        match self
            .buffer_ready_event_fd
            .as_ref()
            .map_or(Ok(()), |buf_ready| buf_ready.write(1))
        {
            Ok(_) => (),
            Err(err) => error!(
                "Could not signal that serial device buffer is ready: {:?}",
                err
            ),
        }
    }
}

pub struct SerialWrapper<T: Trigger, EV: SerialEvents, W: Write> {
    pub serial: Serial<T, EV, W>,
    pub input: Option<Box<dyn ReadableFd + Send>>,
}

impl<W: Write> SerialWrapper<EventFdTrigger, SerialEventsWrapper, W> {
    fn handle_ewouldblock(&self, ops: &mut EventOps) {
        let buffer_ready_fd = self.buffer_ready_evt_fd();
        let input_fd = self.serial_input_fd();
        if input_fd < 0 || buffer_ready_fd < 0 {
            error!("Serial does not have a configured input source.");
            return;
        }
        match ops.add(Events::new(&input_fd, EventSet::IN)) {
            Err(event_manager::Error::FdAlreadyRegistered) => (),
            Err(e) => {
                error!(
                    "Could not register the serial input to the event manager: {:?}",
                    e
                );
            }
            Ok(()) => {
                // Bytes might had come on the unregistered stdin. Try to consume any.
                self.serial.events().in_buffer_empty()
            }
        };
    }

    fn recv_bytes(&mut self) -> io::Result<usize> {
        let avail_cap = self.serial.fifo_capacity();
        if avail_cap == 0 {
            return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
        }

        if let Some(input) = self.input.as_mut() {
            let mut out = vec![0u8; avail_cap];
            let count = input.read(&mut out)?;
            if count > 0 {
                self.serial
                    .raw_input(&out[..count])
                    .map_err(|_| io::Error::from_raw_os_error(libc::ENOBUFS))?;
            }

            return Ok(count);
        }

        Err(io::Error::from_raw_os_error(libc::ENOTTY))
    }

    #[inline]
    fn buffer_ready_evt_fd(&self) -> RawFd {
        self.serial
            .events()
            .buffer_ready_event_fd
            .as_ref()
            .map_or(-1, |buf_ready| buf_ready.as_raw_fd())
    }

    #[inline]
    fn serial_input_fd(&self) -> RawFd {
        self.input.as_ref().map_or(-1, |input| input.as_raw_fd())
    }

    pub fn consume_buffer_ready_event(&self) -> io::Result<u64> {
        self.serial
            .events()
            .buffer_ready_event_fd
            .as_ref()
            .map_or(Ok(0), |buf_ready| buf_ready.read())
    }
}

pub type SerialDevice =
    SerialWrapper<EventFdTrigger, SerialEventsWrapper, Box<dyn io::Write + Send>>;

impl<W: std::io::Write> MutEventSubscriber
    for SerialWrapper<EventFdTrigger, SerialEventsWrapper, W>
{
    /// Handle events on the serial input fd.
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        #[inline]
        fn unregister_source<T: AsRawFd>(ops: &mut EventOps, source: &T) {
            match ops.remove(Events::new(source, EventSet::IN)) {
                Ok(_) => (),
                Err(_) => error!("Could not unregister source fd: {}", source.as_raw_fd()),
            }
        }

        let input_fd = self.serial_input_fd();
        let buffer_ready_fd = self.buffer_ready_evt_fd();
        if input_fd < 0 || buffer_ready_fd < 0 {
            error!("Serial does not have a configured input source.");
            return;
        }

        if buffer_ready_fd == event.fd() {
            match self.consume_buffer_ready_event() {
                Ok(_) => (),
                Err(err) => {
                    error!("Detach serial device input source due to error in consuming the buffer ready event: {:?}", err);
                    unregister_source(ops, &input_fd);
                    unregister_source(ops, &buffer_ready_fd);
                    return;
                }
            }
        }

        // We expect to receive: `EventSet::IN`, `EventSet::HANG_UP` or
        // `EventSet::ERROR`. To process all these events we just have to
        // read from the serial input.
        match self.recv_bytes() {
            Ok(count) => {
                // Handle EOF if the event came from the input source.
                if input_fd == event.fd() && count == 0 {
                    unregister_source(ops, &input_fd);
                    unregister_source(ops, &buffer_ready_fd);
                    warn!("Detached the serial input due to peer close/error.");
                }
            }
            Err(e) => {
                match e.raw_os_error() {
                    Some(errno) if errno == libc::ENOBUFS => {
                        unregister_source(ops, &input_fd);
                    }
                    Some(errno) if errno == libc::EWOULDBLOCK => {
                        self.handle_ewouldblock(ops);
                    }
                    Some(errno) if errno == libc::ENOTTY => {
                        error!("The serial device does not have the input source attached.");
                        unregister_source(ops, &input_fd);
                        unregister_source(ops, &buffer_ready_fd);
                    }
                    Some(_) | None => {
                        // Unknown error, detach the serial input source.
                        unregister_source(ops, &input_fd);
                        unregister_source(ops, &buffer_ready_fd);
                        warn!("Detached the serial input due to peer close/error.");
                    }
                }
            }
        }
    }

    /// Initial registration of pollable objects.
    /// If serial input is present, register the serial input FD as readable.
    fn init(&mut self, ops: &mut EventOps) {
        if self.input.is_some() && self.serial.events().buffer_ready_event_fd.is_some() {
            let serial_fd = self.serial_input_fd();
            let buf_ready_evt = self.buffer_ready_evt_fd();
            if serial_fd != -1 {
                if let Err(e) = ops.add(Events::new(&serial_fd, EventSet::IN)) {
                    warn!("Failed to register serial input fd: {}", e);
                }
            }
            if let Err(e) = ops.add(Events::new(&buf_ready_evt, EventSet::IN)) {
                warn!("Failed to register serial buffer ready event: {}", e);
            }
        }
    }
}

impl<W: Write + Send + 'static> BusDevice
    for SerialWrapper<EventFdTrigger, SerialEventsWrapper, W>
{
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            self.serial.events().metrics.missed_read_count.inc();
            return;
        }
        data[0] = self.serial.read(offset as u8);
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            self.serial.events().metrics.missed_write_count.inc();
            return;
        }
        if let Err(e) = self.serial.write(offset as u8, data[0]) {
            // Counter incremented for any handle_write() error.
            error!("Failed the write to serial: {:?}", e);
            self.serial.events().metrics.error_count.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};
    use utils::eventfd::EventFd;

    #[derive(Clone)]
    struct SharedBuffer {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedBuffer {
        fn new() -> SharedBuffer {
            SharedBuffer {
                buf: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl io::Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.buf.lock().unwrap().write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.buf.lock().unwrap().flush()
        }
    }

    #[test]
    fn test_serial_bus_write() {
        let serial_out = SharedBuffer::new();
        let intr_evt = EventFdTrigger::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        let metrics = Arc::new(SerialDeviceMetrics::default());
        let mut serial = SerialDevice {
            serial: Serial::with_events(
                intr_evt,
                SerialEventsWrapper {
                    metrics: metrics.clone(),
                    buffer_ready_event_fd: None,
                },
                Box::new(serial_out.clone()),
            ),
            input: None,
        };
        let invalid_writes_before = serial.serial.events().metrics.missed_write_count.count();
        <dyn BusDevice>::write(&mut serial, 0u64, &[b'x', b'y']);
        let writes_before = metrics.write_count.count();

        let invalid_writes_after = metrics.missed_write_count.count();
        assert_eq!(invalid_writes_before + 1, invalid_writes_after);
        <dyn BusDevice>::write(&mut serial, 0u64, &[b'a']);
        <dyn BusDevice>::write(&mut serial, 0u64, &[b'b']);
        <dyn BusDevice>::write(&mut serial, 0u64, &[b'c']);
        assert_eq!(
            serial_out.buf.lock().unwrap().as_slice(),
            &[b'a', b'b', b'c']
        );

        let invalid_writes_after_2 = metrics.missed_write_count.count();
        let writes_after = metrics.write_count.count();
        // The `invalid_write_count` metric should be the same as before the one-byte writes.
        assert_eq!(invalid_writes_after_2, invalid_writes_after);
        assert_eq!(writes_after, writes_before + 3);
    }

    #[test]
    fn test_serial_bus_read() {
        let intr_evt = EventFdTrigger::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        let metrics = Arc::new(SerialDeviceMetrics::default());

        let mut serial = SerialDevice {
            serial: Serial::with_events(
                intr_evt,
                SerialEventsWrapper {
                    metrics: metrics.clone(),
                    buffer_ready_event_fd: None,
                },
                Box::new(std::io::sink()),
            ),
            input: None,
        };
        serial.serial.raw_input(&[b'a', b'b', b'c']).unwrap();

        let invalid_reads_before = metrics.missed_read_count.count();
        let mut v = [0x00; 2];
        <dyn BusDevice>::read(&mut serial, 0u64, &mut v);

        let invalid_reads_after = metrics.missed_read_count.count();
        assert_eq!(invalid_reads_before + 1, invalid_reads_after);

        let mut v = [0x00; 1];
        <dyn BusDevice>::read(&mut serial, 0u64, &mut v);
        assert_eq!(v[0], b'a');

        let invalid_reads_after_2 = metrics.missed_read_count.count();
        // The `invalid_read_count` metric should be the same as before the one-byte reads.
        assert_eq!(invalid_reads_after_2, invalid_reads_after);
    }
}
