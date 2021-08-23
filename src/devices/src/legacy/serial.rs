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
