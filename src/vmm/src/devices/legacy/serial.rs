// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Implements a wrapper over an UART serial device.
use std::fmt::Debug;
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};

use event_manager::{EventOps, Events, MutEventSubscriber};
use log::{error, warn};
use serde::Serialize;
use utils::epoll::EventSet;
use vm_superio::serial::{Error as SerialError, SerialEvents};
use vm_superio::{Serial, Trigger};

use crate::devices::legacy::EventFdTrigger;
use crate::logger::{IncMetric, SharedIncMetric};

/// Received Data Available interrupt - for letting the driver know that
/// there is some pending data to be processed.
pub const IER_RDA_BIT: u8 = 0b0000_0001;
/// Received Data Available interrupt offset
pub const IER_RDA_OFFSET: u8 = 1;

/// Metrics specific to the UART device.
#[derive(Debug, Serialize, Default)]
pub struct SerialDeviceMetrics {
    /// Errors triggered while using the UART device.
    pub error_count: SharedIncMetric,
    /// Number of flush operations.
    pub flush_count: SharedIncMetric,
    /// Number of read calls that did not trigger a read.
    pub missed_read_count: SharedIncMetric,
    /// Number of write calls that did not trigger a write.
    pub missed_write_count: SharedIncMetric,
    /// Number of succeeded read calls.
    pub read_count: SharedIncMetric,
    /// Number of succeeded write calls.
    pub write_count: SharedIncMetric,
}
impl SerialDeviceMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            error_count: SharedIncMetric::new(),
            flush_count: SharedIncMetric::new(),
            missed_read_count: SharedIncMetric::new(),
            missed_write_count: SharedIncMetric::new(),
            read_count: SharedIncMetric::new(),
            write_count: SharedIncMetric::new(),
        }
    }
}

/// Stores aggregated metrics
pub(super) static METRICS: SerialDeviceMetrics = SerialDeviceMetrics::new();

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum RawIOError {
    /// Serial error: {0:?}
    Serial(SerialError<io::Error>),
}

pub trait RawIOHandler {
    /// Send raw input to this emulated device.
    fn raw_input(&mut self, _data: &[u8]) -> Result<(), RawIOError>;
}

impl<EV: SerialEvents + Debug, W: Write + Debug> RawIOHandler for Serial<EventFdTrigger, EV, W> {
    // This is not used for anything and is basically just a dummy implementation for `raw_input`.
    fn raw_input(&mut self, data: &[u8]) -> Result<(), RawIOError> {
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

/// Wrapper over available events (i.e metrics, buffer ready etc).
#[derive(Debug)]
pub struct SerialEventsWrapper {
    /// Buffer ready event.
    pub buffer_ready_event_fd: Option<EventFdTrigger>,
}

impl SerialEvents for SerialEventsWrapper {
    fn buffer_read(&self) {
        METRICS.read_count.inc();
    }

    fn out_byte(&self) {
        METRICS.write_count.inc();
    }

    fn tx_lost_byte(&self) {
        METRICS.missed_write_count.inc();
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

#[derive(Debug)]
pub enum SerialOut {
    Sink(std::io::Sink),
    Stdout(std::io::Stdout),
}
impl std::io::Write for SerialOut {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Sink(sink) => sink.write(buf),
            Self::Stdout(stdout) => stdout.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Sink(sink) => sink.flush(),
            Self::Stdout(stdout) => stdout.flush(),
        }
    }
}

/// Wrapper over the imported serial device.
#[derive(Debug)]
pub struct SerialWrapper<T: Trigger, EV: SerialEvents, I: Read + AsRawFd + Send> {
    /// Serial device object.
    pub serial: Serial<T, EV, SerialOut>,
    /// Input to the serial device (needs to be readable).
    pub input: Option<I>,
}

impl<I: Read + AsRawFd + Send + Debug> SerialWrapper<EventFdTrigger, SerialEventsWrapper, I> {
    fn handle_ewouldblock(&self, ops: &mut EventOps) {
        let buffer_ready_fd = self.buffer_ready_evt_fd();
        let input_fd = self.serial_input_fd();
        if input_fd < 0 || buffer_ready_fd < 0 {
            error!("Serial does not have a configured input source.");
            return;
        }
        match ops.add(Events::new(&input_fd, EventSet::IN)) {
            Err(event_manager::Error::FdAlreadyRegistered) => (),
            Err(err) => {
                error!(
                    "Could not register the serial input to the event manager: {:?}",
                    err
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

    fn consume_buffer_ready_event(&self) -> io::Result<u64> {
        self.serial
            .events()
            .buffer_ready_event_fd
            .as_ref()
            .map_or(Ok(0), |buf_ready| buf_ready.read())
    }
}

/// Type for representing a serial device.
pub type SerialDevice<I> = SerialWrapper<EventFdTrigger, SerialEventsWrapper, I>;

impl<I: Read + AsRawFd + Send + Debug> MutEventSubscriber
    for SerialWrapper<EventFdTrigger, SerialEventsWrapper, I>
{
    /// Handle events on the serial input fd.
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        #[inline]
        fn unregister_source<T: AsRawFd + Debug>(ops: &mut EventOps, source: &T) {
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
                    error!(
                        "Detach serial device input source due to error in consuming the buffer \
                         ready event: {:?}",
                        err
                    );
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
            Err(err) => {
                match err.raw_os_error() {
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

            // If the jailer is instructed to daemonize before exec-ing into firecracker, we set
            // stdin, stdout and stderr to be open('/dev/null'). However, if stdin is redirected
            // from /dev/null then trying to register FILENO_STDIN to epoll will fail with EPERM.
            // Therefore, only try to register stdin to epoll if it is a terminal or a FIFO pipe.
            // SAFETY: isatty has no invariants that need to be upheld. If serial_fd is an invalid
            // argument, it will return 0 and set errno to EBADF.
            if unsafe { libc::isatty(serial_fd) } == 1 || is_fifo(serial_fd) {
                if let Err(err) = ops.add(Events::new(&serial_fd, EventSet::IN)) {
                    warn!("Failed to register serial input fd: {}", err);
                }
            }
            if let Err(err) = ops.add(Events::new(&buf_ready_evt, EventSet::IN)) {
                warn!("Failed to register serial buffer ready event: {}", err);
            }
        }
    }
}

/// Checks whether the given file descriptor is a FIFO pipe.
fn is_fifo(fd: RawFd) -> bool {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();

    // SAFETY: No unsafety can be introduced by passing in an invalid file descriptor to fstat,
    // it will return -1 and set errno to EBADF. The pointer passed to fstat is valid for writing
    // a libc::stat structure.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
        return false;
    }

    // SAFETY: We can safely assume the libc::stat structure to be initialized, as libc::fstat
    // returning 0 guarantees that the memory is now initialized with the requested file metadata.
    let stat = unsafe { stat.assume_init() };

    (stat.st_mode & libc::S_IFIFO) != 0
}

impl<I: Read + AsRawFd + Send + Debug + 'static>
    SerialWrapper<EventFdTrigger, SerialEventsWrapper, I>
{
    pub fn bus_read(&mut self, offset: u64, data: &mut [u8]) {
        if let (Ok(offset), 1) = (u8::try_from(offset), data.len()) {
            data[0] = self.serial.read(offset);
        } else {
            METRICS.missed_read_count.inc();
        }
    }

    pub fn bus_write(&mut self, offset: u64, data: &[u8]) {
        if let (Ok(offset), 1) = (u8::try_from(offset), data.len()) {
            if let Err(err) = self.serial.write(offset, data[0]) {
                // Counter incremented for any handle_write() error.
                error!("Failed the write to serial: {:?}", err);
                METRICS.error_count.inc();
            }
        } else {
            METRICS.missed_write_count.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use utils::eventfd::EventFd;

    use super::*;
    use crate::logger::IncMetric;

    #[test]
    fn test_serial_bus_read() {
        let intr_evt = EventFdTrigger::new(EventFd::new(libc::EFD_NONBLOCK).unwrap());

        let metrics = &METRICS;

        let mut serial = SerialDevice {
            serial: Serial::with_events(
                intr_evt,
                SerialEventsWrapper {
                    buffer_ready_event_fd: None,
                },
                SerialOut::Sink(std::io::sink()),
            ),
            input: None::<std::io::Stdin>,
        };
        serial.serial.raw_input(&[b'a', b'b', b'c']).unwrap();

        let invalid_reads_before = metrics.missed_read_count.count();
        let mut v = [0x00; 2];
        serial.bus_read(0u64, &mut v);

        let invalid_reads_after = metrics.missed_read_count.count();
        assert_eq!(invalid_reads_before + 1, invalid_reads_after);

        let mut v = [0x00; 1];
        serial.bus_read(0u64, &mut v);
        assert_eq!(v[0], b'a');

        let invalid_reads_after_2 = metrics.missed_read_count.count();
        // The `invalid_read_count` metric should be the same as before the one-byte reads.
        assert_eq!(invalid_reads_after_2, invalid_reads_after);
    }

    #[test]
    fn test_is_fifo() {
        // invalid file descriptors arent fifos
        let invalid = -1;
        assert!(!is_fifo(invalid));

        // Fifos are fifos
        let mut fds: [libc::c_int; 2] = [0; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert!(rc == 0);

        assert!(is_fifo(fds[0]));
        assert!(is_fifo(fds[1]));

        // Files arent fifos
        let tmp_file = utils::tempfile::TempFile::new().unwrap();
        assert!(!is_fifo(tmp_file.as_file().as_raw_fd()));
    }

    #[test]
    fn test_serial_dev_metrics() {
        let serial_metrics: SerialDeviceMetrics = SerialDeviceMetrics::new();
        let serial_metrics_local: String = serde_json::to_string(&serial_metrics).unwrap();
        // the 1st serialize flushes the metrics and resets values to 0 so that
        // we can compare the values with local metrics.
        serde_json::to_string(&METRICS).unwrap();
        let serial_metrics_global: String = serde_json::to_string(&METRICS).unwrap();
        assert_eq!(serial_metrics_local, serial_metrics_global);
        serial_metrics.read_count.inc();
        assert_eq!(serial_metrics.read_count.count(), 1);
    }
}
