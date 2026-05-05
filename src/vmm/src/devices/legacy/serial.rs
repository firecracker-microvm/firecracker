// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Implements a wrapper over an UART serial device.
use std::collections::VecDeque;
use std::fmt::Debug;
use std::fs::File;
use std::io::{self, Read, Stdin, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use event_manager::{EventOps, Events, MutEventSubscriber};
use libc::EFD_NONBLOCK;
use serde::Serialize;
use utils::time::TimerFd;
use vm_superio::serial::{Error as SerialError, SerialEvents, SerialState};
use vm_superio::{Serial, Trigger};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::devices::legacy::EventFdTrigger;
use crate::logger::{IncMetric, SharedIncMetric, error, warn};
use crate::rate_limiter::{BucketReduction, TokenBucket};
use crate::utils::usize_to_u64;
use crate::vstate::bus::BusDevice;

// Register offsets we need to intercept. These mirror the values used inside
// vm-superio (they are not re-exported), see
// https://docs.rs/vm-superio/0.8.1/src/vm_superio/serial.rs.html
const DATA_OFFSET: u8 = 0;
const LSR_OFFSET: u8 = 5;

// MCR offset and the loopback bit, used to detect whether the guest has put
// the UART in local-loopback mode. In loopback mode vm-superio routes the
// transmitted byte back into the receive FIFO synchronously, so we must NOT
// queue it through our drain path — let the underlying `Serial::write` run
// directly so the receive interrupt and FIFO state stay in sync.
const MCR_OFFSET: u8 = 4;
const MCR_LOOP_BIT: u8 = 0b0001_0000;

// LSR bits we mask while a TX byte is in flight. Real 16550 hardware clears
// these while the transmit shift register holds a byte and the THR is full,
// causing a polling driver (e.g. Linux `wait_for_xmitr`) to wait. vm-superio
// keeps both bits set unconditionally, which is what allows a tight
// `cat /dev/zero > /dev/ttyS0` loop to pin a vCPU thread in MMIO exits.
const LSR_EMPTY_THR_BIT: u8 = 0b0010_0000;
const LSR_IDLE_BIT: u8 = 0b0100_0000;

// Soft "TX FIFO" depth. We accept up to this many bytes from the guest
// without applying backpressure, mirroring a real 16550A's 16-byte transmit
// FIFO (we run a touch deeper to avoid stalling kernel `console_unlock`
// bursts). Once the queue grows past this, the guest sees LSR_THR_EMPTY
// clear and waits — that's what stops a `cat /dev/zero` runaway from
// monopolising the vCPU thread in MMIO exits.
const TX_FIFO_DEPTH: usize = 64;

// Hard cap on the queue. Beyond this we drop bytes and bump the existing
// `tx_lost_byte` metric, matching real-hardware FIFO overrun. Sized to
// absorb a full kernel-boot worth of `printk` so normal operation never
// drops.
const TX_QUEUE_CAPACITY: usize = 64 * 1024;

// One drain tick. timerfd resolution caps at ~1ms in practice. Drain rate
// (bytes/sec) is roughly `TX_FIFO_DEPTH / TX_DRAIN_INTERVAL`, i.e. ~64 KB/s
// at these settings — well above 115200 baud (≈12 KB/s) so we don't slow
// kernel boot, while still cheap enough that the vCPU thread spends most of
// its time in KVM_RUN instead of in MMIO-exit syscalls.
const TX_DRAIN_INTERVAL: Duration = Duration::from_millis(1);

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
    /// Total bytes dropped by the serial output rate limiter.
    pub rate_limiter_dropped_bytes: SharedIncMetric,
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
            rate_limiter_dropped_bytes: SharedIncMetric::new(),
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

/// The underlying output destination.
#[derive(Debug)]
pub enum SerialOutInner {
    Sink,
    Stdout(std::io::Stdout),
    File(File),
}

/// Output sink for the serial device, with optional rate limiting.
#[derive(Debug)]
pub struct SerialOut {
    inner: SerialOutInner,
    /// Optional rate limiter for serial output bandwidth.
    rate_limiter: Option<TokenBucket>,
}

impl SerialOut {
    /// Create a new `SerialOut` with the given inner sink and optional rate limiter.
    pub fn new(inner: SerialOutInner, rate_limiter: Option<TokenBucket>) -> Self {
        Self {
            inner,
            rate_limiter,
        }
    }
}

impl std::io::Write for SerialOut {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let SerialOutInner::Sink = self.inner {
            return Ok(buf.len());
        }

        // Check rate limiter if configured.
        if let Some(ref mut rl) = self.rate_limiter {
            match rl.reduce(usize_to_u64(buf.len())) {
                BucketReduction::Failure | BucketReduction::OverConsumption(_) => {
                    METRICS
                        .rate_limiter_dropped_bytes
                        .add(usize_to_u64(buf.len()));
                    return Ok(buf.len());
                }
                BucketReduction::Success => {}
            }
        }

        match &mut self.inner {
            SerialOutInner::Stdout(stdout) => stdout.write(buf),
            SerialOutInner::File(file) => file.write(buf),
            SerialOutInner::Sink => Ok(buf.len()),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.inner {
            SerialOutInner::Sink => Ok(()),
            SerialOutInner::Stdout(stdout) => stdout.flush(),
            SerialOutInner::File(file) => file.flush(),
        }
    }
}

/// Wrapper over the imported serial device.
///
/// Adds host-side TX backpressure on top of the underlying vm-superio device:
/// guest writes to the data register are queued and drained on a timer rather
/// than written through synchronously, and the LSR bits that signal "TX
/// ready" are masked off while bytes are queued. This prevents a guest tight
/// loop (e.g. `cat /dev/zero > /dev/ttyS0`) from monopolising the vCPU
/// thread in MMIO exits, which otherwise produces guest soft-lockup and RCU
/// stall warnings on the *other* vCPUs.
#[derive(Debug)]
pub struct SerialWrapper<T: Trigger, EV: SerialEvents, I: Read + AsRawFd + Send> {
    /// Serial device object.
    pub serial: Serial<T, EV, SerialOut>,
    /// Input to the serial device (needs to be readable).
    pub input: Option<I>,
    /// Bytes accepted from the guest that have not yet been drained to the
    /// underlying output. Bounded by `TX_QUEUE_CAPACITY`.
    tx_queue: VecDeque<u8>,
    /// Periodic drain timer. Armed while `tx_queue` is non-empty.
    tx_drain_timer: TimerFd,
    /// Whether the drain timer is currently armed. Tracking this here avoids
    /// querying the kernel via `timerfd_gettime` on the hot read path.
    tx_drain_timer_armed: bool,
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
pub type SerialDevice = SerialWrapper<EventFdTrigger, SerialEventsWrapper, Stdin>;

impl<I: Read + AsRawFd + Send> SerialWrapper<EventFdTrigger, SerialEventsWrapper, I> {
    /// Construct a new serial wrapper backed by an arbitrary input source.
    /// Used by integration tests that wire up a mock input fd; production
    /// code goes through [`SerialDevice::new`].
    pub fn with_input(
        serial_in: Option<I>,
        serial_out: SerialOut,
        state: Option<&SerialState>,
    ) -> Result<Self, std::io::Error> {
        let interrupt_evt = EventFdTrigger::new(EventFd::new(EFD_NONBLOCK)?);
        let buffer_read_event_fd = EventFdTrigger::new(EventFd::new(EFD_NONBLOCK)?);
        let events = SerialEventsWrapper {
            buffer_ready_event_fd: Some(buffer_read_event_fd),
        };

        let serial =
            match state {
                Some(state) => Serial::from_state(state, interrupt_evt, events, serial_out)
                    .map_err(|err| match err {
                        SerialError::Trigger(e) | SerialError::IOError(e) => e,
                        SerialError::FullFifo => std::io::Error::other("FIFO buffer too large"),
                    })?,
                None => Serial::with_events(interrupt_evt, events, serial_out),
            };

        Ok(SerialWrapper {
            serial,
            input: serial_in,
            tx_queue: VecDeque::with_capacity(TX_QUEUE_CAPACITY),
            tx_drain_timer: TimerFd::new(),
            tx_drain_timer_armed: false,
        })
    }
}

impl SerialDevice {
    pub fn new(
        serial_in: Option<Stdin>,
        serial_out: SerialOut,
        state: Option<&SerialState>,
    ) -> Result<Self, std::io::Error> {
        Self::with_input(serial_in, serial_out, state)
    }
}

impl<T: Trigger, EV: SerialEvents, I: Read + AsRawFd + Send> SerialWrapper<T, EV, I> {
    /// True when the soft TX FIFO is at or above its modelled depth and
    /// guest writes should be told to wait. We do NOT mask LSR while there
    /// are simply *some* bytes queued, only when the queue is full enough to
    /// emulate a real FIFO holding off the driver — otherwise the guest
    /// would write one byte per drain tick and console output would crawl.
    #[inline]
    fn tx_fifo_full(&self) -> bool {
        self.tx_queue.len() >= TX_FIFO_DEPTH
    }

    /// Mask the THR-empty / line-idle bits while the soft FIFO is at depth.
    /// Real hardware clears these bits while the FIFO is full; vm-superio
    /// always reports them set, so we patch the value here.
    fn lsr_with_tx_mask(&self, raw: u8) -> u8 {
        if self.tx_fifo_full() {
            raw & !(LSR_EMPTY_THR_BIT | LSR_IDLE_BIT)
        } else {
            raw
        }
    }

    fn arm_tx_drain_timer(&mut self) {
        if !self.tx_drain_timer_armed {
            self.tx_drain_timer.arm(TX_DRAIN_INTERVAL, None);
            self.tx_drain_timer_armed = true;
        }
    }

    /// Whether the underlying device has loopback enabled. Read via the
    /// public `Serial::read` API (the inner `modem_control` field is
    /// private). The MCR read path has no side effects.
    fn is_in_loop_mode(&mut self) -> bool {
        (self.serial.read(MCR_OFFSET) & MCR_LOOP_BIT) != 0
    }

    /// Snapshot view of the soft TX FIFO. Used by the persistence layer to
    /// include in-flight bytes in the snapshot file so they survive
    /// snapshot/restore and live migration.
    pub fn tx_queue_snapshot(&self) -> Vec<u8> {
        self.tx_queue.iter().copied().collect()
    }

    /// Restore the soft TX FIFO from a snapshot. Bytes are appended in
    /// order; if the snapshot exceeds the current capacity (e.g. it was
    /// taken with a larger cap) the excess is dropped to preserve the
    /// invariant that `tx_queue.len() <= TX_QUEUE_CAPACITY`. The drain
    /// timer is armed if the queue ends up non-empty so that bytes start
    /// flowing immediately on the restored side.
    pub fn restore_tx_queue(&mut self, bytes: &[u8]) {
        self.tx_queue.clear();
        let take = bytes.len().min(TX_QUEUE_CAPACITY);
        self.tx_queue.extend(&bytes[..take]);
        if !self.tx_queue.is_empty() {
            self.arm_tx_drain_timer();
        }
    }

    /// Drain up to one FIFO's worth of bytes from the queue into the
    /// underlying serial device. Each byte goes through the regular
    /// `Serial::write(DATA, b)` path so it produces the same observable
    /// effects (stdout write, `flush`, optional THR-empty IRQ) as the
    /// unbuffered path — just on the event-manager thread instead of the
    /// vCPU thread.
    ///
    /// We deliberately stop at one FIFO so that, when the guest is flooding
    /// the port, each tick produces one IRQ (or one batch of IRQs) and the
    /// guest then has to wait for the next tick. That is what prevents the
    /// IRQ-storm flavour of vCPU saturation: without the cap, draining a
    /// large queue here would raise hundreds of THR-empty IRQs back-to-back,
    /// which the guest would service inside one IRQ context and spend just
    /// as long pegged as before.
    fn drain_tx_queue(&mut self) {
        for _ in 0..TX_FIFO_DEPTH {
            let Some(byte) = self.tx_queue.pop_front() else {
                break;
            };
            if let Err(err) = self.serial.write(DATA_OFFSET, byte) {
                error!("Failed to drain serial TX byte: {:?}", err);
                METRICS.error_count.inc();
            }
        }
    }
}

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

        // The TX drain timer is independent of the input path: it can fire
        // even when no input source is registered (e.g. when stdin is
        // /dev/null in jailer-daemonised setups), so handle it before the
        // input-fd checks below.
        if self.tx_drain_timer.as_raw_fd() == event.fd() {
            // Consume the timer expirations.
            let _ = self.tx_drain_timer.read();
            self.tx_drain_timer_armed = false;
            self.drain_tx_queue();
            if !self.tx_queue.is_empty() {
                self.arm_tx_drain_timer();
            }
            return;
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
    /// The TX drain timer is registered unconditionally — it is required for
    /// flushing buffered output regardless of whether an input source exists.
    fn init(&mut self, ops: &mut EventOps) {
        let drain_fd = self.tx_drain_timer.as_raw_fd();
        if let Err(err) = ops.add(Events::new(&drain_fd, EventSet::IN)) {
            warn!("Failed to register serial TX drain timer fd: {}", err);
        }

        if self.input.is_some() && self.serial.events().buffer_ready_event_fd.is_some() {
            let serial_fd = self.serial_input_fd();
            let buf_ready_evt = self.buffer_ready_evt_fd();

            // If the jailer is instructed to daemonize before exec-ing into firecracker, we set
            // stdin, stdout and stderr to be open('/dev/null'). However, if stdin is redirected
            // from /dev/null then trying to register FILENO_STDIN to epoll will fail with EPERM.
            // Therefore, only try to register stdin to epoll if it is a terminal or a FIFO pipe.
            // SAFETY: isatty has no invariants that need to be upheld. If serial_fd is an invalid
            // argument, it will return 0 and set errno to EBADF.
            if (unsafe { libc::isatty(serial_fd) } == 1 || is_fifo(serial_fd))
                && let Err(err) = ops.add(Events::new(&serial_fd, EventSet::IN))
            {
                warn!("Failed to register serial input fd: {}", err);
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

impl<I> BusDevice for SerialWrapper<EventFdTrigger, SerialEventsWrapper, I>
where
    I: Read + AsRawFd + Send,
{
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        if let (Ok(offset), 1) = (u8::try_from(offset), data.len()) {
            let value = self.serial.read(offset);
            // Real 16550 hardware reports the THR/idle bits cleared while a
            // byte is in flight. vm-superio always reports them set, so we
            // mask them here whenever our drain queue holds bytes. Without
            // this, a polling-mode guest writer (e.g. the kernel tty layer
            // when an IRQ is unhandled) sees "always ready" and never lets
            // the vCPU return to KVM_RUN, producing soft-lockup warnings.
            data[0] = if offset == LSR_OFFSET {
                self.lsr_with_tx_mask(value)
            } else {
                value
            };
        } else {
            METRICS.missed_read_count.inc();
        }
    }

    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let Ok(offset_u8) = u8::try_from(offset) else {
            METRICS.missed_write_count.inc();
            return None;
        };
        if data.len() != 1 {
            METRICS.missed_write_count.inc();
            return None;
        }
        let value = data[0];

        // Loopback writes are routed back into the receive buffer
        // synchronously by vm-superio. They are not a flooding hazard (the
        // RX FIFO is bounded), so let them go through unchanged to keep RX
        // FIFO state and RDA interrupts in sync with the guest's view.
        if offset_u8 == DATA_OFFSET && !self.is_in_loop_mode() {
            if self.tx_queue.len() < TX_QUEUE_CAPACITY {
                self.tx_queue.push_back(value);
                self.arm_tx_drain_timer();
            } else {
                // Match real-hardware FIFO overrun. `tx_lost_byte` already
                // bumps `missed_write_count` via the events trait, so we
                // don't double-count here.
                self.serial.events().tx_lost_byte();
            }
            return None;
        }

        if let Err(err) = self.serial.write(offset_u8, value) {
            error!("Failed the write to serial: {:?}", err);
            METRICS.error_count.inc();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use vmm_sys_util::eventfd::EventFd;

    use super::*;
    use crate::logger::IncMetric;
    use crate::rate_limiter::TokenBucket;

    /// Helper to create a `SerialOut` with `Sink` inner and no rate limiter for tests.
    fn test_serial_out_sink() -> SerialOut {
        SerialOut::new(SerialOutInner::Sink, None)
    }

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
                test_serial_out_sink(),
            ),
            input: None::<std::io::Stdin>,
            tx_queue: VecDeque::with_capacity(TX_QUEUE_CAPACITY),
            tx_drain_timer: TimerFd::new(),
            tx_drain_timer_armed: false,
        };
        serial.serial.raw_input(b"abc").unwrap();

        let invalid_reads_before = metrics.missed_read_count.count();
        let mut v = [0x00; 2];
        serial.read(0x0, 0u64, &mut v);

        let invalid_reads_after = metrics.missed_read_count.count();
        assert_eq!(invalid_reads_before + 1, invalid_reads_after);

        let mut v = [0x00; 1];
        serial.read(0x0, 0u64, &mut v);
        assert_eq!(v[0], b'a');

        let invalid_reads_after_2 = metrics.missed_read_count.count();
        // The `invalid_read_count` metric should be the same as before the one-byte reads.
        assert_eq!(invalid_reads_after_2, invalid_reads_after);
    }

    #[test]
    fn test_restore_from_state() {
        let mut serial = SerialDevice::new(None, test_serial_out_sink(), None).unwrap();
        serial.serial.raw_input(b"abc").unwrap();

        let state = serial.serial.state();
        let mut restored = SerialDevice::new(None, test_serial_out_sink(), Some(&state)).unwrap();

        // Make sure we read back what we previously injected
        let mut buf = [0u8; 1];
        restored.read(0, 0, &mut buf);
        assert_eq!(buf[0], b'a');
        restored.read(0, 0, &mut buf);
        assert_eq!(buf[0], b'b');
        restored.read(0, 0, &mut buf);
        assert_eq!(buf[0], b'c');
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
        let tmp_file = vmm_sys_util::tempfile::TempFile::new().unwrap();
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

    #[test]
    fn test_serial_out_write_within_budget() {
        let tmp = vmm_sys_util::tempfile::TempFile::new().unwrap();
        let file = tmp.into_file();
        let mut serial_out = SerialOut::new(
            SerialOutInner::File(file.try_clone().unwrap()),
            Some(TokenBucket::new(1024, 0, 1000).unwrap()),
        );

        let data = b"hello";
        let result = serial_out.write(data).unwrap();
        assert_eq!(result, data.len());

        use std::io::Seek;
        let mut file = file;
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"hello");
    }

    #[test]
    fn test_serial_out_write_over_budget() {
        let tmp = vmm_sys_util::tempfile::TempFile::new().unwrap();
        let file = tmp.into_file();
        let mut serial_out = SerialOut::new(
            SerialOutInner::File(file.try_clone().unwrap()),
            Some(TokenBucket::new(4, 0, 1000).unwrap()),
        );

        let result = serial_out.write(b"abcd").unwrap();
        assert_eq!(result, 4);

        let dropped_before = METRICS.rate_limiter_dropped_bytes.count();
        let big_data = vec![b'X'; 1024];
        let result = serial_out.write(&big_data).unwrap();
        assert_eq!(result, 1024);
        let dropped_delta = METRICS.rate_limiter_dropped_bytes.count() - dropped_before;
        assert!(dropped_delta >= 1024);

        use std::io::Seek;
        let mut file = file;
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"abcd");
    }

    #[test]
    fn test_serial_out_sink_discards_everything() {
        let mut serial_out = test_serial_out_sink();
        let dropped_before = METRICS.rate_limiter_dropped_bytes.count();
        let result = serial_out.write(b"anything").unwrap();
        assert_eq!(result, 8);
        assert_eq!(METRICS.rate_limiter_dropped_bytes.count(), dropped_before);
    }

    /// Build a `SerialDevice` writing into the provided `SerialOut`, with no
    /// input source. Used by the TX backpressure tests below.
    fn test_serial_device(out: SerialOut) -> SerialDevice {
        SerialDevice::new(None, out, None).unwrap()
    }

    /// Drive the device through `BusDevice::write` rather than calling the
    /// inner `serial.write` directly — this is what the TX backpressure path
    /// hooks, so unit tests must go through the same entry point as a
    /// guest-issued MMIO write.
    fn bus_write(dev: &mut SerialDevice, offset: u64, byte: u8) {
        dev.write(0, offset, &[byte]);
    }

    fn bus_read(dev: &mut SerialDevice, offset: u64) -> u8 {
        let mut buf = [0u8; 1];
        dev.read(0, offset, &mut buf);
        buf[0]
    }

    #[test]
    fn test_tx_data_writes_are_queued_not_passed_through() {
        // Guest data writes should *not* reach the underlying writer
        // synchronously: they are buffered and only drained on the timer
        // tick. This is the property that prevents the vCPU thread from
        // doing per-byte syscalls. We assert by inspecting the backing
        // file: it must still be empty after the bus write.
        let tmp = vmm_sys_util::tempfile::TempFile::new().unwrap();
        let file = tmp.into_file();
        let mut dev = test_serial_device(SerialOut::new(
            SerialOutInner::File(file.try_clone().unwrap()),
            None,
        ));
        bus_write(&mut dev, DATA_OFFSET as u64, b'X');

        assert_eq!(dev.tx_queue.len(), 1);
        assert!(dev.tx_drain_timer_armed);

        use std::io::Seek;
        let mut file = file;
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut readback = Vec::new();
        file.read_to_end(&mut readback).unwrap();
        assert!(
            readback.is_empty(),
            "byte must not have reached the writer yet, got {readback:?}"
        );
    }

    #[test]
    fn test_drain_flushes_queued_bytes_to_writer() {
        // After a manual drain, every queued byte must reach the underlying
        // writer. We assert by inspecting the file contents, not by reading
        // the (global, racy) `write_count` metric.
        let tmp = vmm_sys_util::tempfile::TempFile::new().unwrap();
        let file = tmp.into_file();
        let mut dev = test_serial_device(SerialOut::new(
            SerialOutInner::File(file.try_clone().unwrap()),
            None,
        ));
        for &b in b"hello" {
            bus_write(&mut dev, DATA_OFFSET as u64, b);
        }
        assert_eq!(dev.tx_queue.len(), 5);

        dev.drain_tx_queue();
        assert_eq!(dev.tx_queue.len(), 0);

        use std::io::Seek;
        let mut file = file;
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut readback = Vec::new();
        file.read_to_end(&mut readback).unwrap();
        assert_eq!(readback, b"hello");
    }

    #[test]
    fn test_drain_caps_at_one_fifo_per_tick() {
        // A single drain tick should pop at most `TX_FIFO_DEPTH` bytes,
        // leaving the remainder for the next tick. This is what gates the
        // guest IRQ rate when it's flooding the port.
        let mut dev = test_serial_device(SerialOut::new(SerialOutInner::Sink, None));
        let burst = TX_FIFO_DEPTH * 2 + 7;
        for _ in 0..burst {
            bus_write(&mut dev, DATA_OFFSET as u64, b'.');
        }
        assert_eq!(dev.tx_queue.len(), burst);

        dev.drain_tx_queue();
        assert_eq!(dev.tx_queue.len(), burst - TX_FIFO_DEPTH);
        dev.drain_tx_queue();
        assert_eq!(dev.tx_queue.len(), burst - 2 * TX_FIFO_DEPTH);
        dev.drain_tx_queue();
        assert_eq!(dev.tx_queue.len(), 0);
    }

    #[test]
    fn test_drain_preserves_byte_order() {
        // Round-trip a payload through the queue + drain into a real File
        // sink and confirm bytes come out in submission order.
        let tmp = vmm_sys_util::tempfile::TempFile::new().unwrap();
        let file = tmp.into_file();
        let mut dev = test_serial_device(SerialOut::new(
            SerialOutInner::File(file.try_clone().unwrap()),
            None,
        ));
        let payload: Vec<u8> = (0u8..32).collect();
        for &b in &payload {
            bus_write(&mut dev, DATA_OFFSET as u64, b);
        }
        dev.drain_tx_queue();

        use std::io::Seek;
        let mut file = file;
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut readback = Vec::new();
        file.read_to_end(&mut readback).unwrap();
        assert_eq!(readback, payload);
    }

    #[test]
    fn test_lsr_thr_empty_masked_only_when_fifo_full() {
        // Real 16550 hardware clears LSR_THR_EMPTY when the TX FIFO is
        // full. Our wrapper applies the same mask via `lsr_with_tx_mask`.
        // Below the FIFO depth: the bits stay set so the guest can keep
        // submitting bytes (otherwise console output would crawl at one
        // byte per drain tick).
        let mut dev = test_serial_device(SerialOut::new(SerialOutInner::Sink, None));

        // Empty queue: both bits set.
        let lsr = bus_read(&mut dev, LSR_OFFSET as u64);
        assert_eq!(lsr & LSR_EMPTY_THR_BIT, LSR_EMPTY_THR_BIT);
        assert_eq!(lsr & LSR_IDLE_BIT, LSR_IDLE_BIT);

        // Below the FIFO depth: still set.
        for _ in 0..TX_FIFO_DEPTH - 1 {
            bus_write(&mut dev, DATA_OFFSET as u64, 0);
        }
        assert!(!dev.tx_fifo_full());
        let lsr = bus_read(&mut dev, LSR_OFFSET as u64);
        assert_eq!(lsr & LSR_EMPTY_THR_BIT, LSR_EMPTY_THR_BIT);
        assert_eq!(lsr & LSR_IDLE_BIT, LSR_IDLE_BIT);

        // At depth: both bits cleared.
        bus_write(&mut dev, DATA_OFFSET as u64, 0);
        assert!(dev.tx_fifo_full());
        let lsr = bus_read(&mut dev, LSR_OFFSET as u64);
        assert_eq!(lsr & LSR_EMPTY_THR_BIT, 0);
        assert_eq!(lsr & LSR_IDLE_BIT, 0);

        // After draining one FIFO's worth, bits return.
        dev.drain_tx_queue();
        assert!(!dev.tx_fifo_full());
        let lsr = bus_read(&mut dev, LSR_OFFSET as u64);
        assert_eq!(lsr & LSR_EMPTY_THR_BIT, LSR_EMPTY_THR_BIT);
    }

    #[test]
    fn test_tx_queue_overflow_drops_bytes() {
        // Past `TX_QUEUE_CAPACITY` we drop bytes, matching real-hardware
        // FIFO overrun. The queue length must not exceed the cap. The
        // associated metric (`missed_write_count`) is global and bumped by
        // other tests in parallel, so we don't assert on it here — see
        // `test_serial_bus_read` for coverage of that counter.
        let mut dev = test_serial_device(SerialOut::new(SerialOutInner::Sink, None));
        for _ in 0..TX_QUEUE_CAPACITY + 100 {
            bus_write(&mut dev, DATA_OFFSET as u64, b'!');
        }
        assert_eq!(dev.tx_queue.len(), TX_QUEUE_CAPACITY);
    }

    #[test]
    fn test_loopback_writes_bypass_queue() {
        // Loopback writes are routed back into the receive FIFO by
        // vm-superio synchronously. They must NOT take our queued path —
        // otherwise RX FIFO state and RDA interrupts would lag behind the
        // guest's view of its own writes.
        let mut dev = test_serial_device(SerialOut::new(SerialOutInner::Sink, None));

        // Set MCR loopback bit via the BusDevice path.
        bus_write(&mut dev, MCR_OFFSET as u64, MCR_LOOP_BIT);
        assert!(dev.is_in_loop_mode());

        // A data write must not enqueue.
        bus_write(&mut dev, DATA_OFFSET as u64, b'L');
        assert!(dev.tx_queue.is_empty());

        // The byte should be readable back from the data register (it was
        // routed into the RX FIFO by vm-superio's loopback path).
        let got = bus_read(&mut dev, DATA_OFFSET as u64);
        assert_eq!(got, b'L');
    }

    #[test]
    fn test_non_data_writes_passthrough() {
        // Writes to non-DATA registers (e.g. IER, LCR, MCR) must reach
        // vm-superio synchronously — they configure the device, not move
        // data — so they must never be queued.
        let mut dev = test_serial_device(SerialOut::new(SerialOutInner::Sink, None));

        // LCR is offset 3.
        bus_write(&mut dev, 3, 0x55);
        assert!(dev.tx_queue.is_empty());
        // Read it back through the bus path.
        assert_eq!(bus_read(&mut dev, 3), 0x55);
    }

    #[test]
    fn test_tx_queue_snapshot_round_trip() {
        // The TX FIFO is part of the snapshot (snapshot v10.1.0+) so that
        // pending console output survives snapshot/restore. Round-trip a
        // payload through `tx_queue_snapshot` -> `restore_tx_queue` and
        // confirm the bytes drain in order on the restored side.
        let mut sender = test_serial_device(SerialOut::new(SerialOutInner::Sink, None));
        let payload: &[u8] = b"snapshot-pending-bytes";
        for &b in payload {
            bus_write(&mut sender, DATA_OFFSET as u64, b);
        }
        let snap = sender.tx_queue_snapshot();
        assert_eq!(snap, payload);

        let tmp = vmm_sys_util::tempfile::TempFile::new().unwrap();
        let file = tmp.into_file();
        let mut receiver = test_serial_device(SerialOut::new(
            SerialOutInner::File(file.try_clone().unwrap()),
            None,
        ));
        receiver.restore_tx_queue(&snap);
        assert_eq!(receiver.tx_queue.len(), payload.len());
        assert!(receiver.tx_drain_timer_armed);

        // Drain enough times to flush the entire queue (queue is shorter
        // than one FIFO so a single drain suffices).
        receiver.drain_tx_queue();
        assert!(receiver.tx_queue.is_empty());

        use std::io::Seek;
        let mut file = file;
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut readback = Vec::new();
        file.read_to_end(&mut readback).unwrap();
        assert_eq!(readback, payload);
    }

    #[test]
    fn test_restore_tx_queue_truncates_to_capacity() {
        // A snapshot taken with a larger cap (or a corrupted one) must not
        // be allowed to push the queue past its current capacity.
        let mut dev = test_serial_device(SerialOut::new(SerialOutInner::Sink, None));
        let oversized = vec![0xABu8; TX_QUEUE_CAPACITY + 1024];
        dev.restore_tx_queue(&oversized);
        assert_eq!(dev.tx_queue.len(), TX_QUEUE_CAPACITY);
    }

    #[test]
    fn test_restore_tx_queue_empty_does_not_arm_timer() {
        // Old (pre-v10.1.0) snapshots carry an empty `tx_queue`. Restoring
        // an empty queue must be a no-op — in particular it must not arm
        // the drain timer (which would cause a spurious wakeup).
        let mut dev = test_serial_device(SerialOut::new(SerialOutInner::Sink, None));
        dev.restore_tx_queue(&[]);
        assert!(dev.tx_queue.is_empty());
        assert!(!dev.tx_drain_timer_armed);
    }
}
