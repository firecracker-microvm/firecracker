// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serial console reader for Nitro Enclaves.
//!
//! Reads serial output from the enclave's info page ring buffer on a 100ms
//! timer and writes it to the configured serial output (file or stdout).

use std::io::{self, Write};
use std::num::Wrapping;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use event_manager::{EventOps, Events, MutEventSubscriber};
use utils::time::TimerFd;
use vm_memory::{VolatileSlice, WriteVolatile};
use vmm_sys_util::epoll::EventSet;

use crate::devices::legacy::serial::METRICS;
use crate::logger::{IncMetric, error};
use crate::nitro_enclave::info_page::InfoPage;
#[cfg(test)]
use crate::nitro_enclave::info_page::PartialSink;
use crate::rate_limiter::{BucketReduction, TokenBucket};
use crate::utils::{open_file_nonblock, set_stdout_nonblocking};

/// Polling interval for the serial ring buffer.
const SERIAL_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Sink for serial data.
enum SerialOutInner {
    File(std::fs::File),
    Stdout(io::Stdout),
    #[cfg(test)]
    Test(PartialSink),
}

/// Output destination for serial data, with an optional output rate limiter.
struct SerialOutput {
    inner: SerialOutInner,
    rate_limiter: Option<TokenBucket>,
}

impl SerialOutput {
    fn flush(&mut self) {
        let result = match &mut self.inner {
            SerialOutInner::File(f) => f.flush(),
            SerialOutInner::Stdout(s) => s.flush(),
            #[cfg(test)]
            SerialOutInner::Test(_) => Ok(()),
        };
        if let Err(e) = result {
            error!("Failed to flush serial output: {e}");
        }
    }
}

impl WriteVolatile for SerialOutput {
    fn write_volatile<B: vm_memory::bitmap::BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<'_, B>,
    ) -> Result<usize, vm_memory::VolatileMemoryError> {
        if let Some(rl) = &mut self.rate_limiter {
            match rl.reduce(buf.len() as u64) {
                BucketReduction::Failure | BucketReduction::OverConsumption(_) => {
                    METRICS.rate_limiter_dropped_bytes.add(buf.len() as u64);
                    return Ok(buf.len());
                }
                BucketReduction::Success => {}
            }
        }
        match &mut self.inner {
            SerialOutInner::File(f) => f.write_volatile(buf),
            SerialOutInner::Stdout(s) => s.write_volatile(buf),
            #[cfg(test)]
            SerialOutInner::Test(v) => v.write_volatile(buf),
        }
    }
}

/// Serial console that reads from the info page ring buffer and writes to output.
pub struct ConsoleReader {
    /// Timer that fires periodically to poll the serial ring buffer
    timer_fd: TimerFd,
    /// Info page containing the serial ring buffer.
    info_page: Arc<InfoPage>,
    /// Output writer (file or stdout).
    output: SerialOutput,
    /// Last write_idx we read from the ring buffer (tracks our position).
    last_write_idx: Wrapping<u32>,
}

impl ConsoleReader {
    /// Create a new serial console reader.
    ///
    /// Output goes to `serial_out_path` if set, else stdout. Either sink is
    /// non-blocking, so a slow consumer cannot block the event thread. When
    /// `rate_limiter` is Some, output over budget is dropped rather than
    /// written.
    pub fn new(
        info_page: Arc<InfoPage>,
        serial_out_path: Option<&Path>,
        rate_limiter: Option<TokenBucket>,
    ) -> io::Result<Self> {
        let inner = match serial_out_path {
            Some(path) => SerialOutInner::File(open_file_nonblock(path)?),
            None => {
                set_stdout_nonblocking();
                SerialOutInner::Stdout(io::stdout())
            }
        };

        let mut timer_fd = TimerFd::new();
        timer_fd.arm(SERIAL_POLL_INTERVAL, Some(SERIAL_POLL_INTERVAL));

        Ok(Self {
            timer_fd,
            info_page,
            output: SerialOutput {
                inner,
                rate_limiter,
            },
            last_write_idx: Wrapping(0),
        })
    }

    /// Create a serial console writing into an in-memory test buffer, with an
    /// optional rate limiter.
    #[cfg(test)]
    fn new_test(info_page: Arc<InfoPage>, rate_limiter: Option<TokenBucket>) -> Self {
        Self::new_test_sink(
            info_page,
            rate_limiter,
            PartialSink::new(usize::MAX, io::ErrorKind::WouldBlock),
        )
    }

    /// Create a serial console writing into `sink`.
    #[cfg(test)]
    fn new_test_sink(
        info_page: Arc<InfoPage>,
        rate_limiter: Option<TokenBucket>,
        sink: PartialSink,
    ) -> Self {
        Self {
            timer_fd: TimerFd::new(),
            info_page,
            output: SerialOutput {
                inner: SerialOutInner::Test(sink),
                rate_limiter,
            },
            last_write_idx: Wrapping(0),
        }
    }

    #[cfg(test)]
    fn test_output(&self) -> &[u8] {
        match &self.output.inner {
            SerialOutInner::Test(sink) => &sink.written,
            _ => panic!("not a test output"),
        }
    }

    /// Read new bytes from the info page serial ring buffer and write to output.
    ///
    /// Returns `false` once the sink has failed for good.
    pub(crate) fn flush_serial(&mut self) -> bool {
        match self
            .info_page
            .write_serial_since(self.last_write_idx, &mut self.output)
        {
            Ok((_, 0)) => {}
            Ok((new_idx, written)) => {
                self.output.flush();
                self.last_write_idx = new_idx;
                METRICS.write_count.add(written.into());
                METRICS.flush_count.inc();
            }
            // Leave the cursor alone so the next tick retries these bytes.
            Err(e) if e.is_retriable() => {}
            Err(e) => {
                error!("Failed to drain the serial ring: {e}");
                METRICS.error_count.inc();
                return false;
            }
        }
        true
    }
}

impl MutEventSubscriber for ConsoleReader {
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        if !event.event_set().contains(EventSet::IN) {
            return;
        }
        // Read the timer to acknowledge it.
        let _ = self.timer_fd.read();
        if self.flush_serial() {
            return;
        }
        error!("Shutting down the serial console: its output is no longer writable");
        if let Err(err) = ops.remove(Events::new(&self.timer_fd, EventSet::IN)) {
            error!("Failed to un-register serial console timer: {err}");
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::new(&self.timer_fd, EventSet::IN)) {
            error!("Failed to register serial console timer: {err}");
        }
    }
}

impl std::fmt::Debug for ConsoleReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsoleReader")
            .field("last_write_idx", &self.last_write_idx)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    #![allow(clippy::cast_possible_truncation)]

    use std::io::ErrorKind;
    use std::ptr;
    use std::sync::Arc;

    use super::*;
    use crate::nitro_enclave::info_page::{self, INFO_PAGE_SIZE, InfoPage};

    #[test]
    fn test_flush_serial_reads_data() {
        let data = b"hello world";
        let page = Arc::new(info_page::make_test_page(data.len() as u32, 256, data));
        let mut console = ConsoleReader::new_test(page, None);

        let before = METRICS.write_count.count();
        console.flush_serial();
        assert_eq!(console.last_write_idx, Wrapping(data.len() as u32));
        assert_eq!(console.test_output(), data);
        assert_eq!(METRICS.write_count.count() - before, data.len() as u64);

        // A second drain is a no-op once caught up.
        console.flush_serial();
        assert_eq!(console.test_output(), data);
    }

    #[test]
    fn test_flush_serial_no_header() {
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                INFO_PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        unsafe { ptr::write_bytes(p.cast::<u8>(), 0, INFO_PAGE_SIZE) };
        let page = Arc::new(InfoPage::from_raw_ptr(p.cast::<u8>()));
        let mut console = ConsoleReader::new_test(page, None);

        // No header means no serial ring, which the hypervisor always
        // publishes: stop polling rather than spin on a page it never filled.
        assert!(!console.flush_serial());
        assert_eq!(console.last_write_idx, Wrapping(0));
    }

    #[test]
    fn test_flush_serial_rate_limited_drops_but_advances() {
        // A drain larger than the bucket is dropped whole, but the cursor still
        // advances past it so the dropped bytes are not re-read on the next
        // poll, and the dropped bytes are counted.
        let cap: u32 = 64;
        let page = Arc::new(info_page::make_test_page(
            cap,
            cap,
            &vec![b'x'; cap as usize],
        ));
        let limiter = TokenBucket::new(8, 0, 1_000_000);
        let mut console = ConsoleReader::new_test(page, limiter);

        let dropped_before = METRICS.rate_limiter_dropped_bytes.count();
        console.flush_serial();

        assert_eq!(console.last_write_idx, Wrapping(cap));
        assert!(console.test_output().is_empty());
        assert_eq!(
            METRICS.rate_limiter_dropped_bytes.count() - dropped_before,
            cap as u64
        );
    }

    #[test]
    fn test_flush_serial_full_sink_retries_without_error() {
        // A full sink is backpressure: keep polling, count no error.
        let data = b"hello world";
        let page = Arc::new(info_page::make_test_page(data.len() as u32, 256, data));
        let mut console =
            ConsoleReader::new_test_sink(page, None, PartialSink::new(4, ErrorKind::WouldBlock));

        let errors_before = METRICS.error_count.count();
        assert!(console.flush_serial());
        assert_eq!(console.last_write_idx, Wrapping(4));
        assert_eq!(console.test_output(), b"hell");

        // Wedged now: the cursor stays put, so the rest is still pending.
        assert!(console.flush_serial());
        assert_eq!(console.last_write_idx, Wrapping(4));
        assert_eq!(METRICS.error_count.count(), errors_before);
    }

    #[test]
    fn test_flush_serial_broken_sink_reports_error() {
        // EPIPE is fatal: count it and stop polling.
        let data = b"hello";
        let page = Arc::new(info_page::make_test_page(data.len() as u32, 256, data));
        let mut console =
            ConsoleReader::new_test_sink(page, None, PartialSink::new(0, ErrorKind::BrokenPipe));

        let errors_before = METRICS.error_count.count();
        assert!(!console.flush_serial());
        assert_eq!(console.last_write_idx, Wrapping(0));
        assert!(console.test_output().is_empty());
        assert_eq!(METRICS.error_count.count() - errors_before, 1);
    }
}
