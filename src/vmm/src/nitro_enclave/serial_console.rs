// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Serial console reader for Nitro Enclaves.
//!
//! Reads serial output from the enclave's info page ring buffer on a 100ms
//! timer and writes it to the configured serial output (file or stdout).

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use event_manager::{EventOps, Events, MutEventSubscriber};
use utils::time::TimerFd;
use vm_memory::{VolatileSlice, WriteVolatile};
use vmm_sys_util::epoll::EventSet;

use crate::logger::error;
use crate::nitro_enclave::info_page::InfoPage;

/// Polling interval for the serial ring buffer.
const SERIAL_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Output destination for serial data.
enum SerialOutput {
    File(std::fs::File),
    Stdout(io::Stdout),
    #[cfg(test)]
    Test(Vec<u8>),
}

impl SerialOutput {
    fn flush(&mut self) {
        let result = match self {
            Self::File(f) => f.flush(),
            Self::Stdout(s) => s.flush(),
            #[cfg(test)]
            Self::Test(_) => Ok(()),
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
        match self {
            Self::File(f) => f.write_volatile(buf),
            Self::Stdout(s) => s.write_volatile(buf),
            #[cfg(test)]
            Self::Test(v) => v.write_volatile(buf),
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
    last_write_idx: u32,
}

impl ConsoleReader {
    /// Create a new serial console reader.
    ///
    /// If `serial_out_path` is Some, output goes to that file (create/append).
    /// If None, output goes to stdout.
    pub fn new(info_page: Arc<InfoPage>, serial_out_path: Option<&Path>) -> io::Result<Self> {
        let output = match serial_out_path {
            Some(path) => {
                SerialOutput::File(OpenOptions::new().create(true).append(true).open(path)?)
            }
            None => SerialOutput::Stdout(io::stdout()),
        };

        let mut timer_fd = TimerFd::new();
        timer_fd.arm(SERIAL_POLL_INTERVAL, Some(SERIAL_POLL_INTERVAL));

        Ok(Self {
            timer_fd,
            info_page,
            output,
            last_write_idx: 0,
        })
    }

    /// Create a serial console with a test output writer.
    #[cfg(test)]
    fn new_with_output(info_page: Arc<InfoPage>, output: SerialOutput) -> Self {
        Self {
            timer_fd: TimerFd::new(),
            info_page,
            output,
            last_write_idx: 0,
        }
    }

    /// Read new bytes from the info page serial ring buffer and write to output.
    fn flush_serial(&mut self) {
        if let Some(new_idx) = self
            .info_page
            .write_serial_since(self.last_write_idx, &mut self.output)
        {
            self.output.flush();
            self.last_write_idx = new_idx;
        }
    }
}

impl MutEventSubscriber for ConsoleReader {
    fn process(&mut self, event: Events, _ops: &mut EventOps) {
        if event.event_set().contains(EventSet::IN) {
            // Read the timer to acknowledge it.
            let _ = self.timer_fd.read();
            self.flush_serial();
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

    use std::ptr;
    use std::sync::Arc;

    use super::*;
    use crate::nitro_enclave::info_page::{self, INFO_PAGE_SIZE, InfoPage};

    #[test]
    fn test_flush_serial_reads_data() {
        let data = b"hello world";
        let page = Arc::new(info_page::make_test_page(data.len() as u32, 256, data));
        let mut console = ConsoleReader::new_with_output(page, SerialOutput::Test(Vec::new()));

        console.flush_serial();
        assert_eq!(console.last_write_idx, data.len() as u32);
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
        let mut console = ConsoleReader::new_with_output(page, SerialOutput::Test(Vec::new()));

        console.flush_serial();
        assert_eq!(console.last_write_idx, 0);
    }
}
