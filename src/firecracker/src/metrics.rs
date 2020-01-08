// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;
use std::time::Duration;

use logger::{Metric, LOGGER, METRICS};
use polly::event_manager::EventHandler;
use polly::pollable::{Pollable, PollableOp, PollableOpBuilder};
use timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};

const WRITE_METRICS_PERIOD_SECONDS: u64 = 60;

pub struct PeriodicMetrics {
    write_metrics_event_fd: TimerFd,
}

impl PeriodicMetrics {
    pub fn new() -> Self {
        let write_metrics_event_fd = TimerFd::new_custom(ClockId::Monotonic, true, true)
            .expect("Cannot create the metrics timer fd.");
        PeriodicMetrics {
            write_metrics_event_fd,
        }
    }

    pub fn start(&mut self) {
        // Arm the log write timer.
        let timer_state = TimerState::Periodic {
            current: Duration::from_secs(WRITE_METRICS_PERIOD_SECONDS),
            interval: Duration::from_secs(WRITE_METRICS_PERIOD_SECONDS),
        };
        self.write_metrics_event_fd
            .set_state(timer_state, SetTimeFlags::Default);

        // Log the metrics straight away to check the process startup time.
        Self::log_metrics();
    }

    fn log_metrics() {
        // Please note that, if LOGGER has no output file configured yet, it will write to
        // stdout, so logging will interfere with console output.
        if let Err(e) = LOGGER.log_metrics() {
            METRICS.logger.missed_metrics_count.inc();
            error!("Failed to log metrics: {}", e);
        }
    }
}

impl EventHandler for PeriodicMetrics {
    /// Handle a read event (EPOLLIN).
    fn handle_read(&mut self, source: Pollable) -> Vec<PollableOp> {
        if source == self.write_metrics_event_fd.as_raw_fd() {
            self.write_metrics_event_fd.read();
            Self::log_metrics();
        } else {
            error!("Spurious METRICS event!");
        }
        vec![]
    }

    /// Initial registration of pollable objects.
    /// Use the PollableOpBuilder to build the vector of PollableOps.
    fn init(&self) -> Vec<PollableOp> {
        vec![
            PollableOpBuilder::new(self.write_metrics_event_fd.as_raw_fd())
                .readable()
                .register(),
        ]
    }
}
