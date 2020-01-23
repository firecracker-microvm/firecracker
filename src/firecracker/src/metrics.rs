// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;
use std::time::Duration;

use logger::{Metric, LOGGER, METRICS};
use polly::event_manager::EventHandler;
use polly::pollable::{Pollable, PollableOp, PollableOpBuilder};
use timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};

/// Metrics reporting period.
pub const WRITE_METRICS_PERIOD_MS: u64 = 60000;

/// Object to drive periodic reporting of metrics.
pub struct PeriodicMetrics {
    write_metrics_event_fd: TimerFd,
    flush_counter: u64,
}

impl PeriodicMetrics {
    /// PeriodicMetrics constructor. Can panic on `TimerFd` creation failure.
    pub fn new() -> Self {
        let write_metrics_event_fd = TimerFd::new_custom(ClockId::Monotonic, true, true)
            .expect("Cannot create the metrics timer fd.");
        PeriodicMetrics {
            write_metrics_event_fd,
            flush_counter: 0,
        }
    }

    /// Start the periodic metrics engine which will flush metrics every `interval_ms` millisecs.
    pub fn start(&mut self, interval_ms: u64) {
        // Arm the log write timer.
        let timer_state = TimerState::Periodic {
            current: Duration::from_millis(interval_ms),
            interval: Duration::from_millis(interval_ms),
        };
        self.write_metrics_event_fd
            .set_state(timer_state, SetTimeFlags::Default);

        // Log the metrics straight away to check the process startup time.
        self.log_metrics();
    }

    fn log_metrics(&mut self) {
        // Please note that, if LOGGER has no output file configured yet, it will write to
        // stdout, so logging will interfere with console output.
        if let Err(e) = LOGGER.log_metrics() {
            METRICS.logger.missed_metrics_count.inc();
            error!("Failed to log metrics: {}", e);
        }

        // Only used in tests, but has virtually no cost in production.
        self.flush_counter += 1;
    }
}

impl EventHandler for PeriodicMetrics {
    /// Handle a read event (EPOLLIN).
    fn handle_read(&mut self, source: Pollable) -> Vec<PollableOp> {
        if source == self.write_metrics_event_fd.as_raw_fd() {
            self.write_metrics_event_fd.read();
            self.log_metrics();
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

#[cfg(test)]
pub mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use polly::event_manager::EventManager;
    use utils::eventfd::EventFd;

    #[test]
    fn test_event_handler_init() {
        let metrics = PeriodicMetrics::new();
        let pollable_ops = metrics.init();
        assert_eq!(pollable_ops.len(), 1);
        match pollable_ops[0] {
            PollableOp::Register(reg_data) => {
                let (pollable, event_set) = reg_data;
                assert_eq!(pollable, metrics.write_metrics_event_fd.as_raw_fd());
                assert!(event_set.is_readable());
                assert!(!event_set.is_writeable());
                assert!(!event_set.is_closed());
            }
            _ => panic!("Unexpected pollable op."),
        }
    }

    #[test]
    fn test_periodic_metrics() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let mut metrics = PeriodicMetrics::new();

        assert_eq!(metrics.flush_counter, 0);
        // Test invalid read event.
        let unrelated_object = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let updated_pollable_ops = metrics.handle_read(unrelated_object.as_raw_fd());
        // No events update is done.
        assert!(updated_pollable_ops.is_empty());
        // No flush happened.
        assert_eq!(metrics.flush_counter, 0);

        let metrics = Arc::new(Mutex::new(metrics));
        event_manager
            .register(metrics.clone())
            .expect("Cannot register the metrics event to the event manager.");

        let flush_period_ms = 50;
        metrics
            .lock()
            .expect("Unlock failed.")
            .start(flush_period_ms);
        // .start() does an initial flush.
        assert_eq!(metrics.lock().expect("Unlock failed.").flush_counter, 1);

        // Wait for at most 1.5x period.
        event_manager
            .run_timeout((flush_period_ms + flush_period_ms / 2) as i32)
            .expect("Metrics event timeout or error.");
        // Verify there was another flush.
        assert_eq!(metrics.lock().expect("Unlock failed.").flush_counter, 2);
    }
}
