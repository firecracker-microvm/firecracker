// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;
use std::time::Duration;

use logger::{Metric, LOGGER, METRICS};
use polly::epoll::{EpollEvent, EventSet};
use polly::event_manager::Subscriber;
use timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};

/// Metrics reporting period.
pub const WRITE_METRICS_PERIOD_MS: u64 = 60000;

/// Object to drive periodic reporting of metrics.
pub struct PeriodicMetrics {
    write_metrics_event_fd: TimerFd,
    #[cfg(test)]
    flush_counter: u64,
}

impl PeriodicMetrics {
    /// PeriodicMetrics constructor. Can panic on `TimerFd` creation failure.
    pub fn new() -> Self {
        let write_metrics_event_fd = TimerFd::new_custom(ClockId::Monotonic, true, true)
            .expect("Cannot create the metrics timer fd.");
        PeriodicMetrics {
            write_metrics_event_fd,
            #[cfg(test)]
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

        #[cfg(test)]
        {
            self.flush_counter += 1;
        }
    }
}

impl Subscriber for PeriodicMetrics {
    /// Handle a read event (EPOLLIN).
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

        if source == self.write_metrics_event_fd.as_raw_fd() {
            self.write_metrics_event_fd.read();
            self.log_metrics();
        } else {
            error!("Spurious METRICS event!");
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.write_metrics_event_fd.as_raw_fd() as u64,
        )]
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use polly::event_manager::EventManager;
    use utils::eventfd::EventFd;

    #[test]
    fn test_interest_list() {
        let metrics = PeriodicMetrics::new();
        let interest_list = metrics.interest_list();
        assert_eq!(interest_list.len(), 1);
        assert_eq!(
            interest_list[0].data() as i32,
            metrics.write_metrics_event_fd.as_raw_fd()
        );
        assert_eq!(
            EventSet::from_bits(interest_list[0].events()).unwrap(),
            EventSet::IN
        );
    }

    #[test]
    fn test_periodic_metrics() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let mut metrics = PeriodicMetrics::new();

        // Test invalid read event.
        let unrelated_object = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let unrelated_event = EpollEvent::new(EventSet::IN, unrelated_object.as_raw_fd() as u64);
        metrics.process(unrelated_event);
        // No flush happened.
        assert_eq!(metrics.flush_counter, 0);

        // Test unsupported event type.
        let unsupported_event = EpollEvent::new(
            EventSet::OUT,
            metrics.write_metrics_event_fd.as_raw_fd() as u64,
        );
        metrics.process(unsupported_event);
        assert_eq!(metrics.flush_counter, 0);

        let metrics = Arc::new(Mutex::new(metrics));
        event_manager
            .add_subscriber(metrics.clone())
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
            .run_with_timeout((flush_period_ms + flush_period_ms / 2) as i32)
            .expect("Metrics event timeout or error.");
        // Verify there was another flush.
        assert_eq!(metrics.lock().expect("Unlock failed.").flush_counter, 2);
    }
}
