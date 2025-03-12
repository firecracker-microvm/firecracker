// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;
use std::time::Duration;

use event_manager::{EventOps, Events, MutEventSubscriber};
use timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};
use vmm::logger::{IncMetric, METRICS, error, warn};
use vmm_sys_util::epoll::EventSet;

/// Metrics reporting period.
pub(crate) const WRITE_METRICS_PERIOD_MS: u64 = 60000;

/// Object to drive periodic reporting of metrics.
#[derive(Debug)]
pub(crate) struct PeriodicMetrics {
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
    pub(crate) fn start(&mut self, interval_ms: u64) {
        // Arm the log write timer.
        let timer_state = TimerState::Periodic {
            current: Duration::from_millis(interval_ms),
            interval: Duration::from_millis(interval_ms),
        };
        self.write_metrics_event_fd
            .set_state(timer_state, SetTimeFlags::Default);

        // Write the metrics straight away to check the process startup time.
        self.write_metrics();
    }

    fn write_metrics(&mut self) {
        if let Err(err) = METRICS.write() {
            METRICS.logger.missed_metrics_count.inc();
            error!("Failed to write metrics: {}", err);
        }

        #[cfg(test)]
        {
            self.flush_counter += 1;
        }
    }
}

impl MutEventSubscriber for PeriodicMetrics {
    /// Handle a read event (EPOLLIN).
    fn process(&mut self, event: Events, _: &mut EventOps) {
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
            self.write_metrics();
        } else {
            error!("Spurious METRICS event!");
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::new(&self.write_metrics_event_fd, EventSet::IN)) {
            error!("Failed to register metrics event: {}", err);
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::{Arc, Mutex};

    use event_manager::{EventManager, SubscriberOps};

    use super::*;

    #[test]
    fn test_periodic_metrics() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let metrics = Arc::new(Mutex::new(PeriodicMetrics::new()));
        event_manager.add_subscriber(metrics.clone());

        let flush_period_ms = 50u16;
        metrics
            .lock()
            .expect("Unlock failed.")
            .start(u64::from(flush_period_ms));
        // .start() does an initial flush.
        assert_eq!(metrics.lock().expect("Unlock failed.").flush_counter, 1);

        // Wait for at most 1.5x period.
        event_manager
            .run_with_timeout(i32::from(flush_period_ms) + i32::from(flush_period_ms) / 2)
            .expect("Metrics event timeout or error.");
        // Verify there was another flush.
        assert_eq!(metrics.lock().expect("Unlock failed.").flush_counter, 2);
    }
}
