// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;
use std::time::Duration;

use event_manager::EventManager;
use logger::{error, warn, IncMetric, METRICS};
use timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};
use utils::epoll::EventSet;

/// Metrics reporting period.
pub(crate) const WRITE_METRICS_PERIOD_MS: u64 = 60000;

/// Object to drive periodic reporting of metrics.
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

    /// Attach to event manager.
    pub fn init(metrics: Arc<Mutex<Self>>, ops: &mut EventManager) {
        let metrics_clone = metrics.clone();
        if let Err(err) = ops.add(
            metrics.lock().unwrap().write_metrics_event_fd,
            event_manager::IN,
            Box::new(move |_: &mut EventManager, _: u32| {
                let m = metrics_clone.lock().unwrap();
                m.write_metrics_event_fd.read();
                m.write_metrics();
            }),
        ) {
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
        PeriodicMetrics::init(metrics.clone(), &mut event_manager);

        let flush_period_ms = 50;
        metrics
            .lock()
            .expect("Unlock failed.")
            .start(flush_period_ms);
        // .start() does an initial flush.
        assert_eq!(metrics.lock().expect("Unlock failed.").flush_counter, 1);

        // Wait for at most 1.5x period.
        assert_eq!(
            event_manager.wait(Some((flush_period_ms + flush_period_ms / 2) as u32)),
            Ok(true),
            "Metrics event timeout or error."
        );
        // Verify there was another flush.
        assert_eq!(metrics.lock().expect("Unlock failed.").flush_counter, 2);
    }
}
