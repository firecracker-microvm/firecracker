// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the metrics system.
//!
//! # Design
//! The main design goals of this system are:
//! * Use lockless operations, preferably ones that don't require anything other than
//!   simple reads/writes being atomic.
//! * Exploit interior mutability and atomics being Sync to allow all methods (including the ones
//!   which are effectively mutable) to be callable on a global non-mut static.
//! * Rely on `serde` to provide the actual serialization for logging the metrics.
//! * Since all metrics start at 0, we implement the `Default` trait via derive for all of them,
//!   to avoid having to initialize everything by hand.
//!
//! Moreover, the value of a metric is currently NOT reset to 0 each time it's being logged. The
//! current approach is to store two values (current and previous) and compute the delta between
//! them each time we do a flush (i.e by serialization). There are a number of advantages
//! to this approach, including:
//! * We don't have to introduce an additional write (to reset the value) from the thread which
//!   does to actual logging, so less synchronization effort is required.
//! * We don't have to worry at all that much about losing some data if logging fails for a while
//!   (this could be a concern, I guess).
//! If if turns out this approach is not really what we want, it's pretty easy to resort to
//! something else, while working behind the same interface.

use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Serialize, Serializer};

/// Used for defining new types of metrics that can be either incremented with an unit
/// or an arbitrary amount of units.
// This trait helps with writing less code. It has to be in scope (via an use directive) in order
// for its methods to be available to call on structs that implement it.
pub trait Metric {
    /// Adds `value` to the current counter.
    fn add(&self, value: usize);
    /// Increments by 1 unit the current counter.
    fn inc(&self) {
        self.add(1);
    }
    /// Returns current value of the counter.
    fn count(&self) -> usize;
}

/// Representation of a metric that is expected to be incremented from more than one thread, so more
/// synchronization is necessary.
// It's currently used for vCPU metrics. An alternative here would be
// to have one instance of every metric for each thread, and to
// aggregate them when logging. However this probably overkill unless we have a lot of vCPUs
// incrementing metrics very often. Still, it's there if we ever need it :-s
#[derive(Default)]
// We will be keeping two values for each metric for being able to reset
// counters on each metric.
// 1st member - current value being updated
// 2nd member - old value that gets the current value whenever metrics is flushed to disk
pub struct SharedMetric(AtomicUsize, AtomicUsize);

impl Metric for SharedMetric {
    // While the order specified for this operation is still Relaxed, the actual instruction will
    // be an asm "LOCK; something" and thus atomic across multiple threads, simply because of the
    // fetch_and_add (as opposed to "store(load() + 1)") implementation for atomics.
    // TODO: would a stronger ordering make a difference here?
    fn add(&self, value: usize) {
        self.0.fetch_add(value, Ordering::Relaxed);
    }

    fn count(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

impl Serialize for SharedMetric {
    /// Reset counters of each metrics. Here we suppose that Serialize's goal is to help with the
    /// flushing of metrics.
    /// !!! Any print of the metrics will also reset them. Use with caution !!!
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // There's no serializer.serialize_usize() for some reason :(
        let snapshot = self.0.load(Ordering::Relaxed);
        let res = serializer.serialize_u64(snapshot as u64 - self.1.load(Ordering::Relaxed) as u64);

        if res.is_ok() {
            self.1.store(snapshot, Ordering::Relaxed);
        }
        res
    }
}

// The following structs are used to define a certain organization for the set of metrics we
// are interested in. Whenever the name of a field differs from its ideal textual representation
// in the serialized form, we can use the #[serde(rename = "name")] attribute to, well, rename it.

/// Metrics related to the internal API server.
#[derive(Default, Serialize)]
pub struct ApiServerMetrics {
    /// Measures the process's startup time in microseconds.
    pub process_startup_time_us: SharedMetric,
    /// Measures the cpu's startup time in microseconds.
    pub process_startup_time_cpu_us: SharedMetric,
    /// Number of failures on API requests triggered by internal errors.
    pub sync_response_fails: SharedMetric,
    /// Number of timeouts during communication with the VMM.
    pub sync_vmm_send_timeout_count: SharedMetric,
}

/// Metrics specific to GET API Requests for counting user triggered actions and/or failures.
#[derive(Default, Serialize)]
pub struct GetRequestsMetrics {
    /// Number of GETs for getting information on the instance.
    pub instance_info_count: SharedMetric,
    /// Number of failures when obtaining information on the current instance.
    pub instance_info_fails: SharedMetric,
    /// Number of GETs for getting status on attaching machine configuration.
    pub machine_cfg_count: SharedMetric,
    /// Number of failures during GETs for getting information on the instance.
    pub machine_cfg_fails: SharedMetric,
}

/// Metrics specific to PUT API Requests for counting user triggered actions and/or failures.
#[derive(Default, Serialize)]
pub struct PutRequestsMetrics {
    /// Number of PUTs triggering an action on the VM.
    pub actions_count: SharedMetric,
    /// Number of failures in triggering an action on the VM.
    pub actions_fails: SharedMetric,
    /// Number of PUTs for attaching source of boot.
    pub boot_source_count: SharedMetric,
    /// Number of failures during attaching source of boot.
    pub boot_source_fails: SharedMetric,
    /// Number of PUTs triggering a block attach.
    pub drive_count: SharedMetric,
    /// Number of failures in attaching a block device.
    pub drive_fails: SharedMetric,
    /// Number of PUTs for initializing the logging system.
    pub logger_count: SharedMetric,
    /// Number of failures in initializing the logging system.
    pub logger_fails: SharedMetric,
    /// Number of PUTs for configuring the machine.
    pub machine_cfg_count: SharedMetric,
    /// Number of failures in configuring the machine.
    pub machine_cfg_fails: SharedMetric,
    /// Number of PUTs for creating a new network interface.
    pub network_count: SharedMetric,
    /// Number of failures in creating a new network interface.
    pub network_fails: SharedMetric,
}

/// Metrics specific to PATCH API Requests for counting user triggered actions and/or failures.
#[derive(Default, Serialize)]
pub struct PatchRequestsMetrics {
    /// Number of tries to PATCH a block device.
    pub drive_count: SharedMetric,
    /// Number of failures in PATCHing a block device.
    pub drive_fails: SharedMetric,
    /// Number of tries to PATCH a net device.
    pub network_count: SharedMetric,
    /// Number of failures in PATCHing a net device.
    pub network_fails: SharedMetric,
    /// Number of PATCHs for configuring the machine.
    pub machine_cfg_count: SharedMetric,
    /// Number of failures in configuring the machine.
    pub machine_cfg_fails: SharedMetric,
}

/// Block Device associated metrics.
#[derive(Default, Serialize)]
pub struct BlockDeviceMetrics {
    /// Number of times when activate failed on a block device.
    pub activate_fails: SharedMetric,
    /// Number of times when interacting with the space config of a block device failed.
    pub cfg_fails: SharedMetric,
    /// Number of times when handling events on a block device failed.
    pub event_fails: SharedMetric,
    /// Number of failures in executing a request on a block device.
    pub execute_fails: SharedMetric,
    /// Number of invalid requests received for this block device.
    pub invalid_reqs_count: SharedMetric,
    /// Number of flushes operation triggered on this block device.
    pub flush_count: SharedMetric,
    /// Number of events triggerd on the queue of this block device.
    pub queue_event_count: SharedMetric,
    /// Number of events ratelimiter-related.
    pub rate_limiter_event_count: SharedMetric,
    /// Number of update operation triggered on this block device.
    pub update_count: SharedMetric,
    /// Number of failures while doing update on this block device.
    pub update_fails: SharedMetric,
    /// Number of bytes read by this block device.
    pub read_bytes: SharedMetric,
    /// Number of bytes written by this block device.
    pub write_bytes: SharedMetric,
    /// Number of successful read operations.
    pub read_count: SharedMetric,
    /// Number of sucessful write operations.
    pub write_count: SharedMetric,
}

/// Metrics specific to the i8042 device.
#[derive(Default, Serialize)]
pub struct I8042DeviceMetrics {
    /// Errors triggered while using the i8042 device.
    pub error_count: SharedMetric,
    /// Number of superfluous read intents on this i8042 device.
    pub missed_read_count: SharedMetric,
    /// Number of superfluous read intents on this i8042 device.
    pub missed_write_count: SharedMetric,
    /// Bytes read by this device.
    pub read_count: SharedMetric,
    /// Number of resets done by this device.
    pub reset_count: SharedMetric,
    /// Bytes written by this device.
    pub write_count: SharedMetric,
}

/// Metrics for the logging subsystem.
#[derive(Default, Serialize)]
pub struct LoggerSystemMetrics {
    /// Number of misses on flushing metrics.
    pub missed_metrics_count: SharedMetric,
    /// Number of errors during metrics handling.
    pub metrics_fails: SharedMetric,
    /// Number of misses on logging human readable content.
    pub missed_log_count: SharedMetric,
    /// Number of errors while trying to log human readable content.
    pub log_fails: SharedMetric,
}

/// Metrics for the MMDS functionality.
#[derive(Default, Serialize)]
pub struct MmdsMetrics {
    /// Number of frames rerouted to MMDS.
    pub rx_accepted: SharedMetric,
    /// Number of errors while handling a frame through MMDS.
    pub rx_accepted_err: SharedMetric,
    /// Number of uncommon events encountered while processing packets through MMDS.
    pub rx_accepted_unusual: SharedMetric,
    /// The number of buffers which couldn't be parsed as valid Ethernet frames by the MMDS.
    pub rx_bad_eth: SharedMetric,
    /// The total number of successful receive operations by the MMDS.
    pub rx_count: SharedMetric,
    /// The total number of bytes sent by the MMDS.
    pub tx_bytes: SharedMetric,
    /// The total number of successful send operations by the MMDS.
    pub tx_count: SharedMetric,
    /// The number of errors raised by the MMDS while attempting to send frames/packets/segments.
    pub tx_errors: SharedMetric,
    /// The number of frames sent by the MMDS.
    pub tx_frames: SharedMetric,
    /// The number of connections successfully accepted by the MMDS TCP handler.
    pub connections_created: SharedMetric,
    /// The number of connections cleaned up by the MMDS TCP handler.
    pub connections_destroyed: SharedMetric,
}

/// Network-related metrics.
#[derive(Default, Serialize)]
pub struct NetDeviceMetrics {
    /// Number of times when activate failed on a network device.
    pub activate_fails: SharedMetric,
    /// Number of times when interacting with the space config of a network device failed.
    pub cfg_fails: SharedMetric,
    /// Number of times when handling events on a network device failed.
    pub event_fails: SharedMetric,
    /// Number of events associated with the receiving queue.
    pub rx_queue_event_count: SharedMetric,
    /// Number of events associated with the rate limiter installed on the receiving path.
    pub rx_event_rate_limiter_count: SharedMetric,
    /// Number of events received on the associated tap.
    pub rx_tap_event_count: SharedMetric,
    /// Number of bytes received.
    pub rx_bytes_count: SharedMetric,
    /// Number of packets received.
    pub rx_packets_count: SharedMetric,
    /// Number of errors while receiving data.
    pub rx_fails: SharedMetric,
    /// Number of successful read operations while receiving data.
    pub rx_count: SharedMetric,
    /// Number of transmitted bytes.
    pub tx_bytes_count: SharedMetric,
    /// Number of errors while transmitting data.
    pub tx_fails: SharedMetric,
    /// Number of successful write operations while transmitting data.
    pub tx_count: SharedMetric,
    /// Number of transmitted packets.
    pub tx_packets_count: SharedMetric,
    /// Number of events associated with the transmitting queue.
    pub tx_queue_event_count: SharedMetric,
    /// Number of events associated with the rate limiter installed on the transmitting path.
    pub tx_rate_limiter_event_count: SharedMetric,
    /// Number of packets with a spoofed mac, sent by the guest.
    pub tx_spoofed_mac_count: SharedMetric,
}

/// Metrics specific to the i8042 device.
#[derive(Default, Serialize)]
pub struct RTCDeviceMetrics {
    /// Errors triggered while using the i8042 device.
    pub error_count: SharedMetric,
    /// Number of superfluous read intents on this i8042 device.
    pub missed_read_count: SharedMetric,
    /// Number of superfluous read intents on this i8042 device.
    pub missed_write_count: SharedMetric,
}

/// Metrics for the seccomp filtering.
#[derive(Default, Serialize)]
pub struct SeccompMetrics {
    /// Number of errors inside the seccomp filtering.
    pub num_faults: SharedMetric,
}

/// Metrics specific to the UART device.
#[derive(Default, Serialize)]
pub struct SerialDeviceMetrics {
    /// Errors triggered while using the UART device.
    pub error_count: SharedMetric,
    /// Number of flush operations.
    pub flush_count: SharedMetric,
    /// Number of read calls that did not trigger a read.
    pub missed_read_count: SharedMetric,
    /// Number of write calls that did not trigger a write.
    pub missed_write_count: SharedMetric,
    /// Number of succeeded read calls.
    pub read_count: SharedMetric,
    /// Number of succeeded write calls.
    pub write_count: SharedMetric,
}

/// Metrics specific to VCPUs' mode of functioning.
#[derive(Default, Serialize)]
pub struct VcpuMetrics {
    /// Number of KVM exits for handling input IO.
    pub exit_io_in: SharedMetric,
    /// Number of KVM exits for handling output IO.
    pub exit_io_out: SharedMetric,
    /// Number of KVM exits for handling MMIO reads.
    pub exit_mmio_read: SharedMetric,
    /// Number of KVM exits for handling MMIO writes.
    pub exit_mmio_write: SharedMetric,
    /// Number of errors during this VCPU's run.
    pub failures: SharedMetric,
    /// Failures in configuring the CPUID.
    pub filter_cpuid: SharedMetric,
}

/// Metrics specific to the machine manager as a whole.
#[derive(Default, Serialize)]
pub struct VmmMetrics {
    /// Number of device related events received for a VM.
    pub device_events: SharedMetric,
    /// Metric for signaling a panic has occurred.
    pub panic_count: SharedMetric,
}

/// Memory usage metrics.
#[derive(Default, Serialize)]
pub struct MemoryMetrics {
    /// Number of pages dirtied since the last call to `KVM_GET_DIRTY_LOG`.
    pub dirty_pages: SharedMetric,
}

/// Metrics related to signals.
#[derive(Default, Serialize)]
pub struct SignalMetrics {
    /// Number of times that SIGBUS was handled.
    pub sigbus: SharedMetric,
    /// Number of times that SIGSEGV was handled.
    pub sigsegv: SharedMetric,
}

// The sole purpose of this struct is to produce an UTC timestamp when an instance is serialized.
#[derive(Default)]
struct SerializeToUtcTimestampMs;

impl Serialize for SerializeToUtcTimestampMs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(
            fc_util::time::get_time(fc_util::time::ClockType::Monotonic) as i64 / 1_000_000,
        )
    }
}

/// Structure storing all metrics while enforcing serialization support on them.
#[derive(Default, Serialize)]
pub struct FirecrackerMetrics {
    utc_timestamp_ms: SerializeToUtcTimestampMs,
    /// API Server related metrics.
    pub api_server: ApiServerMetrics,
    /// A block device's related metrics.
    pub block: BlockDeviceMetrics,
    /// Metrics related to API GET requests.
    pub get_api_requests: GetRequestsMetrics,
    /// Metrics relaetd to the i8042 device.
    pub i8042: I8042DeviceMetrics,
    /// Logging related metrics.
    pub logger: LoggerSystemMetrics,
    /// Metrics specific to MMDS functionality.
    pub mmds: MmdsMetrics,
    /// A network device's related metrics.
    pub net: NetDeviceMetrics,
    /// Metrics related to API PATCH requests.
    pub patch_api_requests: PatchRequestsMetrics,
    /// Metrics related to API PUT requests.
    pub put_api_requests: PutRequestsMetrics,
    /// Metrics related to the RTC device.
    pub rtc: RTCDeviceMetrics,
    /// Metrics related to seccomp filtering.
    pub seccomp: SeccompMetrics,
    /// Metrics related to a vcpu's functioning.
    pub vcpu: VcpuMetrics,
    /// Metrics related to the virtual machine manager.
    pub vmm: VmmMetrics,
    /// Metrics related to the UART device.
    pub uart: SerialDeviceMetrics,
    /// Memory usage metrics.
    pub memory: MemoryMetrics,
    /// Metrics related to signals.
    pub signals: SignalMetrics,
}

lazy_static! {
    /// Static instance used for handling metrics.
    ///
    pub static ref METRICS: FirecrackerMetrics = FirecrackerMetrics::default();
}

#[cfg(test)]
mod tests {
    extern crate serde_json;
    use super::*;

    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_metric() {
        // Test SharedMetric.
        let m2 = Arc::new(SharedMetric::default());

        // We're going to create a number of threads that will attempt to increase this metric
        // in parallel. If everything goes fine we still can't be sure the synchronization works,
        // but it something fails, then we definitely have a problem :-s

        const NUM_THREADS_TO_SPAWN: usize = 4;
        const NUM_INCREMENTS_PER_THREAD: usize = 10_0000;
        const M2_INITIAL_COUNT: usize = 123;

        m2.add(M2_INITIAL_COUNT);

        let mut v = Vec::with_capacity(NUM_THREADS_TO_SPAWN);

        for _ in 0..NUM_THREADS_TO_SPAWN {
            let r = m2.clone();
            v.push(thread::spawn(move || {
                for _ in 0..NUM_INCREMENTS_PER_THREAD {
                    r.inc();
                }
            }));
        }

        for handle in v {
            handle.join().unwrap();
        }

        assert_eq!(
            m2.count(),
            M2_INITIAL_COUNT + NUM_THREADS_TO_SPAWN * NUM_INCREMENTS_PER_THREAD
        );
    }

    #[test]
    fn test_serialize() {
        let s = serde_json::to_string(&FirecrackerMetrics::default());
        assert!(s.is_ok());
    }
}
