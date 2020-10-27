// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines the metrics system.
//!
//! # Metrics format
//! The metrics are flushed in JSON format each 60 seconds. The first field will always be the
//! timestamp followed by the JSON representation of the structures representing each component on
//! which we are capturing specific metrics.
//!
//! ## JSON example with metrics:
//! ```bash
//! {
//!  "utc_timestamp_ms": 1541591155180,
//!  "api_server": {
//!    "process_startup_time_us": 0,
//!    "process_startup_time_cpu_us": 0
//!  },
//!  "block": {
//!    "activate_fails": 0,
//!    "cfg_fails": 0,
//!    "event_fails": 0,
//!    "flush_count": 0,
//!    "queue_event_count": 0,
//!    "read_count": 0,
//!    "write_count": 0
//!  }
//! }
//! ```
//! The example above means that inside the structure representing all the metrics there is a field
//! named `block` which is in turn a serializable child structure collecting metrics for
//! the block device such as `activate_fails`, `cfg_fails`, etc.
//!
//! # Limitations
//! Metrics are only written to buffers.
//!
//! # Design
//! The main design goals of this system are:
//! * Use lockless operations, preferably ones that don't require anything other than
//!   simple reads/writes being atomic.
//! * Exploit interior mutability and atomics being Sync to allow all methods (including the ones
//!   which are effectively mutable) to be callable on a global non-mut static.
//! * Rely on `serde` to provide the actual serialization for writing the metrics.
//! * Since all metrics start at 0, we implement the `Default` trait via derive for all of them,
//!   to avoid having to initialize everything by hand.
//!
//! The system implements 2 types of metrics:
//! * Shared Incremental Metrics (SharedIncMetrics) - dedicated for the metrics which need a counter
//! (i.e the number of times an API request failed). These metrics are reset upon flush.
//! * Shared Store Metrics (SharedStoreMetrics) - are targeted at keeping a persistent value, it is not
//! intended to act as a counter (i.e for measure the process start up time for example).
//!
//! The current approach for the `SharedIncMetrics` type is to store two values (current and previous)
//! and compute the delta between them each time we do a flush (i.e by serialization). There are a number of advantages
//! to this approach, including:
//! * We don't have to introduce an additional write (to reset the value) from the thread which
//!   does to actual writing, so less synchronization effort is required.
//! * We don't have to worry at all that much about losing some data if writing fails for a while
//!   (this could be a concern, I guess).
//! If if turns out this approach is not really what we want, it's pretty easy to resort to
//! something else, while working behind the same interface.

use std::fmt;
use std::io::Write;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use lazy_static::lazy_static;
use serde::{Serialize, Serializer};

use super::extract_guard;

lazy_static! {
    /// Static instance used for handling metrics.
    pub static ref METRICS: Metrics<FirecrackerMetrics> = Metrics::new(FirecrackerMetrics::default());
}

/// Metrics system.
// All member fields have types which are Sync, and exhibit interior mutability, so
// we can call operations on metrics using a non-mut static global variable.
pub struct Metrics<T: Serialize> {
    // Metrics will get flushed here.
    metrics_buf: Mutex<Option<Box<dyn Write + Send>>>,
    is_initialized: AtomicBool,
    pub app_metrics: T,
}

impl<T: Serialize> Metrics<T> {
    /// Creates a new instance of the current metrics.
    // TODO: We need a better name than app_metrics (something that says that these are the actual
    // values that we are writing to the metrics_buf).
    pub fn new(app_metrics: T) -> Metrics<T> {
        Metrics {
            metrics_buf: Mutex::new(None),
            is_initialized: AtomicBool::new(false),
            app_metrics,
        }
    }

    /// Initialize metrics system (once and only once).
    /// Every call made after the first will have no effect besides returning `Ok` or `Err`.
    ///
    /// # Arguments
    ///
    /// * `metrics_dest` - Buffer for JSON formatted metrics. Needs to implement `Write` and `Send`.
    pub fn init(&self, metrics_dest: Box<dyn Write + Send>) -> Result<(), MetricsError> {
        if self.is_initialized.load(Ordering::Relaxed) {
            return Err(MetricsError::AlreadyInitialized);
        }
        {
            let mut g = extract_guard(self.metrics_buf.lock());

            *g = Some(metrics_dest);
        }
        self.is_initialized.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Writes metrics to the destination provided as argument upon initialization of the metrics.
    /// Upon failure, an error is returned if metrics system is initialized and metrics could not be
    /// written.
    /// Upon success, the function will return `True` (if metrics system was initialized and metrics
    /// were successfully written to disk) or `False` (if metrics system was not yet initialized).
    pub fn write(&self) -> Result<bool, MetricsError> {
        if self.is_initialized.load(Ordering::Relaxed) {
            match serde_json::to_string(&self.app_metrics) {
                Ok(msg) => {
                    if let Some(guard) = extract_guard(self.metrics_buf.lock()).as_mut() {
                        // No need to explicitly call flush because the underlying LineWriter flushes
                        // automatically whenever a newline is detected (and we always end with a
                        // newline the current write).
                        return guard
                            .write_all(&(format!("{}\n", msg)).as_bytes())
                            .map_err(MetricsError::Write)
                            .map(|_| true);
                    } else {
                        // We have not incremented `missed_metrics_count` as there is no way to push metrics
                        // if destination lock got poisoned.
                        panic!("Failed to write to the provided metrics destination due to poisoned lock");
                    }
                }
                Err(e) => {
                    return Err(MetricsError::Serde(e.to_string()));
                }
            }
        }
        // If the metrics are not initialized, no error is thrown but we do let the user know that
        // metrics were not written.
        Ok(false)
    }
}

impl<T: Serialize> Deref for Metrics<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.app_metrics
    }
}

/// Describes the errors which may occur while handling metrics scenarios.
#[derive(Debug)]
pub enum MetricsError {
    /// First attempt at initialization failed.
    NeverInitialized(String),
    /// The metrics system does not allow reinitialization.
    AlreadyInitialized,
    /// Error in the serialization of metrics instance.
    Serde(String),
    /// Writing the specified buffer failed.
    Write(std::io::Error),
}

impl fmt::Display for MetricsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            MetricsError::NeverInitialized(ref e) => e.to_string(),
            MetricsError::AlreadyInitialized => {
                "Reinitialization of metrics not allowed.".to_string()
            }
            MetricsError::Serde(ref e) => e.to_string(),
            MetricsError::Write(ref e) => format!("Failed to write metrics. Error: {}", e),
        };
        write!(f, "{}", printable)
    }
}

/// Used for defining new types of metrics that act as a counter (i.e they are continuously updated by
/// incrementing their value).
pub trait IncMetric {
    /// Adds `value` to the current counter.
    fn add(&self, value: usize);
    /// Increments by 1 unit the current counter.
    fn inc(&self) {
        self.add(1);
    }
    /// Returns current value of the counter.
    fn count(&self) -> usize;
}

/// Used for defining new types of metrics that do not need a counter and act as a persistent indicator.
pub trait StoreMetric {
    /// Returns current value of the counter.
    fn fetch(&self) -> usize;
    /// Stores `value` to the current counter.
    fn store(&self, value: usize);
}

/// Representation of a metric that is expected to be incremented from more than one thread, so more
/// synchronization is necessary.
// It's currently used for vCPU metrics. An alternative here would be
// to have one instance of every metric for each thread, and to
// aggregate them when writing. However this probably overkill unless we have a lot of vCPUs
// incrementing metrics very often. Still, it's there if we ever need it :-s
// We will be keeping two values for each metric for being able to reset
// counters on each metric.
// 1st member - current value being updated
// 2nd member - old value that gets the current value whenever metrics is flushed to disk
#[derive(Default)]
pub struct SharedIncMetric(AtomicUsize, AtomicUsize);

#[derive(Default)]
pub struct SharedStoreMetric(AtomicUsize);

impl IncMetric for SharedIncMetric {
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

impl StoreMetric for SharedStoreMetric {
    fn fetch(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }

    fn store(&self, value: usize) {
        self.0.store(value, Ordering::Relaxed);
    }
}

impl Serialize for SharedIncMetric {
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

impl Serialize for SharedStoreMetric {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0.load(Ordering::Relaxed) as u64)
    }
}

// The following structs are used to define a certain organization for the set of metrics we
// are interested in. Whenever the name of a field differs from its ideal textual representation
// in the serialized form, we can use the #[serde(rename = "name")] attribute to, well, rename it.

/// Metrics related to the internal API server.
#[derive(Default, Serialize)]
pub struct ApiServerMetrics {
    /// Measures the process's startup time in microseconds.
    pub process_startup_time_us: SharedStoreMetric,
    /// Measures the cpu's startup time in microseconds.
    pub process_startup_time_cpu_us: SharedStoreMetric,
    /// Number of failures on API requests triggered by internal errors.
    pub sync_response_fails: SharedIncMetric,
    /// Number of timeouts during communication with the VMM.
    pub sync_vmm_send_timeout_count: SharedIncMetric,
}

/// Metrics specific to GET API Requests for counting user triggered actions and/or failures.
#[derive(Default, Serialize)]
pub struct GetRequestsMetrics {
    /// Number of GETs for getting information on the instance.
    pub instance_info_count: SharedIncMetric,
    /// Number of failures when obtaining information on the current instance.
    pub instance_info_fails: SharedIncMetric,
    /// Number of GETs for getting status on attaching machine configuration.
    pub machine_cfg_count: SharedIncMetric,
    /// Number of failures during GETs for getting information on the instance.
    pub machine_cfg_fails: SharedIncMetric,
}

/// Metrics specific to PUT API Requests for counting user triggered actions and/or failures.
#[derive(Default, Serialize)]
pub struct PutRequestsMetrics {
    /// Number of PUTs triggering an action on the VM.
    pub actions_count: SharedIncMetric,
    /// Number of failures in triggering an action on the VM.
    pub actions_fails: SharedIncMetric,
    /// Number of PUTs for attaching source of boot.
    pub boot_source_count: SharedIncMetric,
    /// Number of failures during attaching source of boot.
    pub boot_source_fails: SharedIncMetric,
    /// Number of PUTs triggering a block attach.
    pub drive_count: SharedIncMetric,
    /// Number of failures in attaching a block device.
    pub drive_fails: SharedIncMetric,
    /// Number of PUTs for initializing the logging system.
    pub logger_count: SharedIncMetric,
    /// Number of failures in initializing the logging system.
    pub logger_fails: SharedIncMetric,
    /// Number of PUTs for configuring the machine.
    pub machine_cfg_count: SharedIncMetric,
    /// Number of failures in configuring the machine.
    pub machine_cfg_fails: SharedIncMetric,
    /// Number of PUTs for initializing the metrics system.
    pub metrics_count: SharedIncMetric,
    /// Number of failures in initializing the metrics system.
    pub metrics_fails: SharedIncMetric,
    /// Number of PUTs for creating a new network interface.
    pub network_count: SharedIncMetric,
    /// Number of failures in creating a new network interface.
    pub network_fails: SharedIncMetric,
}

/// Metrics specific to PATCH API Requests for counting user triggered actions and/or failures.
#[derive(Default, Serialize)]
pub struct PatchRequestsMetrics {
    /// Number of tries to PATCH a block device.
    pub drive_count: SharedIncMetric,
    /// Number of failures in PATCHing a block device.
    pub drive_fails: SharedIncMetric,
    /// Number of tries to PATCH a net device.
    pub network_count: SharedIncMetric,
    /// Number of failures in PATCHing a net device.
    pub network_fails: SharedIncMetric,
    /// Number of PATCHs for configuring the machine.
    pub machine_cfg_count: SharedIncMetric,
    /// Number of failures in configuring the machine.
    pub machine_cfg_fails: SharedIncMetric,
}

/// Balloon Device associated metrics.
#[derive(Default, Serialize)]
pub struct BalloonDeviceMetrics {
    /// Number of times when activate failed on a balloon device.
    pub activate_fails: SharedIncMetric,
    /// Number of balloon device inflations.
    pub inflate_count: SharedIncMetric,
    // Number of balloon statistics updates from the driver.
    pub stats_updates_count: SharedIncMetric,
    // Number of balloon statistics update failures.
    pub stats_update_fails: SharedIncMetric,
    /// Number of balloon device deflations.
    pub deflate_count: SharedIncMetric,
    /// Number of times when handling events on a balloon device failed.
    pub event_fails: SharedIncMetric,
}

/// Block Device associated metrics.
#[derive(Default, Serialize)]
pub struct BlockDeviceMetrics {
    /// Number of times when activate failed on a block device.
    pub activate_fails: SharedIncMetric,
    /// Number of times when interacting with the space config of a block device failed.
    pub cfg_fails: SharedIncMetric,
    /// No available buffer for the block queue.
    pub no_avail_buffer: SharedIncMetric,
    /// Number of times when handling events on a block device failed.
    pub event_fails: SharedIncMetric,
    /// Number of failures in executing a request on a block device.
    pub execute_fails: SharedIncMetric,
    /// Number of invalid requests received for this block device.
    pub invalid_reqs_count: SharedIncMetric,
    /// Number of flushes operation triggered on this block device.
    pub flush_count: SharedIncMetric,
    /// Number of events triggerd on the queue of this block device.
    pub queue_event_count: SharedIncMetric,
    /// Number of events ratelimiter-related.
    pub rate_limiter_event_count: SharedIncMetric,
    /// Number of update operation triggered on this block device.
    pub update_count: SharedIncMetric,
    /// Number of failures while doing update on this block device.
    pub update_fails: SharedIncMetric,
    /// Number of bytes read by this block device.
    pub read_bytes: SharedIncMetric,
    /// Number of bytes written by this block device.
    pub write_bytes: SharedIncMetric,
    /// Number of successful read operations.
    pub read_count: SharedIncMetric,
    /// Number of successful write operations.
    pub write_count: SharedIncMetric,
    /// Number of rate limiter throttling events.
    pub rate_limiter_throttled_events: SharedIncMetric,
}

/// Metrics specific to the i8042 device.
#[derive(Default, Serialize)]
pub struct I8042DeviceMetrics {
    /// Errors triggered while using the i8042 device.
    pub error_count: SharedIncMetric,
    /// Number of superfluous read intents on this i8042 device.
    pub missed_read_count: SharedIncMetric,
    /// Number of superfluous write intents on this i8042 device.
    pub missed_write_count: SharedIncMetric,
    /// Bytes read by this device.
    pub read_count: SharedIncMetric,
    /// Number of resets done by this device.
    pub reset_count: SharedIncMetric,
    /// Bytes written by this device.
    pub write_count: SharedIncMetric,
}

/// Metrics for the logging subsystem.
#[derive(Default, Serialize)]
pub struct LoggerSystemMetrics {
    /// Number of misses on flushing metrics.
    pub missed_metrics_count: SharedIncMetric,
    /// Number of errors during metrics handling.
    pub metrics_fails: SharedIncMetric,
    /// Number of misses on logging human readable content.
    pub missed_log_count: SharedIncMetric,
    /// Number of errors while trying to log human readable content.
    pub log_fails: SharedIncMetric,
}

/// Metrics for the MMDS functionality.
#[derive(Default, Serialize)]
pub struct MmdsMetrics {
    /// Number of frames rerouted to MMDS.
    pub rx_accepted: SharedIncMetric,
    /// Number of errors while handling a frame through MMDS.
    pub rx_accepted_err: SharedIncMetric,
    /// Number of uncommon events encountered while processing packets through MMDS.
    pub rx_accepted_unusual: SharedIncMetric,
    /// The number of buffers which couldn't be parsed as valid Ethernet frames by the MMDS.
    pub rx_bad_eth: SharedIncMetric,
    /// The total number of successful receive operations by the MMDS.
    pub rx_count: SharedIncMetric,
    /// The total number of bytes sent by the MMDS.
    pub tx_bytes: SharedIncMetric,
    /// The total number of successful send operations by the MMDS.
    pub tx_count: SharedIncMetric,
    /// The number of errors raised by the MMDS while attempting to send frames/packets/segments.
    pub tx_errors: SharedIncMetric,
    /// The number of frames sent by the MMDS.
    pub tx_frames: SharedIncMetric,
    /// The number of connections successfully accepted by the MMDS TCP handler.
    pub connections_created: SharedIncMetric,
    /// The number of connections cleaned up by the MMDS TCP handler.
    pub connections_destroyed: SharedIncMetric,
}

/// Network-related metrics.
#[derive(Default, Serialize)]
pub struct NetDeviceMetrics {
    /// Number of times when activate failed on a network device.
    pub activate_fails: SharedIncMetric,
    /// Number of times when interacting with the space config of a network device failed.
    pub cfg_fails: SharedIncMetric,
    //// Number of times the mac address was updated through the config space.
    pub mac_address_updates: SharedIncMetric,
    /// No available buffer for the net device rx queue.
    pub no_rx_avail_buffer: SharedIncMetric,
    /// No available buffer for the net device tx queue.
    pub no_tx_avail_buffer: SharedIncMetric,
    /// Number of times when handling events on a network device failed.
    pub event_fails: SharedIncMetric,
    /// Number of events associated with the receiving queue.
    pub rx_queue_event_count: SharedIncMetric,
    /// Number of events associated with the rate limiter installed on the receiving path.
    pub rx_event_rate_limiter_count: SharedIncMetric,
    /// Number of RX partial writes to guest.
    pub rx_partial_writes: SharedIncMetric,
    /// Number of RX rate limiter throttling events.
    pub rx_rate_limiter_throttled: SharedIncMetric,
    /// Number of events received on the associated tap.
    pub rx_tap_event_count: SharedIncMetric,
    /// Number of bytes received.
    pub rx_bytes_count: SharedIncMetric,
    /// Number of packets received.
    pub rx_packets_count: SharedIncMetric,
    /// Number of errors while receiving data.
    pub rx_fails: SharedIncMetric,
    /// Number of successful read operations while receiving data.
    pub rx_count: SharedIncMetric,
    /// Number of times reading from TAP failed.
    pub tap_read_fails: SharedIncMetric,
    /// Number of times writing to TAP failed.
    pub tap_write_fails: SharedIncMetric,
    /// Number of transmitted bytes.
    pub tx_bytes_count: SharedIncMetric,
    /// Number of malformed TX frames.
    pub tx_malformed_frames: SharedIncMetric,
    /// Number of errors while transmitting data.
    pub tx_fails: SharedIncMetric,
    /// Number of successful write operations while transmitting data.
    pub tx_count: SharedIncMetric,
    /// Number of transmitted packets.
    pub tx_packets_count: SharedIncMetric,
    /// Number of TX partial reads from guest.
    pub tx_partial_reads: SharedIncMetric,
    /// Number of events associated with the transmitting queue.
    pub tx_queue_event_count: SharedIncMetric,
    /// Number of events associated with the rate limiter installed on the transmitting path.
    pub tx_rate_limiter_event_count: SharedIncMetric,
    /// Number of RX rate limiter throttling events.
    pub tx_rate_limiter_throttled: SharedIncMetric,
    /// Number of packets with a spoofed mac, sent by the guest.
    pub tx_spoofed_mac_count: SharedIncMetric,
}

/// Performance metrics related for the moment only to snapshots.
// These store the duration of creating/loading a snapshot and of
// pausing/resuming the microVM.
// If there are more than one `/snapshot/create` request in a minute
// (until the metrics are flushed), only the duration of the last
// snapshot creation is stored in the metric. If the user is interested
// in all the durations, a `FlushMetrics` request should be sent after
// each `create` request.
#[derive(Default, Serialize)]
pub struct PerformanceMetrics {
    #[cfg(target_arch = "x86_64")]
    /// Measures the snapshot full create time, at the API (user) level, in microseconds.
    pub full_create_snapshot: SharedStoreMetric,
    #[cfg(target_arch = "x86_64")]
    /// Measures the snapshot diff create time, at the API (user) level, in microseconds.
    pub diff_create_snapshot: SharedStoreMetric,
    #[cfg(target_arch = "x86_64")]
    /// Measures the snapshot load time, at the API (user) level, in microseconds.
    pub load_snapshot: SharedStoreMetric,
    /// Measures the microVM pausing duration, at the API (user) level, in microseconds.
    pub pause_vm: SharedStoreMetric,
    /// Measures the microVM resuming duration, at the API (user) level, in microseconds.
    pub resume_vm: SharedStoreMetric,
    #[cfg(target_arch = "x86_64")]
    /// Measures the snapshot full create time, at the VMM level, in microseconds.
    pub vmm_full_create_snapshot: SharedStoreMetric,
    #[cfg(target_arch = "x86_64")]
    /// Measures the snapshot diff create time, at the VMM level, in microseconds.
    pub vmm_diff_create_snapshot: SharedStoreMetric,
    #[cfg(target_arch = "x86_64")]
    /// Measures the snapshot load time, at the VMM level, in microseconds.
    pub vmm_load_snapshot: SharedStoreMetric,
    /// Measures the microVM pausing duration, at the VMM level, in microseconds.
    pub vmm_pause_vm: SharedStoreMetric,
    /// Measures the microVM resuming duration, at the VMM level, in microseconds.
    pub vmm_resume_vm: SharedStoreMetric,
}

/// Metrics specific to the RTC device.
#[derive(Default, Serialize)]
pub struct RTCDeviceMetrics {
    /// Errors triggered while using the RTC device.
    pub error_count: SharedIncMetric,
    /// Number of superfluous read intents on this RTC device.
    pub missed_read_count: SharedIncMetric,
    /// Number of superfluous write intents on this RTC device.
    pub missed_write_count: SharedIncMetric,
}

/// Metrics for the seccomp filtering.
#[derive(Default, Serialize)]
pub struct SeccompMetrics {
    /// Number of errors inside the seccomp filtering.
    pub num_faults: SharedIncMetric,
}

/// Metrics specific to the UART device.
#[derive(Default, Serialize)]
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

/// Metrics related to signals.
#[derive(Default, Serialize)]
pub struct SignalMetrics {
    /// Number of times that SIGBUS was handled.
    pub sigbus: SharedIncMetric,
    /// Number of times that SIGSEGV was handled.
    pub sigsegv: SharedIncMetric,
    /// Number of times that SIGXFSZ was handled.
    pub sigxfsz: SharedIncMetric,
    /// Number of times that SIGXCPU was handled.
    pub sigxcpu: SharedIncMetric,
    /// Number of times that SIGPIPE was handled.
    pub sigpipe: SharedIncMetric,
    /// Number of times that SIGHUP was handled.
    pub sighup: SharedIncMetric,
    /// Number of times that SIGILL was handled.
    pub sigill: SharedIncMetric,
}

/// Metrics specific to VCPUs' mode of functioning.
#[derive(Default, Serialize)]
pub struct VcpuMetrics {
    /// Number of KVM exits for handling input IO.
    pub exit_io_in: SharedIncMetric,
    /// Number of KVM exits for handling output IO.
    pub exit_io_out: SharedIncMetric,
    /// Number of KVM exits for handling MMIO reads.
    pub exit_mmio_read: SharedIncMetric,
    /// Number of KVM exits for handling MMIO writes.
    pub exit_mmio_write: SharedIncMetric,
    /// Number of errors during this VCPU's run.
    pub failures: SharedIncMetric,
    /// Failures in configuring the CPUID.
    pub filter_cpuid: SharedIncMetric,
}

/// Metrics specific to the machine manager as a whole.
#[derive(Default, Serialize)]
pub struct VmmMetrics {
    /// Number of device related events received for a VM.
    pub device_events: SharedIncMetric,
    /// Metric for signaling a panic has occurred.
    pub panic_count: SharedIncMetric,
}

/// Vsock-related metrics.
#[derive(Default, Serialize)]
pub struct VsockDeviceMetrics {
    /// Number of times when activate failed on a vsock device.
    pub activate_fails: SharedIncMetric,
    /// Number of times when interacting with the space config of a vsock device failed.
    pub cfg_fails: SharedIncMetric,
    /// Number of times when handling RX queue events on a vsock device failed.
    pub rx_queue_event_fails: SharedIncMetric,
    /// Number of times when handling TX queue events on a vsock device failed.
    pub tx_queue_event_fails: SharedIncMetric,
    /// Number of times when handling event queue events on a vsock device failed.
    pub ev_queue_event_fails: SharedIncMetric,
    /// Number of times when handling muxer events on a vsock device failed.
    pub muxer_event_fails: SharedIncMetric,
    /// Number of times when handling connection events on a vsock device failed.
    pub conn_event_fails: SharedIncMetric,
    /// Number of events associated with the receiving queue.
    pub rx_queue_event_count: SharedIncMetric,
    /// Number of events associated with the transmitting queue.
    pub tx_queue_event_count: SharedIncMetric,
    /// Number of bytes received.
    pub rx_bytes_count: SharedIncMetric,
    /// Number of transmitted bytes.
    pub tx_bytes_count: SharedIncMetric,
    /// Number of packets received.
    pub rx_packets_count: SharedIncMetric,
    /// Number of transmitted packets.
    pub tx_packets_count: SharedIncMetric,
    /// Number of added connections.
    pub conns_added: SharedIncMetric,
    /// Number of killed connections.
    pub conns_killed: SharedIncMetric,
    /// Number of removed connections.
    pub conns_removed: SharedIncMetric,
    /// How many times the killq has been resynced.
    pub killq_resync: SharedIncMetric,
    /// How many flush fails have been seen.
    pub tx_flush_fails: SharedIncMetric,
    /// How many write fails have been seen.
    pub tx_write_fails: SharedIncMetric,
    /// Number of times read() has failed.
    pub rx_read_fails: SharedIncMetric,
}

// The sole purpose of this struct is to produce an UTC timestamp when an instance is serialized.
#[derive(Default)]
struct SerializeToUtcTimestampMs;

impl Serialize for SerializeToUtcTimestampMs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(
            utils::time::get_time_ns(utils::time::ClockType::Monotonic) as i64 / 1_000_000,
        )
    }
}

/// Structure storing all metrics while enforcing serialization support on them.
#[derive(Default, Serialize)]
pub struct FirecrackerMetrics {
    utc_timestamp_ms: SerializeToUtcTimestampMs,
    /// API Server related metrics.
    pub api_server: ApiServerMetrics,
    /// A balloon device's related metrics.
    pub balloon: BalloonDeviceMetrics,
    /// A block device's related metrics.
    pub block: BlockDeviceMetrics,
    /// Metrics related to API GET requests.
    pub get_api_requests: GetRequestsMetrics,
    /// Metrics related to the i8042 device.
    pub i8042: I8042DeviceMetrics,
    /// Metrics related to performance measurements.
    pub latencies_us: PerformanceMetrics,
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
    /// Metrics related to signals.
    pub signals: SignalMetrics,
    /// Metrics related to virtio-vsockets.
    pub vsock: VsockDeviceMetrics,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::ErrorKind;
    use std::sync::Arc;
    use std::thread;

    use std::sync::atomic::fence;
    use utils::tempfile::TempFile;

    #[test]
    fn test_init() {
        let m = METRICS.deref();

        // Trying to write metrics, when metrics system is not initialized, should not throw error.
        let res = m.write();
        assert!(res.is_ok() && !res.unwrap());

        let f = TempFile::new().expect("Failed to create temporary metrics file");
        assert!(m.init(Box::new(f.into_file()),).is_ok());

        assert!(m.write().is_ok());

        let f = TempFile::new().expect("Failed to create temporary metrics file");

        assert!(m.init(Box::new(f.into_file()),).is_err());
    }

    #[test]
    fn test_shared_inc_metric() {
        let metric = Arc::new(SharedIncMetric::default());

        // We're going to create a number of threads that will attempt to increase this metric
        // in parallel. If everything goes fine we still can't be sure the synchronization works,
        // but if something fails, then we definitely have a problem :-s

        const NUM_THREADS_TO_SPAWN: usize = 4;
        const NUM_INCREMENTS_PER_THREAD: usize = 10_0000;
        const M2_INITIAL_COUNT: usize = 123;

        metric.add(M2_INITIAL_COUNT);

        let mut v = Vec::with_capacity(NUM_THREADS_TO_SPAWN);

        for _ in 0..NUM_THREADS_TO_SPAWN {
            let r = metric.clone();
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
            metric.count(),
            M2_INITIAL_COUNT + NUM_THREADS_TO_SPAWN * NUM_INCREMENTS_PER_THREAD
        );
    }

    #[test]
    fn test_shared_store_metric() {
        let m1 = Arc::new(SharedStoreMetric::default());
        m1.store(1);
        fence(Ordering::SeqCst);
        assert_eq!(1, m1.fetch());
    }

    #[test]
    fn test_serialize() {
        let s = serde_json::to_string(&FirecrackerMetrics::default());
        assert!(s.is_ok());
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(
            format!(
                "{}",
                MetricsError::NeverInitialized(String::from("Bad Metrics Path Provided"))
            ),
            "Bad Metrics Path Provided"
        );
        assert_eq!(
            format!("{}", MetricsError::AlreadyInitialized),
            "Reinitialization of metrics not allowed."
        );
        assert_eq!(
            format!(
                "{}",
                MetricsError::Write(std::io::Error::new(ErrorKind::Interrupted, "write"))
            ),
            "Failed to write metrics. Error: write"
        );
        assert_eq!(
            format!(
                "{}",
                MetricsError::Serde("Failed to serialize the given data structure.".to_string())
            ),
            "Failed to serialize the given data structure."
        );
    }
}
