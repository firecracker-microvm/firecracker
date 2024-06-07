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
//! ```json
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
//! * Use lockless operations, preferably ones that don't require anything other than simple
//!   reads/writes being atomic.
//! * Exploit interior mutability and atomics being Sync to allow all methods (including the ones
//!   which are effectively mutable) to be callable on a global non-mut static.
//! * Rely on `serde` to provide the actual serialization for writing the metrics.
//! * Since all metrics start at 0, we implement the `Default` trait via derive for all of them, to
//!   avoid having to initialize everything by hand.
//!
//! The system implements 2 types of metrics:
//! * Shared Incremental Metrics (SharedIncMetrics) - dedicated for the metrics which need a counter
//! (i.e the number of times an API request failed). These metrics are reset upon flush.
//! * Shared Store Metrics (SharedStoreMetrics) - are targeted at keeping a persistent value, it is
//!   not
//! intended to act as a counter (i.e for measure the process start up time for example).
//!
//! The current approach for the `SharedIncMetrics` type is to store two values (current and
//! previous) and compute the delta between them each time we do a flush (i.e by serialization).
//! There are a number of advantages to this approach, including:
//! * We don't have to introduce an additional write (to reset the value) from the thread which does
//!   to actual writing, so less synchronization effort is required.
//! * We don't have to worry at all that much about losing some data if writing fails for a while
//!   (this could be a concern, I guess).
//! If if turns out this approach is not really what we want, it's pretty easy to resort to
//! something else, while working behind the same interface.

use std::fmt::Debug;
use std::io::Write;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use serde::{Serialize, Serializer};

use super::FcLineWriter;
use crate::devices::legacy;
use crate::devices::virtio::balloon::metrics as balloon_metrics;
use crate::devices::virtio::block::virtio::metrics as block_metrics;
use crate::devices::virtio::net::metrics as net_metrics;
use crate::devices::virtio::rng::metrics as entropy_metrics;
use crate::devices::virtio::vhost_user_metrics;
use crate::devices::virtio::vsock::metrics as vsock_metrics;

/// Static instance used for handling metrics.
pub static METRICS: Metrics<FirecrackerMetrics, FcLineWriter> =
    Metrics::<FirecrackerMetrics, FcLineWriter>::new(FirecrackerMetrics::new());

/// Metrics system.
// All member fields have types which are Sync, and exhibit interior mutability, so
// we can call operations on metrics using a non-mut static global variable.
#[derive(Debug)]
pub struct Metrics<T: Serialize, M: Write + Send> {
    // Metrics will get flushed here.
    metrics_buf: OnceLock<Mutex<M>>,
    pub app_metrics: T,
}

impl<T: Serialize + Debug, M: Write + Send + Debug> Metrics<T, M> {
    /// Creates a new instance of the current metrics.
    pub const fn new(app_metrics: T) -> Metrics<T, M> {
        Metrics {
            metrics_buf: OnceLock::new(),
            app_metrics,
        }
    }

    /// Initialize metrics system (once and only once).
    /// Every call made after the first will have no effect besides returning `Ok` or `Err`.
    ///
    /// This function is supposed to be called only from a single thread, once.
    /// It is not thread-safe and is not meant to be used in a multithreaded
    /// scenario. The reason `is_initialized` is an `AtomicBool` instead of
    /// just a `bool` is that `lazy_static` enforces thread-safety on all its
    /// members.
    ///
    /// # Arguments
    ///
    /// * `metrics_dest` - Buffer for JSON formatted metrics. Needs to implement `Write` and `Send`.
    pub fn init(&self, metrics_dest: M) -> Result<(), MetricsError> {
        self.metrics_buf
            .set(Mutex::new(metrics_dest))
            .map_err(|_| MetricsError::AlreadyInitialized)
    }

    /// Writes metrics to the destination provided as argument upon initialization of the metrics.
    /// Upon failure, an error is returned if metrics system is initialized and metrics could not be
    /// written.
    /// Upon success, the function will return `True` (if metrics system was initialized and metrics
    /// were successfully written to disk) or `False` (if metrics system was not yet initialized).
    ///
    /// This function is usually supposed to be called only from a single thread and
    /// is not meant to be used in a multithreaded scenario. The reason
    /// `metrics_buf` is enclosed in a `Mutex` is that `lazy_static` enforces
    /// thread-safety on all its members.
    /// The only exception is for signal handlers that result in process exit, which may be run on
    /// any thread. To prevent the race condition present in the serialisation step of
    /// SharedIncMetrics, deadly signals use SharedStoreMetrics instead (which have a thread-safe
    /// serialise implementation).
    /// The only known caveat is that other metrics may not be properly written before exiting from
    /// a signal handler. We make this compromise since the process will be killed anyway and the
    /// important metric in this case is the signal one.
    /// The alternative is to hold a Mutex over the entire function call, but this increases the
    /// known deadlock potential.
    pub fn write(&self) -> Result<bool, MetricsError> {
        if let Some(lock) = self.metrics_buf.get() {
            match serde_json::to_string(&self.app_metrics) {
                Ok(msg) => {
                    if let Ok(mut guard) = lock.lock() {
                        // No need to explicitly call flush because the underlying LineWriter
                        // flushes automatically whenever a newline is
                        // detected (and we always end with a newline the
                        // current write).
                        guard
                            .write_all(format!("{msg}\n",).as_bytes())
                            .map_err(MetricsError::Write)
                            .map(|_| true)
                    } else {
                        // We have not incremented `missed_metrics_count` as there is no way to push
                        // metrics if destination lock got poisoned.
                        panic!(
                            "Failed to write to the provided metrics destination due to poisoned \
                             lock"
                        );
                    }
                }
                Err(err) => Err(MetricsError::Serde(err.to_string())),
            }
        } else {
            // If the metrics are not initialized, no error is thrown but we do let the user know
            // that metrics were not written.
            Ok(false)
        }
    }
}

impl<T: Serialize + Debug, M: Write + Send + Debug> Deref for Metrics<T, M> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.app_metrics
    }
}

/// Describes the errors which may occur while handling metrics scenarios.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MetricsError {
    /// {0}
    NeverInitialized(String),
    /// Reinitialization of metrics not allowed.
    AlreadyInitialized,
    /// {0}
    Serde(String),
    /// Failed to write metrics: {0}
    Write(std::io::Error),
}

/// Used for defining new types of metrics that act as a counter (i.e they are continuously updated
/// by incrementing their value).
pub trait IncMetric {
    /// Adds `value` to the current counter.
    fn add(&self, value: u64);
    /// Increments by 1 unit the current counter.
    fn inc(&self) {
        self.add(1);
    }
    /// Returns current value of the counter.
    fn count(&self) -> u64;

    /// Returns diff of current and old value of the counter.
    /// Mostly used in process of aggregating per device metrics.
    fn fetch_diff(&self) -> u64;
}

/// Used for defining new types of metrics that do not need a counter and act as a persistent
/// indicator.
pub trait StoreMetric {
    /// Returns current value of the counter.
    fn fetch(&self) -> u64;
    /// Stores `value` to the current counter.
    fn store(&self, value: u64);
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
#[derive(Debug, Default)]
pub struct SharedIncMetric(AtomicU64, AtomicU64);
impl SharedIncMetric {
    /// Const default construction.
    pub const fn new() -> Self {
        Self(AtomicU64::new(0), AtomicU64::new(0))
    }
}

/// Representation of a metric that is expected to hold a value that can be accessed
/// from more than one thread, so more synchronization is necessary.
#[derive(Debug, Default)]
pub struct SharedStoreMetric(AtomicU64);
impl SharedStoreMetric {
    /// Const default construction.
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
}

impl IncMetric for SharedIncMetric {
    // While the order specified for this operation is still Relaxed, the actual instruction will
    // be an asm "LOCK; something" and thus atomic across multiple threads, simply because of the
    // fetch_and_add (as opposed to "store(load() + 1)") implementation for atomics.
    // TODO: would a stronger ordering make a difference here?
    fn add(&self, value: u64) {
        self.0.fetch_add(value, Ordering::Relaxed);
    }

    fn count(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    fn fetch_diff(&self) -> u64 {
        self.0.load(Ordering::Relaxed) - self.1.load(Ordering::Relaxed)
    }
}

impl StoreMetric for SharedStoreMetric {
    fn fetch(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    fn store(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }
}

impl Serialize for SharedIncMetric {
    /// Reset counters of each metrics. Here we suppose that Serialize's goal is to help with the
    /// flushing of metrics.
    /// !!! Any print of the metrics will also reset them. Use with caution !!!
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let snapshot = self.0.load(Ordering::Relaxed);
        let res = serializer.serialize_u64(snapshot - self.1.load(Ordering::Relaxed));

        if res.is_ok() {
            self.1.store(snapshot, Ordering::Relaxed);
        }
        res
    }
}

impl Serialize for SharedStoreMetric {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0.load(Ordering::Relaxed))
    }
}

/// Reporter object which computes the process wall time and
/// process CPU time and populates the metric with the results.
#[derive(Debug)]
pub struct ProcessTimeReporter {
    // Process start time in us.
    start_time_us: Option<u64>,
    // Process CPU start time in us.
    start_time_cpu_us: Option<u64>,
    // Firecracker's parent process CPU time.
    parent_cpu_time_us: Option<u64>,
}

impl ProcessTimeReporter {
    /// Constructor for the process time-related reporter.
    pub fn new(
        start_time_us: Option<u64>,
        start_time_cpu_us: Option<u64>,
        parent_cpu_time_us: Option<u64>,
    ) -> ProcessTimeReporter {
        ProcessTimeReporter {
            start_time_us,
            start_time_cpu_us,
            parent_cpu_time_us,
        }
    }

    /// Obtain process start time in microseconds.
    pub fn report_start_time(&self) {
        if let Some(start_time) = self.start_time_us {
            let delta_us = utils::time::get_time_us(utils::time::ClockType::Monotonic) - start_time;
            METRICS.api_server.process_startup_time_us.store(delta_us);
        }
    }

    /// Obtain process CPU start time in microseconds.
    pub fn report_cpu_start_time(&self) {
        if let Some(cpu_start_time) = self.start_time_cpu_us {
            let delta_us = utils::time::get_time_us(utils::time::ClockType::ProcessCpu)
                - cpu_start_time
                + self.parent_cpu_time_us.unwrap_or_default();
            METRICS
                .api_server
                .process_startup_time_cpu_us
                .store(delta_us);
        }
    }
}

// The following structs are used to define a certain organization for the set of metrics we
// are interested in. Whenever the name of a field differs from its ideal textual representation
// in the serialized form, we can use the #[serde(rename = "name")] attribute to, well, rename it.

/// Metrics related to the internal API server.
#[derive(Debug, Default, Serialize)]
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
impl ApiServerMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            process_startup_time_us: SharedStoreMetric::new(),
            process_startup_time_cpu_us: SharedStoreMetric::new(),
            sync_response_fails: SharedIncMetric::new(),
            sync_vmm_send_timeout_count: SharedIncMetric::new(),
        }
    }
}

/// Metrics specific to GET API Requests for counting user triggered actions and/or failures.
#[derive(Debug, Default, Serialize)]
pub struct GetRequestsMetrics {
    /// Number of GETs for getting information on the instance.
    pub instance_info_count: SharedIncMetric,
    /// Number of GETs for getting status on attaching machine configuration.
    pub machine_cfg_count: SharedIncMetric,
    /// Number of GETs for getting mmds.
    pub mmds_count: SharedIncMetric,
    /// Number of GETs for getting the VMM version.
    pub vmm_version_count: SharedIncMetric,
}
impl GetRequestsMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            instance_info_count: SharedIncMetric::new(),
            machine_cfg_count: SharedIncMetric::new(),
            mmds_count: SharedIncMetric::new(),
            vmm_version_count: SharedIncMetric::new(),
        }
    }
}

/// Metrics specific to PUT API Requests for counting user triggered actions and/or failures.
#[derive(Debug, Default, Serialize)]
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
    /// Number of PUTs for hotplugging
    pub hotplug: SharedIncMetric,
    /// Number of failures for hotplugging.
    pub hotplug_fails: SharedIncMetric,
    /// Number of PUTs for initializing the logging system.
    pub logger_count: SharedIncMetric,
    /// Number of failures in initializing the logging system.
    pub logger_fails: SharedIncMetric,
    /// Number of PUTs for configuring the machine.
    pub machine_cfg_count: SharedIncMetric,
    /// Number of failures in configuring the machine.
    pub machine_cfg_fails: SharedIncMetric,
    /// Number of PUTs for configuring a guest's vCPUs.
    pub cpu_cfg_count: SharedIncMetric,
    /// Number of failures in configuring a guest's vCPUs.
    pub cpu_cfg_fails: SharedIncMetric,
    /// Number of PUTs for initializing the metrics system.
    pub metrics_count: SharedIncMetric,
    /// Number of failures in initializing the metrics system.
    pub metrics_fails: SharedIncMetric,
    /// Number of PUTs for creating a new network interface.
    pub network_count: SharedIncMetric,
    /// Number of failures in creating a new network interface.
    pub network_fails: SharedIncMetric,
    /// Number of PUTs for creating mmds.
    pub mmds_count: SharedIncMetric,
    /// Number of failures in creating a new mmds.
    pub mmds_fails: SharedIncMetric,
    /// Number of PUTs for creating a vsock device.
    pub vsock_count: SharedIncMetric,
    /// Number of failures in creating a vsock device.
    pub vsock_fails: SharedIncMetric,
}
impl PutRequestsMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            actions_count: SharedIncMetric::new(),
            actions_fails: SharedIncMetric::new(),
            boot_source_count: SharedIncMetric::new(),
            boot_source_fails: SharedIncMetric::new(),
            drive_count: SharedIncMetric::new(),
            drive_fails: SharedIncMetric::new(),
            hotplug: SharedIncMetric::new(),
            hotplug_fails: SharedIncMetric::new(),
            logger_count: SharedIncMetric::new(),
            logger_fails: SharedIncMetric::new(),
            machine_cfg_count: SharedIncMetric::new(),
            machine_cfg_fails: SharedIncMetric::new(),
            cpu_cfg_count: SharedIncMetric::new(),
            cpu_cfg_fails: SharedIncMetric::new(),
            metrics_count: SharedIncMetric::new(),
            metrics_fails: SharedIncMetric::new(),
            network_count: SharedIncMetric::new(),
            network_fails: SharedIncMetric::new(),
            mmds_count: SharedIncMetric::new(),
            mmds_fails: SharedIncMetric::new(),
            vsock_count: SharedIncMetric::new(),
            vsock_fails: SharedIncMetric::new(),
        }
    }
}

/// Metrics specific to PATCH API Requests for counting user triggered actions and/or failures.
#[derive(Debug, Default, Serialize)]
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
    /// Number of tries to PATCH an mmds.
    pub mmds_count: SharedIncMetric,
    /// Number of failures in PATCHing an mmds.
    pub mmds_fails: SharedIncMetric,
}
impl PatchRequestsMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            drive_count: SharedIncMetric::new(),
            drive_fails: SharedIncMetric::new(),
            network_count: SharedIncMetric::new(),
            network_fails: SharedIncMetric::new(),
            machine_cfg_count: SharedIncMetric::new(),
            machine_cfg_fails: SharedIncMetric::new(),
            mmds_count: SharedIncMetric::new(),
            mmds_fails: SharedIncMetric::new(),
        }
    }
}

/// Metrics related to deprecated user-facing API calls.
#[derive(Debug, Default, Serialize)]
pub struct DeprecatedApiMetrics {
    /// Total number of calls to deprecated HTTP endpoints.
    pub deprecated_http_api_calls: SharedIncMetric,
    /// Total number of calls to deprecated CMD line parameters.
    pub deprecated_cmd_line_api_calls: SharedIncMetric,
}
impl DeprecatedApiMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            deprecated_http_api_calls: SharedIncMetric::new(),
            deprecated_cmd_line_api_calls: SharedIncMetric::new(),
        }
    }
}

/// Metrics for the logging subsystem.
#[derive(Debug, Default, Serialize)]
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
impl LoggerSystemMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            missed_metrics_count: SharedIncMetric::new(),
            metrics_fails: SharedIncMetric::new(),
            missed_log_count: SharedIncMetric::new(),
            log_fails: SharedIncMetric::new(),
        }
    }
}

/// Metrics for the MMDS functionality.
#[derive(Debug, Default, Serialize)]
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
impl MmdsMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            rx_accepted: SharedIncMetric::new(),
            rx_accepted_err: SharedIncMetric::new(),
            rx_accepted_unusual: SharedIncMetric::new(),
            rx_bad_eth: SharedIncMetric::new(),
            rx_count: SharedIncMetric::new(),
            tx_bytes: SharedIncMetric::new(),
            tx_count: SharedIncMetric::new(),
            tx_errors: SharedIncMetric::new(),
            tx_frames: SharedIncMetric::new(),
            connections_created: SharedIncMetric::new(),
            connections_destroyed: SharedIncMetric::new(),
        }
    }
}

/// Performance metrics related for the moment only to snapshots.
// These store the duration of creating/loading a snapshot and of
// pausing/resuming the microVM.
// If there are more than one `/snapshot/create` request in a minute
// (until the metrics are flushed), only the duration of the last
// snapshot creation is stored in the metric. If the user is interested
// in all the durations, a `FlushMetrics` request should be sent after
// each `create` request.
#[derive(Debug, Default, Serialize)]
pub struct PerformanceMetrics {
    /// Measures the snapshot full create time, at the API (user) level, in microseconds.
    pub full_create_snapshot: SharedStoreMetric,
    /// Measures the snapshot diff create time, at the API (user) level, in microseconds.
    pub diff_create_snapshot: SharedStoreMetric,
    /// Measures the snapshot load time, at the API (user) level, in microseconds.
    pub load_snapshot: SharedStoreMetric,
    /// Measures the microVM pausing duration, at the API (user) level, in microseconds.
    pub pause_vm: SharedStoreMetric,
    /// Measures the microVM resuming duration, at the API (user) level, in microseconds.
    pub resume_vm: SharedStoreMetric,
    /// Measures the snapshot full create time, at the VMM level, in microseconds.
    pub vmm_full_create_snapshot: SharedStoreMetric,
    /// Measures the snapshot diff create time, at the VMM level, in microseconds.
    pub vmm_diff_create_snapshot: SharedStoreMetric,
    /// Measures the snapshot load time, at the VMM level, in microseconds.
    pub vmm_load_snapshot: SharedStoreMetric,
    /// Measures the microVM pausing duration, at the VMM level, in microseconds.
    pub vmm_pause_vm: SharedStoreMetric,
    /// Measures the microVM resuming duration, at the VMM level, in microseconds.
    pub vmm_resume_vm: SharedStoreMetric,
}
impl PerformanceMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            full_create_snapshot: SharedStoreMetric::new(),
            diff_create_snapshot: SharedStoreMetric::new(),
            load_snapshot: SharedStoreMetric::new(),
            pause_vm: SharedStoreMetric::new(),
            resume_vm: SharedStoreMetric::new(),
            vmm_full_create_snapshot: SharedStoreMetric::new(),
            vmm_diff_create_snapshot: SharedStoreMetric::new(),
            vmm_load_snapshot: SharedStoreMetric::new(),
            vmm_pause_vm: SharedStoreMetric::new(),
            vmm_resume_vm: SharedStoreMetric::new(),
        }
    }
}

/// Metrics for the seccomp filtering.
#[derive(Debug, Default, Serialize)]
pub struct SeccompMetrics {
    /// Number of errors inside the seccomp filtering.
    pub num_faults: SharedStoreMetric,
}
impl SeccompMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            num_faults: SharedStoreMetric::new(),
        }
    }
}

/// Metrics related to signals.
/// Deadly signals must be of `SharedStoreMetric` type, since they can ever be either 0 or 1.
/// This avoids a tricky race condition caused by the unatomic serialize method of
/// `SharedIncMetric`, between two threads calling `METRICS.write()`.
#[derive(Debug, Default, Serialize)]
pub struct SignalMetrics {
    /// Number of times that SIGBUS was handled.
    pub sigbus: SharedStoreMetric,
    /// Number of times that SIGSEGV was handled.
    pub sigsegv: SharedStoreMetric,
    /// Number of times that SIGXFSZ was handled.
    pub sigxfsz: SharedStoreMetric,
    /// Number of times that SIGXCPU was handled.
    pub sigxcpu: SharedStoreMetric,
    /// Number of times that SIGPIPE was handled.
    pub sigpipe: SharedIncMetric,
    /// Number of times that SIGHUP was handled.
    pub sighup: SharedStoreMetric,
    /// Number of times that SIGILL was handled.
    pub sigill: SharedStoreMetric,
}
impl SignalMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            sigbus: SharedStoreMetric::new(),
            sigsegv: SharedStoreMetric::new(),
            sigxfsz: SharedStoreMetric::new(),
            sigxcpu: SharedStoreMetric::new(),
            sigpipe: SharedIncMetric::new(),
            sighup: SharedStoreMetric::new(),
            sigill: SharedStoreMetric::new(),
        }
    }
}

/// Provides efficient way to record LatencyAggregateMetrics
#[derive(Debug)]
pub struct LatencyMetricsRecorder<'a> {
    start_time: u64,
    metric: &'a LatencyAggregateMetrics,
}

impl<'a> LatencyMetricsRecorder<'a> {
    /// Const default construction.
    fn new(metric: &'a LatencyAggregateMetrics) -> Self {
        Self {
            start_time: utils::time::get_time_us(utils::time::ClockType::Monotonic),
            metric,
        }
    }
}
impl<'a> Drop for LatencyMetricsRecorder<'a> {
    /// records aggregate (min/max/sum) for the given metric
    /// This captures delta between self.start_time and current time
    /// and updates min/max/sum metrics.
    ///  self.start_time is recorded in new() and metrics are updated in drop
    fn drop(&mut self) {
        let delta_us =
            utils::time::get_time_us(utils::time::ClockType::Monotonic) - self.start_time;
        self.metric.sum_us.add(delta_us);
        let min_us = self.metric.min_us.fetch();
        let max_us = self.metric.max_us.fetch();
        if (0 == min_us) || (min_us > delta_us) {
            self.metric.min_us.store(delta_us);
        }
        if (0 == max_us) || (max_us < delta_us) {
            self.metric.max_us.store(delta_us);
        }
    }
}

/// Used to record Aggregate (min/max/sum) of latency metrics
#[derive(Debug, Default, Serialize)]
pub struct LatencyAggregateMetrics {
    /// represents minimum value of the metrics in microseconds
    pub min_us: SharedStoreMetric,
    /// represents maximum value of the metrics in microseconds
    pub max_us: SharedStoreMetric,
    /// represents sum of the metrics in microseconds
    pub sum_us: SharedIncMetric,
}
impl LatencyAggregateMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            min_us: SharedStoreMetric::new(),
            max_us: SharedStoreMetric::new(),
            sum_us: SharedIncMetric::new(),
        }
    }

    /// returns a latency recorder which captures stores start_time
    /// and updates the actual metrics at the end of recorders lifetime.
    /// in short instead of below 2 lines :
    /// 1st for start_time_us = get_time_us()
    /// 2nd for delta_time_us = get_time_us() - start_time; and metrics.store(delta_time_us)
    /// we have just `_m = metrics.record_latency_metrics()`
    pub fn record_latency_metrics(&self) -> LatencyMetricsRecorder {
        LatencyMetricsRecorder::new(self)
    }
}

/// Structure provides Metrics specific to VCPUs' mode of functioning.
/// Sample_count or number of kvm exits for IO and MMIO VM exits are covered by:
/// `exit_io_in`, `exit_io_out`, `exit_mmio_read` and , `exit_mmio_write`.
/// Count of other vm exits for events like shutdown/hlt/errors are
/// covered by existing "failures" metric.
/// The only vm exit for which sample_count is not covered is system
/// event reset/shutdown but that should be fine since they are not
/// failures and the vm is terminated anyways.
/// LatencyAggregateMetrics only covers minimum, maximum and sum
/// because average can be deduced from available metrics. e.g.
/// dividing `exit_io_in_agg.sum_us` by exit_io_in` gives average of KVM exits handling input IO.
#[derive(Debug, Default, Serialize)]
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
    /// Provides Min/max/sum for KVM exits handling input IO.
    pub exit_io_in_agg: LatencyAggregateMetrics,
    /// Provides Min/max/sum for KVM exits handling output IO.
    pub exit_io_out_agg: LatencyAggregateMetrics,
    /// Provides Min/max/sum for KVM exits handling MMIO reads.
    pub exit_mmio_read_agg: LatencyAggregateMetrics,
    /// Provides Min/max/sum for KVM exits handling MMIO writes.
    pub exit_mmio_write_agg: LatencyAggregateMetrics,
}
impl VcpuMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            exit_io_in: SharedIncMetric::new(),
            exit_io_out: SharedIncMetric::new(),
            exit_mmio_read: SharedIncMetric::new(),
            exit_mmio_write: SharedIncMetric::new(),
            failures: SharedIncMetric::new(),
            exit_io_in_agg: LatencyAggregateMetrics::new(),
            exit_io_out_agg: LatencyAggregateMetrics::new(),
            exit_mmio_read_agg: LatencyAggregateMetrics::new(),
            exit_mmio_write_agg: LatencyAggregateMetrics::new(),
        }
    }
}

/// Metrics specific to the machine manager as a whole.
#[derive(Debug, Default, Serialize)]
pub struct VmmMetrics {
    /// Number of device related events received for a VM.
    pub device_events: SharedIncMetric,
    /// Metric for signaling a panic has occurred.
    pub panic_count: SharedStoreMetric,
}
impl VmmMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            device_events: SharedIncMetric::new(),
            panic_count: SharedStoreMetric::new(),
        }
    }
}

/// Metrics specific to hotplugging
#[derive(Debug, Default, Serialize)]
pub struct HotplugMetrics {
    pub hotplug_request_count: SharedIncMetric,
    pub hotplug_request_fails: SharedIncMetric,
    pub vcpu_hotplug_request_fails: SharedIncMetric,
    pub vcpus_added: SharedIncMetric,
}

impl HotplugMetrics {
    /// Const default construction.

    pub const fn new() -> Self {
        Self {
            hotplug_request_count: SharedIncMetric::new(),
            hotplug_request_fails: SharedIncMetric::new(),
            vcpu_hotplug_request_fails: SharedIncMetric::new(),
            vcpus_added: SharedIncMetric::new(),
        }
    }
}

// The sole purpose of this struct is to produce an UTC timestamp when an instance is serialized.
#[derive(Debug, Default)]
struct SerializeToUtcTimestampMs;
impl SerializeToUtcTimestampMs {
    /// Const default construction.
    pub const fn new() -> Self {
        SerializeToUtcTimestampMs
    }
}

impl Serialize for SerializeToUtcTimestampMs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(
            i64::try_from(utils::time::get_time_ns(utils::time::ClockType::Real) / 1_000_000)
                .unwrap(),
        )
    }
}

macro_rules! create_serialize_proxy {
    // By using the below structure in FirecrackerMetrics it is easy
    // to serialise Firecracker app_metrics as a single json object which
    // otherwise would have required extra string manipulation to pack
    // $metric_mod as part of the same json object as FirecrackerMetrics.
    ($proxy_struct:ident, $metric_mod:ident) => {
        #[derive(Default, Debug)]
        pub struct $proxy_struct;

        impl Serialize for $proxy_struct {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                $metric_mod::flush_metrics(serializer)
            }
        }
    };
}

create_serialize_proxy!(BlockMetricsSerializeProxy, block_metrics);
create_serialize_proxy!(NetMetricsSerializeProxy, net_metrics);
create_serialize_proxy!(VhostUserMetricsSerializeProxy, vhost_user_metrics);
create_serialize_proxy!(BalloonMetricsSerializeProxy, balloon_metrics);
create_serialize_proxy!(EntropyMetricsSerializeProxy, entropy_metrics);
create_serialize_proxy!(VsockMetricsSerializeProxy, vsock_metrics);
create_serialize_proxy!(LegacyDevMetricsSerializeProxy, legacy);

/// Structure storing all metrics while enforcing serialization support on them.
#[derive(Debug, Default, Serialize)]
pub struct FirecrackerMetrics {
    utc_timestamp_ms: SerializeToUtcTimestampMs,
    /// API Server related metrics.
    pub api_server: ApiServerMetrics,
    #[serde(flatten)]
    /// A balloon device's related metrics.
    pub balloon_ser: BalloonMetricsSerializeProxy,
    #[serde(flatten)]
    /// A block device's related metrics.
    pub block_ser: BlockMetricsSerializeProxy,
    /// Metrics related to deprecated API calls.
    pub deprecated_api: DeprecatedApiMetrics,
    /// Metrics related to API GET requests.
    pub get_api_requests: GetRequestsMetrics,
    /// Metrics related to hot-plugging.
    pub hotplug: HotplugMetrics,
    #[serde(flatten)]
    /// Metrics related to the legacy device.
    pub legacy_dev_ser: LegacyDevMetricsSerializeProxy,
    /// Metrics related to performance measurements.
    pub latencies_us: PerformanceMetrics,
    /// Logging related metrics.
    pub logger: LoggerSystemMetrics,
    /// Metrics specific to MMDS functionality.
    pub mmds: MmdsMetrics,
    #[serde(flatten)]
    /// A network device's related metrics.
    pub net_ser: NetMetricsSerializeProxy,
    /// Metrics related to API PATCH requests.
    pub patch_api_requests: PatchRequestsMetrics,
    /// Metrics related to API PUT requests.
    pub put_api_requests: PutRequestsMetrics,
    /// Metrics related to seccomp filtering.
    pub seccomp: SeccompMetrics,
    /// Metrics related to a vcpu's functioning.
    pub vcpu: VcpuMetrics,
    /// Metrics related to the virtual machine manager.
    pub vmm: VmmMetrics,
    /// Metrics related to signals.
    pub signals: SignalMetrics,
    #[serde(flatten)]
    /// Metrics related to virtio-vsockets.
    pub vsock_ser: VsockMetricsSerializeProxy,
    #[serde(flatten)]
    /// Metrics related to virtio-rng entropy device.
    pub entropy_ser: EntropyMetricsSerializeProxy,
    #[serde(flatten)]
    /// Vhost-user device related metrics.
    pub vhost_user_ser: VhostUserMetricsSerializeProxy,
}
impl FirecrackerMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            utc_timestamp_ms: SerializeToUtcTimestampMs::new(),
            api_server: ApiServerMetrics::new(),
            balloon_ser: BalloonMetricsSerializeProxy {},
            block_ser: BlockMetricsSerializeProxy {},
            deprecated_api: DeprecatedApiMetrics::new(),
            get_api_requests: GetRequestsMetrics::new(),
            hotplug: HotplugMetrics::new(),
            legacy_dev_ser: LegacyDevMetricsSerializeProxy {},
            latencies_us: PerformanceMetrics::new(),
            logger: LoggerSystemMetrics::new(),
            mmds: MmdsMetrics::new(),
            net_ser: NetMetricsSerializeProxy {},
            patch_api_requests: PatchRequestsMetrics::new(),
            put_api_requests: PutRequestsMetrics::new(),
            seccomp: SeccompMetrics::new(),
            vcpu: VcpuMetrics::new(),
            vmm: VmmMetrics::new(),
            signals: SignalMetrics::new(),
            vsock_ser: VsockMetricsSerializeProxy {},
            entropy_ser: EntropyMetricsSerializeProxy {},
            vhost_user_ser: VhostUserMetricsSerializeProxy {},
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind, LineWriter};
    use std::sync::atomic::fence;
    use std::sync::Arc;
    use std::thread;

    use utils::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_init() {
        // This test has a conflict with the vmm_config test
        // `test_init_metrics` which also uses "METRICS" and
        // tests fail with an already initialized error.
        // This test is to validate the init() which doesn't require
        // using METRICS specifically. So, to avoid the conflict we
        // use a local Metrics to test init() instead of the global
        // "METRICS"
        let m = &Metrics::<_, FcLineWriter>::new(FirecrackerMetrics::new());

        // Trying to write metrics, when metrics system is not initialized, should not throw error.
        let res = m.write();
        assert!(res.is_ok() && !res.unwrap());

        let f = TempFile::new().expect("Failed to create temporary metrics file");
        m.init(LineWriter::new(f.into_file())).unwrap();

        m.write().unwrap();

        let f = TempFile::new().expect("Failed to create temporary metrics file");

        m.init(LineWriter::new(f.into_file())).unwrap_err();
    }

    #[test]
    fn test_shared_inc_metric() {
        let metric = Arc::new(SharedIncMetric::default());

        // We're going to create a number of threads that will attempt to increase this metric
        // in parallel. If everything goes fine we still can't be sure the synchronization works,
        // but if something fails, then we definitely have a problem :-s

        const NUM_THREADS_TO_SPAWN: usize = 4;
        const NUM_INCREMENTS_PER_THREAD: u64 = 10_0000;
        const M2_INITIAL_COUNT: u64 = 123;

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
            M2_INITIAL_COUNT + NUM_THREADS_TO_SPAWN as u64 * NUM_INCREMENTS_PER_THREAD
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
        s.unwrap();
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
            "Failed to write metrics: write"
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
