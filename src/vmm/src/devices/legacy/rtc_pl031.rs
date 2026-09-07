// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use std::sync::{Arc, RwLock};

use serde::Serialize;
use vm_superio::Rtc;
use vm_superio::rtc_pl031::RtcEvents;

use crate::logger::{IncMetric, SharedIncMetric, warn};

/// Metrics specific to the RTC device.
#[derive(Debug, Serialize, Default)]
pub struct RTCDeviceMetrics {
    /// Errors triggered while using the RTC device.
    pub error_count: SharedIncMetric,
    /// Number of superfluous read intents on this RTC device.
    pub missed_read_count: SharedIncMetric,
    /// Number of superfluous write intents on this RTC device.
    pub missed_write_count: SharedIncMetric,
}

impl RtcEvents for RTCDeviceMetrics {
    fn invalid_read(&self) {
        self.missed_read_count.inc();
        self.error_count.inc();
        warn!("Guest read at invalid offset.")
    }

    fn invalid_write(&self) {
        self.missed_write_count.inc();
        self.error_count.inc();
        warn!("Guest write at invalid offset.")
    }
}

/// Stores the metrics of the (single) RTC device.
///
/// The device owns its `Arc<RTCDeviceMetrics>` (via the inner `Rtc`, which `vm-superio` implements
/// `RtcEvents` for `Arc<EV>`) and registers a clone here on construction, so that `flush_metrics`
/// can serialize them. Keeping the metrics off a process-wide global lets unit tests, which each
/// build their own device, run in parallel without clobbering each other's counters.
pub static METRICS: RwLock<Option<Arc<RTCDeviceMetrics>>> = RwLock::new(None);

/// Wrapper over vm_superio's RTC implementation.
#[derive(Debug)]
pub struct RTCDevice(vm_superio::Rtc<Arc<RTCDeviceMetrics>>);

impl Default for RTCDevice {
    fn default() -> Self {
        let metrics = Arc::new(RTCDeviceMetrics::default());
        // A microVM only ever has one RTC device, so replacing the slot is fine.
        let _ = METRICS.write().unwrap().replace(metrics.clone());
        RTCDevice(Rtc::with_events(metrics))
    }
}

impl RTCDevice {
    pub fn new() -> RTCDevice {
        Default::default()
    }
}

impl std::ops::Deref for RTCDevice {
    type Target = vm_superio::Rtc<Arc<RTCDeviceMetrics>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for RTCDevice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// Implements Bus functions for AMBA PL031 RTC device
impl RTCDevice {
    pub fn bus_read(&mut self, offset: u64, data: &mut [u8]) {
        if let (Ok(offset), 4) = (u16::try_from(offset), data.len()) {
            // read() function from RTC implementation expects a slice of
            // len 4, and we just validated that this is the data length
            self.read(offset, data.try_into().unwrap())
        } else {
            warn!(
                "Found invalid data offset/length while trying to read from the RTC: {}, {}",
                offset,
                data.len()
            );
            self.0.events().error_count.inc();
        }
    }

    pub fn bus_write(&mut self, offset: u64, data: &[u8]) {
        if let (Ok(offset), 4) = (u16::try_from(offset), data.len()) {
            // write() function from RTC implementation expects a slice of
            // len 4, and we just validated that this is the data length
            self.write(offset, data.try_into().unwrap())
        } else {
            warn!(
                "Found invalid data offset/length while trying to write to the RTC: {}, {}",
                offset,
                data.len()
            );
            self.0.events().error_count.inc();
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl crate::vstate::bus::BusDevice for RTCDevice {
    fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
        self.bus_read(offset, data)
    }

    fn write(
        &mut self,
        _base: u64,
        offset: u64,
        data: &[u8],
    ) -> Option<std::sync::Arc<std::sync::Barrier>> {
        self.bus_write(offset, data);
        None
    }
}

#[cfg(test)]
mod tests {
    use vm_superio::Rtc;

    use super::*;
    use crate::logger::IncMetric;

    /// Build an `RTCDevice` backed by a caller-owned metrics instance, bypassing the module-level
    /// `METRICS` registration so each test observes only its own counters.
    fn build_test_rtc(metrics: Arc<RTCDeviceMetrics>) -> RTCDevice {
        RTCDevice(Rtc::with_events(metrics))
    }

    #[test]
    fn test_rtc_device_invalid_write() {
        let metrics = Arc::new(RTCDeviceMetrics::default());
        let mut rtc_pl031 = build_test_rtc(metrics.clone());
        let data = [0; 4];

        // Write to the DR register. Since this is a RO register, the write
        // function should fail. The device is freshly built, so the counters start at 0.
        rtc_pl031.bus_write(0x000, &data);
        assert_eq!(metrics.missed_write_count.count(), 1);
        assert_eq!(metrics.error_count.count(), 1);
    }

    #[test]
    fn test_rtc_invalid_buf_len() {
        let metrics = Arc::new(RTCDeviceMetrics::default());
        let mut rtc_pl031 = build_test_rtc(metrics);
        let write_data_good = 123u32.to_le_bytes();
        let mut data_bad = [0; 2];
        let mut read_data_good = [0; 4];

        rtc_pl031.bus_write(0x008, &write_data_good);
        rtc_pl031.bus_write(0x008, &data_bad);
        rtc_pl031.bus_read(0x008, &mut read_data_good);
        rtc_pl031.bus_read(0x008, &mut data_bad);
        assert_eq!(u32::from_le_bytes(read_data_good), 123);
        assert_eq!(u16::from_le_bytes(data_bad), 0);
    }

    #[test]
    fn test_rtc_dev_metrics() {
        let metrics = RTCDeviceMetrics::default();
        metrics.error_count.inc();
        metrics.missed_read_count.add(2);

        let serialized = serde_json::to_string(&metrics).unwrap();
        let json: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.get("error_count").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(
            obj.get("missed_read_count").and_then(|v| v.as_u64()),
            Some(2)
        );
    }
}
