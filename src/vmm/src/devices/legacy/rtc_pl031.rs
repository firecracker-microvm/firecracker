// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;

use serde::Serialize;
use vm_superio::rtc_pl031::RtcEvents;

use crate::logger::{warn, IncMetric, SharedIncMetric};

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

impl RTCDeviceMetrics {
    /// Const default construction.
    pub const fn new() -> Self {
        Self {
            error_count: SharedIncMetric::new(),
            missed_read_count: SharedIncMetric::new(),
            missed_write_count: SharedIncMetric::new(),
        }
    }
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

impl RtcEvents for &'static RTCDeviceMetrics {
    fn invalid_read(&self) {
        RTCDeviceMetrics::invalid_read(self);
    }

    fn invalid_write(&self) {
        RTCDeviceMetrics::invalid_write(self);
    }
}

/// Stores aggregated metrics
pub static METRICS: RTCDeviceMetrics = RTCDeviceMetrics::new();

/// Wrapper over vm_superio's RTC implementation.
#[derive(Debug)]
pub struct RTCDevice(pub vm_superio::Rtc<&'static RTCDeviceMetrics>);

impl std::ops::Deref for RTCDevice {
    type Target = vm_superio::Rtc<&'static RTCDeviceMetrics>;

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
            // len 4, and we just validated that this is the data lengt
            self.read(offset, data.try_into().unwrap())
        } else {
            warn!(
                "Found invalid data offset/length while trying to read from the RTC: {}, {}",
                offset,
                data.len()
            );
            METRICS.error_count.inc();
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
            METRICS.error_count.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use vm_superio::Rtc;

    use super::*;
    use crate::logger::IncMetric;

    #[test]
    fn test_rtc_device() {
        static TEST_RTC_DEVICE_METRICS: RTCDeviceMetrics = RTCDeviceMetrics::new();
        let mut rtc_pl031 = RTCDevice(Rtc::with_events(&TEST_RTC_DEVICE_METRICS));
        let data = [0; 4];

        // Write to the DR register. Since this is a RO register, the write
        // function should fail.
        let invalid_writes_before = TEST_RTC_DEVICE_METRICS.missed_write_count.count();
        let error_count_before = TEST_RTC_DEVICE_METRICS.error_count.count();
        rtc_pl031.bus_write(0x000, &data);
        let invalid_writes_after = TEST_RTC_DEVICE_METRICS.missed_write_count.count();
        let error_count_after = TEST_RTC_DEVICE_METRICS.error_count.count();
        assert_eq!(invalid_writes_after - invalid_writes_before, 1);
        assert_eq!(error_count_after - error_count_before, 1);
    }

    #[test]
    fn test_rtc_invalid_buf_len() {
        static TEST_RTC_INVALID_BUF_LEN_METRICS: RTCDeviceMetrics = RTCDeviceMetrics::new();
        let mut rtc_pl031 = RTCDevice(Rtc::with_events(&TEST_RTC_INVALID_BUF_LEN_METRICS));
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
}
