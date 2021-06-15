// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{convert::TryInto, sync::Arc};

use logger::{warn, IncMetric, RTCDeviceMetrics, METRICS};

use crate::BusDevice;

pub type RTCDevice = vm_superio::RTC<Arc<RTCDeviceMetrics>>;

// Implements Bus functions for AMBA PL031 RTC device
#[cfg(target_arch = "aarch64")]
impl BusDevice for RTCDevice {
    fn read(&mut self, offset: u64, data: &mut [u8]) {
        if data.len() == 4 {
            // read() function from RTC implementation expects a slice of
            // len 4, and we just validated that this is the data lengt
            self.read(offset as u16, data.try_into().unwrap())
        } else {
            warn!(
                "Found invalid data length while trying to read from the RTC: {}",
                data.len()
            );
            METRICS.rtc.as_ref().error_count.inc();
        }
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() == 4 {
            // write() function from RTC implementation expects a slice of
            // len 4, and we just validated that this is the data length
            self.write(offset as u16, data.try_into().unwrap())
        } else {
            warn!(
                "Found invalid data length while trying to write to the RTC: {}",
                data.len()
            );
            METRICS.rtc.as_ref().error_count.inc();
        }
    }
}

#[cfg(test)]
mod tests {
    use logger::IncMetric;
    use vm_superio::RTC;

    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_rtc_device() {
        let metrics = Arc::new(RTCDeviceMetrics::default());
        let mut rtc_pl031 = RTC::with_events(metrics.clone());
        let data = [0; 4];

        // Write to the DR register. Since this is a RO register, the write
        // function should fail.
        let invalid_writes_before = metrics.missed_write_count.count();
        let error_count_before = metrics.error_count.count();
        <dyn BusDevice>::write(&mut rtc_pl031, 0x000, &data);
        let invalid_writes_after = metrics.missed_write_count.count();
        let error_count_after = metrics.error_count.count();
        assert_eq!(invalid_writes_after - invalid_writes_before, 1);
        assert_eq!(error_count_after - error_count_before, 1);
    }

    #[test]
    fn test_rtc_invalid_buf_len() {
        let metrics = Arc::new(RTCDeviceMetrics::default());
        let mut rtc_pl031 = RTC::with_events(metrics);
        let write_data_good = 123u32.to_le_bytes();
        let mut data_bad = [0; 2];
        let mut read_data_good = [0; 4];

        <dyn BusDevice>::write(&mut rtc_pl031, 0x008, &write_data_good);
        <dyn BusDevice>::write(&mut rtc_pl031, 0x008, &data_bad);
        <dyn BusDevice>::read(&mut rtc_pl031, 0x008, &mut read_data_good);
        <dyn BusDevice>::read(&mut rtc_pl031, 0x008, &mut data_bad);
        assert_eq!(u32::from_le_bytes(read_data_good), 123);
        assert_eq!(u16::from_le_bytes(data_bad), 0);
    }
}
