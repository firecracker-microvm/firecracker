// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Barrier};

use utils::time::TimestampUs;

use crate::logger::info;
use crate::vstate::bus::BusDevice;

const MAGIC_VALUE_SIGNAL_GUEST_BOOT_COMPLETE: u8 = 123;

/// Pseudo device to record the kernel boot time.
#[derive(Debug, Clone)]
pub struct BootTimer {
    start_ts: TimestampUs,
}

impl BusDevice for BootTimer {
    fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        // Only handle byte length instructions at a zero offset.
        if data.len() != 1 || offset != 0 {
            return None;
        }

        if data[0] == MAGIC_VALUE_SIGNAL_GUEST_BOOT_COMPLETE {
            let now_tm_us = TimestampUs::default();

            let boot_time_us = now_tm_us.time_us - self.start_ts.time_us;
            let boot_time_cpu_us = now_tm_us.cputime_us - self.start_ts.cputime_us;
            info!(
                "Guest-boot-time = {:>6} us {} ms, {:>6} CPU us {} CPU ms",
                boot_time_us,
                boot_time_us / 1000,
                boot_time_cpu_us,
                boot_time_cpu_us / 1000
            );
        }

        None
    }

    fn read(&mut self, _base: u64, _offset: u64, _data: &mut [u8]) {}
}

impl BootTimer {
    /// Create a device at a certain point in time.
    pub fn new(start_ts: TimestampUs) -> BootTimer {
        BootTimer { start_ts }
    }
}
