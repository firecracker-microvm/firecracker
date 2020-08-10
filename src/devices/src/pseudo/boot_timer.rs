// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::bus::BusDevice;
use logger::info;
use utils::time::TimestampUs;

const MAGIC_VALUE_SIGNAL_GUEST_BOOT_COMPLETE: u8 = 123;

/// Pseudo device to record the kernel boot time.
pub struct BootTimer {
    start_ts: TimestampUs,
}

impl BusDevice for BootTimer {
    fn write(&mut self, offset: u64, data: &[u8]) {
        // Only handle byte length instructions at a zero offset.
        if data.len() != 1 || offset != 0 {
            return;
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
    }
}

impl BootTimer {
    pub fn new(start_ts: TimestampUs) -> BootTimer {
        BootTimer { start_ts }
    }
}
