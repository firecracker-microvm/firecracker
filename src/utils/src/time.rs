// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// Constant to convert seconds to nanoseconds.
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Wrapper over `libc::clockid_t` to specify Linux Kernel clock source.
pub enum ClockType {
    /// Equivalent to `libc::CLOCK_MONOTONIC`.
    Monotonic,
    /// Equivalent to `libc::CLOCK_REALTIME`.
    Real,
    /// Equivalent to `libc::CLOCK_PROCESS_CPUTIME_ID`.
    ProcessCpu,
    /// Equivalent to `libc::CLOCK_THREAD_CPUTIME_ID`.
    ThreadCpu,
}

impl Into<libc::clockid_t> for ClockType {
    fn into(self) -> libc::clockid_t {
        match self {
            ClockType::Monotonic => libc::CLOCK_MONOTONIC,
            ClockType::Real => libc::CLOCK_REALTIME,
            ClockType::ProcessCpu => libc::CLOCK_PROCESS_CPUTIME_ID,
            ClockType::ThreadCpu => libc::CLOCK_THREAD_CPUTIME_ID,
        }
    }
}

/// Structure representing the date in local time with nanosecond precision.
pub struct LocalTime {
    /// Seconds in current minute.
    sec: i32,
    /// Minutes in current hour.
    min: i32,
    /// Hours in current day, 24H format.
    hour: i32,
    /// Days in current month.
    mday: i32,
    /// Months in current year.
    mon: i32,
    /// Years passed since 1900 BC.
    year: i32,
    /// Nanoseconds in current second.
    nsec: i64,
}

impl LocalTime {
    /// Returns the [LocalTime](struct.LocalTime.html) structure for the calling moment.
    pub fn now() -> LocalTime {
        let mut timespec = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut tm: libc::tm = libc::tm {
            tm_sec: 0,
            tm_min: 0,
            tm_hour: 0,
            tm_mday: 0,
            tm_mon: 0,
            tm_year: 0,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            tm_zone: std::ptr::null(),
        };

        // Safe because the parameters are valid.
        unsafe {
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut timespec);
            libc::localtime_r(&timespec.tv_sec, &mut tm);
        }

        LocalTime {
            sec: tm.tm_sec,
            min: tm.tm_min,
            hour: tm.tm_hour,
            mday: tm.tm_mday,
            mon: tm.tm_mon,
            year: tm.tm_year,
            nsec: timespec.tv_nsec,
        }
    }
}

impl fmt::Display for LocalTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}",
            self.year + 1900,
            self.mon + 1,
            self.mday,
            self.hour,
            self.min,
            self.sec,
            self.nsec
        )
    }
}

/// Holds a micro-second resolution timestamp with both the real time and cpu time.
#[derive(Clone)]
pub struct TimestampUs {
    /// Real time in microseconds.
    pub time_us: u64,
    /// Cpu time in microseconds.
    pub cputime_us: u64,
}

impl Default for TimestampUs {
    fn default() -> TimestampUs {
        TimestampUs {
            time_us: get_time_us(ClockType::Monotonic),
            cputime_us: get_time_us(ClockType::ProcessCpu),
        }
    }
}

/// Returns a timestamp in nanoseconds from a monotonic clock.
///
/// Uses `_rdstc` on `x86_64` and [`get_time`](fn.get_time.html) on other architectures.
pub fn timestamp_cycles() -> u64 {
    #[cfg(target_arch = "x86_64")]
    // Safe because there's nothing that can go wrong with this call.
    unsafe {
        std::arch::x86_64::_rdtsc() as u64
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        get_time_ns(ClockType::Monotonic)
    }
}

/// Returns a timestamp in nanoseconds based on the provided clock type.
///
/// # Arguments
///
/// * `clock_type` - Identifier of the Linux Kernel clock on which to act.
pub fn get_time_ns(clock_type: ClockType) -> u64 {
    let mut time_struct = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Safe because the parameters are valid.
    unsafe { libc::clock_gettime(clock_type.into(), &mut time_struct) };
    seconds_to_nanoseconds(time_struct.tv_sec).expect("Time conversion overflow") as u64
        + (time_struct.tv_nsec as u64)
}

/// Returns a timestamp in microseconds based on the provided clock type.
///
/// # Arguments
///
/// * `clock_type` - Identifier of the Linux Kernel clock on which to act.
pub fn get_time_us(clock_type: ClockType) -> u64 {
    get_time_ns(clock_type) / 1000
}

/// Converts a timestamp in seconds to an equivalent one in nanoseconds.
/// Returns `None` if the conversion overflows.
///
/// # Arguments
///
/// * `value` - Timestamp in seconds.
pub fn seconds_to_nanoseconds(value: i64) -> Option<i64> {
    value.checked_mul(NANOS_PER_SECOND as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_time() {
        for _ in 0..1000 {
            assert!(get_time_ns(ClockType::Monotonic) <= get_time_ns(ClockType::Monotonic));
        }

        for _ in 0..1000 {
            assert!(get_time_ns(ClockType::ProcessCpu) <= get_time_ns(ClockType::ProcessCpu));
        }

        for _ in 0..1000 {
            assert!(get_time_ns(ClockType::ThreadCpu) <= get_time_ns(ClockType::ThreadCpu));
        }

        assert_ne!(get_time_ns(ClockType::Real), 0);
        assert_ne!(get_time_us(ClockType::Real), 0);
        assert!(get_time_ns(ClockType::Real) / 1000 <= get_time_us(ClockType::Real));
    }

    #[test]
    fn test_local_time_display() {
        let local_time = LocalTime {
            sec: 30,
            min: 15,
            hour: 10,
            mday: 4,
            mon: 6,
            year: 119,
            nsec: 123_456_789,
        };
        assert_eq!(
            String::from("2019-07-04T10:15:30.123456789"),
            local_time.to_string()
        );

        let local_time = LocalTime {
            sec: 5,
            min: 5,
            hour: 5,
            mday: 23,
            mon: 7,
            year: 44,
            nsec: 123,
        };
        assert_eq!(
            String::from("1944-08-23T05:05:05.000000123"),
            local_time.to_string()
        );

        let local_time = LocalTime::now();
        assert!(local_time.mon >= 0 && local_time.mon <= 11);
    }

    #[test]
    fn test_seconds_to_nanoseconds() {
        assert_eq!(
            seconds_to_nanoseconds(100).unwrap() as u64,
            100 * NANOS_PER_SECOND
        );

        assert!(seconds_to_nanoseconds(9_223_372_037).is_none());
    }
}
