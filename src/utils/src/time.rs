// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::time::Duration;
use std::{fmt, ptr};

/// Constant to convert seconds to nanoseconds.
pub const NANOS_PER_SECOND: u64 = 1_000_000_000;
/// Constant to convert milliseconds to nanoseconds.
pub const NANOS_PER_MILLISECOND: u64 = 1_000_000;

/// Wrapper over `libc::clockid_t` to specify Linux Kernel clock source.
#[derive(Debug)]
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

impl From<ClockType> for libc::clockid_t {
    fn from(clock_type: ClockType) -> Self {
        match clock_type {
            ClockType::Monotonic => libc::CLOCK_MONOTONIC,
            ClockType::Real => libc::CLOCK_REALTIME,
            ClockType::ProcessCpu => libc::CLOCK_PROCESS_CPUTIME_ID,
            ClockType::ThreadCpu => libc::CLOCK_THREAD_CPUTIME_ID,
        }
    }
}

/// Structure representing the date in local time with nanosecond precision.
#[derive(Debug)]
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

        // SAFETY: Safe because the parameters are valid.
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
#[derive(Debug, Clone)]
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
    // SAFETY: Safe because there's nothing that can go wrong with this call.
    unsafe {
        std::arch::x86_64::_rdtsc()
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
    // SAFETY: Safe because the parameters are valid.
    unsafe { libc::clock_gettime(clock_type.into(), &mut time_struct) };
    u64::try_from(seconds_to_nanoseconds(time_struct.tv_sec).expect("Time conversion overflow"))
        .unwrap()
        + u64::try_from(time_struct.tv_nsec).unwrap()
}

/// Returns a timestamp in microseconds based on the provided clock type.
///
/// # Arguments
///
/// * `clock_type` - Identifier of the Linux Kernel clock on which to act.
pub fn get_time_us(clock_type: ClockType) -> u64 {
    get_time_ns(clock_type) / 1000
}

/// Returns a timestamp in milliseconds based on the provided clock type.
///
/// # Arguments
///
/// * `clock_type` - Identifier of the Linux Kernel clock on which to act.
pub fn get_time_ms(clock_type: ClockType) -> u64 {
    get_time_ns(clock_type) / NANOS_PER_MILLISECOND
}

/// Converts a timestamp in seconds to an equivalent one in nanoseconds.
/// Returns `None` if the conversion overflows.
///
/// # Arguments
///
/// * `value` - Timestamp in seconds.
pub fn seconds_to_nanoseconds(value: i64) -> Option<i64> {
    value.checked_mul(i64::try_from(NANOS_PER_SECOND).unwrap())
}

/// Wrapper for timerfd
#[derive(Debug)]
pub struct TimerFd(File);

#[allow(clippy::new_without_default)]
impl TimerFd {
    /// Creates new MONOTONIC and NONBLOCK timerfd
    pub fn new() -> Self {
        // SAFETY: all arguments are valid constants
        let fd = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
            )
        };
        assert!(
            0 <= fd,
            "TimerFd creation failed: {:#}",
            std::io::Error::last_os_error()
        );
        // SAFETY: we just created valid fd
        TimerFd(unsafe { File::from_raw_fd(fd) })
    }

    /// Arm the timer to be triggered after `duration` and then
    /// at optional `interval`
    pub fn arm(&mut self, duration: Duration, interval: Option<Duration>) {
        #[allow(clippy::cast_possible_wrap)]
        let spec = libc::itimerspec {
            it_value: libc::timespec {
                tv_sec: duration.as_secs() as i64,
                tv_nsec: duration.subsec_nanos() as i64,
            },
            it_interval: if let Some(interval) = interval {
                libc::timespec {
                    tv_sec: interval.as_secs() as i64,
                    tv_nsec: interval.subsec_nanos() as i64,
                }
            } else {
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }
            },
        };
        // SAFETY: Safe because this doesn't modify any memory and we check the return value.
        let ret = unsafe { libc::timerfd_settime(self.as_raw_fd(), 0, &spec, ptr::null_mut()) };
        assert!(
            0 <= ret,
            "TimerFd arm failed: {:#}",
            std::io::Error::last_os_error()
        );
    }

    /// Read the value from the timerfd. Since it is always created with NONBLOCK flag,
    /// this function does not block.
    pub fn read(&mut self) -> u64 {
        let mut buf = [0u8; size_of::<u64>()];
        match self.0.read(buf.as_mut_slice()) {
            Ok(_) => u64::from_ne_bytes(buf),
            Err(inner) if inner.kind() == ErrorKind::WouldBlock => 0,
            Err(err) => panic!("TimerFd read failed: {err:#}"),
        }
    }

    /// Tell if the timer is currently armed.
    pub fn is_armed(&self) -> bool {
        // SAFETY: Zero init of a PDO type.
        let mut spec: libc::itimerspec = unsafe { std::mem::zeroed() };
        // SAFETY: Safe because timerfd_gettime is trusted to only modify `spec`.
        let ret = unsafe { libc::timerfd_gettime(self.as_raw_fd(), &mut spec) };
        assert!(
            0 <= ret,
            "TimerFd arm failed: {:#}",
            std::io::Error::last_os_error()
        );
        spec.it_value.tv_sec != 0 || spec.it_value.tv_nsec != 0
    }
}

impl AsRawFd for TimerFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
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
        assert!(
            get_time_ns(ClockType::Real) / NANOS_PER_MILLISECOND <= get_time_ms(ClockType::Real)
        );
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
            u64::try_from(seconds_to_nanoseconds(100).unwrap()).unwrap(),
            100 * NANOS_PER_SECOND
        );

        assert!(seconds_to_nanoseconds(9_223_372_037).is_none());
    }
}
