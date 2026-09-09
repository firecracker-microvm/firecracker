// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::time::{Duration, Instant};
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

/// A source of monotonic time; real, or a controllable virtual clock for tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Clock {
    /// Real monotonic time via [`Instant::now`].
    #[default]
    Real,
    /// A controllable virtual clock, that only advances via [`Clock::advance`].
    #[cfg(any(test, feature = "test-utils"))]
    Mock(MockClock),
}

impl Clock {
    /// Returns the current time according to this clock.
    pub fn now(&self) -> Instant {
        match self {
            Clock::Real => Instant::now(),
            #[cfg(any(test, feature = "test-utils"))]
            Clock::Mock(clock) => clock.now(),
        }
    }
}

/// Wrapper for a one-shot / interval timer.
/// Either backed by a real Linux `timerfd`, or mocked for testing.
#[derive(Debug)]
pub enum TimerFd {
    /// A real, kernel-backed `timerfd`.
    Real(File),
    /// A deterministic, test-only timer driven by a [`MockClock`].
    #[cfg(any(test, feature = "test-utils"))]
    Mock(MockTimer),
}

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
        TimerFd::Real(unsafe { File::from_raw_fd(fd) })
    }

    /// Creates a deterministic timer registered on `clock`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_mocked(clock: &MockClock) -> Self {
        TimerFd::Mock(MockTimer::new(clock))
    }

    /// Arm the timer to be triggered after `duration` and then
    /// at optional `interval`
    pub fn arm(&mut self, duration: Duration, interval: Option<Duration>) {
        let file = match self {
            TimerFd::Real(file) => file,
            #[cfg(any(test, feature = "test-utils"))]
            TimerFd::Mock(mock) => return mock.arm(duration, interval),
        };
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
        let ret = unsafe { libc::timerfd_settime(file.as_raw_fd(), 0, &spec, ptr::null_mut()) };
        assert!(
            0 <= ret,
            "TimerFd arm failed: {:#}",
            std::io::Error::last_os_error()
        );
    }

    /// Read the value from the timer. Since a real timer is always created with the NONBLOCK
    /// flag, this function does not block and returns `0` if the timer has not fired. For a mock
    /// timer it returns the number of expirations that have occurred (per the virtual clock)
    /// since the previous read.
    pub fn read(&mut self) -> u64 {
        let file = match self {
            TimerFd::Real(file) => file,
            #[cfg(any(test, feature = "test-utils"))]
            TimerFd::Mock(mock) => return mock.read(),
        };
        let mut buf = [0u8; size_of::<u64>()];
        match file.read(buf.as_mut_slice()) {
            Ok(_) => u64::from_ne_bytes(buf),
            Err(inner) if inner.kind() == ErrorKind::WouldBlock => 0,
            Err(err) => panic!("TimerFd read failed: {err:#}"),
        }
    }

    /// Tell if the timer is currently armed.
    pub fn is_armed(&self) -> bool {
        let file = match self {
            TimerFd::Real(file) => file,
            #[cfg(any(test, feature = "test-utils"))]
            TimerFd::Mock(mock) => return mock.is_armed(),
        };
        // SAFETY: Zero init of a PDO type.
        let mut spec: libc::itimerspec = unsafe { std::mem::zeroed() };
        // SAFETY: Safe because timerfd_gettime is trusted to only modify `spec`.
        let ret = unsafe { libc::timerfd_gettime(file.as_raw_fd(), &mut spec) };
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
        match self {
            TimerFd::Real(file) => file.as_raw_fd(),
            #[cfg(any(test, feature = "test-utils"))]
            TimerFd::Mock(_) => panic!("Mocked timer doesn't support fd"),
        }
    }
}

/// Test-only mock clock and timer, used to make time-based unit tests deterministic.
///
/// Gated behind `#[cfg(any(test, feature = "test-utils"))]` at the module level so the individual
/// items don't each need the attribute. Re-exported from the parent so callers keep using
/// [`MockClock`]/[`MockTimer`] directly.
#[cfg(any(test, feature = "test-utils"))]
mod mock {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// A controllable virtual clock for tests. Starts at the current real time, but only moves
    /// forward via [`MockClock::advance`]. Cheap to [`Clone`]; all clones share the same
    /// underlying time, so multiple consumers advance together.
    #[derive(Debug, Clone)]
    pub struct MockClock {
        base: Instant,
        elapsed: Arc<Mutex<Duration>>,
    }

    #[allow(clippy::new_without_default)]
    impl MockClock {
        /// Creates a new virtual clock with zero elapsed time.
        pub fn new() -> Self {
            MockClock {
                base: Instant::now(),
                elapsed: Arc::new(Mutex::new(Duration::ZERO)),
            }
        }

        /// Returns the total virtual time elapsed since creation.
        pub fn elapsed(&self) -> Duration {
            *self.elapsed.lock().unwrap()
        }

        /// Advances the clock (and every clone of it) forward by `duration`.
        pub fn advance(&self, duration: Duration) {
            let mut clock_data = self.elapsed.lock().unwrap();
            *clock_data = clock_data.saturating_add(duration)
        }

        /// Returns the current virtual time as an [`Instant`] (creation time plus elapsed).
        pub fn now(&self) -> Instant {
            self.base + self.elapsed()
        }
    }

    impl PartialEq for MockClock {
        fn eq(&self, other: &Self) -> bool {
            self.base.eq(&other.base) && Arc::ptr_eq(&self.elapsed, &other.elapsed)
        }
    }

    impl Eq for MockClock {}

    /// The deterministic, virtual-clock timer behind [`TimerFd::Mock`](super::TimerFd::Mock)
    ///
    /// It holds no OS resources: expiry is tracked purely against its shared [`MockClock`], so
    /// "firing" happens when the clock is advanced past the armed expiry rather than via the
    /// kernel. Consequently, it has no file descriptor
    /// ([`TimerFd::as_raw_fd`](super::TimerFd::as_raw_fd) panics).
    #[derive(Debug)]
    pub struct MockTimer {
        clock: MockClock,
        // Elapsed virtual time at which the timer first fires; `None` if disarmed.
        expiry: Option<Duration>,
        // Periodic re-arm interval. `None` (or a zero interval) means the timer is one-shot.
        interval: Option<Duration>,
        // Number of expirations already reported by `read`.
        fired: u64,
    }

    impl MockTimer {
        pub(super) fn new(clock: &MockClock) -> Self {
            MockTimer {
                clock: clock.clone(),
                expiry: None,
                interval: None,
                fired: 0,
            }
        }

        pub(super) fn arm(&mut self, duration: Duration, interval: Option<Duration>) {
            // A zero `it_value` disarms a real `timerfd` (regardless of the interval) and discards
            // any pending expirations, so mirror that here instead of firing immediately.
            if duration.is_zero() {
                self.expiry = None;
                self.interval = None;
                self.fired = 0;
                return;
            }
            let elapsed = self.clock.elapsed();
            self.expiry = Some(elapsed.saturating_add(duration));
            self.interval = interval.filter(|i| !i.is_zero());
            self.fired = 0;
        }

        pub(super) fn is_armed(&self) -> bool {
            match self.expiry {
                None => false,
                // A one-shot timer stops being armed once it has fired; a periodic one stays armed.
                Some(expiry) => match self.interval {
                    None => self.clock.elapsed() < expiry,
                    Some(_) => true,
                },
            }
        }

        /// Returns the number of expirations that have occurred (per the virtual clock) since the
        /// previous read, consuming them — mirroring the non-blocking read of a real `timerfd`.
        pub(super) fn read(&mut self) -> u64 {
            let Some(expiry) = self.expiry else {
                return 0;
            };
            let elapsed = self.clock.elapsed();
            if elapsed < expiry {
                return 0;
            }
            // Total expirations up to `elapsed`.
            let total = match self.interval {
                // One-shot: it has fired exactly once.
                None => 1,
                // Periodic: the initial expiration plus one per full interval elapsed since.
                Some(interval) => {
                    let ticks = 1 + (elapsed - expiry).as_nanos() / interval.as_nanos();
                    u64::try_from(ticks).unwrap_or(u64::MAX)
                }
            };
            let new = total - self.fired;
            // Only report expirations not yet consumed by a previous read.
            self.fired = total;
            new
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub use mock::{MockClock, MockTimer};

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

    #[test]
    fn test_mock_timer_fd_one_shot() {
        let clock = MockClock::new();
        let mut timer = TimerFd::new_mocked(&clock);

        // A fresh timer is disarmed and has no pending expirations.
        assert!(!timer.is_armed());
        assert_eq!(timer.read(), 0);

        timer.arm(Duration::from_millis(100), None);
        assert!(timer.is_armed());

        // Advancing short of the expiry does nothing.
        clock.advance(Duration::from_millis(50));
        assert!(timer.is_armed());
        assert_eq!(timer.read(), 0);

        // Crossing the expiry fires exactly once and disarms the one-shot timer.
        clock.advance(Duration::from_millis(50));
        assert!(!timer.is_armed());
        assert_eq!(timer.read(), 1);
        // The expiration is consumed by the read.
        assert_eq!(timer.read(), 0);
    }

    #[test]
    fn test_mock_timer_fd_periodic() {
        let clock = MockClock::new();
        let mut timer = TimerFd::new_mocked(&clock);
        timer.arm(Duration::from_millis(100), Some(Duration::from_millis(50)));

        // Jumping across three interval boundaries accumulates three expirations, and the
        // periodic timer stays armed.
        clock.advance(Duration::from_millis(200));
        assert!(timer.is_armed());
        assert_eq!(timer.read(), 3);
        assert_eq!(timer.read(), 0);

        // The next boundary is at 250ms.
        clock.advance(Duration::from_millis(50));
        assert_eq!(timer.read(), 1);
        assert_eq!(timer.read(), 0);

        // Jumping two intervals
        clock.advance(Duration::from_millis(100));
        assert_eq!(timer.read(), 2);
        assert_eq!(timer.read(), 0);
    }

    #[test]
    fn test_mock_timer_fd_zero_interval_is_one_shot() {
        let clock = MockClock::new();
        let mut timer = TimerFd::new_mocked(&clock);
        // A zero interval must behave as one-shot, matching `timerfd_settime` semantics.
        timer.arm(Duration::from_millis(100), Some(Duration::ZERO));

        clock.advance(Duration::from_millis(500));
        assert!(!timer.is_armed());
        assert_eq!(timer.read(), 1);
        assert_eq!(timer.read(), 0);
    }

    #[test]
    fn test_mock_timer_fd_zero_duration_disarms() {
        let clock = MockClock::new();
        let mut timer = TimerFd::new_mocked(&clock);

        // Arming with a zero duration must disarm the timer and discard pending expirations,
        // matching `timerfd_settime` with `it_value == 0` (this is how the codebase stops a
        // timer, e.g. balloon `_reset`).
        timer.arm(Duration::ZERO, None);
        assert!(!timer.is_armed());
        clock.advance(Duration::from_millis(500));
        assert!(!timer.is_armed());
        assert_eq!(timer.read(), 0);

        // Disarming an already-armed timer clears its pending expirations.
        timer.arm(Duration::from_millis(100), None);
        clock.advance(Duration::from_millis(50));
        assert!(timer.is_armed());
        timer.arm(Duration::ZERO, None);
        assert!(!timer.is_armed());
        clock.advance(Duration::from_millis(500));
        assert_eq!(timer.read(), 0);

        // A zero duration disarms regardless of the interval.
        timer.arm(Duration::from_millis(100), Some(Duration::from_millis(50)));
        timer.arm(Duration::ZERO, Some(Duration::from_millis(50)));
        assert!(!timer.is_armed());
        clock.advance(Duration::from_millis(500));
        assert_eq!(timer.read(), 0);
    }
}
