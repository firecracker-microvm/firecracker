extern crate libc;

#[macro_use]
extern crate logger;

pub mod ratelimiter;
pub mod validators;

#[cfg(target_arch = "x86_64")]
pub fn timestamp_cycles() -> u64 {
    // Safe because there's nothing that can go wrong with this call.
    unsafe { std::arch::x86_64::_rdtsc() as u64 }
}

fn timespec_to_us(time_struct: &libc::timespec) -> u64 {
    (time_struct.tv_sec as u64) * 1_000_000 + (time_struct.tv_nsec as u64) / 1000
}

pub fn now_cputime_us() -> u64 {
    let mut time_struct = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Safe because the parameters are valid.
    unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut time_struct) };
    timespec_to_us(&time_struct)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_cycles() {
        for _ in 0..1000 {
            assert!(timestamp_cycles() < timestamp_cycles());
        }
    }

    #[test]
    fn test_now_cputime_us() {
        for _ in 0..1000 {
            assert!(now_cputime_us() <= now_cputime_us());
        }
    }
}
