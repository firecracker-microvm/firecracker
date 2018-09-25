#[macro_use]
extern crate logger;

pub mod ratelimiter;
pub mod validators;

#[cfg(target_arch = "x86_64")]
pub fn timestamp_cycles() -> u64 {
    // Safe because there's nothing that can go wrong with this call.
    unsafe { std::arch::x86_64::_rdtsc() as u64 }
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
}
