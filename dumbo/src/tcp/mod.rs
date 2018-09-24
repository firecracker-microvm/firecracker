use std::num::Wrapping;

/// The largest possible window size ever (requires the window scaling option).
pub const MAX_WINDOW_SIZE: u32 = 1_073_725_440;

/// The default MSS value, used when no MSS information is carried over the initial handshake.
pub const MSS_DEFAULT: u16 = 536;

// Please note this is not a connex binary relation; in other words, given two sequence numbers a
// and b, it's sometimes possible that seq_at_or_after(a, b) || seq_at_or_after(b, a) == false. This
// is why we can't define seq_after(a, b) as simply !seq_at_or_after(b, a).
#[inline]
pub fn seq_at_or_after(a: Wrapping<u32>, b: Wrapping<u32>) -> bool {
    (a - b).0 < MAX_WINDOW_SIZE
}

#[inline]
pub fn seq_after(a: Wrapping<u32>, b: Wrapping<u32>) -> bool {
    a != b && (a - b).0 < MAX_WINDOW_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seq_at_or_after() {
        let a = Wrapping(123);
        let b = a + Wrapping(100);
        let c = a + Wrapping(MAX_WINDOW_SIZE);

        assert!(seq_at_or_after(a, a));
        assert!(!seq_after(a, a));
        assert!(seq_at_or_after(b, a));
        assert!(seq_after(b, a));
        assert!(!seq_at_or_after(a, b));
        assert!(!seq_after(a, b));
        assert!(!seq_at_or_after(c, a));
        assert!(!seq_after(c, a));
        assert!(seq_at_or_after(c, b));
        assert!(seq_after(c, b));
    }
}
