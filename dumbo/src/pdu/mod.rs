//! A module for interpreting byte slices as `PDU`s.
//!
//! PDU stands for protocol data unit, and represents data transmitted as a single unit during
//! communication using a specific protocol. Ethernet frames, IP packets, and TCP segments are all
//! example of protocol data units.

pub mod arp;
pub mod bytes;
pub mod ethernet;
pub mod ipv4;

#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    Arp(arp::Error),
    Ethernet(ethernet::Error),
}

/// This is the baseline definition of the Incomplete struct, which wraps a PDU that does not have
/// everything filled in. It's mostly important when writing PDUs, because fields like checksum
/// can only be calculated after the payload becomes known. Also, we want the length of the
/// underlying slice to be equal to the size of the PDU, so whenever a variable-length payload is
/// involved, we'll want to shrink the slice to an exact fit. The particular ways of completing an
/// Incomplete<T> are implemented by each specific PDU.

pub struct Incomplete<T> {
    inner: T,
}

impl<T> Incomplete<T> {
    #[inline]
    fn new(inner: T) -> Self {
        Incomplete { inner }
    }

    #[inline]
    pub fn inner(&self) -> &T {
        &self.inner
    }

    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}
