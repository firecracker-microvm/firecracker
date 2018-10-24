//! A module for interpreting byte slices as protocol data units (PDUs).
//!
//! A PDU represents data transmitted as a single unit during communication using a specific
//! protocol. Ethernet frames, IP packets, and TCP segments are all examples of protocol data
//! units.

pub mod arp;
pub mod bytes;
pub mod ethernet;
pub mod ipv4;
pub mod tcp;

#[cfg_attr(test, derive(Debug, PartialEq))]
pub enum Error {
    Arp(arp::Error),
    Ethernet(ethernet::Error),
}

/// This is the baseline definition of the `Incomplete` struct, which wraps a PDU that does is
/// still missing some values or content.
///
/// It's mostly important when writing PDUs, because fields like checksum
/// can only be computed after the payload becomes known. Also, the length of the underlying slice
/// should be equal to the actual size for a complete PDU. To that end, whenever a variable-length
/// payload is involved, the slice is shrunk to an exact fit. The particular ways of completing an
/// `Incomplete<T>` are implemented for each specific PDU.
pub struct Incomplete<T> {
    inner: T,
}

impl<T> Incomplete<T> {
    #[inline]
    fn new(inner: T) -> Self {
        Incomplete { inner }
    }

    /// Returns a reference to the wrapped object.
    #[inline]
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Returns a mutable reference to the wrapped object.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}
