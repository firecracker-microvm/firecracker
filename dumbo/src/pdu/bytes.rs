use std::marker::PhantomData;
use std::mem::replace;
use std::ops::{Deref, DerefMut};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

/// Represents a slice into an array of bytes that stands for different values packed together using
/// network byte ordering (such as a network packet). Its main use is reading and writing numerical
/// values at a given offsets in the underlying slice.
///
/// Why do we need this? Given a byte slice, there are two approaches to reading/writing packet data
/// which come to mind:
///
/// (1) Have structs which represent the potential contents of each packet type, unsafely cast the
/// bytes slice to a struct pointer/reference (after doing the required checks), and then use the
/// newly obtained pointer/reference to access the data.
///
/// (2) Access fields by reading bytes at the appropriate offset from the original slice.
///
/// The first solution looks more appealing at first, but it requires some unsafe blocks. Moreover,
/// de-referencing unaligned pointers or references is considered undefined behaviour in Rust, and
/// it's not clear whether this undermines the approach or not. Until any further developments,
/// we'll use the second option, based on the NetworkBytes implementation.
///
/// What's with the T: Deref<Target = [u8]? Do we really want/need to be that generic? Not really.
/// We actually only expect to work with byte slices (&[u8] and &mut [u8]), but there's an
/// annoying inconvenience we have to deal with :-s Let's say we define NetworkBytes as:
///
/// struct NetworkBytes<'a> {
///     bytes: &'a [u8],
/// }
///
/// This is perfectly fine for reading values from immutable slices, but what about writing values?
/// Implementing methods such as fn write_something(&mut self), is not really possible, because
/// even with a mutable reference to self, self.bytes is still an immutable slice. On the other
/// hand, we could define NetworkBytes as:
///
/// struct NetworkBytes<'a> {
///     bytes: &'a mut [u8],
/// }
///
/// This allows both reads and writes, but requires a mutable reference at all times (and it looks
/// weird to use one for immutable operations). This is where one interesting feature of Rust
/// comes in handy; given a type Something<T>, we can implement different features depending on
/// trait bounds on T. For NetworkBytes, if T implements Deref<Target = [u8]> (which &[u8] does),
/// we define read operations. If T implements DerefMut<Target = [u8]>, we define write operations.
/// Since DerefMut<Target = [u8]> implies Deref<Target = [u8]>, NetworkBytes<&mut [u8]> implements
/// both read and write operations.
///
/// This can theoretically lead to code bloat when using both &u[8] and &mut [u8] (as opposed to
/// just &mut [u8]), but most calls should be inlined anyway, so it probably doesn't matter
/// in the end. NetworkBytes itself implements Deref (and DerefMut when T: DerefMut) so we can
/// extend this line of reasoning to structs which represent different kinds of protocol data units
/// (such as IPv4 packets, Ethernet frames, etc.) based on it.
///
/// Finally, why Deref and not something like AsRef? The answer is Deref coercion, which in our case
/// means that a NetworkBytes value will automatically coerce to &[u8] (or &mut [u8]), without
/// having to go through an explicit .as_ref() call, which makes the code easier to work with.

pub trait NetworkBytes: Deref<Target = [u8]> {
    // Method names have the 'unchecked' suffix as a reminder that we do not check whether the
    // read/write goes past the ends of the slice. Callers must take the necessary precautions to
    // avoid panics.

    // TODO: We're relying on the byteorder crate for now, but we could switch to manually
    // handling bytes, to remove the dependency and any potential unnecessary overhead. Before
    // attempting this, we should have a look at the optimized assembly output for operations with
    // byteorder, because they may already be as fast as they can get.

    /// Reads an `u16` value from the specified offset, and converts it to host byte ordering.
    #[inline]
    fn ntohs_unchecked(&self, offset: usize) -> u16 {
        // The unwrap() can fail when the offset is invalid, or there aren't enough bytes (2 in this
        // case) left until the end of the slice. The caller must ensure this doesn't happen (hence
        // the `unchecked` suffix).
        (&self[offset..]).read_u16::<BigEndian>().unwrap()
    }

    /// Reads an `u32` value from the specified offset, and converts it to host byte ordering.
    #[inline]
    fn ntohl_unchecked(&self, offset: usize) -> u32 {
        (&self[offset..]).read_u32::<BigEndian>().unwrap()
    }

    /// Shrinks the current slice to the given `len`. Does not check whether `len` is actually
    /// smaller than `self.len()`.
    fn shrink_unchecked(&mut self, len: usize);
}

pub trait NetworkBytesMut: NetworkBytes + DerefMut<Target = [u8]> {
    /// Writes the given `u16` value at the specified `offset` using network byte ordering.
    #[inline]
    fn htons_unchecked(&mut self, offset: usize, value: u16) {
        (&mut self[offset..]).write_u16::<BigEndian>(value).unwrap()
    }

    /// Writes the given `u32` value at the specified `offset` using network byte ordering.
    #[inline]
    fn htonl_unchecked(&mut self, offset: usize, value: u32) {
        (&mut self[offset..]).write_u32::<BigEndian>(value).unwrap()
    }
}

impl<'a> NetworkBytes for &'a [u8] {
    #[inline]
    fn shrink_unchecked(&mut self, len: usize) {
        *self = &self[..len];
    }
}
impl<'a> NetworkBytes for &'a mut [u8] {
    #[inline]
    fn shrink_unchecked(&mut self, len: usize) {
        *self = &mut replace(self, &mut [])[..len];
    }
}

impl<'a> NetworkBytesMut for &'a mut [u8] {}

// This struct is used as a convenience for any type which contains a generic member implementing
// NetworkBytes with a lifetime, so we don't have to also add the PhantomData member each time. We
// use pub(super) here because we only want this to be usable by the child modules of `pdu`.
pub(super) struct InnerBytes<'a, T: 'a> {
    bytes: T,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> InnerBytes<'a, T> {
    #[inline]
    pub fn new(bytes: T) -> Self {
        InnerBytes {
            bytes,
            phantom: PhantomData,
        }
    }
}

impl<'a, T: Deref<Target = [u8]>> Deref for InnerBytes<'a, T> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.bytes.deref()
    }
}

impl<'a, T: DerefMut<Target = [u8]>> DerefMut for InnerBytes<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        self.bytes.deref_mut()
    }
}

impl<'a, T: NetworkBytes> NetworkBytes for InnerBytes<'a, T> {
    #[inline]
    fn shrink_unchecked(&mut self, len: usize) {
        self.bytes.shrink_unchecked(len);
    }
}

impl<'a, T: NetworkBytesMut> NetworkBytesMut for InnerBytes<'a, T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_bytes() {
        let mut buf = [0u8; 1000];

        {
            let mut a = buf.as_mut();

            a.htons_unchecked(1, 123);
            a.htonl_unchecked(100, 1234);

            assert_eq!(a.ntohs_unchecked(1), 123);
            assert_eq!(a.ntohl_unchecked(100), 1234);

            a.shrink_unchecked(500);

            assert_eq!(a.len(), 500);
            assert_eq!(a.ntohs_unchecked(1), 123);
            assert_eq!(a.ntohl_unchecked(100), 1234);
        }

        {
            let mut b = buf.as_ref();
            b.shrink_unchecked(500);

            assert_eq!(b.len(), 500);
            assert_eq!(b.ntohs_unchecked(1), 123);
            assert_eq!(b.ntohl_unchecked(100), 1234);
        }
    }
}
