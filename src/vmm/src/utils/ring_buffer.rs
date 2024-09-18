// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::u32_to_usize;

/// Simple ring buffer of fixed size. Because we probably will never
/// need to have buffers with size bigger that u32::MAX,
/// indexes in this struct are u32, so the maximum size is u32::MAX.
/// This saves 8 bytes compared to `VecDequeue` in the standard library.
/// (24 bytes vs 32 bytes)
/// Making indexes smaller than u32 does not make sense, as the alignment
/// of `Box` is 8 bytes.
#[derive(Debug, Default, Clone)]
pub struct RingBuffer<T: std::fmt::Debug + Default + Clone> {
    /// Fixed array of items.
    pub items: Box<[T]>,
    /// Start index.
    pub start: u32,
    /// Current length of the ring.
    pub len: u32,
}

impl<T: std::fmt::Debug + Default + Clone> RingBuffer<T> {
    /// New with specified size.
    pub fn new_with_size(size: u32) -> Self {
        Self {
            items: vec![T::default(); u32_to_usize(size)].into_boxed_slice(),
            start: 0,
            len: 0,
        }
    }

    /// Get number of items in the buffer
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Check if ring is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Check if ring is full
    pub fn is_full(&self) -> bool {
        u32_to_usize(self.len) == self.items.len()
    }

    /// Returns a reference to the first element if ring is not empty.
    pub fn first(&self) -> Option<&T> {
        if self.is_empty() {
            None
        } else {
            Some(&self.items[u32_to_usize(self.start)])
        }
    }

    /// Push new item to the end of the ring and increases
    /// the length.
    /// If there is no space for it, nothing will happen.
    pub fn push_back(&mut self, item: T) {
        if !self.is_full() {
            let index = u32_to_usize(self.start + self.len) % self.items.len();
            self.items[index] = item;
            self.len += 1;
        }
    }

    /// Pop item from the from of the ring and return
    /// a reference to it.
    /// If ring is empty returns None.
    pub fn pop_front(&mut self) -> Option<&T> {
        if self.is_empty() {
            None
        } else {
            let index = u32_to_usize(self.start);
            self.start += 1;

            // Need to allow this, because we cast `items.len()` to u32,
            // but this is safe as the max size of the buffer is u32::MAX.
            #[allow(clippy::cast_possible_truncation)]
            let items_len = self.items.len() as u32;

            self.start %= items_len;
            self.len -= 1;
            Some(&self.items[index])
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let a = RingBuffer::<u8>::new_with_size(69);
        assert_eq!(a.items.len(), 69);
        assert_eq!(a.start, 0);
        assert_eq!(a.len, 0);
        assert!(a.is_empty());
        assert!(!a.is_full());
    }

    #[test]
    fn test_push() {
        let mut a = RingBuffer::<u8>::new_with_size(4);

        a.push_back(0);
        assert!(!a.is_empty());
        assert!(!a.is_full());

        a.push_back(1);
        assert!(!a.is_empty());
        assert!(!a.is_full());

        a.push_back(2);
        assert!(!a.is_empty());
        assert!(!a.is_full());

        a.push_back(3);
        assert!(!a.is_empty());
        assert!(a.is_full());

        assert_eq!(a.items.as_ref(), &[0, 1, 2, 3]);

        a.push_back(4);
        assert!(!a.is_empty());
        assert!(a.is_full());

        assert_eq!(a.items.as_ref(), &[0, 1, 2, 3]);
    }

    #[test]
    fn test_pop_front() {
        let mut a = RingBuffer::<u8>::new_with_size(4);
        a.push_back(0);
        a.push_back(1);
        a.push_back(2);
        a.push_back(3);
        assert!(!a.is_empty());
        assert!(a.is_full());

        assert_eq!(*a.pop_front().unwrap(), 0);
        assert!(!a.is_empty());
        assert!(!a.is_full());

        assert_eq!(*a.pop_front().unwrap(), 1);
        assert!(!a.is_empty());
        assert!(!a.is_full());

        assert_eq!(*a.pop_front().unwrap(), 2);
        assert!(!a.is_empty());
        assert!(!a.is_full());

        assert_eq!(*a.pop_front().unwrap(), 3);
        assert!(a.is_empty());
        assert!(!a.is_full());

        assert!(a.pop_front().is_none());
        assert!(a.is_empty());
        assert!(!a.is_full());
    }
}
