// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
#[derive(Debug, Default, Clone)]
pub struct RingBuffer<T: std::fmt::Debug + Default + Clone> {
    pub items: Box<[T]>,
    pub start: usize,
    pub len: usize,
}

impl<T: std::fmt::Debug + Default + Clone> RingBuffer<T> {
    /// New with zero size
    pub fn new() -> Self {
        Self {
            items: Box::new([]),
            start: 0,
            len: 0,
        }
    }

    /// New with specified size
    pub fn new_with_size(size: usize) -> Self {
        Self {
            items: vec![T::default(); size].into_boxed_slice(),
            start: 0,
            len: 0,
        }
    }

    /// Get number of items in the buffer
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if ring is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Check if ring is full
    pub fn is_full(&self) -> bool {
        self.len == self.items.len()
    }

    /// Push new item to the end of the ring and increases
    /// the length.
    /// If there is no space for it, nothing will happen.
    pub fn push(&mut self, item: T) {
        if !self.is_full() {
            let index = (self.start + self.len) % self.items.len();
            self.items[index] = item;
            self.len += 1;
        }
    }

    /// Return next item that will be written to and increases
    /// the length.
    /// If ring is full returns None.
    pub fn next_available(&mut self) -> Option<&mut T> {
        if self.is_full() {
            None
        } else {
            let index = (self.start + self.len) % self.items.len();
            self.len += 1;
            Some(&mut self.items[index])
        }
    }

    /// Pop item from the from of the ring.
    /// If ring is empty returns None.
    pub fn pop_front(&mut self) -> Option<&mut T> {
        if self.is_empty() {
            None
        } else {
            let index = self.start;
            self.start += 1;
            self.start %= self.items.len();
            self.len -= 1;
            Some(&mut self.items[index])
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let a = RingBuffer::<u8>::new();
        assert_eq!(a.items.len(), 0);
        assert_eq!(a.start, 0);
        assert_eq!(a.len, 0);
        assert!(a.is_empty());
        assert!(a.is_full());

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

        a.push(0);
        assert!(!a.is_empty());
        assert!(!a.is_full());

        a.push(1);
        assert!(!a.is_empty());
        assert!(!a.is_full());

        a.push(2);
        assert!(!a.is_empty());
        assert!(!a.is_full());

        a.push(3);
        assert!(!a.is_empty());
        assert!(a.is_full());

        assert_eq!(a.items.as_ref(), &[0, 1, 2, 3]);

        a.push(4);
        assert!(!a.is_empty());
        assert!(a.is_full());

        assert_eq!(a.items.as_ref(), &[0, 1, 2, 3]);
    }

    #[test]
    fn test_next_available() {
        let mut a = RingBuffer::<u8>::new_with_size(4);
        assert!(a.is_empty());
        assert!(!a.is_full());

        *a.next_available().unwrap() = 0;
        assert!(!a.is_empty());
        assert!(!a.is_full());

        *a.next_available().unwrap() = 1;
        assert!(!a.is_empty());
        assert!(!a.is_full());

        *a.next_available().unwrap() = 2;
        assert!(!a.is_empty());
        assert!(!a.is_full());

        *a.next_available().unwrap() = 3;
        assert!(!a.is_empty());
        assert!(a.is_full());

        assert_eq!(a.items.as_ref(), &[0, 1, 2, 3]);

        assert!(a.next_available().is_none());

        assert_eq!(a.items.as_ref(), &[0, 1, 2, 3]);
    }

    #[test]
    fn test_pop_front() {
        let mut a = RingBuffer::<u8>::new_with_size(4);
        a.push(0);
        a.push(1);
        a.push(2);
        a.push(3);
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
