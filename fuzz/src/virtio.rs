// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Module containing helpers for fuzzing virtio devices

use std::borrow::Cow;
use std::convert::TryInto;

use bitvec::vec::BitVec;
use vmm::devices::virtio::queue::VIRTQ_DESC_F_NEXT;
use vmm::devices::virtio::test_utils::{VirtQueue, VirtqDesc};
use vmm::vstate::memory::{Bytes, GuestAddress};

#[derive(Debug)]
pub struct InsufficientData;

/// Trait representing a source of bytes provided by the fuzzer
///
/// Due to orphan rules, we cannot simply do `impl &[u8]`, so we create a trait and
/// implement it for `&[u8]`
pub trait FuzzData<'a> {
    /// Splits of `len` bytes off this [`FuzzData`], returning the consumed bytes
    ///
    /// Returns [`InsufficientData`] if there arent enough bytes left in the input
    fn take_slice(&mut self, len: usize) -> Result<&'a [u8], InsufficientData>;

    /// Returns the number of unconsumed bytes left in this [`FuzzData`]
    fn remaining(&self) -> usize;

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], InsufficientData> {
        // We know that if `.bytes()` returned `Ok`, it'll've given us exactly the number of bytes
        // requested, so `try_into` will not fail.
        self.take_slice(N).map(|bytes| bytes.try_into().unwrap())
    }

    fn take_bool(&mut self) -> Result<bool, InsufficientData> {
        self.take_u8().map(|byte| byte % 2 == 0)
    }

    fn take_u8(&mut self) -> Result<u8, InsufficientData> {
        self.take_array::<1>().map(|[b]| b)
    }

    /// Splits a single byte of fuzz data into 8 booleans, one for each bit
    fn take_bools(&mut self) -> Result<[bool; 8], InsufficientData> {
        self.take_u8().map(|b| {
            [
                b & 0x1 == 0x1,
                b & 0x2 == 0x2,
                b & 0x4 == 0x4,
                b & 0x8 == 0x8,
                b & 0x10 == 0x10,
                b & 0x20 == 0x20,
                b & 0x40 == 0x40,
                b & 0x80 == 0x80,
            ]
        })
    }

    fn take_u16(&mut self) -> Result<u16, InsufficientData> {
        self.take_array::<2>().map(u16::from_le_bytes)
    }

    fn take_u32(&mut self) -> Result<u32, InsufficientData> {
        self.take_array::<4>().map(u32::from_le_bytes)
    }

    fn take_u64(&mut self) -> Result<u64, InsufficientData> {
        self.take_array::<8>().map(u64::from_le_bytes)
    }

    fn take_clamp_u64(&mut self, min: u64, max: u64) -> Result<u64, InsufficientData> {
        self.take_u64().map(|u| u % (max - min + 1) + min)
    }

    fn take_clamp_usize(&mut self, min: usize, max: usize) -> Result<usize, InsufficientData> {
        self.take_clamp_u64(min as u64, max as u64)
            .map(|u| u as usize)
    }

    fn take_bitvec(&mut self, len: usize) -> Result<BitVec, InsufficientData> {
        let v: BitVec = (0..len.div_ceil(8))
            .map(|_| self.take_bools()) // generate 8 bools
            .flatten() // flatten results
            .flatten() // flatten slices
            .take(len)
            .collect();
        if v.len() == len {
            Ok(v)
        } else {
            Err(InsufficientData)
        }
    }

    /// Attempts to populate the given VirtqDesc with fuzz data
    ///
    /// Takes 4 bytes to populate the `addr` (2 bytes), `flags` and `next` (1 byte each) fields, and
    /// then calls the given closure for generating the data of to be put into the descriptor. The
    /// `len` field is then set to the number of bytes returned by the closure.
    ///
    /// The closure `data_gen` is passed the address to which its generated data would be written,
    /// so it can ensure nothing would be written outside of the bounds of guest memory. It can
    /// assume that at least one byte of data is available. The length of data returned MUST NOT
    /// exceed `u32::MAX`.
    ///
    /// Returns true if the descriptor has a next one in the chain (has VIRTQ_DESC_F_NEXT set in the
    /// flags)
    fn fill_virt_desc<'b, F>(
        &mut self,
        desc: &mut VirtqDesc<'b>,
        data_gen: F,
        min_addr: u64,
    ) -> Result<bool, InsufficientData>
    where
        F: Fn(&mut Self) -> Result<Cow<'a, [u8]>, InsufficientData>,
    {
        let addr = (self.take_u16()? as u64).max(min_addr);
        let flags = self.take_u8()? as u16;
        let next = self.take_u8()? as u16;

        match data_gen(self) {
            Ok(data) => {
                desc.set(addr, data.len() as u32, flags, next);

                // This can fail, as part (or all of) the memory range we're trying to write
                // to might be out of bounds.
                let _ = desc.memory().write_slice(&data, GuestAddress(addr));
            }
            Err(InsufficientData) => {
                desc.set(addr, 0, flags, next);
            }
        }

        Ok(flags & VIRTQ_DESC_F_NEXT != 0)
    }

    /// Fills the given VirtQueue with a random amount of randomly placed virtq descriptors
    ///
    /// The buffers of the descriptors are generated by calling the given closure. The
    /// `prevent_overwrite_queue` parameter controls whether it should be allowed for virtio
    /// descriptor buffers to overwrite the part of the guest memory at which the queue's struct
    /// itself is stored. It should be set to `true` if the device writes non-deterministic data to
    /// its buffers
    fn fill_virt_queue<'b, F>(
        &mut self,
        queue: &mut VirtQueue<'b>,
        data_gen: F,
        prevent_overwrite_queue: bool,
    ) -> Result<(), InsufficientData>
    where
        F: Fn(&mut Self) -> Result<Cow<'a, [u8]>, InsufficientData>,
    {
        let queue_size = queue.dtable.len();
        // How many descriptors should we try to put into the virtio queue?
        let num_descriptors = self.take_u8()? as usize % queue_size + 1;

        // According to the virtio spec, `avail_idx` is the index (modulo queue_size) into the
        // available ring at which the driver will place the _next_ descriptor head it wants to
        // pass to the device.
        let mut avail_idx = queue.avail.idx.get();

        let minimal_desc_addr = if prevent_overwrite_queue {
            queue.end().0
        } else {
            0
        };

        let mut prev_had_next = false;
        for _ in 0..num_descriptors {
            if self.remaining() < 1 {
                // Not enough data to even determine an index into the descriptor table, lets be
                // happy with what we (hopefully) put in there in previous iterations.
                break;
            }

            // where in the descriptor table do we want to put this particular descriptor?
            let idx = self.take_u8()? as usize % queue_size;

            match self.fill_virt_desc(&mut queue.dtable[idx], &data_gen, minimal_desc_addr) {
                Ok(has_next) => {
                    // add it to the ring only if not part of a chain
                    if !prev_had_next {
                        queue.avail.ring[(avail_idx as usize) % queue_size].set(idx as u16);
                        avail_idx = avail_idx.wrapping_add(1);
                        queue.avail.idx.set(avail_idx);
                    }
                    prev_had_next = has_next;
                }
                Err(_) => break, // we ran out of data :(
            }
        }

        // If we still have data, randomly set the used_event field (the last u16 of the available
        // ring), as the harness might enable notification suppression.
        if let Ok(idx) = self.take_u16() {
            queue.avail.event.set(idx);
        }

        Ok(())
    }
}

impl<'a> FuzzData<'a> for &'a [u8] {
    fn take_slice(&mut self, how_many: usize) -> Result<&'a [u8], InsufficientData> {
        if how_many > self.remaining() {
            return Err(InsufficientData);
        }
        let result = &self[..how_many];
        *self = &self[how_many..];
        Ok(result)
    }

    fn remaining(&self) -> usize {
        self.len()
    }
}

/// A function to pass to [`FuzzData::fill_virtq`] to fill the descriptors with raw fuzzer input
pub fn fuzz_data_descriptor<'a>(
    input: &mut impl FuzzData<'a>,
) -> Result<Cow<'a, [u8]>, InsufficientData> {
    let requested = input.take_u16()? as usize;
    input
        .take_slice(input.remaining().min(requested))
        .map(Cow::Borrowed)
}
