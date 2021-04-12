// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use vm_memory::{GuestAddress, GuestUsize};

use crate::address::AddressAllocator;
use crate::gsi::GsiAllocator;
#[cfg(target_arch = "x86_64")]
use crate::gsi::GsiApic;

use libc::{sysconf, _SC_PAGESIZE};

/// Safe wrapper for `sysconf(_SC_PAGESIZE)`.
#[inline(always)]
fn pagesize() -> usize {
    // Trivially safe
    unsafe { sysconf(_SC_PAGESIZE) as usize }
}

/// Manages allocating system resources such as address space and interrupt numbers.
///
/// # Example - Use the `SystemAddress` builder.
///
/// ```
/// # #[cfg(target_arch = "x86_64")]
/// # use vm_allocator::{GsiApic, SystemAllocator};
/// # #[cfg(target_arch = "aarch64")]
/// # use vm_allocator::SystemAllocator;
/// # use vm_memory::{Address, GuestAddress, GuestUsize};
///   let mut allocator = SystemAllocator::new(
///           #[cfg(target_arch = "x86_64")] GuestAddress(0x1000),
///           #[cfg(target_arch = "x86_64")] 0x10000,
///           GuestAddress(0x10000000), 0x10000000,
///           GuestAddress(0x20000000), 0x100000,
///           #[cfg(target_arch = "x86_64")] vec![GsiApic::new(5, 19)]).unwrap();
///   #[cfg(target_arch = "x86_64")]
///   assert_eq!(allocator.allocate_irq(), Some(5));
///   #[cfg(target_arch = "aarch64")]
///   assert_eq!(allocator.allocate_irq(), Some(0));
///   #[cfg(target_arch = "x86_64")]
///   assert_eq!(allocator.allocate_irq(), Some(6));
///   #[cfg(target_arch = "aarch64")]
///   assert_eq!(allocator.allocate_irq(), Some(1));
///   assert_eq!(allocator.allocate_mmio_addresses(None, 0x1000, Some(0x1000)), Some(GuestAddress(0x1fff_f000)));
///
/// ```
pub struct SystemAllocator {
    #[cfg(target_arch = "x86_64")]
    io_address_space: AddressAllocator,
    mmio_address_space: AddressAllocator,
    mmio_hole_address_space: AddressAllocator,
    gsi_allocator: GsiAllocator,
}

impl SystemAllocator {
    /// Creates a new `SystemAllocator` for managing addresses and irq numvers.
    /// Can return `None` if `base` + `size` overflows a u64
    ///
    /// * `io_base` - (X86) The starting address of IO memory.
    /// * `io_size` - (X86) The size of IO memory.
    /// * `mmio_base` - The starting address of MMIO memory.
    /// * `mmio_size` - The size of MMIO memory.
    /// * `mmio_hole_base` - The starting address of MMIO memory in 32-bit address space.
    /// * `mmio_hole_size` - The size of MMIO memory in 32-bit address space.
    /// * `apics` - (X86) Vector of APIC's.
    ///
    pub fn new(
        #[cfg(target_arch = "x86_64")] io_base: GuestAddress,
        #[cfg(target_arch = "x86_64")] io_size: GuestUsize,
        mmio_base: GuestAddress,
        mmio_size: GuestUsize,
        mmio_hole_base: GuestAddress,
        mmio_hole_size: GuestUsize,
        #[cfg(target_arch = "x86_64")] apics: Vec<GsiApic>,
    ) -> Option<Self> {
        Some(SystemAllocator {
            #[cfg(target_arch = "x86_64")]
            io_address_space: AddressAllocator::new(io_base, io_size)?,
            mmio_address_space: AddressAllocator::new(mmio_base, mmio_size)?,
            mmio_hole_address_space: AddressAllocator::new(mmio_hole_base, mmio_hole_size)?,
            #[cfg(target_arch = "x86_64")]
            gsi_allocator: GsiAllocator::new(apics),
            #[cfg(target_arch = "aarch64")]
            gsi_allocator: GsiAllocator::new(),
        })
    }

    /// Reserves the next available system irq number.
    pub fn allocate_irq(&mut self) -> Option<u32> {
        self.gsi_allocator.allocate_irq().ok()
    }

    /// Reserves the next available GSI.
    pub fn allocate_gsi(&mut self) -> Option<u32> {
        self.gsi_allocator.allocate_gsi().ok()
    }

    #[cfg(target_arch = "x86_64")]
    /// Reserves a section of `size` bytes of IO address space.
    pub fn allocate_io_addresses(
        &mut self,
        address: Option<GuestAddress>,
        size: GuestUsize,
        align_size: Option<GuestUsize>,
    ) -> Option<GuestAddress> {
        self.io_address_space
            .allocate(address, size, Some(align_size.unwrap_or(0x1)))
    }

    /// Reserves a section of `size` bytes of MMIO address space.
    pub fn allocate_mmio_addresses(
        &mut self,
        address: Option<GuestAddress>,
        size: GuestUsize,
        align_size: Option<GuestUsize>,
    ) -> Option<GuestAddress> {
        self.mmio_address_space.allocate(
            address,
            size,
            Some(align_size.unwrap_or(pagesize() as u64)),
        )
    }

    /// Reserves a section of `size` bytes of MMIO address space.
    pub fn allocate_mmio_hole_addresses(
        &mut self,
        address: Option<GuestAddress>,
        size: GuestUsize,
        align_size: Option<GuestUsize>,
    ) -> Option<GuestAddress> {
        self.mmio_hole_address_space.allocate(
            address,
            size,
            Some(align_size.unwrap_or(pagesize() as u64)),
        )
    }

    #[cfg(target_arch = "x86_64")]
    /// Free an IO address range.
    /// We can only free a range if it matches exactly an already allocated range.
    pub fn free_io_addresses(&mut self, address: GuestAddress, size: GuestUsize) {
        self.io_address_space.free(address, size)
    }

    /// Free an MMIO address range.
    /// We can only free a range if it matches exactly an already allocated range.
    pub fn free_mmio_addresses(&mut self, address: GuestAddress, size: GuestUsize) {
        self.mmio_address_space.free(address, size)
    }

    /// Free an MMIO address range from the 32 bits hole.
    /// We can only free a range if it matches exactly an already allocated range.
    pub fn free_mmio_hole_addresses(&mut self, address: GuestAddress, size: GuestUsize) {
        self.mmio_hole_address_space.free(address, size)
    }
}
