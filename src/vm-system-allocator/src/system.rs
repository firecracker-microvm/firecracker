// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fmt::{Debug, Formatter};

use vm_memory::{GuestAddress, GuestUsize};

use crate::address::AddressAllocator;
use crate::gsi::GsiAllocator;
#[cfg(target_arch = "x86_64")]
use crate::gsi::GsiApic;
use crate::page_size::get_page_size;

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
///           #[cfg(target_arch = "x86_64")] vec![GsiApic::new(5, 19)]).unwrap();
///   #[cfg(target_arch = "x86_64")]
///   assert_eq!(allocator.allocate_irq(), Some(5));
///   #[cfg(target_arch = "aarch64")]
///   assert_eq!(allocator.allocate_irq(), Some(32));
///   #[cfg(target_arch = "x86_64")]
///   assert_eq!(allocator.allocate_irq(), Some(6));
///   #[cfg(target_arch = "aarch64")]
///   assert_eq!(allocator.allocate_irq(), Some(33));
///   assert_eq!(allocator.allocate_platform_mmio_addresses(None, 0x1000, Some(0x1000)), Some(GuestAddress(0x1fff_f000)));
///
/// ```
pub struct SystemAllocator {
    #[cfg(target_arch = "x86_64")]
    io_address_space: AddressAllocator,
    platform_mmio_address_space: AddressAllocator,
    gsi_allocator: GsiAllocator,
}

impl Debug for SystemAllocator {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("SystemAllocator")
            .finish()
    }
}

impl SystemAllocator {
    /// Creates a new `SystemAllocator` for managing addresses and irq numbers.
    /// Can return `None` if `base` + `size` overflows a u64
    ///
    /// * `io_base` - (X86) The starting address of IO memory.
    /// * `io_size` - (X86) The size of IO memory.
    /// * `platform_mmio_base` - The starting address of platform MMIO memory.
    /// * `platform_mmio_size` - The size of platform MMIO memory.
    /// * `apics` - (X86) Vector of APIC's.
    ///
    pub fn new(
        #[cfg(target_arch = "x86_64")] io_base: GuestAddress,
        #[cfg(target_arch = "x86_64")] io_size: GuestUsize,
        platform_mmio_base: GuestAddress,
        platform_mmio_size: GuestUsize,
        #[cfg(target_arch = "x86_64")] apics: Vec<GsiApic>,
    ) -> Option<Self> {
        Some(SystemAllocator {
            #[cfg(target_arch = "x86_64")]
            io_address_space: AddressAllocator::new(io_base, io_size)?,
            platform_mmio_address_space: AddressAllocator::new(
                platform_mmio_base,
                platform_mmio_size,
            )?,
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

    /// Reserves a section of `size` bytes of platform MMIO address space.
    pub fn allocate_platform_mmio_addresses(
        &mut self,
        address: Option<GuestAddress>,
        size: GuestUsize,
        align_size: Option<GuestUsize>,
    ) -> Option<GuestAddress> {
        self.platform_mmio_address_space.allocate(
            address,
            size,
            Some(align_size.unwrap_or_else(get_page_size)),
        )
    }

    #[cfg(target_arch = "x86_64")]
    /// Free an IO address range.
    /// We can only free a range if it matches exactly an already allocated range.
    pub fn free_io_addresses(&mut self, address: GuestAddress, size: GuestUsize) {
        self.io_address_space.free(address, size)
    }

    /// Free a platform MMIO address range.
    /// We can only free a range if it matches exactly an already allocated range.
    pub fn free_platform_mmio_addresses(&mut self, address: GuestAddress, size: GuestUsize) {
        self.platform_mmio_address_space.free(address, size)
    }
}
