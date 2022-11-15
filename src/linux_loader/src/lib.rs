// Copyright (c) 2019 Intel Corporation. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

#![deny(missing_docs)]

//! A Linux kernel image loading crate.
//!
//! This crate offers support for loading raw ELF (vmlinux), compressed
//! big zImage (bzImage) and PE (Image) kernel images.
//! ELF support includes the Linux and PVH boot protocols.
//! Support for any other kernel image format can be added by implementing
//! the [`KernelLoader`] and [`BootConfigurator`].
//!
//! # Platform support
//!
//! - `x86_64`
//! - `ARM64`
//!
//! # Example - load an ELF kernel and configure boot params with the PVH protocol
//!
//! This example shows how to prepare a VM for booting with an ELF kernel, following the PVH
//! boot protocol.
//!
//! ```rust
//! # extern crate linux_loader;
//! # extern crate vm_memory;
//! # use std::{io::{Cursor, Read}, fs::File};
//! # use linux_loader::configurator::{BootConfigurator, BootParams};
//! # #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
//! # use linux_loader::configurator::pvh::PvhBootConfigurator;
//! # #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
//! # use linux_loader::loader::elf::start_info::{hvm_memmap_table_entry, hvm_start_info};
//! # #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
//! # use linux_loader::loader::elf::Elf;
//! # use linux_loader::loader::KernelLoader;
//! # use vm_memory::{Address, GuestAddress, GuestMemoryMmap};
//! # const E820_RAM: u32 = 1;
//! # const MEM_SIZE: usize = 0x100_0000;
//! # const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336ec578;
//!
//! # #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
//! fn build_boot_params() -> (hvm_start_info, Vec<hvm_memmap_table_entry>) {
//!     let mut start_info = hvm_start_info::default();
//!     let memmap_entry = hvm_memmap_table_entry {
//!         addr: 0x7000,
//!         size: 0,
//!         type_: E820_RAM,
//!         reserved: 0,
//!     };
//!     start_info.magic = XEN_HVM_START_MAGIC_VALUE;
//!     start_info.version = 1;
//!     start_info.nr_modules = 0;
//!     start_info.memmap_entries = 0;
//!     (start_info, vec![memmap_entry])
//! }
//!
//! # #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
//! fn main() {
//!     let guest_mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), MEM_SIZE)]).unwrap();
//!
//!     let mut elf_pvh_image = Vec::new();
//!     let path = concat!(
//!         env!("CARGO_MANIFEST_DIR"),
//!         "/../../resources/linux_loader/loader/x86_64/elf/test_elfnote.bin"
//!     );
//!     let mut file = File::open(path).unwrap();
//!     file.read_to_end(&mut elf_pvh_image).unwrap();
//!
//!     // Load the kernel image.
//!     let loader_result =
//!         Elf::load(&guest_mem, None, &mut Cursor::new(&elf_pvh_image), None).unwrap();
//!
//!     // Build boot parameters.
//!     let (mut start_info, memmap_entries) = build_boot_params();
//!     // Address in guest memory where the `start_info` struct will be written.
//!     let start_info_addr = GuestAddress(0x6000);
//!     // Address in guest memory where the memory map will be written.
//!     let memmap_addr = GuestAddress(0x7000);
//!     start_info.memmap_paddr = memmap_addr.raw_value();
//!
//!     // Write boot parameters in guest memory.
//!     let mut boot_params = BootParams::new::<hvm_start_info>(&start_info, start_info_addr);
//!     boot_params.set_sections::<hvm_memmap_table_entry>(&memmap_entries, memmap_addr);
//!     PvhBootConfigurator::write_bootparams::<GuestMemoryMmap>(&boot_params, &guest_mem).unwrap();
//! }
//!
//! # #[cfg(target_arch = "aarch64")]
//! # fn main() {}
//! ```
//!
//! [`BootConfigurator`]: trait.BootConfigurator.html
//! [`KernelLoader`]: trait.KernelLoader.html

pub mod cmdline;
pub mod configurator;
pub mod loader;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod loader_gen;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use loader_gen::*;

extern crate vm_memory;
