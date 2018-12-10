// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod layout;

use memory_model::{GuestAddress, GuestMemory};

/// Stub function that needs to be implemented when aarch64 functionality is added.
pub fn arch_memory_regions(size: usize) -> Vec<(GuestAddress, usize)> {
    vec![(GuestAddress(0), size)]
}

/// Stub function that needs to be implemented when aarch64 functionality is added.
pub fn configure_system(
    _guest_mem: &GuestMemory,
    _cmdline_addr: GuestAddress,
    _cmdline_size: usize,
    _num_cpus: u8,
) -> super::Result<()> {
    Ok(())
}

/// Stub function that needs to be implemented when aarch64 functionality is added.
pub fn get_reserved_mem_addr() -> usize {
    0
}
