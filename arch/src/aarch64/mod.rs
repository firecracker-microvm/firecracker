// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod layout;

use memory_model::{AddressSpace, GuestAddress, GuestMemory};

/// Stub function that needs to be implemented when aarch64 functionality is added.
pub fn create_address_space(size: usize) -> Result<AddressSpace, super::Error> {
    let address_space = AddressSpace::with_capacity(1);
    address_space
        .add_default_memory(GuestAddress(0), size)
        .map_err(|_| super::Error::ZeroPagePastRamEnd)?;
    Ok(address_space)
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
