// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::sync::{Arc, Barrier};
use std::{io, result};

use vm_allocator::AddressAllocator;

use crate::configuration::{self, PciBarRegionType};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// Setup of the device capabilities failed: {0}.
    CapabilitiesSetup(configuration::Error),
    /// Allocating space for an IO BAR failed, size={0}.
    IoAllocationFailed(u64),
    /// Registering an IO BAR at address {0} failed: {1}
    IoRegistrationFailed(u64, configuration::Error),
    /// Expected resource not found.
    MissingResource,
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarReprogrammingParams {
    pub old_base: u64,
    pub new_base: u64,
    pub len: u64,
    pub region_type: PciBarRegionType,
}

pub trait PciDevice: Send {
    /// Allocates the needed PCI BARs space using the `allocate` function which takes a size and
    /// returns an address. Returns a Vec of (GuestAddress, GuestUsize) tuples.
    fn allocate_bars(
        &mut self,
        _mmio32_allocator: &mut AddressAllocator,
        _mmio64_allocator: &mut AddressAllocator,
    ) -> Result<()> {
        Ok(())
    }

    /// Frees the PCI BARs previously allocated with a call to allocate_bars().
    fn free_bars(
        &mut self,
        _mmio32_allocator: &mut AddressAllocator,
        _mmio64_allocator: &mut AddressAllocator,
    ) -> Result<()> {
        Ok(())
    }

    /// Sets a register in the configuration space.
    /// * `reg_idx` - The index of the config register to modify.
    /// * `offset` - Offset into the register.
    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> Option<Arc<Barrier>>;
    /// Gets a register from the configuration space.
    /// * `reg_idx` - The index of the config register to read.
    fn read_config_register(&mut self, reg_idx: usize) -> u32;
    /// Detects if a BAR is being reprogrammed.
    fn detect_bar_reprogramming(
        &mut self,
        _reg_idx: usize,
        _data: &[u8],
    ) -> Option<BarReprogrammingParams> {
        None
    }
    /// Reads from a BAR region mapped into the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - Filled with the data from `addr`.
    fn read_bar(&mut self, _base: u64, _offset: u64, _data: &mut [u8]) {}
    /// Writes to a BAR region mapped into the device.
    /// * `addr` - The guest address inside the BAR.
    /// * `data` - The data to write.
    fn write_bar(&mut self, _base: u64, _offset: u64, _data: &[u8]) -> Option<Arc<Barrier>> {
        None
    }
    /// Relocates the BAR to a different address in guest address space.
    fn move_bar(&mut self, _old_base: u64, _new_base: u64) -> result::Result<(), io::Error> {
        Ok(())
    }
}

/// This trait defines a set of functions which can be triggered whenever a
/// PCI device is modified in any way.
pub trait DeviceRelocation: Send + Sync {
    /// The BAR needs to be moved to a different location in the guest address
    /// space. This follows a decision from the software running in the guest.
    fn move_bar(
        &self,
        old_base: u64,
        new_base: u64,
        len: u64,
        pci_dev: &mut dyn PciDevice,
        region_type: PciBarRegionType,
    ) -> result::Result<(), io::Error>;
}
