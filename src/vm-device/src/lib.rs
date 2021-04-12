// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate serde_derive;
extern crate vm_memory;

use std::io;

mod bus;
pub mod dma_mapping;
pub mod interrupt;

pub use self::bus::{Bus, BusDevice, Error as BusError};

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
}

/// Type of Message Signalled Interrupt
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum MsiIrqType {
    /// PCI MSI IRQ numbers.
    PciMsi,
    /// PCI MSIx IRQ numbers.
    PciMsix,
    /// Generic MSI IRQ numbers.
    GenericMsi,
}

/// Enumeration for device resources.
#[allow(missing_docs)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Resource {
    /// IO Port address range.
    PioAddressRange { base: u16, size: u16 },
    /// Memory Mapped IO address range.
    MmioAddressRange { base: u64, size: u64 },
    /// Legacy IRQ number.
    LegacyIrq(u32),
    /// Message Signaled Interrupt
    MsiIrq {
        ty: MsiIrqType,
        base: u32,
        size: u32,
    },
    /// Network Interface Card MAC address.
    MacAddress(String),
    /// KVM memslot index.
    KvmMemSlot(u32),
}
