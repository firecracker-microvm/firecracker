// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Copyright © 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::{Deserialize, Serialize};

mod bus;
pub mod interrupt;

pub use self::bus::{Bus, BusDevice, BusDeviceSync, Error as BusError};

/// Type of Message Signalled Interrupt
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MsiIrqType {
    /// PCI MSI IRQ numbers.
    PciMsi,
    /// PCI MSIx IRQ numbers.
    PciMsix,
    /// Generic MSI IRQ numbers.
    GenericMsi,
}

#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum PciBarType {
    Io,
    Mmio32,
    Mmio64,
}

/// Enumeration for device resources.
#[allow(missing_docs)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Resource {
    /// IO Port address range.
    PioAddressRange { base: u16, size: u16 },
    /// Memory Mapped IO address range.
    MmioAddressRange { base: u64, size: u64 },
    /// PCI BAR
    PciBar {
        index: usize,
        base: u64,
        size: u64,
        type_: PciBarType,
        prefetchable: bool,
    },
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
