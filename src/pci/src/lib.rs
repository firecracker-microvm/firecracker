// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Implements pci devices and busses.

// mod bus;
pub mod configuration;
pub mod device;
pub mod msi;
pub mod msix;
pub mod vfio;

// pub use self::bus::{PciBus, PciConfigIo, PciConfigMmio, PciRoot, PciRootError};
pub use self::device::{
    BarReprogrammingParams, DeviceRelocation, Error as PciDeviceError, PciDevice,
};

pub use self::configuration::{
    PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciCapability, PciCapabilityId,
    PciClassCode, PciConfiguration, PciHeaderType, PciMassStorageSubclass,
    PciNetworkControllerSubclass, PciProgrammingInterface, PciSerialBusSubClass, PciSubclass,
};

pub use self::msi::{msi_num_enabled_vectors, MsiCap, MsiConfig};
pub use self::msix::{MsixCap, MsixConfig, MsixTableEntry, MSIX_TABLE_ENTRY_SIZE};

pub use self::vfio::{VfioPciDevice, VfioPciError};
/// PCI has four interrupt pins A->D.
#[derive(Copy, Clone)]
pub enum PciInterruptPin {
    IntA,
    IntB,
    IntC,
    IntD,
}

impl PciInterruptPin {
    pub fn to_mask(self) -> u32 {
        self as u32
    }
}
