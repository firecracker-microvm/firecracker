// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Implements pci devices and busses.
#[macro_use]
extern crate log;

mod bus;
mod configuration;
mod device;
mod msix;

use std::fmt::{self, Debug, Display};
use std::num::ParseIntError;
use std::str::FromStr;

use serde::de::Visitor;

pub use self::bus::{PciBus, PciConfigIo, PciConfigMmio, PciRoot, PciRootError};
pub use self::configuration::{
    PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciCapability, PciCapabilityId,
    PciClassCode, PciConfiguration, PciConfigurationState, PciExpressCapabilityId, PciHeaderType,
    PciMassStorageSubclass, PciNetworkControllerSubclass, PciProgrammingInterface,
    PciSerialBusSubClass, PciSubclass, PCI_CONFIGURATION_ID,
};
pub use self::device::{
    BarReprogrammingParams, DeviceRelocation, Error as PciDeviceError, PciDevice,
};
pub use self::msix::{Error as MsixError, MsixCap, MsixConfig, MsixConfigState, MsixTableEntry};

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

#[cfg(target_arch = "x86_64")]
pub const PCI_CONFIG_IO_PORT: u64 = 0xcf8;
#[cfg(target_arch = "x86_64")]
pub const PCI_CONFIG_IO_PORT_SIZE: u64 = 0x8;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd)]
pub struct PciBdf(u32);

struct PciBdfVisitor;

impl Visitor<'_> for PciBdfVisitor {
    type Value = PciBdf;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("struct PciBdf")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        PciBdf::from_str(v).map_err(serde::de::Error::custom)
    }
}

impl<'de> serde::Deserialize<'de> for PciBdf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(PciBdfVisitor)
    }
}

impl serde::Serialize for PciBdf {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self.to_string())
    }
}

impl PciBdf {
    pub fn segment(&self) -> u16 {
        ((self.0 >> 16) & 0xffff) as u16
    }

    pub fn bus(&self) -> u8 {
        ((self.0 >> 8) & 0xff) as u8
    }

    pub fn device(&self) -> u8 {
        ((self.0 >> 3) & 0x1f) as u8
    }

    pub fn function(&self) -> u8 {
        (self.0 & 0x7) as u8
    }

    pub fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self(
            ((segment as u32) << 16)
                | ((bus as u32) << 8)
                | (((device & 0x1f) as u32) << 3)
                | (function & 0x7) as u32,
        )
    }
}

impl From<u32> for PciBdf {
    fn from(bdf: u32) -> Self {
        Self(bdf)
    }
}

impl From<PciBdf> for u32 {
    fn from(bdf: PciBdf) -> Self {
        bdf.0
    }
}

impl From<&PciBdf> for u32 {
    fn from(bdf: &PciBdf) -> Self {
        bdf.0
    }
}

impl From<PciBdf> for u16 {
    fn from(bdf: PciBdf) -> Self {
        (bdf.0 & 0xffff) as u16
    }
}

impl From<&PciBdf> for u16 {
    fn from(bdf: &PciBdf) -> Self {
        (bdf.0 & 0xffff) as u16
    }
}

impl Debug for PciBdf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:04x}:{:02x}:{:02x}.{:01x}",
            self.segment(),
            self.bus(),
            self.device(),
            self.function()
        )
    }
}

impl Display for PciBdf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:04x}:{:02x}:{:02x}.{:01x}",
            self.segment(),
            self.bus(),
            self.device(),
            self.function()
        )
    }
}

/// Errors associated with parsing a BDF string.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PciBdfParseError {
    /// Unable to parse bus/device/function number hex: {0}
    InvalidHex(#[from] ParseIntError),
    /// Invalid format: {0} (expected format: 0000:00:00.0)
    InvalidFormat(String),
}

impl FromStr for PciBdf {
    type Err = PciBdfParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let items: Vec<&str> = s.split('.').collect();
        if items.len() != 2 {
            return Err(PciBdfParseError::InvalidFormat(s.to_string()));
        }
        let function = u8::from_str_radix(items[1], 16)?;
        let items: Vec<&str> = items[0].split(':').collect();
        if items.len() != 3 {
            return Err(PciBdfParseError::InvalidFormat(s.to_string()));
        }
        let segment = u16::from_str_radix(items[0], 16)?;
        let bus = u8::from_str_radix(items[1], 16)?;
        let device = u8::from_str_radix(items[2], 16)?;
        Ok(PciBdf::new(segment, bus, device, function))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pci_bdf_new() {
        let bdf = PciBdf::new(0x1234, 0x56, 0x1f, 0x7);
        assert_eq!(bdf.segment(), 0x1234);
        assert_eq!(bdf.bus(), 0x56);
        assert_eq!(bdf.device(), 0x1f);
        assert_eq!(bdf.function(), 0x7);
    }

    #[test]
    fn test_pci_bdf_from_u32() {
        let bdf = PciBdf::from(0x12345678);
        assert_eq!(bdf.segment(), 0x1234);
        assert_eq!(bdf.bus(), 0x56);
        assert_eq!(bdf.device(), 0x0f);
        assert_eq!(bdf.function(), 0x0);
    }

    #[test]
    fn test_pci_bdf_to_u32() {
        let bdf = PciBdf::new(0x1234, 0x56, 0x1f, 0x7);
        let val: u32 = bdf.into();
        assert_eq!(val, 0x123456ff);
    }

    #[test]
    fn test_pci_bdf_to_u16() {
        let bdf = PciBdf::new(0x1234, 0x56, 0x1f, 0x7);
        let val: u16 = bdf.into();
        assert_eq!(val, 0x56ff);
    }

    #[test]
    fn test_pci_bdf_from_str_valid() {
        let bdf = PciBdf::from_str("1234:56:1f.7").unwrap();
        assert_eq!(bdf.segment(), 0x1234);
        assert_eq!(bdf.bus(), 0x56);
        assert_eq!(bdf.device(), 0x1f);
        assert_eq!(bdf.function(), 0x7);
    }

    #[test]
    fn test_pci_bdf_from_str_zero() {
        let bdf = PciBdf::from_str("0000:00:00.0").unwrap();
        assert_eq!(bdf.segment(), 0);
        assert_eq!(bdf.bus(), 0);
        assert_eq!(bdf.device(), 0);
        assert_eq!(bdf.function(), 0);
    }

    #[test]
    fn test_pci_bdf_from_str_invalid_format() {
        assert!(matches!(
            PciBdf::from_str("invalid"),
            Err(PciBdfParseError::InvalidFormat(_))
        ));
        assert!(matches!(
            PciBdf::from_str("1234:56"),
            Err(PciBdfParseError::InvalidFormat(_))
        ));
        assert!(matches!(
            PciBdf::from_str("1234:56:78:9a.b"),
            Err(PciBdfParseError::InvalidFormat(_))
        ));
    }

    #[test]
    fn test_pci_bdf_from_str_invalid_hex() {
        assert!(matches!(
            PciBdf::from_str("xxxx:00:00.0"),
            Err(PciBdfParseError::InvalidHex(_))
        ));
        assert!(matches!(
            PciBdf::from_str("0000:xx:00.0"),
            Err(PciBdfParseError::InvalidHex(_))
        ));
        assert!(matches!(
            PciBdf::from_str("0000:00:xx.0"),
            Err(PciBdfParseError::InvalidHex(_))
        ));
        assert!(matches!(
            PciBdf::from_str("0000:00:00.x"),
            Err(PciBdfParseError::InvalidHex(_))
        ));
    }

    #[test]
    fn test_pci_bdf_display() {
        let bdf = PciBdf::new(0x1234, 0x56, 0x1f, 0x7);
        assert_eq!(format!("{}", bdf), "1234:56:1f.7");
    }

    #[test]
    fn test_pci_bdf_debug() {
        let bdf = PciBdf::new(0x1234, 0x56, 0x1f, 0x7);
        assert_eq!(format!("{:?}", bdf), "1234:56:1f.7");
    }

    #[test]
    fn test_pci_bdf_partial_eq() {
        let bdf1 = PciBdf::new(0x1234, 0x56, 0x1f, 0x7);
        let bdf2 = PciBdf::new(0x1234, 0x56, 0x1f, 0x7);
        let bdf3 = PciBdf::new(0x1234, 0x56, 0x1f, 0x6);
        assert_eq!(bdf1, bdf2);
        assert_ne!(bdf1, bdf3);
    }

    #[test]
    fn test_pci_bdf_partial_ord() {
        let bdf1 = PciBdf::new(0x1234, 0x56, 0x1f, 0x6);
        let bdf2 = PciBdf::new(0x1234, 0x56, 0x1f, 0x7);
        assert!(bdf1 < bdf2);
    }

    #[test]
    fn test_pci_bdf_deserialize_ok() {
        // Test deserializer
        let visitor = PciBdfVisitor;
        let result = visitor
            .visit_str::<serde::de::value::Error>("1234:56:1f.7")
            .unwrap();
        assert_eq!(result, PciBdf::new(0x1234, 0x56, 0x1f, 0x7));
    }

    #[test]
    fn test_pci_bdf_deserialize_invalid() {
        // Test deserializer with invalid input returns error
        let visitor = PciBdfVisitor;
        assert!(visitor
            .visit_str::<serde::de::value::Error>("invalid")
            .is_err());
    }

    #[test]
    fn test_pci_bdf_serialize() {
        // Test serializer using serde_test
        let bdf = PciBdf::new(0x1234, 0x56, 0x1f, 0x7);
        serde_test::assert_tokens(&bdf, &[serde_test::Token::Str("1234:56:1f.7")]);
    }
}
