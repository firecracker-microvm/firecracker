// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Implements pci devices and busses.

extern crate log;

use std::fmt::{self, Debug, Display};
use std::num::ParseIntError;
use std::str::FromStr;

use serde::de::Visitor;
use serde::{Deserialize, Serialize};

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

/// Represents the types of PCI headers allowed in the configuration registers.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PciHeaderType {
    Device,
    Bridge,
}

/// Classes of PCI nodes.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciClassCode {
    TooOld,
    MassStorage,
    NetworkController,
    DisplayController,
    MultimediaController,
    MemoryController,
    BridgeDevice,
    SimpleCommunicationController,
    BaseSystemPeripheral,
    InputDevice,
    DockingStation,
    Processor,
    SerialBusController,
    WirelessController,
    IntelligentIoController,
    EncryptionController,
    DataAcquisitionSignalProcessing,
    Other = 0xff,
}

impl PciClassCode {
    pub fn get_register_value(self) -> u8 {
        self as u8
    }
}

/// A PCI subclass. Each class in `PciClassCode` can specify a unique set of subclasses. This trait
/// is implemented by each subclass. It allows use of a trait object to generate configurations.
pub trait PciSubclass {
    /// Convert this subclass to the value used in the PCI specification.
    fn get_register_value(&self) -> u8;
}

/// Subclasses of the MultimediaController class.
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciMultimediaSubclass {
    VideoController = 0x00,
    AudioController = 0x01,
    TelephonyDevice = 0x02,
    AudioDevice = 0x03,
    Other = 0x80,
}

impl PciSubclass for PciMultimediaSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Subclasses of the BridgeDevice
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciBridgeSubclass {
    HostBridge = 0x00,
    IsaBridge = 0x01,
    EisaBridge = 0x02,
    McaBridge = 0x03,
    PciToPciBridge = 0x04,
    PcmciaBridge = 0x05,
    NuBusBridge = 0x06,
    CardBusBridge = 0x07,
    RacEwayBridge = 0x08,
    PciToPciSemiTransparentBridge = 0x09,
    InfiniBrandToPciHostBridge = 0x0a,
    OtherBridgeDevice = 0x80,
}

impl PciSubclass for PciBridgeSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Subclass of the SerialBus
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciSerialBusSubClass {
    Firewire = 0x00,
    Accessbus = 0x01,
    Ssa = 0x02,
    Usb = 0x03,
}

impl PciSubclass for PciSerialBusSubClass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Mass Storage Sub Classes
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciMassStorageSubclass {
    ScsiStorage = 0x00,
    IdeInterface = 0x01,
    FloppyController = 0x02,
    IpiController = 0x03,
    RaidController = 0x04,
    AtaController = 0x05,
    SataController = 0x06,
    SerialScsiController = 0x07,
    NvmController = 0x08,
    MassStorage = 0x80,
}

impl PciSubclass for PciMassStorageSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Network Controller Sub Classes
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum PciNetworkControllerSubclass {
    EthernetController = 0x00,
    TokenRingController = 0x01,
    FddiController = 0x02,
    AtmController = 0x03,
    IsdnController = 0x04,
    WorldFipController = 0x05,
    PicmgController = 0x06,
    InfinibandController = 0x07,
    FabricController = 0x08,
    NetworkController = 0x80,
}

impl PciSubclass for PciNetworkControllerSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

/// Types of PCI capabilities.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum PciCapabilityId {
    ListId = 0,
    PowerManagement = 0x01,
    AcceleratedGraphicsPort = 0x02,
    VitalProductData = 0x03,
    SlotIdentification = 0x04,
    MessageSignalledInterrupts = 0x05,
    CompactPciHotSwap = 0x06,
    PciX = 0x07,
    HyperTransport = 0x08,
    VendorSpecific = 0x09,
    Debugport = 0x0A,
    CompactPciCentralResourceControl = 0x0B,
    PciStandardHotPlugController = 0x0C,
    BridgeSubsystemVendorDeviceId = 0x0D,
    AgpTargetPciPcibridge = 0x0E,
    SecureDevice = 0x0F,
    PciExpress = 0x10,
    MsiX = 0x11,
    SataDataIndexConf = 0x12,
    PciAdvancedFeatures = 0x13,
    PciEnhancedAllocation = 0x14,
}

impl From<u8> for PciCapabilityId {
    fn from(c: u8) -> Self {
        match c {
            0 => PciCapabilityId::ListId,
            0x01 => PciCapabilityId::PowerManagement,
            0x02 => PciCapabilityId::AcceleratedGraphicsPort,
            0x03 => PciCapabilityId::VitalProductData,
            0x04 => PciCapabilityId::SlotIdentification,
            0x05 => PciCapabilityId::MessageSignalledInterrupts,
            0x06 => PciCapabilityId::CompactPciHotSwap,
            0x07 => PciCapabilityId::PciX,
            0x08 => PciCapabilityId::HyperTransport,
            0x09 => PciCapabilityId::VendorSpecific,
            0x0A => PciCapabilityId::Debugport,
            0x0B => PciCapabilityId::CompactPciCentralResourceControl,
            0x0C => PciCapabilityId::PciStandardHotPlugController,
            0x0D => PciCapabilityId::BridgeSubsystemVendorDeviceId,
            0x0E => PciCapabilityId::AgpTargetPciPcibridge,
            0x0F => PciCapabilityId::SecureDevice,
            0x10 => PciCapabilityId::PciExpress,
            0x11 => PciCapabilityId::MsiX,
            0x12 => PciCapabilityId::SataDataIndexConf,
            0x13 => PciCapabilityId::PciAdvancedFeatures,
            0x14 => PciCapabilityId::PciEnhancedAllocation,
            _ => PciCapabilityId::ListId,
        }
    }
}

/// Types of PCI Express capabilities.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[allow(dead_code)]
#[repr(u16)]
pub enum PciExpressCapabilityId {
    NullCapability = 0x0000,
    AdvancedErrorReporting = 0x0001,
    VirtualChannelMultiFunctionVirtualChannelNotPresent = 0x0002,
    DeviceSerialNumber = 0x0003,
    PowerBudgeting = 0x0004,
    RootComplexLinkDeclaration = 0x0005,
    RootComplexInternalLinkControl = 0x0006,
    RootComplexEventCollectorEndpointAssociation = 0x0007,
    MultiFunctionVirtualChannel = 0x0008,
    VirtualChannelMultiFunctionVirtualChannelPresent = 0x0009,
    RootComplexRegisterBlock = 0x000a,
    VendorSpecificExtendedCapability = 0x000b,
    ConfigurationAccessCorrelation = 0x000c,
    AccessControlServices = 0x000d,
    AlternativeRoutingIdentificationInterpretation = 0x000e,
    AddressTranslationServices = 0x000f,
    SingleRootIoVirtualization = 0x0010,
    DeprecatedMultiRootIoVirtualization = 0x0011,
    Multicast = 0x0012,
    PageRequestInterface = 0x0013,
    ReservedForAmd = 0x0014,
    ResizeableBar = 0x0015,
    DynamicPowerAllocation = 0x0016,
    ThpRequester = 0x0017,
    LatencyToleranceReporting = 0x0018,
    SecondaryPciExpress = 0x0019,
    ProtocolMultiplexing = 0x001a,
    ProcessAddressSpaceId = 0x001b,
    LnRequester = 0x001c,
    DownstreamPortContainment = 0x001d,
    L1PmSubstates = 0x001e,
    PrecisionTimeMeasurement = 0x001f,
    PciExpressOverMphy = 0x0020,
    FRSQueueing = 0x0021,
    ReadinessTimeReporting = 0x0022,
    DesignatedVendorSpecificExtendedCapability = 0x0023,
    VfResizeableBar = 0x0024,
    DataLinkFeature = 0x0025,
    PhysicalLayerSixteenGts = 0x0026,
    LaneMarginingAtTheReceiver = 0x0027,
    HierarchyId = 0x0028,
    NativePcieEnclosureManagement = 0x0029,
    PhysicalLayerThirtyTwoGts = 0x002a,
    AlternateProtocol = 0x002b,
    SystemFirmwareIntermediary = 0x002c,
    ShadowFunctions = 0x002d,
    DataObjectExchange = 0x002e,
    Reserved = 0x002f,
    ExtendedCapabilitiesAbsence = 0xffff,
}

impl From<u16> for PciExpressCapabilityId {
    fn from(c: u16) -> Self {
        match c {
            0x0000 => PciExpressCapabilityId::NullCapability,
            0x0001 => PciExpressCapabilityId::AdvancedErrorReporting,
            0x0002 => PciExpressCapabilityId::VirtualChannelMultiFunctionVirtualChannelNotPresent,
            0x0003 => PciExpressCapabilityId::DeviceSerialNumber,
            0x0004 => PciExpressCapabilityId::PowerBudgeting,
            0x0005 => PciExpressCapabilityId::RootComplexLinkDeclaration,
            0x0006 => PciExpressCapabilityId::RootComplexInternalLinkControl,
            0x0007 => PciExpressCapabilityId::RootComplexEventCollectorEndpointAssociation,
            0x0008 => PciExpressCapabilityId::MultiFunctionVirtualChannel,
            0x0009 => PciExpressCapabilityId::VirtualChannelMultiFunctionVirtualChannelPresent,
            0x000a => PciExpressCapabilityId::RootComplexRegisterBlock,
            0x000b => PciExpressCapabilityId::VendorSpecificExtendedCapability,
            0x000c => PciExpressCapabilityId::ConfigurationAccessCorrelation,
            0x000d => PciExpressCapabilityId::AccessControlServices,
            0x000e => PciExpressCapabilityId::AlternativeRoutingIdentificationInterpretation,
            0x000f => PciExpressCapabilityId::AddressTranslationServices,
            0x0010 => PciExpressCapabilityId::SingleRootIoVirtualization,
            0x0011 => PciExpressCapabilityId::DeprecatedMultiRootIoVirtualization,
            0x0012 => PciExpressCapabilityId::Multicast,
            0x0013 => PciExpressCapabilityId::PageRequestInterface,
            0x0014 => PciExpressCapabilityId::ReservedForAmd,
            0x0015 => PciExpressCapabilityId::ResizeableBar,
            0x0016 => PciExpressCapabilityId::DynamicPowerAllocation,
            0x0017 => PciExpressCapabilityId::ThpRequester,
            0x0018 => PciExpressCapabilityId::LatencyToleranceReporting,
            0x0019 => PciExpressCapabilityId::SecondaryPciExpress,
            0x001a => PciExpressCapabilityId::ProtocolMultiplexing,
            0x001b => PciExpressCapabilityId::ProcessAddressSpaceId,
            0x001c => PciExpressCapabilityId::LnRequester,
            0x001d => PciExpressCapabilityId::DownstreamPortContainment,
            0x001e => PciExpressCapabilityId::L1PmSubstates,
            0x001f => PciExpressCapabilityId::PrecisionTimeMeasurement,
            0x0020 => PciExpressCapabilityId::PciExpressOverMphy,
            0x0021 => PciExpressCapabilityId::FRSQueueing,
            0x0022 => PciExpressCapabilityId::ReadinessTimeReporting,
            0x0023 => PciExpressCapabilityId::DesignatedVendorSpecificExtendedCapability,
            0x0024 => PciExpressCapabilityId::VfResizeableBar,
            0x0025 => PciExpressCapabilityId::DataLinkFeature,
            0x0026 => PciExpressCapabilityId::PhysicalLayerSixteenGts,
            0x0027 => PciExpressCapabilityId::LaneMarginingAtTheReceiver,
            0x0028 => PciExpressCapabilityId::HierarchyId,
            0x0029 => PciExpressCapabilityId::NativePcieEnclosureManagement,
            0x002a => PciExpressCapabilityId::PhysicalLayerThirtyTwoGts,
            0x002b => PciExpressCapabilityId::AlternateProtocol,
            0x002c => PciExpressCapabilityId::SystemFirmwareIntermediary,
            0x002d => PciExpressCapabilityId::ShadowFunctions,
            0x002e => PciExpressCapabilityId::DataObjectExchange,
            0xffff => PciExpressCapabilityId::ExtendedCapabilitiesAbsence,
            _ => PciExpressCapabilityId::Reserved,
        }
    }
}

/// See pci_regs.h in kernel
#[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum PciBarRegionType {
    Memory32BitRegion = 0,
    IoRegion = 0x01,
    Memory64BitRegion = 0x04,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum PciBarPrefetchable {
    NotPrefetchable = 0,
    Prefetchable = 0x08,
}

impl From<PciBarPrefetchable> for bool {
    fn from(val: PciBarPrefetchable) -> Self {
        match val {
            PciBarPrefetchable::NotPrefetchable => false,
            PciBarPrefetchable::Prefetchable => true,
        }
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
