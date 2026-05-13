// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

/// PCI bus logic
pub mod bus;
/// PCI configuration space handling
pub mod configuration;
/// MSI-X logic
pub mod msix;

use std::fmt::{Debug, Display};
use std::sync::{Arc, Barrier};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Parameters for performing a BAR reprogramming operation
pub struct BarReprogrammingParams {
    /// Previous address of the BAR
    pub old_base: u64,
    /// New address of the BAR
    pub new_base: u64,
    /// Size of the BAR
    pub len: u64,
}

/// Common logic of all PCI devices
pub trait PciDevice: Send {
    /// Sets a register in the configuration space.
    /// * `reg_idx` - The index of the config register to modify.
    /// * `offset` - Offset into the register.
    fn write_config_register(
        &mut self,
        reg_idx: u16,
        offset: u8,
        data: &[u8],
    ) -> Option<Arc<Barrier>>;
    /// Gets a register from the configuration space.
    /// * `reg_idx` - The index of the config register to read.
    fn read_config_register(&mut self, reg_idx: u16) -> u32;
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
}

/// Segment with associated Device BDF
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
pub struct PciSBDF(u32);

impl PciSBDF {
    /// Get segment part
    pub fn segment(&self) -> u16 {
        ((self.0 >> 16) & 0xffff) as u16
    }

    /// Get bus part
    pub fn bus(&self) -> u8 {
        ((self.0 >> 8) & 0xff) as u8
    }

    /// Get device part
    pub fn device(&self) -> u8 {
        ((self.0 >> 3) & 0x1f) as u8
    }

    /// Get function part
    pub fn function(&self) -> u8 {
        (self.0 & 0x7) as u8
    }

    /// Construct new BDF from pieces.
    pub fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self(
            ((segment as u32) << 16)
                | ((bus as u32) << 8)
                | (((device & 0x1f) as u32) << 3)
                | (function & 0x7) as u32,
        )
    }
}

impl From<u32> for PciSBDF {
    fn from(bdf: u32) -> Self {
        Self(bdf)
    }
}

impl From<PciSBDF> for u32 {
    fn from(bdf: PciSBDF) -> Self {
        bdf.0
    }
}

impl From<&PciSBDF> for u32 {
    fn from(bdf: &PciSBDF) -> Self {
        bdf.0
    }
}

impl Debug for PciSBDF {
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

impl Display for PciSBDF {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#?}", self)
    }
}

/// Classes of PCI nodes.
/// https://admin.pci-ids.ucw.cz/read/PD/
#[allow(dead_code, missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum PciClassCode {
    UnclassifiedDevice = 0x00,
    MassStorageController = 0x01,
    NetworkController = 0x02,
    DisplayController = 0x03,
    MultimediaController = 0x04,
    MemoryController = 0x05,
    Bridge = 0x06,
    CommunicationController = 0x07,
    GenericSystemPeripheral = 0x08,
    InputDeviceController = 0x09,
    DockingStation = 0x0a,
    Processor = 0x0b,
    SerialBusController = 0x0c,
    WirelessController = 0x0d,
    IntelligentController = 0x0e,
    SatelliteCommunicationsController = 0x0f,
    EncryptionController = 0x10,
    SignalProcessingController = 0x11,
    ProcessingAccelerators = 0x12,
    NonEssentialInstrumentation = 0x13,
    Coprocessor = 0x40,
    UnassignedClass = 0xff,
}

/// Subclasses of the MultimediaController class.
#[allow(dead_code, missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum PciMultimediaSubclass {
    VideoController = 0x00,
    AudioController = 0x01,
    TelephonyDevice = 0x02,
    AudioDevice = 0x03,
    Other = 0x80,
}

/// Subclasses of the BridgeDevice
#[allow(dead_code, missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
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

/// Subclass of the SerialBus
#[allow(dead_code, missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum PciSerialBusSubClass {
    Firewire = 0x00,
    Accessbus = 0x01,
    Ssa = 0x02,
    Usb = 0x03,
}

/// Mass Storage Sub Classes
#[allow(dead_code, missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
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

/// Network Controller Sub Classes
#[allow(dead_code, missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
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

/// Types of PCI capabilities.
#[allow(dead_code, missing_docs)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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
#[allow(dead_code, missing_docs)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pci_bdf_new() {
        let sbdf = PciSBDF::new(0x1234, 0x56, 0x1f, 0x7);
        assert_eq!(sbdf.segment(), 0x1234);
        assert_eq!(sbdf.bus(), 0x56);
        assert_eq!(sbdf.device(), 0x1f);
        assert_eq!(sbdf.function(), 0x7);
    }

    #[test]
    fn test_pci_bdf_from_u32() {
        let sbdf = PciSBDF::from(0x12345678);
        assert_eq!(sbdf.segment(), 0x1234);
        assert_eq!(sbdf.bus(), 0x56);
        assert_eq!(sbdf.device(), 0x0f);
        assert_eq!(sbdf.function(), 0x0);
    }
}
