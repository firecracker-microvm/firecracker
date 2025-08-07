// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

use std::fmt::{self, Display};
use std::sync::{Arc, Mutex};

use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};

use crate::device::BarReprogrammingParams;
use crate::MsixConfig;

// The number of 32bit registers in the config space, 4096 bytes.
const NUM_CONFIGURATION_REGISTERS: usize = 1024;

const STATUS_REG: usize = 1;
const STATUS_REG_CAPABILITIES_USED_MASK: u32 = 0x0010_0000;
const BAR0_REG: usize = 4;
const ROM_BAR_REG: usize = 12;
const BAR_IO_ADDR_MASK: u32 = 0xffff_fffc;
const BAR_MEM_ADDR_MASK: u32 = 0xffff_fff0;
const ROM_BAR_ADDR_MASK: u32 = 0xffff_f800;
const MSI_CAPABILITY_REGISTER_MASK: u32 = 0x0071_0000;
const MSIX_CAPABILITY_REGISTER_MASK: u32 = 0xc000_0000;
const NUM_BAR_REGS: usize = 6;
const CAPABILITY_LIST_HEAD_OFFSET: usize = 0x34;
const FIRST_CAPABILITY_OFFSET: usize = 0x40;
const CAPABILITY_MAX_OFFSET: usize = 192;

pub const PCI_CONFIGURATION_ID: &str = "pci_configuration";

/// Represents the types of PCI headers allowed in the configuration registers.
#[derive(Copy, Clone)]
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

/// Trait to define a PCI class programming interface
///
/// Each combination of `PciClassCode` and `PciSubclass` can specify a
/// set of register-level programming interfaces.
/// This trait is implemented by each programming interface.
/// It allows use of a trait object to generate configurations.
pub trait PciProgrammingInterface {
    /// Convert this programming interface to the value used in the PCI specification.
    fn get_register_value(&self) -> u8;
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

/// A PCI capability list. Devices can optionally specify capabilities in their configuration space.
pub trait PciCapability {
    fn bytes(&self) -> &[u8];
    fn id(&self) -> PciCapabilityId;
}

fn encode_32_bits_bar_size(bar_size: u32) -> Option<u32> {
    if bar_size > 0 {
        return Some(!(bar_size - 1));
    }
    None
}

fn decode_32_bits_bar_size(bar_size: u32) -> Option<u32> {
    if bar_size > 0 {
        return Some(!bar_size + 1);
    }
    None
}

fn encode_64_bits_bar_size(bar_size: u64) -> Option<(u32, u32)> {
    if bar_size > 0 {
        let result = !(bar_size - 1);
        let result_hi = (result >> 32) as u32;
        let result_lo = (result & 0xffff_ffff) as u32;
        return Some((result_hi, result_lo));
    }
    None
}

fn decode_64_bits_bar_size(bar_size_hi: u32, bar_size_lo: u32) -> Option<u64> {
    let bar_size: u64 = ((bar_size_hi as u64) << 32) | (bar_size_lo as u64);
    if bar_size > 0 {
        return Some(!bar_size + 1);
    }
    None
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
struct PciBar {
    addr: u32,
    size: u32,
    used: bool,
    r#type: Option<PciBarRegionType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PciConfigurationState {
    registers: Vec<u32>,
    writable_bits: Vec<u32>,
    bars: Vec<PciBar>,
    rom_bar_addr: u32,
    rom_bar_size: u32,
    rom_bar_used: bool,
    last_capability: Option<(usize, usize)>,
    msix_cap_reg_idx: Option<usize>,
}

/// Contains the configuration space of a PCI node.
///
/// See the [specification](https://en.wikipedia.org/wiki/PCI_configuration_space).
/// The configuration space is accessed with DWORD reads and writes from the guest.
pub struct PciConfiguration {
    registers: [u32; NUM_CONFIGURATION_REGISTERS],
    writable_bits: [u32; NUM_CONFIGURATION_REGISTERS], // writable bits for each register.
    bars: [PciBar; NUM_BAR_REGS],
    rom_bar_addr: u32,
    rom_bar_size: u32,
    rom_bar_used: bool,
    // Contains the byte offset and size of the last capability.
    last_capability: Option<(usize, usize)>,
    msix_cap_reg_idx: Option<usize>,
    msix_config: Option<Arc<Mutex<MsixConfig>>>,
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

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct PciBarConfiguration {
    pub addr: u64,
    pub size: u64,
    pub idx: usize,
    pub region_type: PciBarRegionType,
    pub prefetchable: PciBarPrefetchable,
}

#[derive(Debug)]
pub enum Error {
    BarAddressInvalid(u64, u64),
    BarInUse(usize),
    BarInUse64(usize),
    BarInvalid(usize),
    BarInvalid64(usize),
    BarSizeInvalid(u64),
    CapabilitySpaceFull(usize),
    Decode32BarSize,
    Decode64BarSize,
    Encode32BarSize,
    Encode64BarSize,
    RomBarAddressInvalid(u64, u64),
    RomBarInUse(usize),
    RomBarInvalid(usize),
    RomBarSizeInvalid(u64),
}
pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;
        match self {
            BarAddressInvalid(a, s) => write!(f, "address {a} size {s} too big"),
            BarInUse(b) => write!(f, "bar {b} already used"),
            BarInUse64(b) => write!(f, "64bit bar {b} already used(requires two regs)"),
            BarInvalid(b) => write!(f, "bar {} invalid, max {}", b, NUM_BAR_REGS - 1),
            BarInvalid64(b) => write!(
                f,
                "64bitbar {} invalid, requires two regs, max {}",
                b,
                NUM_BAR_REGS - 1
            ),
            BarSizeInvalid(s) => write!(f, "bar address {s} not a power of two"),
            CapabilitySpaceFull(s) => write!(f, "capability of size {s} doesn't fit"),
            Decode32BarSize => write!(f, "failed to decode 32 bits BAR size"),
            Decode64BarSize => write!(f, "failed to decode 64 bits BAR size"),
            Encode32BarSize => write!(f, "failed to encode 32 bits BAR size"),
            Encode64BarSize => write!(f, "failed to encode 64 bits BAR size"),
            RomBarAddressInvalid(a, s) => write!(f, "address {a} size {s} too big"),
            RomBarInUse(b) => write!(f, "rom bar {b} already used"),
            RomBarInvalid(b) => write!(f, "rom bar {} invalid, max {}", b, NUM_BAR_REGS - 1),
            RomBarSizeInvalid(s) => write!(f, "rom bar address {s} not a power of two"),
        }
    }
}

impl PciConfiguration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vendor_id: u16,
        device_id: u16,
        revision_id: u8,
        class_code: PciClassCode,
        subclass: &dyn PciSubclass,
        programming_interface: Option<&dyn PciProgrammingInterface>,
        header_type: PciHeaderType,
        subsystem_vendor_id: u16,
        subsystem_id: u16,
        msix_config: Option<Arc<Mutex<MsixConfig>>>,
        state: Option<PciConfigurationState>,
    ) -> Self {
        let (
            registers,
            writable_bits,
            bars,
            rom_bar_addr,
            rom_bar_size,
            rom_bar_used,
            last_capability,
            msix_cap_reg_idx,
        ) = if let Some(state) = state {
            (
                state.registers.try_into().unwrap(),
                state.writable_bits.try_into().unwrap(),
                state.bars.try_into().unwrap(),
                state.rom_bar_addr,
                state.rom_bar_size,
                state.rom_bar_used,
                state.last_capability,
                state.msix_cap_reg_idx,
            )
        } else {
            let mut registers = [0u32; NUM_CONFIGURATION_REGISTERS];
            let mut writable_bits = [0u32; NUM_CONFIGURATION_REGISTERS];
            registers[0] = (u32::from(device_id) << 16) | u32::from(vendor_id);
            // TODO(dverkamp): Status should be write-1-to-clear
            writable_bits[1] = 0x0000_ffff; // Status (r/o), command (r/w)
            let pi = if let Some(pi) = programming_interface {
                pi.get_register_value()
            } else {
                0
            };
            registers[2] = (u32::from(class_code.get_register_value()) << 24)
                | (u32::from(subclass.get_register_value()) << 16)
                | (u32::from(pi) << 8)
                | u32::from(revision_id);
            writable_bits[3] = 0x0000_00ff; // Cacheline size (r/w)
            match header_type {
                PciHeaderType::Device => {
                    registers[3] = 0x0000_0000; // Header type 0 (device)
                    writable_bits[15] = 0x0000_00ff; // Interrupt line (r/w)
                }
                PciHeaderType::Bridge => {
                    registers[3] = 0x0001_0000; // Header type 1 (bridge)
                    writable_bits[9] = 0xfff0_fff0; // Memory base and limit
                    writable_bits[15] = 0xffff_00ff; // Bridge control (r/w), interrupt line (r/w)
                }
            };
            registers[11] = (u32::from(subsystem_id) << 16) | u32::from(subsystem_vendor_id);

            (
                registers,
                writable_bits,
                [PciBar::default(); NUM_BAR_REGS],
                0,
                0,
                false,
                None,
                None,
            )
        };

        PciConfiguration {
            registers,
            writable_bits,
            bars,
            rom_bar_addr,
            rom_bar_size,
            rom_bar_used,
            last_capability,
            msix_cap_reg_idx,
            msix_config,
        }
    }

    pub fn state(&self) -> PciConfigurationState {
        PciConfigurationState {
            registers: self.registers.to_vec(),
            writable_bits: self.writable_bits.to_vec(),
            bars: self.bars.to_vec(),
            rom_bar_addr: self.rom_bar_addr,
            rom_bar_size: self.rom_bar_size,
            rom_bar_used: self.rom_bar_used,
            last_capability: self.last_capability,
            msix_cap_reg_idx: self.msix_cap_reg_idx,
        }
    }

    /// Reads a 32bit register from `reg_idx` in the register map.
    pub fn read_reg(&self, reg_idx: usize) -> u32 {
        *(self.registers.get(reg_idx).unwrap_or(&0xffff_ffff))
    }

    /// Writes a 32bit register to `reg_idx` in the register map.
    pub fn write_reg(&mut self, reg_idx: usize, value: u32) {
        let mut mask = self.writable_bits[reg_idx];

        if (BAR0_REG..BAR0_REG + NUM_BAR_REGS).contains(&reg_idx) {
            // Handle very specific case where the BAR is being written with
            // all 1's to retrieve the BAR size during next BAR reading.
            if value == 0xffff_ffff {
                mask &= self.bars[reg_idx - 4].size;
            }
        } else if reg_idx == ROM_BAR_REG {
            // Handle very specific case where the BAR is being written with
            // all 1's on bits 31-11 to retrieve the BAR size during next BAR
            // reading.
            if value & ROM_BAR_ADDR_MASK == ROM_BAR_ADDR_MASK {
                mask &= self.rom_bar_size;
            }
        }

        if let Some(r) = self.registers.get_mut(reg_idx) {
            *r = (*r & !self.writable_bits[reg_idx]) | (value & mask);
        } else {
            warn!("bad PCI register write {}", reg_idx);
        }
    }

    /// Writes a 16bit word to `offset`. `offset` must be 16bit aligned.
    pub fn write_word(&mut self, offset: usize, value: u16) {
        let shift = match offset % 4 {
            0 => 0,
            2 => 16,
            _ => {
                warn!("bad PCI config write offset {}", offset);
                return;
            }
        };
        let reg_idx = offset / 4;

        if let Some(r) = self.registers.get_mut(reg_idx) {
            let writable_mask = self.writable_bits[reg_idx];
            let mask = (0xffffu32 << shift) & writable_mask;
            let shifted_value = (u32::from(value) << shift) & writable_mask;
            *r = *r & !mask | shifted_value;
        } else {
            warn!("bad PCI config write offset {}", offset);
        }
    }

    /// Writes a byte to `offset`.
    pub fn write_byte(&mut self, offset: usize, value: u8) {
        self.write_byte_internal(offset, value, true);
    }

    /// Writes a byte to `offset`, optionally enforcing read-only bits.
    fn write_byte_internal(&mut self, offset: usize, value: u8, apply_writable_mask: bool) {
        let shift = (offset % 4) * 8;
        let reg_idx = offset / 4;

        if let Some(r) = self.registers.get_mut(reg_idx) {
            let writable_mask = if apply_writable_mask {
                self.writable_bits[reg_idx]
            } else {
                0xffff_ffff
            };
            let mask = (0xffu32 << shift) & writable_mask;
            let shifted_value = (u32::from(value) << shift) & writable_mask;
            *r = *r & !mask | shifted_value;
        } else {
            warn!("bad PCI config write offset {}", offset);
        }
    }

    /// Adds a region specified by `config`.  Configures the specified BAR(s) to
    /// report this region and size to the guest kernel.  Enforces a few constraints
    /// (i.e, region size must be power of two, register not already used).
    pub fn add_pci_bar(&mut self, config: &PciBarConfiguration) -> Result<()> {
        let bar_idx = config.idx;
        let reg_idx = BAR0_REG + bar_idx;

        if bar_idx >= NUM_BAR_REGS {
            return Err(Error::BarInvalid(bar_idx));
        }

        if self.bars[bar_idx].used {
            return Err(Error::BarInUse(bar_idx));
        }

        if !config.size.is_power_of_two() {
            return Err(Error::BarSizeInvalid(config.size));
        }

        let end_addr = config
            .addr
            .checked_add(config.size - 1)
            .ok_or(Error::BarAddressInvalid(config.addr, config.size))?;
        match config.region_type {
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::IoRegion => {
                if end_addr > u64::from(u32::MAX) {
                    return Err(Error::BarAddressInvalid(config.addr, config.size));
                }

                // Encode the BAR size as expected by the software running in
                // the guest.
                self.bars[bar_idx].size =
                    encode_32_bits_bar_size(config.size as u32).ok_or(Error::Encode32BarSize)?;
            }
            PciBarRegionType::Memory64BitRegion => {
                if bar_idx + 1 >= NUM_BAR_REGS {
                    return Err(Error::BarInvalid64(bar_idx));
                }

                if self.bars[bar_idx + 1].used {
                    return Err(Error::BarInUse64(bar_idx + 1));
                }

                // Encode the BAR size as expected by the software running in
                // the guest.
                let (bar_size_hi, bar_size_lo) =
                    encode_64_bits_bar_size(config.size).ok_or(Error::Encode64BarSize)?;

                self.registers[reg_idx + 1] = (config.addr >> 32) as u32;
                self.writable_bits[reg_idx + 1] = 0xffff_ffff;
                self.bars[bar_idx + 1].addr = self.registers[reg_idx + 1];
                self.bars[bar_idx].size = bar_size_lo;
                self.bars[bar_idx + 1].size = bar_size_hi;
                self.bars[bar_idx + 1].used = true;
            }
        }

        let (mask, lower_bits) = match config.region_type {
            PciBarRegionType::Memory32BitRegion | PciBarRegionType::Memory64BitRegion => (
                BAR_MEM_ADDR_MASK,
                config.prefetchable as u32 | config.region_type as u32,
            ),
            PciBarRegionType::IoRegion => (BAR_IO_ADDR_MASK, config.region_type as u32),
        };

        self.registers[reg_idx] = ((config.addr as u32) & mask) | lower_bits;
        self.writable_bits[reg_idx] = mask;
        self.bars[bar_idx].addr = self.registers[reg_idx];
        self.bars[bar_idx].used = true;
        self.bars[bar_idx].r#type = Some(config.region_type);

        Ok(())
    }

    /// Returns the address of the given BAR region.
    pub fn get_bar_addr(&self, bar_num: usize) -> u64 {
        let bar_idx = BAR0_REG + bar_num;

        let mut addr = u64::from(self.bars[bar_num].addr & self.writable_bits[bar_idx]);

        if let Some(bar_type) = self.bars[bar_num].r#type {
            if bar_type == PciBarRegionType::Memory64BitRegion {
                addr |= u64::from(self.bars[bar_num + 1].addr) << 32;
            }
        }

        addr
    }

    /// Adds the capability `cap_data` to the list of capabilities.
    ///
    /// `cap_data` should not include the two-byte PCI capability header (type, next).
    /// Correct values will be generated automatically based on `cap_data.id()` and
    /// `cap_data.len()`.
    pub fn add_capability(&mut self, cap_data: &dyn PciCapability) -> Result<usize> {
        let total_len = cap_data.bytes().len() + 2;
        let (cap_offset, tail_offset) = match self.last_capability {
            Some((offset, len)) => (Self::next_dword(offset, len), offset + 1),
            None => (FIRST_CAPABILITY_OFFSET, CAPABILITY_LIST_HEAD_OFFSET),
        };
        let end_offset = cap_offset
            .checked_add(total_len)
            .ok_or(Error::CapabilitySpaceFull(total_len))?;
        if end_offset > CAPABILITY_MAX_OFFSET {
            return Err(Error::CapabilitySpaceFull(total_len));
        }
        self.registers[STATUS_REG] |= STATUS_REG_CAPABILITIES_USED_MASK;
        self.write_byte_internal(tail_offset, cap_offset as u8, false);
        self.write_byte_internal(cap_offset, cap_data.id() as u8, false);
        self.write_byte_internal(cap_offset + 1, 0, false); // Next pointer.
        for (i, byte) in cap_data.bytes().iter().enumerate() {
            self.write_byte_internal(cap_offset + i + 2, *byte, false);
        }
        self.last_capability = Some((cap_offset, total_len));

        match cap_data.id() {
            PciCapabilityId::MessageSignalledInterrupts => {
                self.writable_bits[cap_offset / 4] = MSI_CAPABILITY_REGISTER_MASK;
            }
            PciCapabilityId::MsiX => {
                self.msix_cap_reg_idx = Some(cap_offset / 4);
                self.writable_bits[self.msix_cap_reg_idx.unwrap()] = MSIX_CAPABILITY_REGISTER_MASK;
            }
            _ => {}
        }

        Ok(cap_offset)
    }

    // Find the next aligned offset after the one given.
    fn next_dword(offset: usize, len: usize) -> usize {
        let next = offset + len;
        (next + 3) & !3
    }

    pub fn write_config_register(&mut self, reg_idx: usize, offset: u64, data: &[u8]) {
        if reg_idx >= NUM_CONFIGURATION_REGISTERS {
            return;
        }

        if offset as usize + data.len() > 4 {
            return;
        }

        // Handle potential write to MSI-X message control register
        if let Some(msix_cap_reg_idx) = self.msix_cap_reg_idx {
            if let Some(msix_config) = &self.msix_config {
                if msix_cap_reg_idx == reg_idx && offset == 2 && data.len() == 2 {
                    // 2-bytes write in the Message Control field
                    msix_config
                        .lock()
                        .unwrap()
                        .set_msg_ctl(LittleEndian::read_u16(data));
                } else if msix_cap_reg_idx == reg_idx && offset == 0 && data.len() == 4 {
                    // 4 bytes write at the beginning. Ignore the first 2 bytes which are the
                    // capability id and next capability pointer
                    msix_config
                        .lock()
                        .unwrap()
                        .set_msg_ctl((LittleEndian::read_u32(data) >> 16) as u16);
                }
            }
        }

        match data.len() {
            1 => self.write_byte(reg_idx * 4 + offset as usize, data[0]),
            2 => self.write_word(
                reg_idx * 4 + offset as usize,
                u16::from(data[0]) | (u16::from(data[1]) << 8),
            ),
            4 => self.write_reg(reg_idx, LittleEndian::read_u32(data)),
            _ => (),
        }
    }

    pub fn detect_bar_reprogramming(
        &mut self,
        reg_idx: usize,
        data: &[u8],
    ) -> Option<BarReprogrammingParams> {
        if data.len() != 4 {
            return None;
        }

        let value = LittleEndian::read_u32(data);

        let mask = self.writable_bits[reg_idx];
        if (BAR0_REG..BAR0_REG + NUM_BAR_REGS).contains(&reg_idx) {
            // Ignore the case where the BAR size is being asked for.
            if value == 0xffff_ffff {
                return None;
            }

            let bar_idx = reg_idx - 4;
            // Handle special case where the address being written is
            // different from the address initially provided. This is a
            // BAR reprogramming case which needs to be properly caught.
            if let Some(bar_type) = self.bars[bar_idx].r#type {
                // In case of 64 bits memory BAR, we don't do anything until
                // the upper BAR is modified, otherwise we would be moving the
                // BAR to a wrong location in memory.
                if bar_type == PciBarRegionType::Memory64BitRegion {
                    return None;
                }

                // Ignore the case where the value is unchanged.
                if (value & mask) == (self.bars[bar_idx].addr & mask) {
                    return None;
                }

                info!(
                    "Detected BAR reprogramming: (BAR {}) 0x{:x}->0x{:x}",
                    reg_idx, self.registers[reg_idx], value
                );
                let old_base = u64::from(self.bars[bar_idx].addr & mask);
                let new_base = u64::from(value & mask);
                let len = u64::from(
                    decode_32_bits_bar_size(self.bars[bar_idx].size)
                        .ok_or(Error::Decode32BarSize)
                        .unwrap(),
                );
                let region_type = bar_type;

                self.bars[bar_idx].addr = value;

                return Some(BarReprogrammingParams {
                    old_base,
                    new_base,
                    len,
                    region_type,
                });
            } else if (reg_idx > BAR0_REG)
                && (
                    // The lower BAR (of this 64bit BAR) has been reprogrammed to a different value
                    // than it used to be
                    (self.registers[reg_idx - 1] & self.writable_bits[reg_idx - 1])
                    != (self.bars[bar_idx - 1].addr & self.writable_bits[reg_idx - 1]) ||
                    // Or the lower BAR hasn't been changed but the upper one is being reprogrammed
                    // now to a different value
                    (value & mask) != (self.bars[bar_idx].addr & mask)
                )
            {
                info!(
                    "Detected BAR reprogramming: (BAR {}) 0x{:x}->0x{:x}",
                    reg_idx, self.registers[reg_idx], value
                );
                let old_base = (u64::from(self.bars[bar_idx].addr & mask) << 32)
                    | u64::from(self.bars[bar_idx - 1].addr & self.writable_bits[reg_idx - 1]);
                let new_base = (u64::from(value & mask) << 32)
                    | u64::from(self.registers[reg_idx - 1] & self.writable_bits[reg_idx - 1]);
                let len =
                    decode_64_bits_bar_size(self.bars[bar_idx].size, self.bars[bar_idx - 1].size)
                        .ok_or(Error::Decode64BarSize)
                        .unwrap();
                let region_type = PciBarRegionType::Memory64BitRegion;

                self.bars[bar_idx].addr = value;
                self.bars[bar_idx - 1].addr = self.registers[reg_idx - 1];

                return Some(BarReprogrammingParams {
                    old_base,
                    new_base,
                    len,
                    region_type,
                });
            }
        } else if reg_idx == ROM_BAR_REG && (value & mask) != (self.rom_bar_addr & mask) {
            // Ignore the case where the BAR size is being asked for.
            if value & ROM_BAR_ADDR_MASK == ROM_BAR_ADDR_MASK {
                return None;
            }

            info!(
                "Detected ROM BAR reprogramming: (BAR {}) 0x{:x}->0x{:x}",
                reg_idx, self.registers[reg_idx], value
            );
            let old_base = u64::from(self.rom_bar_addr & mask);
            let new_base = u64::from(value & mask);
            let len = u64::from(
                decode_32_bits_bar_size(self.rom_bar_size)
                    .ok_or(Error::Decode32BarSize)
                    .unwrap(),
            );
            let region_type = PciBarRegionType::Memory32BitRegion;

            self.rom_bar_addr = value;

            return Some(BarReprogrammingParams {
                old_base,
                new_base,
                len,
                region_type,
            });
        }

        None
    }
}

impl Default for PciBarConfiguration {
    fn default() -> Self {
        PciBarConfiguration {
            idx: 0,
            addr: 0,
            size: 0,
            region_type: PciBarRegionType::Memory64BitRegion,
            prefetchable: PciBarPrefetchable::NotPrefetchable,
        }
    }
}

#[cfg(test)]
mod tests {

    use vm_memory::ByteValued;

    use super::*;
    use crate::MsixCap;

    #[repr(C, packed)]
    #[derive(Clone, Copy, Default)]
    #[allow(dead_code)]
    struct TestCap {
        len: u8,
        foo: u8,
    }

    // SAFETY: All members are simple numbers and any value is valid.
    unsafe impl ByteValued for TestCap {}

    impl PciCapability for TestCap {
        fn bytes(&self) -> &[u8] {
            self.as_slice()
        }

        fn id(&self) -> PciCapabilityId {
            PciCapabilityId::VendorSpecific
        }
    }

    struct BadCap {
        data: Vec<u8>,
    }

    impl BadCap {
        fn new(len: u8) -> Self {
            Self {
                data: (0..len).collect(),
            }
        }
    }

    impl PciCapability for BadCap {
        fn bytes(&self) -> &[u8] {
            &self.data
        }

        fn id(&self) -> PciCapabilityId {
            PciCapabilityId::VendorSpecific
        }
    }

    #[test]
    fn add_capability() {
        let mut cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            0x1,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            None,
            PciHeaderType::Device,
            0xABCD,
            0x2468,
            None,
            None,
        );

        // Bad size capabilities
        assert!(matches!(
            cfg.add_capability(&BadCap::new(127)),
            Err(Error::CapabilitySpaceFull(129))
        ));
        cfg.add_capability(&BadCap::new(62)).unwrap();
        cfg.add_capability(&BadCap::new(62)).unwrap();
        assert!(matches!(
            cfg.add_capability(&BadCap::new(0)),
            Err(Error::CapabilitySpaceFull(2))
        ));
        // Reset capabilities
        cfg.last_capability = None;

        // Add two capabilities with different contents.
        let cap1 = TestCap { len: 4, foo: 0xAA };
        let cap1_offset = cfg.add_capability(&cap1).unwrap();
        assert_eq!(cap1_offset % 4, 0);

        let cap2 = TestCap {
            len: 0x04,
            foo: 0x55,
        };
        let cap2_offset = cfg.add_capability(&cap2).unwrap();
        assert_eq!(cap2_offset % 4, 0);

        // The capability list head should be pointing to cap1.
        let cap_ptr = cfg.read_reg(CAPABILITY_LIST_HEAD_OFFSET / 4) & 0xFF;
        assert_eq!(cap1_offset, cap_ptr as usize);

        // Verify the contents of the capabilities.
        let cap1_data = cfg.read_reg(cap1_offset / 4);
        assert_eq!(cap1_data & 0xFF, 0x09); // capability ID
        assert_eq!((cap1_data >> 8) & 0xFF, cap2_offset as u32); // next capability pointer
        assert_eq!((cap1_data >> 16) & 0xFF, 0x04); // cap1.len
        assert_eq!((cap1_data >> 24) & 0xFF, 0xAA); // cap1.foo

        let cap2_data = cfg.read_reg(cap2_offset / 4);
        assert_eq!(cap2_data & 0xFF, 0x09); // capability ID
        assert_eq!((cap2_data >> 8) & 0xFF, 0x00); // next capability pointer
        assert_eq!((cap2_data >> 16) & 0xFF, 0x04); // cap2.len
        assert_eq!((cap2_data >> 24) & 0xFF, 0x55); // cap2.foo
    }

    #[test]
    fn test_msix_capability() {
        let mut cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            0x1,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            None,
            PciHeaderType::Device,
            0xABCD,
            0x2468,
            None,
            None,
        );

        // Information about the MSI-X capability layout: https://wiki.osdev.org/PCI#Enabling_MSI-X
        let msix_cap = MsixCap::new(
            3,      // Using BAR3 for message control table
            1024,   // 1024 MSI-X vectors
            0x4000, // Offset of message control table inside the BAR
            4,      // BAR4 used for pending control bit
            0x420,  // Offset of pending bit array (PBA) inside BAR
        );
        cfg.add_capability(&msix_cap).unwrap();

        let cap_reg = FIRST_CAPABILITY_OFFSET / 4;
        let reg = cfg.read_reg(cap_reg);
        // Capability ID is MSI-X
        assert_eq!(
            PciCapabilityId::from((reg & 0xff) as u8),
            PciCapabilityId::MsiX
        );
        // We only have one capability, so `next` should be 0
        assert_eq!(((reg >> 8) & 0xff) as u8, 0);
        let msg_ctl = (reg >> 16) as u16;

        // MSI-X is enabled
        assert_eq!(msg_ctl & 0x8000, 0x8000);
        // Vectors are not masked
        assert_eq!(msg_ctl & 0x4000, 0x0);
        // Reserved bits are 0
        assert_eq!(msg_ctl & 0x3800, 0x0);
        // We've got 1024 vectors (Table size is N-1 encoded)
        assert_eq!((msg_ctl & 0x7ff) + 1, 1024);

        let reg = cfg.read_reg(cap_reg + 1);
        // We are using BAR3
        assert_eq!(reg & 0x7, 3);
        // Message Control Table is located in offset 0x4000 inside the BAR
        // We don't need to shift. Offset needs to be 8-byte aligned - so BIR
        // is stored in its last 3 bits (which we need to mask out).
        assert_eq!(reg & 0xffff_fff8, 0x4000);

        let reg = cfg.read_reg(cap_reg + 2);
        // PBA is 0x420 bytes inside BAR4
        assert_eq!(reg & 0x7, 4);
        assert_eq!(reg & 0xffff_fff8, 0x420);

        // Check read/write mask
        // Capability Id of MSI-X is 0x11
        cfg.write_config_register(cap_reg, 0, &[0x0]);
        assert_eq!(
            PciCapabilityId::from((cfg.read_reg(cap_reg) & 0xff) as u8),
            PciCapabilityId::MsiX
        );
        // Cannot override next capability pointer
        cfg.write_config_register(cap_reg, 1, &[0x42]);
        assert_eq!((cfg.read_reg(cap_reg) >> 8) & 0xff, 0);

        // We are writing this:
        //
        // meaning: | MSI enabled | Vectors Masked | Reserved | Table size |
        // bit:     |     15      |       14       |  13 - 11 |   0 - 10   |
        // R/W:     |     R/W     |       R/W      |     R    |     R      |
        let msg_ctl = (cfg.read_reg(cap_reg) >> 16) as u16;
        // Try to flip all bits
        cfg.write_config_register(cap_reg, 2, &u16::to_le_bytes(!msg_ctl));
        let msg_ctl = (cfg.read_reg(cap_reg) >> 16) as u16;
        // MSI enabled and Vectors masked should be flipped (MSI disabled and vectors masked)
        assert_eq!(msg_ctl & 0xc000, 0x4000);
        // Reserved bits should still be 0
        assert_eq!(msg_ctl & 0x3800, 0);
        // Table size should not have changed
        assert_eq!((msg_ctl & 0x07ff) + 1, 1024);

        // Table offset is read only
        let table_offset = cfg.read_reg(cap_reg + 1);
        // Try to flip all bits
        cfg.write_config_register(cap_reg + 1, 0, &u32::to_le_bytes(!table_offset));
        // None should be flipped
        assert_eq!(cfg.read_reg(cap_reg + 1), table_offset);

        // PBA offset also
        let pba_offset = cfg.read_reg(cap_reg + 2);
        // Try to flip all bits
        cfg.write_config_register(cap_reg + 2, 0, &u32::to_le_bytes(!pba_offset));
        // None should be flipped
        assert_eq!(cfg.read_reg(cap_reg + 2), pba_offset);
    }

    #[derive(Copy, Clone)]
    enum TestPi {
        Test = 0x5a,
    }

    impl PciProgrammingInterface for TestPi {
        fn get_register_value(&self) -> u8 {
            *self as u8
        }
    }

    #[test]
    fn class_code() {
        let cfg = PciConfiguration::new(
            0x1234,
            0x5678,
            0x1,
            PciClassCode::MultimediaController,
            &PciMultimediaSubclass::AudioController,
            Some(&TestPi::Test),
            PciHeaderType::Device,
            0xABCD,
            0x2468,
            None,
            None,
        );

        let class_reg = cfg.read_reg(2);
        let class_code = (class_reg >> 24) & 0xFF;
        let subclass = (class_reg >> 16) & 0xFF;
        let prog_if = (class_reg >> 8) & 0xFF;
        assert_eq!(class_code, 0x04);
        assert_eq!(subclass, 0x01);
        assert_eq!(prog_if, 0x5a);
    }

    #[test]
    fn test_bar_size_encoding() {
        assert!(encode_32_bits_bar_size(0).is_none());
        assert!(decode_32_bits_bar_size(0).is_none());
        assert!(encode_64_bits_bar_size(0).is_none());
        assert!(decode_64_bits_bar_size(0, 0).is_none());

        // According to OSDev wiki (https://wiki.osdev.org/PCI#Address_and_size_of_the_BAR):
        //
        // > To determine the amount of address space needed by a PCI device, you must save the
        // > original value of the BAR, write a value of all 1's to the register, then read it back.
        // > The amount of memory can then be determined by masking the information bits, performing
        // > a bitwise NOT ('~' in C), and incrementing the value by 1. The original value of the
        // BAR > should then be restored. The BAR register is naturally aligned and as such you can
        // only > modify the bits that are set. For example, if a device utilizes 16 MB it will
        // have BAR0 > filled with 0xFF000000 (0x1000000 after decoding) and you can only modify
        // the upper > 8-bits.
        //
        // So we should be encoding an address like this: `addr` -> `!(addr - 1)`
        let encoded = encode_32_bits_bar_size(0x0101_0101).unwrap();
        assert_eq!(encoded, 0xfefe_feff);
        assert_eq!(decode_32_bits_bar_size(encoded), Some(0x0101_0101));

        // Similarly we encode a 64 bits size and then store it as a 2 32bit addresses (we use
        // two BARs).
        let (hi, lo) = encode_64_bits_bar_size(0xffff_ffff_ffff_fff0).unwrap();
        assert_eq!(hi, 0);
        assert_eq!(lo, 0x0000_0010);
        assert_eq!(decode_64_bits_bar_size(hi, lo), Some(0xffff_ffff_ffff_fff0));
    }

    #[test]
    fn test_add_pci_bar() {
        let mut pci_config = PciConfiguration::new(
            0x42,
            0x0,
            0x0,
            PciClassCode::MassStorage,
            &PciMassStorageSubclass::SerialScsiController,
            None,
            PciHeaderType::Device,
            0x13,
            0x12,
            None,
            None,
        );

        // BAR size can only be a power of 2
        assert!(matches!(
            pci_config.add_pci_bar(&PciBarConfiguration {
                addr: 0x1000,
                size: 0x1001,
                idx: 0,
                region_type: PciBarRegionType::Memory32BitRegion,
                prefetchable: PciBarPrefetchable::Prefetchable,
            }),
            Err(Error::BarSizeInvalid(0x1001))
        ));

        // Invalid BAR index
        assert!(matches!(
            pci_config.add_pci_bar(&PciBarConfiguration {
                addr: 0x1000,
                size: 0x1000,
                idx: NUM_BAR_REGS,
                region_type: PciBarRegionType::Memory32BitRegion,
                prefetchable: PciBarPrefetchable::Prefetchable
            }),
            Err(Error::BarInvalid(NUM_BAR_REGS))
        ));
        // 64bit BARs need 2 BAR slots actually
        assert!(matches!(
            pci_config.add_pci_bar(&PciBarConfiguration {
                addr: 0x1000,
                size: 0x1000,
                idx: NUM_BAR_REGS - 1,
                region_type: PciBarRegionType::Memory64BitRegion,
                prefetchable: PciBarPrefetchable::Prefetchable
            }),
            Err(Error::BarInvalid64(_))
        ));

        // Check for valid addresses
        // Can't have an address that exceeds 32 bits for a 32bit BAR
        assert!(matches!(
            pci_config.add_pci_bar(&PciBarConfiguration {
                addr: 0x1000_0000_0000_0000,
                size: 0x1000,
                idx: 0,
                region_type: PciBarRegionType::Memory32BitRegion,
                prefetchable: PciBarPrefetchable::Prefetchable
            }),
            Err(Error::BarAddressInvalid(0x1000_0000_0000_0000, 0x1000))
        ));
        // Ensure that we handle properly overflows in 64bit BAR ranges
        assert!(matches!(
            pci_config.add_pci_bar(&PciBarConfiguration {
                addr: u64::MAX,
                size: 0x2,
                idx: 0,
                region_type: PciBarRegionType::Memory64BitRegion,
                prefetchable: PciBarPrefetchable::Prefetchable
            }),
            Err(Error::BarAddressInvalid(u64::MAX, 2))
        ));

        // We can't reuse a BAR slot
        pci_config
            .add_pci_bar(&PciBarConfiguration {
                addr: 0x1000,
                size: 0x1000,
                idx: 0,
                region_type: PciBarRegionType::Memory32BitRegion,
                prefetchable: PciBarPrefetchable::Prefetchable,
            })
            .unwrap();
        assert!(matches!(
            pci_config.add_pci_bar(&PciBarConfiguration {
                addr: 0x1000,
                size: 0x1000,
                idx: 0,
                region_type: PciBarRegionType::Memory32BitRegion,
                prefetchable: PciBarPrefetchable::Prefetchable,
            }),
            Err(Error::BarInUse(0))
        ));
        pci_config
            .add_pci_bar(&PciBarConfiguration {
                addr: 0x0000_0001_0000_0000,
                size: 0x2000,
                idx: 2,
                region_type: PciBarRegionType::Memory64BitRegion,
                prefetchable: PciBarPrefetchable::Prefetchable,
            })
            .unwrap();
        // For 64bit BARs two BARs are used (in this case BARs 1 and 2)
        assert!(matches!(
            pci_config.add_pci_bar(&PciBarConfiguration {
                addr: 0x0000_0001_0000_0000,
                size: 0x1000,
                idx: 2,
                region_type: PciBarRegionType::Memory64BitRegion,
                prefetchable: PciBarPrefetchable::Prefetchable,
            }),
            Err(Error::BarInUse(2))
        ));
        assert!(matches!(
            pci_config.add_pci_bar(&PciBarConfiguration {
                addr: 0x0000_0001_0000_0000,
                size: 0x1000,
                idx: 1,
                region_type: PciBarRegionType::Memory64BitRegion,
                prefetchable: PciBarPrefetchable::Prefetchable,
            }),
            Err(Error::BarInUse64(2))
        ));

        assert_eq!(pci_config.get_bar_addr(0), 0x1000);
        assert_eq!(pci_config.get_bar_addr(2), 0x1_0000_0000);
    }

    #[test]
    fn test_access_invalid_reg() {
        let mut pci_config = PciConfiguration::new(
            0x42,
            0x0,
            0x0,
            PciClassCode::MassStorage,
            &PciMassStorageSubclass::SerialScsiController,
            None,
            PciHeaderType::Device,
            0x13,
            0x12,
            None,
            None,
        );

        // Can't read past the end of the configuration space
        assert_eq!(
            pci_config.read_reg(NUM_CONFIGURATION_REGISTERS),
            0xffff_ffff
        );

        // Read out all of configuration space
        let config_space: Vec<u32> = (0..NUM_CONFIGURATION_REGISTERS)
            .map(|reg_idx| pci_config.read_reg(reg_idx))
            .collect();

        // Various invalid write accesses

        // Past the end of config space
        pci_config.write_config_register(NUM_CONFIGURATION_REGISTERS, 0, &[0x42]);
        pci_config.write_config_register(NUM_CONFIGURATION_REGISTERS, 0, &[0x42, 0x42]);
        pci_config.write_config_register(NUM_CONFIGURATION_REGISTERS, 0, &[0x42, 0x42, 0x42, 0x42]);

        // Past register boundaries
        pci_config.write_config_register(NUM_CONFIGURATION_REGISTERS, 1, &[0x42, 0x42, 0x42, 0x42]);
        pci_config.write_config_register(NUM_CONFIGURATION_REGISTERS, 2, &[0x42, 0x42, 0x42]);
        pci_config.write_config_register(NUM_CONFIGURATION_REGISTERS, 3, &[0x42, 0x42]);
        pci_config.write_config_register(NUM_CONFIGURATION_REGISTERS, 4, &[0x42]);
        pci_config.write_config_register(NUM_CONFIGURATION_REGISTERS, 5, &[]);

        for (reg_idx, reg) in config_space.iter().enumerate() {
            assert_eq!(*reg, pci_config.read_reg(reg_idx));
        }
    }

    #[test]
    fn test_detect_bar_reprogramming() {
        let mut pci_config = PciConfiguration::new(
            0x42,
            0x0,
            0x0,
            PciClassCode::MassStorage,
            &PciMassStorageSubclass::SerialScsiController,
            None,
            PciHeaderType::Device,
            0x13,
            0x12,
            None,
            None,
        );

        // Trying to reprogram with something less than 4 bytes (length of the address) should fail
        assert!(pci_config
            .detect_bar_reprogramming(BAR0_REG, &[0x13])
            .is_none());
        assert!(pci_config
            .detect_bar_reprogramming(BAR0_REG, &[0x13, 0x12])
            .is_none());
        assert!(pci_config
            .detect_bar_reprogramming(BAR0_REG, &[0x13, 0x12])
            .is_none());
        assert!(pci_config
            .detect_bar_reprogramming(BAR0_REG, &[0x13, 0x12, 0x16])
            .is_none());

        // Writing all 1s is a special case where we're actually asking for the size of the BAR
        assert!(pci_config
            .detect_bar_reprogramming(BAR0_REG, &u32::to_le_bytes(0xffff_ffff))
            .is_none());

        // Trying to reprogram a BAR that hasn't be initialized does nothing
        for reg_idx in BAR0_REG..BAR0_REG + NUM_BAR_REGS {
            assert!(pci_config
                .detect_bar_reprogramming(reg_idx, &u32::to_le_bytes(0x1312_4243))
                .is_none());
        }

        // Reprogramming of a 32bit BAR
        pci_config
            .add_pci_bar(&PciBarConfiguration {
                addr: 0x1000,
                size: 0x1000,
                idx: 0,
                region_type: PciBarRegionType::Memory32BitRegion,
                prefetchable: PciBarPrefetchable::Prefetchable,
            })
            .unwrap();

        assert_eq!(
            pci_config.detect_bar_reprogramming(BAR0_REG, &u32::to_le_bytes(0x2000)),
            Some(BarReprogrammingParams {
                old_base: 0x1000,
                new_base: 0x2000,
                len: 0x1000,
                region_type: PciBarRegionType::Memory32BitRegion
            })
        );

        pci_config.write_config_register(BAR0_REG, 0, &u32::to_le_bytes(0x2000));
        assert_eq!(pci_config.read_reg(BAR0_REG) & 0xffff_fff0, 0x2000);

        // Attempting to reprogram the BAR with the same address should not have any effect
        assert!(pci_config
            .detect_bar_reprogramming(BAR0_REG, &u32::to_le_bytes(0x2000))
            .is_none());

        // Reprogramming of a 64bit BAR
        pci_config
            .add_pci_bar(&PciBarConfiguration {
                addr: 0x13_1200_0000,
                size: 0x8000,
                idx: 1,
                region_type: PciBarRegionType::Memory64BitRegion,
                prefetchable: PciBarPrefetchable::Prefetchable,
            })
            .unwrap();

        assert_eq!(pci_config.read_reg(BAR0_REG + 1) & 0xffff_fff0, 0x1200_0000);
        assert_eq!(
            pci_config.bars[1].r#type,
            Some(PciBarRegionType::Memory64BitRegion)
        );
        assert_eq!(pci_config.read_reg(BAR0_REG + 2), 0x13);
        assert!(pci_config.bars[2].r#type.is_none());

        // First we write the lower 32 bits and this shouldn't cause any reprogramming
        assert!(pci_config
            .detect_bar_reprogramming(BAR0_REG + 1, &u32::to_le_bytes(0x4200_0000))
            .is_none());
        pci_config.write_config_register(BAR0_REG + 1, 0, &u32::to_le_bytes(0x4200_0000));

        // Writing the upper 32 bits should trigger the reprogramming
        assert_eq!(
            pci_config.detect_bar_reprogramming(BAR0_REG + 2, &u32::to_le_bytes(0x84)),
            Some(BarReprogrammingParams {
                old_base: 0x13_1200_0000,
                new_base: 0x84_4200_0000,
                len: 0x8000,
                region_type: PciBarRegionType::Memory64BitRegion
            })
        );
        pci_config.write_config_register(BAR0_REG + 2, 0, &u32::to_le_bytes(0x84));

        // Trying to reprogram the upper bits directly (without first touching the lower bits)
        // should trigger a reprogramming
        assert_eq!(
            pci_config.detect_bar_reprogramming(BAR0_REG + 2, &u32::to_le_bytes(0x1312)),
            Some(BarReprogrammingParams {
                old_base: 0x84_4200_0000,
                new_base: 0x1312_4200_0000,
                len: 0x8000,
                region_type: PciBarRegionType::Memory64BitRegion
            })
        );
        pci_config.write_config_register(BAR0_REG + 2, 0, &u32::to_le_bytes(0x1312));

        // Attempting to reprogram the BAR with the same address should not have any effect
        assert!(pci_config
            .detect_bar_reprogramming(BAR0_REG + 1, &u32::to_le_bytes(0x4200_0000))
            .is_none());
        assert!(pci_config
            .detect_bar_reprogramming(BAR0_REG + 2, &u32::to_le_bytes(0x1312))
            .is_none());
    }
}
