// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Emulation of the PCI Express Capability structure (PCI capability ID `0x10`).
//!
//! This models the register layout defined in the PCI Express Base
//! Specification, Rev. 4.0, §7.5.3.

use vm_memory::ByteValued;

use crate::pci::PciCapabilityId;
use crate::pci::configuration::PciCapability;

// -------------------------------------------------------------------------
// Register offsets, relative to the first byte of the capability (the
// capability ID byte). These match the `PCI_EXP_*` offsets in the Linux
// `include/uapi/linux/pci_regs.h` header.
// -------------------------------------------------------------------------

/// PCI Express Capabilities Register (16-bit).
pub const PCI_EXP_FLAGS: u16 = 0x02;
/// Device Capabilities Register (32-bit).
pub const PCI_EXP_DEVCAP: u16 = 0x04;
/// Device Control Register (16-bit).
pub const PCI_EXP_DEVCTL: u16 = 0x08;
/// Device Status Register (16-bit).
pub const PCI_EXP_DEVSTA: u16 = 0x0a;
/// Link Capabilities Register (32-bit).
pub const PCI_EXP_LNKCAP: u16 = 0x0c;
/// Link Control Register (16-bit).
pub const PCI_EXP_LNKCTL: u16 = 0x10;
/// Link Status Register (16-bit).
pub const PCI_EXP_LNKSTA: u16 = 0x12;
/// Slot Capabilities Register (32-bit).
pub const PCI_EXP_SLTCAP: u16 = 0x14;
/// Slot Control Register (16-bit).
pub const PCI_EXP_SLTCTL: u16 = 0x18;
/// Slot Status Register (16-bit).
pub const PCI_EXP_SLTSTA: u16 = 0x1a;
/// Root Control Register (16-bit).
pub const PCI_EXP_RTCTL: u16 = 0x1c;
/// Root Capabilities Register (16-bit).
pub const PCI_EXP_RTCAP: u16 = 0x1e;
/// Root Status Register (32-bit).
pub const PCI_EXP_RTSTA: u16 = 0x20;

// -------------------------------------------------------------------------
// PCI Express Capabilities Register (`PCI_EXP_FLAGS`) fields.
// -------------------------------------------------------------------------

/// Capability Version field mask (bits 3:0).
pub const PCI_EXP_FLAGS_VERS: u16 = 0x000f;
/// Device/Port Type field mask (bits 7:4).
pub const PCI_EXP_FLAGS_TYPE: u16 = 0x00f0;
/// Device/Port Type field shift.
pub const PCI_EXP_FLAGS_TYPE_SHIFT: u16 = 4;
/// Slot Implemented bit (bit 8). Only meaningful for Downstream Ports.
pub const PCI_EXP_FLAGS_SLOT: u16 = 0x0100;

/// Device/Port Type: root port of a PCI Express Root Complex. Only valid for
/// Type 1 (bridge) configuration headers.
pub const PCI_EXP_TYPE_ROOT_PORT: u16 = 0x4;

// -------------------------------------------------------------------------
// Slot Capabilities Register (`PCI_EXP_SLTCAP`) fields. PCIe 4.0 §7.5.3.9.
// -------------------------------------------------------------------------

/// Attention Button Present (bit 0).
pub const PCI_EXP_SLTCAP_ABP: u32 = 0x0000_0001;
/// Power Controller Present (bit 1).
pub const PCI_EXP_SLTCAP_PCP: u32 = 0x0000_0002;
/// MRL Sensor Present (bit 2).
pub const PCI_EXP_SLTCAP_MRLSP: u32 = 0x0000_0004;
/// Power Indicator Present (bit 4).
pub const PCI_EXP_SLTCAP_PIP: u32 = 0x0000_0010;
/// Hot-Plug Surprise (bit 5).
pub const PCI_EXP_SLTCAP_HPS: u32 = 0x0000_0020;
/// Hot-Plug Capable (bit 6).
pub const PCI_EXP_SLTCAP_HPC: u32 = 0x0000_0040;
/// Electromechanical Interlock Present (bit 17).
pub const PCI_EXP_SLTCAP_EIP: u32 = 0x0002_0000;
/// No Command Completed Support (bit 18).
pub const PCI_EXP_SLTCAP_NCCS: u32 = 0x0004_0000;
/// Physical Slot Number field shift (bits 31:19).
pub const PCI_EXP_SLTCAP_PSN_SHIFT: u32 = 19;

// -------------------------------------------------------------------------
// Slot Control Register (`PCI_EXP_SLTCTL`) fields. PCIe 4.0 §7.5.3.10.
// -------------------------------------------------------------------------

/// Attention Button Pressed Enable (bit 0).
pub const PCI_EXP_SLTCTL_ABPE: u16 = 0x0001;
/// Power Fault Detected Enable (bit 1).
pub const PCI_EXP_SLTCTL_PFDE: u16 = 0x0002;
/// MRL Sensor Changed Enable (bit 2).
pub const PCI_EXP_SLTCTL_MRLSCE: u16 = 0x0004;
/// Presence Detect Changed Enable (bit 3).
pub const PCI_EXP_SLTCTL_PDCE: u16 = 0x0008;
/// Command Completed Interrupt Enable (bit 4).
pub const PCI_EXP_SLTCTL_CCIE: u16 = 0x0010;
/// Hot-Plug Interrupt Enable (bit 5).
pub const PCI_EXP_SLTCTL_HPIE: u16 = 0x0020;
/// Attention Indicator Control field mask (bits 7:6).
pub const PCI_EXP_SLTCTL_AIC: u16 = 0x00c0;
/// Power Indicator Control field mask (bits 9:8).
pub const PCI_EXP_SLTCTL_PIC: u16 = 0x0300;
/// Power Indicator Control encoding for "off" (both bits set).
pub const PCI_EXP_SLTCTL_PWR_IND_OFF: u16 = 0x0300;
/// Power Controller Control (bit 10). Off = 1, On = 0.
pub const PCI_EXP_SLTCTL_PCC: u16 = 0x0400;
/// Electromechanical Interlock Control (bit 11).
pub const PCI_EXP_SLTCTL_EIC: u16 = 0x0800;
/// Data Link Layer State Changed Enable (bit 12).
pub const PCI_EXP_SLTCTL_DLLSCE: u16 = 0x1000;

// -------------------------------------------------------------------------
// Slot Status Register (`PCI_EXP_SLTSTA`) fields. PCIe 4.0 §7.5.3.11.
// The change bits (0-4, 8) are write-1-to-clear.
// -------------------------------------------------------------------------

/// Attention Button Pressed (bit 0, RW1C).
pub const PCI_EXP_SLTSTA_ABP: u16 = 0x0001;
/// Power Fault Detected (bit 1, RW1C).
pub const PCI_EXP_SLTSTA_PFD: u16 = 0x0002;
/// MRL Sensor Changed (bit 2, RW1C).
pub const PCI_EXP_SLTSTA_MRLSC: u16 = 0x0004;
/// Presence Detect Changed (bit 3, RW1C).
pub const PCI_EXP_SLTSTA_PDC: u16 = 0x0008;
/// Command Completed (bit 4, RW1C).
pub const PCI_EXP_SLTSTA_CC: u16 = 0x0010;
/// MRL Sensor State (bit 5, RO).
pub const PCI_EXP_SLTSTA_MRLSS: u16 = 0x0020;
/// Presence Detect State (bit 6, RO).
pub const PCI_EXP_SLTSTA_PDS: u16 = 0x0040;
/// Electromechanical Interlock Status (bit 7, RO).
pub const PCI_EXP_SLTSTA_EIS: u16 = 0x0080;
/// Data Link Layer State Changed (bit 8, RW1C).
pub const PCI_EXP_SLTSTA_DLLSC: u16 = 0x0100;

/// Mask of all write-1-to-clear bits in the Slot Status register.
pub const PCI_EXP_SLTSTA_RW1C: u16 = PCI_EXP_SLTSTA_ABP
    | PCI_EXP_SLTSTA_PFD
    | PCI_EXP_SLTSTA_MRLSC
    | PCI_EXP_SLTSTA_PDC
    | PCI_EXP_SLTSTA_CC
    | PCI_EXP_SLTSTA_DLLSC;

// -------------------------------------------------------------------------
// Link Capabilities / Status fields relevant to hot-plug.
// -------------------------------------------------------------------------

/// Data Link Layer Link Active Reporting Capable (Link Capabilities bit 20).
pub const PCI_EXP_LNKCAP_DLLLARC: u32 = 0x0010_0000;
/// Data Link Layer Link Active (Link Status bit 13).
pub const PCI_EXP_LNKSTA_DLLLA: u16 = 0x2000;

/// Capability Version 2 value for the Capability Version field.
pub const PCI_EXP_FLAGS_VERSION_2: u16 = 0x2;

/// The PCI Express Capability structure, version 2 (PCIe 4.0 §7.5.3).
///
/// The layout begins at the PCI Express Capabilities Register; the two-byte
/// generic capability header (Capability ID and Next Pointer) is prepended by
/// PciConfiguration::add_capability().
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PciExpressCap {
    pcie_caps: u16,
    dev_caps: u32,
    dev_control: u16,
    dev_status: u16,
    link_caps: u32,
    link_control: u16,
    link_status: u16,
    slot_caps: u32,
    slot_control: u16,
    slot_status: u16,
    root_control: u16,
    root_caps: u16,
    root_status: u32,
    dev_caps2: u32,
    dev_control2: u16,
    dev_status2: u16,
    link_caps2: u32,
    link_control2: u16,
    link_status2: u16,
    slot_caps2: u32,
    slot_control2: u16,
    slot_status2: u16,
}

// SAFETY: `PciExpressCap` is `#[repr(C, packed)]` and contains only unsigned
// integer fields, so it has no padding and every possible byte pattern is a
// valid value.
unsafe impl ByteValued for PciExpressCap {}

impl PciCapability for PciExpressCap {
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn id(&self) -> PciCapabilityId {
        PciCapabilityId::PciExpress
    }
}

impl PciExpressCap {
    /// Build the PCI Express Capability for a hot-plug capable root port.
    pub fn new_root_port(slot_number: u16) -> Self {
        let pcie_caps = PCI_EXP_FLAGS_VERSION_2
            | (PCI_EXP_TYPE_ROOT_PORT << PCI_EXP_FLAGS_TYPE_SHIFT)
            | PCI_EXP_FLAGS_SLOT;

        let psn = (u32::from(slot_number) & 0x1fff) << PCI_EXP_SLTCAP_PSN_SHIFT;

        let slot_caps = PCI_EXP_SLTCAP_HPC // Hot-Plug Capable
            | PCI_EXP_SLTCAP_ABP           // Attention Button Present
            | PCI_EXP_SLTCAP_PIP           // Power Indicator Present
            | PCI_EXP_SLTCAP_NCCS          // No Command Completed Support
            | psn;

        // 2.5 GT/s, x1 width, and Data Link Layer Link Active reporting capable
        let link_caps = 0x1 | (0x1 << 4) | PCI_EXP_LNKCAP_DLLLARC;

        PciExpressCap {
            pcie_caps,
            link_caps,
            slot_caps,
            ..Default::default()
        }
    }
}
