// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vfio_bindings::bindings::vfio::*;
pub use vfio_ioctls::{
    VfioContainer, VfioDevice as InternalVfioDevice, VfioDeviceFd, VfioRegionInfoCap,
    VfioRegionInfoCapSparseMmap, VfioRegionSparseMmapArea,
};
use zerocopy::IntoBytes;

use crate::logger::debug;
use crate::pci::msix::MsixCap;
use crate::pci::{PciCapabilityId, PciExpressCapabilityId};

// Capability register offset in the PCI config space.
const PCI_CONFIG_CAPABILITY_OFFSET: u32 = 0x34;
// Extended capabilities register offset in the PCI config space.
const PCI_CONFIG_EXTENDED_CAPABILITY_OFFSET: u16 = 0x100;

/// Mask for specific register in the configuration space
#[derive(Debug)]
pub struct VfioRegisterMask {
    /// register
    pub register: u16,
    /// applied as (R & mask) | value
    pub mask: u32,
    /// value
    pub value: u32,
}

#[allow(clippy::type_complexity)]
fn vfio_device_get_pci_capabilities(
    device: &InternalVfioDevice,
) -> (Option<(MsixCap, u8)>, Vec<VfioRegisterMask>) {
    let mut next_cap_offset: u8 = 0;
    device.region_read(
        VFIO_PCI_CONFIG_REGION_INDEX,
        next_cap_offset.as_mut_bytes(),
        PCI_CONFIG_CAPABILITY_OFFSET as u64,
    );
    debug!("PCI CAPS offset: {}", next_cap_offset);

    let mut has_pci_express_cap = false;
    let mut msix_cap_and_register = None;
    // The legacy region with PCI capis is 256 bytes long and
    // split into 4 byte registers.
    const LOOP_UPPER_BOUND: u32 = 256 / 4;
    let mut loop_bound: u32 = 0;
    while next_cap_offset != 0 && loop_bound < LOOP_UPPER_BOUND {
        loop_bound += 1;

        let mut cap_id_and_next_ptr: u16 = 0;
        device.region_read(
            VFIO_PCI_CONFIG_REGION_INDEX,
            cap_id_and_next_ptr.as_mut_bytes(),
            next_cap_offset as u64,
        );
        // clear low 2 bits just in case to get 4 byte aligned address
        next_cap_offset &= 0xfc;

        let current_cap_offset = next_cap_offset;

        // PCIe spec revision 6.0: 7.5.3.1 PCI Express Capability List Register
        // |      2 bytes    |     1 byte    |          1 byte         |
        // |   Cap register  | Capability ID | Next Capability Pointer |
        let cap_id: u8 = (cap_id_and_next_ptr & 0xff) as u8;
        next_cap_offset = ((cap_id_and_next_ptr & 0xff00) >> 8) as u8;
        debug!("PCI CAP id: {cap_id} next offset: {next_cap_offset:#x}");

        let cap = PciCapabilityId::from(cap_id);
        let register = current_cap_offset / 4;
        debug!("Found pci cap: {cap:?} at offset: {current_cap_offset:#x}({register})");

        match cap {
            PciCapabilityId::PciExpress => {
                has_pci_express_cap = true;
            }
            PciCapabilityId::MsiX => {
                if let Some(irq_info) = device.get_irq_info(VFIO_PCI_MSIX_IRQ_INDEX) {
                    if irq_info.count != 0 {
                        // PCIe spec revision 6.0: 7.7.2 MSI-X Capability and Table Structure
                        let mut msg_ctl: u16 = 0;
                        let mut table: u32 = 0;
                        let mut pba: u32 = 0;
                        device.region_read(
                            VFIO_PCI_CONFIG_REGION_INDEX,
                            msg_ctl.as_mut_bytes(),
                            (current_cap_offset as u64) + 2,
                        );
                        device.region_read(
                            VFIO_PCI_CONFIG_REGION_INDEX,
                            table.as_mut_bytes(),
                            (current_cap_offset as u64) + 4,
                        );
                        device.region_read(
                            VFIO_PCI_CONFIG_REGION_INDEX,
                            pba.as_mut_bytes(),
                            (current_cap_offset as u64) + 8,
                        );
                        msix_cap_and_register = Some((
                            MsixCap {
                                msg_ctl,
                                table,
                                pba,
                            },
                            register,
                        ));
                    } else {
                        debug!(
                            "Found MSI-X cap, but the device does not support MSI-X interrupts."
                        );
                    }
                }
            }
            _ => {
                // We don't mask PCI capabilities, so all of them will be presented to the guest.
            }
        };
    }

    let mut masks = Vec::new();
    if has_pci_express_cap {
        let mut next_cap_offset: u16 = PCI_CONFIG_EXTENDED_CAPABILITY_OFFSET;

        // The PCIe region is 4K in size and split into 4 byte registers
        const LOOP_UPPER_BOUND: u32 = 4096 / 4;
        let mut loop_bound: u32 = 0;
        while next_cap_offset != 0 && loop_bound < LOOP_UPPER_BOUND {
            loop_bound += 1;

            let mut cap_id_and_next_ptr: u32 = 0;
            device.region_read(
                VFIO_PCI_CONFIG_REGION_INDEX,
                cap_id_and_next_ptr.as_mut_bytes(),
                next_cap_offset as u64,
            );
            // clear low 2 bits just in case to get 4 byte aligned address
            next_cap_offset &= 0xfffc;

            let current_cap_offset = next_cap_offset;

            // PCIe spec revision 6.0: 7.7.3.1 Secondary PCI Express Extended Capability Header
            // |           31-20        |         19-16       |          15-0         |
            // | Next capability offset | Capability Version  |   PCIe Capability ID  |
            let cap_id: u16 = (cap_id_and_next_ptr & 0xffff) as u16;
            next_cap_offset = (cap_id_and_next_ptr >> 20) as u16;

            let pci_cap = PciExpressCapabilityId::from(cap_id);
            let register = current_cap_offset / 4;
            debug!(
                "Found pci ext cap: {pci_cap:?} cap at offset: {current_cap_offset:#x}({register})"
            );

            // Find registers which contain the headers of PCIe caps we want to filter out of
            // the capability list. The "filtering" is done by changing the "PCI Express Cap ID"
            // part of the register (the first byte) to 0. 0 represents the "null" capability in
            // the PCIe spec. The actual chain of capabilities is not broken by this action. When
            // guest driver encounters this capability it just jumps to the next one since the
            // "Next Cap Pointer" (second byte) is intact.
            //
            // NOTE: the list of capabilities is hardcoded for now. In the future this
            // may be configurable from the user side.
            match pci_cap {
                PciExpressCapabilityId::AlternativeRoutingIdentificationInterpretation => {
                    debug!(
                        "Found ARI cap to be masked at register: \
                         {register}({current_cap_offset:#x})"
                    );
                    masks.push(VfioRegisterMask {
                        register,
                        mask: 0xffff_0000,
                        value: 0x0000_0000,
                    })
                }
                PciExpressCapabilityId::ResizeableBar => {
                    debug!(
                        "Found ResizableBar cap to be masked at register: \
                         {register}({current_cap_offset:#x})"
                    );
                    masks.push(VfioRegisterMask {
                        register,
                        mask: 0xffff_0000,
                        value: 0x0000_0000,
                    });

                    // PCIe spec revision 6.0: 7.8.6 Resizable BAR Extended Capability
                    // Header followed by (Capability, Control) register pairs,
                    // one pair per resizable BAR. Number of pairs N (in [1, 6])
                    // is encoded in bits 7:5 of Control Register (0), so total
                    // structure size is 4 + 8*N bytes.
                    //
                    // +000h  PCI Express Extended Capability Header
                    // +004h  Resizable BAR Capability Register (0)
                    // +008h  Resizable BAR Control Register    (0)
                    // +00Ch  Resizable BAR Capability Register (1)
                    // +010h  Resizable BAR Control Register    (1)
                    //  ...   up to 6 pairs
                    //
                    // We only need read number of BARs field from Resizable BAR Capability
                    // Register (0) do determine the number of BARs since: "The field is valid in
                    // Resizable BAR Control register (0) (at offset 008h), and is RsvdP for all
                    // others."
                    let mut control_register: u32 = 0;
                    device.region_read(
                        VFIO_PCI_CONFIG_REGION_INDEX,
                        control_register.as_mut_bytes(),
                        current_cap_offset as u64 + 8,
                    );
                    let number_of_bars = ((control_register >> 5) & 0b111) as u16;

                    let start_register = register + 1;
                    let end_register = start_register + 2 * number_of_bars;
                    for r in start_register..end_register {
                        masks.push(VfioRegisterMask {
                            register: r,
                            mask: 0x0000_0000,
                            value: 0x0000_0000,
                        });
                    }
                }
                PciExpressCapabilityId::SingleRootIoVirtualization => {
                    debug!(
                        "Found SR-IOV cap to be masked at register: \
                         {register}({current_cap_offset:#x})"
                    );
                    masks.push(VfioRegisterMask {
                        register,
                        mask: 0xffff_0000,
                        value: 0x0000_0000,
                    });

                    // PCIe spec revision 6.0: 9.3.3 SR-IOV Extended Capability
                    // Fixed 64 byte (16 register) layout. Last register is
                    // VF Migration State Array Offset at +03Ch, so we mask
                    // registers 1..=15 relative to the header.
                    //
                    // +000h  PCI Express Extended Capability Header
                    // +004h  SR-IOV Capabilities
                    // +008h  SR-IOV Status         | SR-IOV Control
                    // +00Ch  TotalVFs              | InitialVFs
                    // +010h  Function Dep Link     | NumVFs
                    // +014h  VF Stride             | First VF Offset
                    // +018h  VF Device ID          | RsvdP
                    // +01Ch  Supported Page Sizes
                    // +020h  System Page Size
                    // +024h  VF BAR0
                    // +028h  VF BAR1
                    // +02Ch  VF BAR2
                    // +030h  VF BAR3
                    // +034h  VF BAR4
                    // +038h  VF BAR5
                    // +03Ch  VF Migration State Array Offset
                    let start_register = register + 1;
                    let end_register = start_register + 15;
                    for r in start_register..end_register {
                        masks.push(VfioRegisterMask {
                            register: r,
                            mask: 0x0000_0000,
                            value: 0x0000_0000,
                        });
                    }
                }
                _ => {
                    // Rest of PCI Extended capabilities are presented to the guest.
                }
            }
        }
    }
    (msix_cap_and_register, masks)
}
