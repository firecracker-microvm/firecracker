// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// TODO remove this once all code is used
#![allow(dead_code)]

pub use vfio_ioctls::{
    VfioContainer, VfioDevice as InternalVfioDevice, VfioDeviceFd, VfioRegionInfoCap,
    VfioRegionInfoCapSparseMmap, VfioRegionSparseMmapArea,
};
use zerocopy::IntoBytes;

use crate::logger::debug;
use crate::pci::msix::MsixCap;
use crate::pci::{PciCapabilityId, PciExpressCapabilityId};

// Number of 4 byte registers in the config space
const PCI_CONFIG_SPACE_REGS: u16 = 1024;
// Capability register offset in the PCI config space.
const PCI_CONFIG_CAPABILITY_OFFSET: u32 = 0x34;
// Extended capabilities register offset in the PCI config space.
const PCI_CONFIG_EXTENDED_CAPABILITY_OFFSET: u16 = 0x100;

/// Mask for specific register in the configuration space
#[derive(Debug)]
struct VfioRegisterMask {
    /// Register id to mask
    register: u16,
    /// Mask for bits which should remain intact.
    /// Applied as (R & mask) | value
    mask: u32,
    /// Value to use with the mask
    value: u32,
}

/// Go through the PCI config space and reads all legacy and PCIe capabilities. Find the MSIx
/// cap if present and construct an array of masks which should be used to overwrite values in the
/// config space during read operations.
fn vfio_get_pci_capabilities(
    config_space: &[u32; PCI_CONFIG_SPACE_REGS as usize],
) -> (Option<(MsixCap, u8)>, Vec<VfioRegisterMask>) {
    let (msix_cap_and_register, has_pci_express_cap) = vfio_read_legacy_caps(config_space);

    // PCIe extended capabilities only exist if the device exposes a PCI Express capability.
    let masks = if has_pci_express_cap {
        vfio_read_extended_caps(config_space)
    } else {
        Vec::new()
    };

    (msix_cap_and_register, masks)
}

/// Minor utility function to read `bytes.len()` bytes from `config_space` starting at `offset`.
fn vfio_config_space_read_bytes(
    config_space: &[u32; PCI_CONFIG_SPACE_REGS as usize],
    offset: u32,
    bytes: &mut [u8],
) {
    let reg_idx = offset / 4;
    let in_reg_offset = offset % 4;
    let reg = config_space[reg_idx as usize];
    bytes.copy_from_slice(&reg.as_bytes()[in_reg_offset as usize..][0..bytes.len()]);
}

/// Walk the legacy PCI capability list. Return the MSI-X capability together with the register it
/// resides in (if present) and whether the device exposes a PCI Express capability.
fn vfio_read_legacy_caps(
    config_space: &[u32; PCI_CONFIG_SPACE_REGS as usize],
) -> (Option<(MsixCap, u8)>, bool) {
    let mut next_cap_offset: u8 = 0;
    vfio_config_space_read_bytes(
        config_space,
        PCI_CONFIG_CAPABILITY_OFFSET,
        next_cap_offset.as_mut_bytes(),
    );
    debug!("PCI CAPS offset: {}", next_cap_offset);

    let mut msix_cap_and_register = None;
    let mut has_pci_express_cap = false;
    // The legacy region with PCI cap is 256 bytes long and
    // split into 4 byte registers.
    const LOOP_UPPER_BOUND: u32 = 256 / 4;
    let mut loop_counter: u32 = 0;
    while next_cap_offset != 0 && loop_counter < LOOP_UPPER_BOUND {
        loop_counter += 1;

        // clear low 2 bits just in case to get 4 byte aligned address
        next_cap_offset &= 0xfc;

        let mut cap_id_and_next_ptr: u16 = 0;
        vfio_config_space_read_bytes(
            config_space,
            next_cap_offset as u32,
            cap_id_and_next_ptr.as_mut_bytes(),
        );

        let current_cap_offset = next_cap_offset;

        // PCIe spec revision 6.0: 7.5.3.1 PCI Express Capability List Register
        // |       32-16     |          15-8           |      7-0      |
        // |   Cap register  | Next Capability Pointer | Capability ID |
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
                // PCIe spec revision 6.0: 7.7.2 MSI-X Capability and Table Structure
                let mut msg_ctl: u16 = 0;
                let mut table: u32 = 0;
                let mut pba: u32 = 0;
                vfio_config_space_read_bytes(
                    config_space,
                    (current_cap_offset as u32) + 2,
                    msg_ctl.as_mut_bytes(),
                );
                vfio_config_space_read_bytes(
                    config_space,
                    (current_cap_offset as u32) + 4,
                    table.as_mut_bytes(),
                );
                vfio_config_space_read_bytes(
                    config_space,
                    (current_cap_offset as u32) + 8,
                    pba.as_mut_bytes(),
                );
                msix_cap_and_register = Some((
                    MsixCap {
                        msg_ctl,
                        table,
                        pba,
                    },
                    register,
                ));
            }
            _ => {
                // We don't mask legacy PCI capabilities, so all of them will be presented to the
                // guest.
            }
        };
    }

    (msix_cap_and_register, has_pci_express_cap)
}

/// Walk the PCIe extended capability list and construct an array of masks which should be used to
/// overwrite values in the config space during read operations.
fn vfio_read_extended_caps(
    config_space: &[u32; PCI_CONFIG_SPACE_REGS as usize],
) -> Vec<VfioRegisterMask> {
    let mut masks = Vec::new();
    let mut next_cap_offset: u16 = PCI_CONFIG_EXTENDED_CAPABILITY_OFFSET;

    // The PCIe region is 4K in size and split into 4 byte registers
    const LOOP_UPPER_BOUND: u16 = PCI_CONFIG_SPACE_REGS;
    let mut loop_counter: u16 = 0;
    while next_cap_offset != 0 && loop_counter < LOOP_UPPER_BOUND {
        loop_counter += 1;

        // clear high 4 bits and low 2 bits to get 12 bit value of 4 byte aligned address
        next_cap_offset &= 0x0ffc;

        let mut cap_id_and_next_ptr: u32 = 0;
        vfio_config_space_read_bytes(
            config_space,
            next_cap_offset as u32,
            cap_id_and_next_ptr.as_mut_bytes(),
        );

        let current_cap_offset = next_cap_offset;

        // PCIe spec revision 6.0: 7.7.3.1 Secondary PCI Express Extended Capability Header
        // |           31-20        |         19-16       |          15-0         |
        // | Next capability offset | Capability Version  |   PCIe Capability ID  |
        let cap_id: u16 = (cap_id_and_next_ptr & 0xffff) as u16;
        next_cap_offset = (cap_id_and_next_ptr >> 20) as u16;

        let pci_cap = PciExpressCapabilityId::from(cap_id);
        let register = current_cap_offset / 4;
        debug!("Found pci ext cap: {pci_cap:?} cap at offset: {current_cap_offset:#x}({register})");

        // Find registers which contain the headers of PCIe caps we want to filter out of the
        // capability list. The "filtering" is done by changing the "PCI Express Cap ID" part
        // of the register (the first byte) to 0 and masking off the whole body if the
        // capability. Cap ID of 0 represents the "null" capability in the PCIe spec. The
        // actual chain of capabilities is not broken by this action. When guest driver
        // encounters this capability it just jumps to the next one since the "Next Cap
        // Pointer" (second byte) is intact.
        //
        // NOTE: the list of capabilities is hard-coded for now. In the future this may be
        // configurable from the user side.
        match pci_cap {
            // Mask ARI since we don't implement it
            PciExpressCapabilityId::AlternativeRoutingIdentificationInterpretation => {
                debug!(
                    "Found ARI cap to be masked at register: \
                     {register}({current_cap_offset:#x})"
                );
                masks.push(VfioRegisterMask {
                    register,
                    mask: 0xffff_0000,
                    value: 0x0000_0000,
                });

                // PCIe spec revision 6.0: 7.8.8 ARI Extended Capability
                //
                // +000h  PCI Express Extended Capability Header
                // +004h  ARI Control Register  | ARI Capability Register
                let r = (current_cap_offset + 4) / 4;
                if (r as usize) < config_space.len() {
                    masks.push(VfioRegisterMask {
                        register: r,
                        mask: 0x0000_0000,
                        value: 0x0000_0000,
                    });
                }
            }
            // Mask ReBAR since we don't implement it
            PciExpressCapabilityId::ResizeableBar => {
                vfio_mask_resizeable_bar(config_space, current_cap_offset, register, &mut masks);
            }
            // Mask SR-IOV since it should not be exposed to the VM and it contains host
            // physical addresses of BARs.
            PciExpressCapabilityId::SingleRootIoVirtualization => {
                vfio_mask_sriov(current_cap_offset, register, &mut masks);
            }
            _ => {
                // Rest of PCI Extended capabilities are presented to the guest.
            }
        }
    }

    masks
}

/// Append masks needed to mask ReBar cap
fn vfio_mask_resizeable_bar(
    config_space: &[u32; PCI_CONFIG_SPACE_REGS as usize],
    current_cap_offset: u16,
    register: u16,
    masks: &mut Vec<VfioRegisterMask>,
) {
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
    // Register (0) to determine the number of BARs since: "The field is valid in
    // Resizable BAR Control register (0) (at offset 008h), and is RsvdP for all
    // others."

    // It should never happen that the PCIe cap is partially beyond the config
    // space, but since `current_cap_offset` is obtained from a device, do the
    // check.
    let r = (current_cap_offset + 8) / 4;
    if (r as usize) < config_space.len() {
        let mut control_register: u32 = 0;
        vfio_config_space_read_bytes(
            config_space,
            current_cap_offset as u32 + 8,
            control_register.as_mut_bytes(),
        );
        let number_of_bars = ((control_register >> 5) & 0b111) as u16;
        let number_of_bars = number_of_bars.clamp(1, 6);

        let start_register = (register + 1).min(PCI_CONFIG_SPACE_REGS - 1);
        let end_register = (start_register + 2 * number_of_bars).min(PCI_CONFIG_SPACE_REGS);
        for r in start_register..end_register {
            masks.push(VfioRegisterMask {
                register: r,
                mask: 0x0000_0000,
                value: 0x0000_0000,
            });
        }
    } else {
        // Still try to mask the offset 004h if it is possible
        let r = (current_cap_offset + 4) / 4;
        if (r as usize) < config_space.len() {
            masks.push(VfioRegisterMask {
                register: r,
                mask: 0x0000_0000,
                value: 0x0000_0000,
            });
        }
    }
}

/// Append masks needed to mask ReBar SR-IOV cap
fn vfio_mask_sriov(current_cap_offset: u16, register: u16, masks: &mut Vec<VfioRegisterMask>) {
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
    let start_register = (register + 1).min(PCI_CONFIG_SPACE_REGS - 1);
    let end_register = (start_register + 15).min(PCI_CONFIG_SPACE_REGS);
    for r in start_register..end_register {
        masks.push(VfioRegisterMask {
            register: r,
            mask: 0x0000_0000,
            value: 0x0000_0000,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_space_write_u8(config_space: &mut [u32; 1024], offset: u32, val: u8) {
        let reg = &mut config_space[(offset / 4) as usize];
        let shift = (offset % 4) * 8;
        *reg &= !(0xFF << shift);
        *reg |= (val as u32) << shift;
    }

    fn config_space_add_legacy_cap(
        config_space: &mut [u32; 1024],
        offset: u8,
        cap_id: u8,
        next: u8,
    ) {
        config_space_write_u8(config_space, offset as u32, cap_id);
        config_space_write_u8(config_space, offset as u32 + 1, next);
    }

    fn config_space_add_ext_cap(
        config_space: &mut [u32; 1024],
        offset: u16,
        cap_id: u16,
        next_offset: u16,
    ) -> u16 {
        let header = ((next_offset as u32) << 20) | (1 << 16) | (cap_id as u32);
        config_space[(offset / 4) as usize] = header;
        offset / 4
    }

    #[test]
    fn test_vfio_read_legacy_caps_none() {
        let config_space = [0u32; 1024];
        let (msix, has_pci_express_cap) = vfio_read_legacy_caps(&config_space);
        assert!(msix.is_none());
        assert!(!has_pci_express_cap);
    }

    #[test]
    fn test_vfio_read_legacy_caps_pci_express() {
        let mut config_space = [0u32; 1024];

        config_space_write_u8(&mut config_space, PCI_CONFIG_CAPABILITY_OFFSET, 0x40);
        config_space_add_legacy_cap(
            &mut config_space,
            0x40,
            PciCapabilityId::PciExpress as u8,
            0x00,
        );

        let (msix, has_pci_express_cap) = vfio_read_legacy_caps(&config_space);
        assert!(msix.is_none());
        assert!(has_pci_express_cap);
    }

    #[test]
    fn test_vfio_read_legacy_caps_msix() {
        let mut config_space = [0u32; 1024];

        config_space_write_u8(&mut config_space, PCI_CONFIG_CAPABILITY_OFFSET, 0x40);

        let msg_ctl: u16 = 0x6969;
        config_space[0x40 / 4] = (msg_ctl as u32) << 16;
        let table: u32 = 0x1111;
        config_space[0x40 / 4 + 1] = table;
        let pba: u32 = 0x2222;
        config_space[0x40 / 4 + 2] = pba;
        config_space_add_legacy_cap(&mut config_space, 0x40, PciCapabilityId::MsiX as u8, 0x00);

        let (msix, has_pci_express_cap) = vfio_read_legacy_caps(&config_space);
        assert!(!has_pci_express_cap);

        let (cap, register) = msix.unwrap();
        assert_eq!(register, 0x40 / 4);
        let MsixCap {
            msg_ctl: got_msg_ctl,
            table: got_table,
            pba: got_pba,
        } = cap;
        assert_eq!(got_msg_ctl, msg_ctl);
        assert_eq!(got_table, table);
        assert_eq!(got_pba, pba);
    }

    #[test]
    fn test_vfio_read_legacy_caps_iteration_limit() {
        let mut config_space = [0u32; 1024];

        config_space_write_u8(&mut config_space, PCI_CONFIG_CAPABILITY_OFFSET, 0x40);

        // the loop
        config_space_add_legacy_cap(&mut config_space, 0x40, 0x0, 0x40);

        let (msix, has_pci_express_cap) = vfio_read_legacy_caps(&config_space);
        assert!(msix.is_none());
        assert!(!has_pci_express_cap);
    }

    #[test]
    fn test_vfio_read_extended_caps_ari_masking() {
        let mut config_space = [0u32; 1024];

        let ari_id = PciExpressCapabilityId::AlternativeRoutingIdentificationInterpretation as u16;
        let reg = config_space_add_ext_cap(&mut config_space, 0x100, ari_id, 0);

        let masks = vfio_read_extended_caps(&config_space);
        assert_eq!(masks.len(), 2);
        assert_eq!(masks[0].register, reg);
        assert_eq!(masks[0].mask, 0xffff_0000);
        assert_eq!(masks[0].value, 0);
        assert_eq!(masks[1].register, reg + 1);
        assert_eq!(masks[1].mask, 0);
        assert_eq!(masks[1].value, 0);
    }

    #[test]
    fn test_vfio_read_extended_caps_resizeable_bar_masking() {
        let mut config_space = [0u32; 1024];

        let rebar_id = PciExpressCapabilityId::ResizeableBar as u16;
        let reg = config_space_add_ext_cap(&mut config_space, 0x100, rebar_id, 0);

        // Control Register (0) is at the cap_offset + 8 = 0x108
        // bits 7:5 encode number of BARs; set to 3
        config_space[0x108 / 4] = 3 << 5;

        let masks = vfio_read_extended_caps(&config_space);

        // header + 2 * 3 register masks = 7
        assert_eq!(masks.len(), 7);
        assert_eq!(masks[0].register, reg);
        assert_eq!(masks[0].mask, 0xffff_0000);

        for (i, m) in masks[1..].iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let i = i as u16;
            assert_eq!(m.register, reg + 1 + i);
            assert_eq!(m.mask, 0);
            assert_eq!(m.value, 0);
        }
    }

    #[test]
    fn test_vfio_read_extended_caps_sriov_masking() {
        let mut config_space = [0u32; 1024];

        let sriov_id = PciExpressCapabilityId::SingleRootIoVirtualization as u16;
        let reg = config_space_add_ext_cap(&mut config_space, 0x100, sriov_id, 0);

        let masks = vfio_read_extended_caps(&config_space);

        // header + 15 register masks = 16
        assert_eq!(masks.len(), 16);
        assert_eq!(masks[0].register, reg);
        assert_eq!(masks[0].mask, 0xffff_0000);

        for (i, m) in masks[1..].iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let i = i as u16;
            assert_eq!(m.register, reg + 1 + i);
            assert_eq!(m.mask, 0);
            assert_eq!(m.value, 0);
        }
    }

    #[test]
    fn test_vfio_read_extended_caps_chained() {
        let mut config_space = [0u32; 1024];

        let ari_id = PciExpressCapabilityId::AlternativeRoutingIdentificationInterpretation as u16;
        let sriov_id = PciExpressCapabilityId::SingleRootIoVirtualization as u16;
        config_space_add_ext_cap(&mut config_space, 0x100, ari_id, 0x140);
        config_space_add_ext_cap(&mut config_space, 0x140, sriov_id, 0);

        let masks = vfio_read_extended_caps(&config_space);

        // ARI = 2 masks, SR-IOV = 16 masks
        assert_eq!(masks.len(), 18);
        assert_eq!(masks[0].register, 0x100 / 4);
        assert_eq!(masks[2].register, 0x140 / 4);
    }

    #[test]
    fn test_vfio_read_extended_caps_iteration_limit() {
        let mut config_space = [0u32; 1024];

        // The loop setup
        config_space_add_ext_cap(&mut config_space, 0x100, 0x0, 0x100);

        let masks = vfio_read_extended_caps(&config_space);
        assert!(masks.is_empty());
    }

    #[test]
    fn test_vfio_get_pci_capabilities_requires_pci_express_cap() {
        let mut config_space = [0u32; 1024];

        // An extended capability is present, but there is no legacy PCI Express capability.
        let sriov_id = PciExpressCapabilityId::SingleRootIoVirtualization as u16;
        config_space_add_ext_cap(&mut config_space, 0x100, sriov_id, 0);

        // Extended capabilities must not be scanned without a PCI Express capability.
        let (msix, masks) = vfio_get_pci_capabilities(&config_space);
        assert!(msix.is_none());
        assert!(masks.is_empty());
    }

    #[test]
    fn test_vfio_get_pci_capabilities_msix_and_masks() {
        let mut config_space = [0u32; 1024];

        config_space_write_u8(&mut config_space, PCI_CONFIG_CAPABILITY_OFFSET, 0x40);
        config_space_add_legacy_cap(&mut config_space, 0x40, PciCapabilityId::MsiX as u8, 0x60);
        config_space_add_legacy_cap(
            &mut config_space,
            0x60,
            PciCapabilityId::PciExpress as u8,
            0x00,
        );

        let sriov_id = PciExpressCapabilityId::SingleRootIoVirtualization as u16;
        config_space_add_ext_cap(&mut config_space, 0x100, sriov_id, 0);

        let (msix, masks) = vfio_get_pci_capabilities(&config_space);
        assert!(msix.is_some());
        // header + 15 register masks = 16
        assert_eq!(masks.len(), 16);
    }
}
