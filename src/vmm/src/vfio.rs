// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// TODO remove this once all code is used
#![allow(dead_code)]

use std::ops::DerefMut;
use std::sync::Arc;

use vfio_bindings::bindings::vfio::*;
pub use vfio_ioctls::{
    VfioContainer, VfioDevice as InternalVfioDevice, VfioDeviceFd, VfioRegionInfoCap,
    VfioRegionInfoCapSparseMmap, VfioRegionSparseMmapArea,
};
use vm_allocator::{AllocPolicy, RangeInclusive};
use zerocopy::IntoBytes;

use crate::arch::host_page_size;
use crate::logger::{debug, warn};
use crate::pci::configuration::{
    Bars, NUM_BAR_REGS, decode_32_bits_bar_size, decode_64_bits_bar_size,
};
use crate::pci::msix::MsixCap;
use crate::pci::{PciCapabilityId, PciExpressCapabilityId};
use crate::utils::{u64_to_usize, usize_to_u64};
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vm::KvmVm;

// Number of 4 byte registers in the config space
const PCI_CONFIG_SPACE_REGS: u16 = 1024;
// First BAR offset in the PCI config space.
const PCI_CONFIG_BAR_OFFSET: u32 = 0x10;
// Capability register offset in the PCI config space.
const PCI_CONFIG_CAPABILITY_OFFSET: u32 = 0x34;
// Extended capabilities register offset in the PCI config space.
const PCI_CONFIG_EXTENDED_CAPABILITY_OFFSET: u16 = 0x100;
// IO BAR when first BAR bit is 1.
const PCI_CONFIG_IO_BAR: u32 = 1 << 0;
// 64-bit memory bar flag.
const PCI_CONFIG_MEMORY_BAR_64BIT: u32 = 1 << 2;
// Prefetchable BAR bit
const PCI_CONFIG_BAR_PREFETCHABLE: u32 = 1 << 3;

/// VfioError
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VfioError {
    /// Failed to allocate guest address for BAR
    BarAllocation,
}

/// Wrapper around `Bars` type to automate dropping
#[derive(Debug)]
struct VfioBars {
    bars: Bars,
    vm: Arc<KvmVm>,
}

impl VfioBars {
    fn new(device: &InternalVfioDevice, vm: Arc<KvmVm>) -> Result<Self, VfioError> {
        let bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] = std::array::from_fn(|i| {
            #[allow(clippy::cast_possible_truncation)]
            vfio_get_single_bar_info(device, i as u8)
        });
        let bars = {
            let mut resource_allocator_lock = vm.resource_allocator();
            let resource_allocator = resource_allocator_lock.deref_mut();
            vfio_allocate_memory_ranges_for_bars(resource_allocator, &bar_infos)?
        };
        Ok(Self { bars, vm })
    }
}

impl Drop for VfioBars {
    fn drop(&mut self) {
        let mut resource_allocator_lock = self.vm.resource_allocator();
        let resource_allocator = resource_allocator_lock.deref_mut();
        vfio_dellocate_memory_ranges_for_bars(resource_allocator, &self.bars);
    }
}

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
        // capability list. The "filtering" is done by changing the "PCI Express Cap ID" part of
        // the register to 0 which represents the "null" capability in the PCIe spec. The actual
        // chain of capabilities is not broken by this action. When guest driver encounters this
        // capability it just jumps to the next one since the "Next Cap Pointer" is intact.
        //
        // NOTE: the list of capabilities is hard-coded for now. In the future this may be
        // configurable from the user side.
        match pci_cap {
            // Mask ARI since we don't implement it
            PciExpressCapabilityId::AlternativeRoutingIdentificationInterpretation |
            // Mask ReBAR since we don't implement it
            PciExpressCapabilityId::ResizeableBar |
            // Mask SR-IOV since it should not be exposed to the VM and it contains host
            // physical addresses of BARs.
            PciExpressCapabilityId::SingleRootIoVirtualization => {
                debug!(
                    "Found {pci_cap:?} cap to be masked: {register}({current_cap_offset:#x})"
                );
                masks.push(VfioRegisterMask {
                    register,
                    mask: 0xffff_0000,
                    value: 0x0000_0000,
                });
            }
            _ => {
                // Rest of PCI Extended capabilities are presented to the guest.
            }
        }
    }

    masks
}

/// Internal type storing BAR value and size obtained from the device
#[derive(Debug)]
struct VfioBarInfo {
    /// Value of the BAR (since it contains both address and the additional bits of information)
    value: u32,
    /// Size of the BAR
    size: u32,
}

fn vfio_get_single_bar_info(device: &InternalVfioDevice, bar_idx: u8) -> VfioBarInfo {
    // PCIe spec revision 6.0: 7.5.1.2.1 Base Address Registers
    // IMPLEMENTATION NOTE: SIZING A 32-BIT BASE ADDRESS REGISTER
    let bar_offset = u64::from(PCI_CONFIG_BAR_OFFSET) + u64::from(bar_idx) * 4;
    let mut value: u32 = 0;
    let mut size: u32 = 0;
    device.region_read(
        VFIO_PCI_CONFIG_REGION_INDEX,
        value.as_mut_bytes(),
        bar_offset,
    );
    device.region_write(
        VFIO_PCI_CONFIG_REGION_INDEX,
        0xffff_ffff_u32.as_bytes(),
        bar_offset,
    );
    device.region_read(
        VFIO_PCI_CONFIG_REGION_INDEX,
        size.as_mut_bytes(),
        bar_offset,
    );
    device.region_write(VFIO_PCI_CONFIG_REGION_INDEX, value.as_bytes(), bar_offset);
    VfioBarInfo { value, size }
}

/// Allocate memory ranges for BARs from mmio32 or mmio64 allocators.
fn vfio_allocate_memory_ranges_for_bars(
    resource_allocator: &mut ResourceAllocator,
    bar_infos: &[VfioBarInfo; NUM_BAR_REGS as usize],
) -> Result<Bars, VfioError> {
    let mut bars = Bars::default();
    let mut bar_idx = 0;
    while bar_idx < NUM_BAR_REGS {
        let VfioBarInfo {
            value: bar_value,
            size: mut bar_size_lower,
        } = bar_infos[bar_idx as usize];

        let is_io_bar = bar_value & PCI_CONFIG_IO_BAR != 0;
        let is_64_bits = bar_value & PCI_CONFIG_MEMORY_BAR_64BIT != 0;
        let is_prefetchable = bar_value & PCI_CONFIG_BAR_PREFETCHABLE != 0;

        if is_64_bits && bar_idx == NUM_BAR_REGS - 1 {
            warn!("BAR{bar_idx} is last BAR but marked as 64bit. Skipping");
            break;
        }

        let size = if is_io_bar {
            bar_size_lower &= !0b11;
            u64::from(decode_32_bits_bar_size(bar_size_lower))
        } else if !is_64_bits {
            bar_size_lower &= !0b1111;
            u64::from(decode_32_bits_bar_size(bar_size_lower))
        } else {
            bar_size_lower &= !0b1111;
            let VfioBarInfo {
                value: _,
                size: bar_size_upper,
            } = bar_infos[(bar_idx + 1) as usize];
            decode_64_bits_bar_size(bar_size_upper, bar_size_lower)
        };

        // This checks both size being power of 2 and size != 0
        if size.is_power_of_two() {
            // PCIe spec revision 6.0: 7.5.1.2.1 Base Address Registers
            // This design implies that all address spaces used are a power of two
            // in size and are naturally aligned.
            let alignment = std::cmp::max(host_page_size(), u64_to_usize(size));
            let alignment = usize_to_u64(alignment);

            let gpa;
            if is_io_bar {
                warn!(
                    "BAR{bar_idx} size: {size:>#10x} io_bar: {is_io_bar} 64bits: {is_64_bits} \
                     prefetchable: {is_prefetchable} Skipping IO BAR"
                );
                bar_idx += 1;
                continue;
            } else if is_64_bits {
                match resource_allocator.mmio64_memory.allocate(
                    size,
                    alignment,
                    AllocPolicy::FirstMatch,
                ) {
                    Ok(range) => {
                        gpa = range.start();
                        bars.set_bar_64(bar_idx, gpa, size, is_prefetchable.into());
                    }
                    Err(_) => {
                        vfio_dellocate_memory_ranges_for_bars(resource_allocator, &bars);
                        return Err(VfioError::BarAllocation);
                    }
                }
            } else {
                match resource_allocator.mmio32_memory.allocate(
                    size,
                    alignment,
                    AllocPolicy::FirstMatch,
                ) {
                    Ok(range) => {
                        gpa = range.start();
                        // SAFETY: both `gpa` and `size` went through 32bit resource allocator,
                        // so they must fit in u32
                        #[allow(clippy::cast_possible_truncation)]
                        bars.set_bar_32(bar_idx, gpa as u32, size as u32, is_prefetchable.into());
                    }
                    Err(_) => {
                        vfio_dellocate_memory_ranges_for_bars(resource_allocator, &bars);
                        return Err(VfioError::BarAllocation);
                    }
                }
            }
            debug!(
                "BAR{bar_idx} gpa: [{:#x}..{:#x}] size: {size:>#10x} io_bar: {is_io_bar} 64bits: \
                 {is_64_bits} prefetchable: {is_prefetchable}",
                gpa,
                gpa + size
            );
        } else {
            if size == 0 {
                debug!("BAR{bar_idx} has 0 size. Skipping");
            } else {
                warn!("BAR{bar_idx} has non power of 2 size: {size}. Skipping");
            }
        }
        if is_64_bits {
            bar_idx += 1;
        }
        bar_idx += 1;
    }
    Ok(bars)
}

/// Give memory ranges allocated for BARs back to the resource allocator
fn vfio_dellocate_memory_ranges_for_bars(resource_allocator: &mut ResourceAllocator, bars: &Bars) {
    let mut bar_idx = 0;
    while bar_idx < NUM_BAR_REGS {
        if bars.bars[bar_idx as usize].used() {
            let start = bars.get_bar_addr(bar_idx);
            let size = bars.get_bar_size(bar_idx);
            // SAFETY: these values were provided by the allocator in the first place
            let range = RangeInclusive::new(start, start + size - 1).unwrap();
            if bars.bars[bar_idx as usize].is_64bit() {
                resource_allocator.mmio64_memory.free(&range).unwrap();
                bar_idx += 2;
            } else {
                resource_allocator.mmio32_memory.free(&range).unwrap();
                bar_idx += 1;
            }
        } else {
            bar_idx += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::configuration::{encode_32_bits_bar_size, encode_64_bits_bar_size};

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
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0].register, reg);
        assert_eq!(masks[0].mask, 0xffff_0000);
        assert_eq!(masks[0].value, 0);
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

        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0].register, reg);
        assert_eq!(masks[0].mask, 0xffff_0000);
        assert_eq!(masks[0].value, 0);
    }

    #[test]
    fn test_vfio_read_extended_caps_sriov_masking() {
        let mut config_space = [0u32; 1024];

        let sriov_id = PciExpressCapabilityId::SingleRootIoVirtualization as u16;
        let reg = config_space_add_ext_cap(&mut config_space, 0x100, sriov_id, 0);

        let masks = vfio_read_extended_caps(&config_space);

        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0].register, reg);
        assert_eq!(masks[0].mask, 0xffff_0000);
        assert_eq!(masks[0].value, 0);
    }

    #[test]
    fn test_vfio_read_extended_caps_chained() {
        let mut config_space = [0u32; 1024];

        let ari_id = PciExpressCapabilityId::AlternativeRoutingIdentificationInterpretation as u16;
        let rebar_id = PciExpressCapabilityId::ResizeableBar as u16;
        let sriov_id = PciExpressCapabilityId::SingleRootIoVirtualization as u16;
        config_space_add_ext_cap(&mut config_space, 0x100, ari_id, 0x140);
        config_space_add_ext_cap(&mut config_space, 0x140, rebar_id, 0x240);
        config_space_add_ext_cap(&mut config_space, 0x240, sriov_id, 0);

        let masks = vfio_read_extended_caps(&config_space);

        assert_eq!(masks.len(), 3);
        assert_eq!(masks[0].register, 0x100 / 4);
        assert_eq!(masks[1].register, 0x140 / 4);
        assert_eq!(masks[2].register, 0x240 / 4);
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
        assert_eq!(masks.len(), 1);
    }

    #[test]
    fn test_vfio_allocate_memory_ranges_for_bars_valid_64bit_bars() {
        let mut bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
            std::array::from_fn(|_| VfioBarInfo { value: 0, size: 0 });

        let (size_hi, size_lo) = encode_64_bits_bar_size(8 << 30);
        for i in (0..NUM_BAR_REGS).step_by(2) {
            bar_infos[i as usize] = VfioBarInfo {
                value: PCI_CONFIG_MEMORY_BAR_64BIT | PCI_CONFIG_BAR_PREFETCHABLE,
                size: size_lo,
            };
            bar_infos[(i + 1) as usize] = VfioBarInfo {
                value: 0,
                size: size_hi,
            };
        }

        let mut resource_allocator = ResourceAllocator::new();
        let bars =
            vfio_allocate_memory_ranges_for_bars(&mut resource_allocator, &bar_infos).unwrap();
        for i in (0..NUM_BAR_REGS).step_by(2) {
            assert!(bars.bars[i as usize].used());
            assert!(bars.bars[i as usize].is_64bit());
            assert!(bars.bars[i as usize].is_prefetchable());
            assert_eq!(bars.get_bar_size_64(i), 8 << 30);
        }
    }

    #[test]
    fn test_vfio_allocate_memory_ranges_for_bars_valid_32bit_bars() {
        let bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
            std::array::from_fn(|_| VfioBarInfo {
                value: PCI_CONFIG_BAR_PREFETCHABLE,
                size: encode_32_bits_bar_size(64 << 20),
            });

        let mut resource_allocator = ResourceAllocator::new();
        let bars =
            vfio_allocate_memory_ranges_for_bars(&mut resource_allocator, &bar_infos).unwrap();
        for i in 0..NUM_BAR_REGS {
            assert_eq!(bars.get_bar_size_32(i), 64 << 20);
            assert!(bars.bars[i as usize].used());
            assert!(!bars.bars[i as usize].is_64bit());
            assert!(bars.bars[i as usize].is_prefetchable());
        }

        // We just allocated 6 * 64MB = 384MB of 32bit mmio space. On both x86 and aarch64 the 32
        // bit space is ~750MB, so additional allocation must fail
        vfio_allocate_memory_ranges_for_bars(&mut resource_allocator, &bar_infos).unwrap_err();
    }

    #[test]
    fn test_vfio_allocate_memory_ranges_for_bars_invalid_32bit_bars() {
        // zero size
        {
            let bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
                std::array::from_fn(|_| VfioBarInfo { value: 0, size: 0 });

            let mut resource_allocator = ResourceAllocator::new();
            let bars =
                vfio_allocate_memory_ranges_for_bars(&mut resource_allocator, &bar_infos).unwrap();
            for i in 0..NUM_BAR_REGS {
                assert!(!bars.bars[i as usize].used());
            }
        }

        // non power of 2 size
        {
            let bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
                std::array::from_fn(|_| VfioBarInfo {
                    value: 0,
                    size: encode_32_bits_bar_size(0x69),
                });

            let mut resource_allocator = ResourceAllocator::new();
            let bars =
                vfio_allocate_memory_ranges_for_bars(&mut resource_allocator, &bar_infos).unwrap();
            for i in 0..NUM_BAR_REGS {
                assert!(!bars.bars[i as usize].used());
            }
        }
    }

    #[test]
    fn test_vfio_allocate_memory_ranges_for_bars_allocation_failure_on_32bit_bars() {
        // Try to allocate 6 * 256MB BARs which exceeds the 32bit MMIO region on both x86_64 and
        // aarch64. This causes the clean up code to give all the memory back to the allocator
        let bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
            std::array::from_fn(|_| VfioBarInfo {
                value: 0,
                size: encode_32_bits_bar_size(256 << 20),
            });

        let mut resource_allocator = ResourceAllocator::new();
        vfio_allocate_memory_ranges_for_bars(&mut resource_allocator, &bar_infos).unwrap_err();
        assert_eq!(
            resource_allocator.mmio32_memory,
            ResourceAllocator::new().mmio32_memory
        );
    }

    #[test]
    fn test_vfio_allocate_memory_ranges_for_bars_allocation_failure_on_64bit_bars() {
        // Try to allocate 3 * 128GB 64bit BARs which exceeds the 64bit MMIO region (256GB) on
        // both x86_64 and aarch64. This causes the clean up code to give all the memory back to
        // the allocator.
        let mut bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
            std::array::from_fn(|_| VfioBarInfo { value: 0, size: 0 });

        let (size_hi, size_lo) = encode_64_bits_bar_size(128 << 30);
        for i in (0..NUM_BAR_REGS).step_by(2) {
            bar_infos[i as usize] = VfioBarInfo {
                value: PCI_CONFIG_MEMORY_BAR_64BIT,
                size: size_lo,
            };
            bar_infos[(i + 1) as usize] = VfioBarInfo {
                value: 0,
                size: size_hi,
            };
        }

        let mut resource_allocator = ResourceAllocator::new();
        vfio_allocate_memory_ranges_for_bars(&mut resource_allocator, &bar_infos).unwrap_err();
        assert_eq!(
            resource_allocator.mmio64_memory,
            ResourceAllocator::new().mmio64_memory
        );
    }

    #[test]
    fn test_vfio_allocate_memory_ranges_for_bars_io_bar_skipped() {
        let bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
            std::array::from_fn(|_| VfioBarInfo {
                value: PCI_CONFIG_IO_BAR,
                size: encode_32_bits_bar_size(1 << 29),
            });

        let mut resource_allocator = ResourceAllocator::new();
        let bars =
            vfio_allocate_memory_ranges_for_bars(&mut resource_allocator, &bar_infos).unwrap();
        for i in 0..NUM_BAR_REGS {
            assert!(!bars.bars[i as usize].used());
        }
    }

    #[test]
    fn test_vfio_allocate_memory_ranges_for_bars_last_bar_64bit_skipped() {
        let mut bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
            std::array::from_fn(|_| VfioBarInfo { value: 0, size: 0 });

        let (size_hi, size_lo) = encode_64_bits_bar_size(8 << 30);
        bar_infos[5] = VfioBarInfo {
            value: PCI_CONFIG_MEMORY_BAR_64BIT,
            size: size_lo,
        };
        let _ = size_hi;

        let mut resource_allocator = ResourceAllocator::new();
        let bars =
            vfio_allocate_memory_ranges_for_bars(&mut resource_allocator, &bar_infos).unwrap();
        assert!(!bars.bars[5].used());
    }

    #[test]
    fn test_vfio_dellocate_memory_ranges_for_bars_32bit() {
        let bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
            std::array::from_fn(|_| VfioBarInfo {
                value: 0,
                size: encode_32_bits_bar_size(64 << 20),
            });

        let mut resource_allocator = ResourceAllocator::new();
        let bars =
            vfio_allocate_memory_ranges_for_bars(&mut resource_allocator, &bar_infos).unwrap();
        let first_bar_addr = bars.get_bar_addr_32(0);

        vfio_dellocate_memory_ranges_for_bars(&mut resource_allocator, &bars);

        let bars2 =
            vfio_allocate_memory_ranges_for_bars(&mut resource_allocator, &bar_infos).unwrap();
        let first_bar_addr2 = bars2.get_bar_addr_32(0);
        assert_eq!(first_bar_addr, first_bar_addr2);
        for i in 0..NUM_BAR_REGS {
            assert!(bars2.bars[i as usize].used());
        }
    }

    #[test]
    fn test_vfio_dellocate_memory_ranges_for_bars_64bit() {
        let mut bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
            std::array::from_fn(|_| VfioBarInfo { value: 0, size: 0 });

        let (size_hi, size_lo) = encode_64_bits_bar_size(0x10000);
        bar_infos[0] = VfioBarInfo {
            value: PCI_CONFIG_MEMORY_BAR_64BIT,
            size: size_lo,
        };
        bar_infos[1] = VfioBarInfo {
            value: 0,
            size: size_hi,
        };

        let mut resource_allocator = ResourceAllocator::new();
        let bars =
            vfio_allocate_memory_ranges_for_bars(&mut resource_allocator, &bar_infos).unwrap();
        let first_bar_addr = bars.get_bar_addr_64(0);

        vfio_dellocate_memory_ranges_for_bars(&mut resource_allocator, &bars);

        let bars2 =
            vfio_allocate_memory_ranges_for_bars(&mut resource_allocator, &bar_infos).unwrap();
        let first_bar_addr2 = bars2.get_bar_addr_64(0);
        assert_eq!(first_bar_addr, first_bar_addr2);
        assert!(bars2.bars[0].used());
    }
}
