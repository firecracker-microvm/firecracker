// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

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
use crate::utils::usize_to_u64;
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vm::KvmVm;

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
pub struct VfioBars {
    /// bars
    pub bars: Bars,
    /// vm
    pub vm: Arc<KvmVm>,
}

impl VfioBars {
    /// New VfioBars
    fn new(device: &InternalVfioDevice, vm: Arc<KvmVm>) -> Result<Self, VfioError> {
        let bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] = std::array::from_fn(|i| {
            #[allow(clippy::cast_possible_truncation)]
            vfio_device_get_single_bar_info(device, i as u8)
        });
        let bars = {
            let mut resource_allocator_lock = vm.resource_allocator();
            let resource_allocator = resource_allocator_lock.deref_mut();
            vfio_device_allocate_bars(resource_allocator, &bar_infos)?
        };
        Ok(Self { bars, vm })
    }
}

impl Drop for VfioBars {
    fn drop(&mut self) {
        let mut resource_allocator_lock = self.vm.resource_allocator();
        let resource_allocator = resource_allocator_lock.deref_mut();
        vfio_deallocate_bars(resource_allocator, &self.bars);
    }
}

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
    config_space: &[u32; 1024],
) -> (Option<(MsixCap, u8)>, Vec<VfioRegisterMask>) {
    fn config_space_read_bytes(config_space: &[u32; 1024], offset: u32, bytes: &mut [u8]) {
        let reg_idx = offset / 4;
        let in_reg_offset = offset % 4;
        let reg = config_space[reg_idx as usize];
        bytes.copy_from_slice(&reg.as_bytes()[in_reg_offset as usize..][0..bytes.len()]);
    }

    let mut next_cap_offset: u8 = 0;
    config_space_read_bytes(
        config_space,
        PCI_CONFIG_CAPABILITY_OFFSET,
        next_cap_offset.as_mut_bytes(),
    );
    debug!("PCI CAPS offset: {}", next_cap_offset);

    let mut msix_cap_and_register = None;
    let mut has_pci_express_cap = false;
    // The legacy region with PCI capis is 256 bytes long and
    // split into 4 byte registers.
    const LOOP_UPPER_BOUND: u32 = 256 / 4;
    let mut loop_bound: u32 = 0;
    while next_cap_offset != 0 && loop_bound < LOOP_UPPER_BOUND {
        loop_bound += 1;

        let mut cap_id_and_next_ptr: u16 = 0;
        config_space_read_bytes(
            config_space,
            u32::from(next_cap_offset),
            cap_id_and_next_ptr.as_mut_bytes(),
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
                // if let Some(irq_info) = device.get_irq_info(VFIO_PCI_MSIX_IRQ_INDEX) {
                // if msix_irq_info.count != 0 {
                // PCIe spec revision 6.0: 7.7.2 MSI-X Capability and Table Structure
                let mut msg_ctl: u16 = 0;
                let mut table: u32 = 0;
                let mut pba: u32 = 0;
                config_space_read_bytes(
                    config_space,
                    (current_cap_offset as u32) + 2,
                    msg_ctl.as_mut_bytes(),
                );
                config_space_read_bytes(
                    config_space,
                    (current_cap_offset as u32) + 4,
                    table.as_mut_bytes(),
                );
                config_space_read_bytes(
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
            config_space_read_bytes(
                config_space,
                next_cap_offset as u32,
                cap_id_and_next_ptr.as_mut_bytes(),
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
                    config_space_read_bytes(
                        config_space,
                        current_cap_offset as u32 + 8,
                        control_register.as_mut_bytes(),
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

/// Internal type storing BAR value and size obtained from the device
#[derive(Debug)]
struct VfioBarInfo {
    /// value
    value: u32,
    /// size
    size: u32,
}

fn vfio_device_get_single_bar_info(device: &InternalVfioDevice, bar_idx: u8) -> VfioBarInfo {
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

fn vfio_device_allocate_bars(
    resource_allocator: &mut ResourceAllocator,
    bar_infos: &[VfioBarInfo; 6],
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

        if size.is_power_of_two() {
            if size != 0 {
                fn calculate_alignment(size: u64) -> u64 {
                    // PCIe spec revision 6.0: 7.5.1.2.1 Base Address Registers
                    // This design implies that all address spaces used are a power of two
                    // in size and are naturally aligned.
                    let alignment = std::cmp::max(host_page_size(), 1 << size.trailing_zeros());
                    usize_to_u64(alignment)
                }

                let idx = bar_idx;
                let gpa;
                if is_io_bar {
                    warn!(
                        "BAR{bar_idx} size: {size:>#10x} io_bar: {is_io_bar} 64bits: {is_64_bits} \
                         prefetchable: {is_prefetchable} Skipping IO BAR"
                    );
                    bar_idx += 1;
                    continue;
                } else if is_64_bits {
                    let alignment = calculate_alignment(size);
                    let range = resource_allocator
                        .mmio64_memory
                        .allocate(size, alignment, AllocPolicy::FirstMatch)
                        .map_err(|_| VfioError::BarAllocation)?;
                    gpa = range.start();
                    if gpa.checked_add(size - 1).is_some() {
                        bars.set_bar_64(idx, gpa, size, is_prefetchable.into());
                    } else {
                        resource_allocator.mmio64_memory.free(&range).unwrap();
                        return Err(VfioError::BarAllocation);
                    }
                } else {
                    let alignment = calculate_alignment(size);
                    let range = resource_allocator
                        .mmio32_memory
                        .allocate(size, alignment, AllocPolicy::FirstMatch)
                        .map_err(|_| VfioError::BarAllocation)?;
                    gpa = range.start();
                    let gpa = u32::try_from(gpa).unwrap();
                    let size = u32::try_from(size).unwrap();
                    if gpa.checked_add(size - 1).is_some() {
                        bars.set_bar_32(idx, gpa, size, is_prefetchable.into());
                    } else {
                        resource_allocator.mmio32_memory.free(&range).unwrap();
                        return Err(VfioError::BarAllocation);
                    }
                }
                debug!(
                    "BAR{bar_idx} gpa: [{:#x}..{:#x}] size: {size:>#10x} io_bar: {is_io_bar} \
                     64bits: {is_64_bits} prefetchable: {is_prefetchable}",
                    gpa,
                    gpa + size
                );
            } else {
                debug!("BAR{bar_idx} has 0 size. Skipping");
            }
        } else {
            warn!("BAR{bar_idx} has non power of 2 size: {size}. Skipping");
        }
        if is_64_bits {
            bar_idx += 1;
        }
        bar_idx += 1;
    }
    Ok(bars)
}

fn vfio_deallocate_bars(resource_allocator: &mut ResourceAllocator, bars: &Bars) {
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
    fn test_vfio_device_get_pci_capabilities_no_legacy_caps() {
        let config_space = [0u32; 1024];
        let (msix, masks) = vfio_device_get_pci_capabilities(&config_space);
        assert!(msix.is_none());
        assert!(masks.is_empty());
    }

    #[test]
    fn test_vfio_device_get_pci_capabilities_no_extended_caps() {
        let mut config_space = [0u32; 1024];

        config_space_write_u8(&mut config_space, PCI_CONFIG_CAPABILITY_OFFSET, 0x40);
        config_space_add_legacy_cap(
            &mut config_space,
            0x40,
            PciCapabilityId::PciExpress as u8,
            0x00,
        );

        let (msix, masks) = vfio_device_get_pci_capabilities(&config_space);
        assert!(msix.is_none());
        assert!(masks.is_empty());
    }

    #[test]
    fn test_vfio_device_get_pci_capabilities_msix_legacy_cap() {
        let mut config_space = [0u32; 1024];

        config_space_write_u8(&mut config_space, PCI_CONFIG_CAPABILITY_OFFSET, 0x40);

        let msg_ctl: u16 = 0x6969;
        config_space[0x40 / 4] = (msg_ctl as u32) << 16;
        let table: u32 = 0x1111;
        config_space[0x40 / 4 + 1] = table;
        let pba: u32 = 0x2222;
        config_space[0x40 / 4 + 2] = pba;
        config_space_add_legacy_cap(&mut config_space, 0x40, PciCapabilityId::MsiX as u8, 0x00);

        let (msix, masks) = vfio_device_get_pci_capabilities(&config_space);
        assert!(masks.is_empty());

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
    fn test_vfio_device_get_pci_capabilities_ari_masking() {
        let mut config_space = [0u32; 1024];

        config_space_write_u8(&mut config_space, PCI_CONFIG_CAPABILITY_OFFSET, 0x40);
        config_space_add_legacy_cap(&mut config_space, 0x40, PciCapabilityId::MsiX as u8, 0x60);
        config_space_add_legacy_cap(
            &mut config_space,
            0x60,
            PciCapabilityId::PciExpress as u8,
            0x00,
        );

        let ari_id = PciExpressCapabilityId::AlternativeRoutingIdentificationInterpretation as u16;
        let reg = config_space_add_ext_cap(&mut config_space, 0x100, ari_id, 0);

        let (_, masks) = vfio_device_get_pci_capabilities(&config_space);
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0].register, reg);
        assert_eq!(masks[0].mask, 0xffff_0000);
        assert_eq!(masks[0].value, 0);
    }

    #[test]
    fn test_vfio_device_get_pci_capabilities_resizeable_bar_masking() {
        let mut config_space = [0u32; 1024];

        config_space_write_u8(&mut config_space, PCI_CONFIG_CAPABILITY_OFFSET, 0x40);
        config_space_add_legacy_cap(&mut config_space, 0x40, PciCapabilityId::MsiX as u8, 0x60);
        config_space_add_legacy_cap(
            &mut config_space,
            0x60,
            PciCapabilityId::PciExpress as u8,
            0x00,
        );

        let rebar_id = PciExpressCapabilityId::ResizeableBar as u16;
        let reg = config_space_add_ext_cap(&mut config_space, 0x100, rebar_id, 0);

        // Control Register (0) is at the cap_offset + 8 = 0x108
        // bits 7:5 encode number of BARs; set to 3
        config_space[0x108 / 4] = 3 << 5;

        let (_, masks) = vfio_device_get_pci_capabilities(&config_space);

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
    fn test_vfio_device_get_pci_capabilities_sriov_masking() {
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
        let reg = config_space_add_ext_cap(&mut config_space, 0x100, sriov_id, 0);

        let (_, masks) = vfio_device_get_pci_capabilities(&config_space);

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
    fn test_vfio_device_get_pci_capabilities_chained_extended_caps() {
        let mut config_space = [0u32; 1024];

        config_space_write_u8(&mut config_space, PCI_CONFIG_CAPABILITY_OFFSET, 0x40);
        config_space_add_legacy_cap(&mut config_space, 0x40, PciCapabilityId::MsiX as u8, 0x60);
        config_space_add_legacy_cap(
            &mut config_space,
            0x60,
            PciCapabilityId::PciExpress as u8,
            0x00,
        );

        let ari_id = PciExpressCapabilityId::AlternativeRoutingIdentificationInterpretation as u16;
        let sriov_id = PciExpressCapabilityId::SingleRootIoVirtualization as u16;
        config_space_add_ext_cap(&mut config_space, 0x100, ari_id, 0x140);
        config_space_add_ext_cap(&mut config_space, 0x140, sriov_id, 0);

        let (_, masks) = vfio_device_get_pci_capabilities(&config_space);

        // ARI = 1 mask, SR-IOV = 16 masks
        assert_eq!(masks.len(), 17);
        assert_eq!(masks[0].register, 0x100 / 4);
        assert_eq!(masks[1].register, 0x140 / 4);
    }

    #[test]
    fn test_vfio_device_get_pci_capabilities_iteration_limit_legacy_cap() {
        let mut config_space = [0u32; 1024];

        config_space_write_u8(&mut config_space, PCI_CONFIG_CAPABILITY_OFFSET, 0x40);

        // the loop
        config_space_add_legacy_cap(&mut config_space, 0x40, 0x0, 0x40);

        let (msix, masks) = vfio_device_get_pci_capabilities(&config_space);
        assert!(msix.is_none());
        assert!(masks.is_empty());
    }

    #[test]
    fn test_vfio_device_get_pci_capabilities_iteration_limit_extended_cap() {
        let mut config_space = [0u32; 1024];

        config_space_write_u8(&mut config_space, PCI_CONFIG_CAPABILITY_OFFSET, 0x40);
        config_space_add_legacy_cap(
            &mut config_space,
            0x40,
            PciCapabilityId::PciExpress as u8,
            0x00,
        );

        // the loop
        config_space_add_ext_cap(&mut config_space, 0x100, 0x0, 0x100);

        let (msix, masks) = vfio_device_get_pci_capabilities(&config_space);
        assert!(msix.is_none());
        assert!(masks.is_empty());
    }

    #[test]
    fn test_vfio_device_allocate_bars_valid_64bit_bars() {
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
        let bars = vfio_device_allocate_bars(&mut resource_allocator, &bar_infos).unwrap();
        for i in (0..NUM_BAR_REGS).step_by(2) {
            assert!(bars.bars[i as usize].used());
            assert!(bars.bars[i as usize].is_64bit());
            assert!(bars.bars[0].is_prefetchable());
            assert_eq!(bars.get_bar_size_64(i), 8 << 30);
        }
    }

    #[test]
    fn test_vfio_device_allocate_bars_valid_32bit_bars() {
        let bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
            std::array::from_fn(|_| VfioBarInfo {
                value: PCI_CONFIG_BAR_PREFETCHABLE,
                size: encode_32_bits_bar_size(64 << 20),
            });

        let mut resource_allocator = ResourceAllocator::new();
        let bars = vfio_device_allocate_bars(&mut resource_allocator, &bar_infos).unwrap();
        for i in 0..NUM_BAR_REGS {
            assert_eq!(bars.get_bar_size_32(i), 64 << 20);
            assert!(bars.bars[i as usize].used());
            assert!(!bars.bars[i as usize].is_64bit());
            assert!(bars.bars[i as usize].is_prefetchable());
        }

        // We just allocated 6 * 64MB = 386MB of 32bit mmio space. On both x86 and aarch64 the 32
        // bit space is ~750MB, so additional allocation must fail
        vfio_device_allocate_bars(&mut resource_allocator, &bar_infos).unwrap_err();
    }

    #[test]
    fn test_vfio_device_allocate_bars_invalid_32bit_bars() {
        // zero size
        {
            let bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
                std::array::from_fn(|_| VfioBarInfo { value: 0, size: 0 });

            let mut resource_allocator = ResourceAllocator::new();
            let bars = vfio_device_allocate_bars(&mut resource_allocator, &bar_infos).unwrap();
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
            let bars = vfio_device_allocate_bars(&mut resource_allocator, &bar_infos).unwrap();
            for i in 0..NUM_BAR_REGS {
                assert!(!bars.bars[i as usize].used());
            }
        }
    }

    #[test]
    fn test_vfio_device_allocate_bars_io_bar_skipped() {
        let bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
            std::array::from_fn(|_| VfioBarInfo {
                value: PCI_CONFIG_IO_BAR,
                size: encode_32_bits_bar_size(1 << 29),
            });

        let mut resource_allocator = ResourceAllocator::new();
        let bars = vfio_device_allocate_bars(&mut resource_allocator, &bar_infos).unwrap();
        for i in 0..NUM_BAR_REGS {
            assert!(!bars.bars[i as usize].used());
        }
    }

    #[test]
    fn test_vfio_device_allocate_bars_last_bar_64bit_skipped() {
        let mut bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
            std::array::from_fn(|_| VfioBarInfo { value: 0, size: 0 });

        let (size_hi, size_lo) = encode_64_bits_bar_size(8 << 30);
        bar_infos[5] = VfioBarInfo {
            value: PCI_CONFIG_MEMORY_BAR_64BIT,
            size: size_lo,
        };
        let _ = size_hi;

        let mut resource_allocator = ResourceAllocator::new();
        let bars = vfio_device_allocate_bars(&mut resource_allocator, &bar_infos).unwrap();
        assert!(!bars.bars[5].used());
    }

    #[test]
    fn test_vfio_deallocate_bars_32bit() {
        let bar_infos: [VfioBarInfo; NUM_BAR_REGS as usize] =
            std::array::from_fn(|_| VfioBarInfo {
                value: 0,
                size: encode_32_bits_bar_size(64 << 20),
            });

        let mut resource_allocator = ResourceAllocator::new();
        let bars = vfio_device_allocate_bars(&mut resource_allocator, &bar_infos).unwrap();
        let first_bar_addr = bars.get_bar_addr_32(0);

        vfio_deallocate_bars(&mut resource_allocator, &bars);

        let bars2 = vfio_device_allocate_bars(&mut resource_allocator, &bar_infos).unwrap();
        let first_bar_addr2 = bars2.get_bar_addr_32(0);
        assert_eq!(first_bar_addr, first_bar_addr2);
        for i in 0..NUM_BAR_REGS {
            assert!(bars2.bars[i as usize].used());
        }
    }

    #[test]
    fn test_vfio_deallocate_bars_64bit() {
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
        let bars = vfio_device_allocate_bars(&mut resource_allocator, &bar_infos).unwrap();
        let first_bar_addr = bars.get_bar_addr_64(0);

        vfio_deallocate_bars(&mut resource_allocator, &bars);

        let bars2 = vfio_device_allocate_bars(&mut resource_allocator, &bar_infos).unwrap();
        let first_bar_addr2 = bars2.get_bar_addr_64(0);
        assert_eq!(first_bar_addr, first_bar_addr2);
        assert!(bars2.bars[0].used());
    }
}
