// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ops::DerefMut;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Barrier, Mutex};

use arrayvec::ArrayVec;
use bitflags::bitflags;
use kvm_bindings::{
    kvm_create_device, kvm_device_type_KVM_DEV_TYPE_VFIO, kvm_userspace_memory_region,
};
use vfio_bindings::bindings::vfio::*;
pub use vfio_ioctls::{
    VfioContainer, VfioDevice, VfioDeviceFd, VfioRegionInfoCap, VfioRegionInfoCapSparseMmap,
    VfioRegionSparseMmapArea,
};
use vm_allocator::{AllocPolicy, RangeInclusive};
use vm_memory::{GuestMemory, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;
use zerocopy::IntoBytes;

use crate::arch::host_page_size;
use crate::logger::{debug, error, trace, warn};
use crate::pci::configuration::{
    BAR0_REG_IDX, Bars, NUM_BAR_REGS, decode_32_bits_bar_size, decode_64_bits_bar_size,
};
use crate::pci::msix::{MsixCap, MsixConfig};
use crate::pci::{PciCapabilityId, PciDevice, PciExpressCapabilityId, PciSBDF};
use crate::utils::{
    align_down_host_page, align_up_host_page, offset_from_lower_host_page, u64_to_usize,
    usize_to_u64,
};
use crate::vmm_config::vfio::VfioConfig;
use crate::vstate::bus::BusDevice;
use crate::vstate::interrupts::InterruptError;
use crate::vstate::memory::{GuestMemoryMmap, GuestRegionType};
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
    /// mmap failed
    Mmap,
    /// Failed to allocate KVM slot
    KvmSlot,
    /// Failed to set KVM user memory region: {0}
    SetUserMemoryRegion(String),
    /// Cannot create Msix vector group: {0}
    MsixConfig(#[from] InterruptError),
    /// Device does not provide MSIx irq
    NoMsixIrq,
    /// KVM failed to create KVM_DEV_TYPE_VFIO device: {0}
    KVMCreateVfioDevice(kvm_ioctls::Error),
    /// vfio-ioctls crate error: {0}
    VfioIoctls(#[from] vfio_ioctls::VfioError),
    /// BAR{0} MSI-X table at offset {1:#x} size {2:#x} does not fit in region of size {3:#x}
    MsixTableOutOfRange(u8, u64, u64, u64),
    /// BAR{0} MSI-X PBA at offset {1:#x} size {2:#x} does not fit in region of size {3:#x}
    MsixPbaOutOfRange(u8, u64, u64, u64),
    /// BAR{0} sparse mmap area at offset {1:#x} size {2:#x} does not fit in region of size {3:#x}
    SparseMmapAreaOutOfRange(u8, u64, u64, u64),
}

#[derive(Debug, Clone)]
struct VfioRegionInfo {
    pub flags: u32,
    pub size: u64,
    pub offset: u64,
    pub caps: Vec<VfioRegionInfoCap>,
}

/// Mask for specific register in the configuration space
#[derive(Debug)]
pub struct RegisterMask {
    /// register
    pub register: u16,
    /// applied as (R & mask) | value
    pub mask: u32,
    /// value
    pub value: u32,
}

bitflags! {
    /// Type of the hole in the bar. A single hole can contain both
    /// the MSI-X table and PBA when their host-page-aligned ranges overlap.
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct BarHoleInfoUsage: u8 {
        /// The hole contains MSIx table
        const TABLE = 1 << 0;
        /// The hole contains MSIx pba
        const PBA = 1 << 1;
    }
}

/// Information about the location of the hole in the bar
#[derive(Debug, Copy, Clone)]
pub struct BarHoleInfo {
    /// Guest location of the hole
    pub gpa: u64,
    /// Size of the hole
    pub size: u64,
    /// What does the hole contain
    pub usage: BarHoleInfoUsage,
}

/// Information about the bar mapping
#[derive(Debug, Copy, Clone)]
pub struct BarMapping {
    /// KVM slot assigned to the mapping
    pub slot: u32,
    /// Guest physical address
    pub iova: u64,
    /// Size
    pub size: u64,
    /// Host virtual address
    pub hva: u64,
}

/// Container for everything MSIx related
#[derive(Debug)]
pub struct MsixState {
    /// Register idx where the capability is in the configuration space
    pub register: u8,
    /// The actual capability (without first 2 bytes)
    pub cap: MsixCap,
    /// Info about Table and Pba holes
    pub bar_hole_infos: ArrayVec<BarHoleInfo, 2>,
    /// Config
    pub config: MsixConfig,
}

/// The VFIO device bundle
pub struct VfioDeviceBundle {
    /// Configuration with which the device was created
    pub config: VfioConfig,
    /// SBDF of the device in the configuration space
    pub sbdf: PciSBDF,
    /// Device
    pub device: VfioDevice,
    /// Information about BARs
    pub bars: Bars,
    /// DMA mapped BARs
    pub bar_mappings: Vec<BarMapping>,
    /// MSIx state
    pub msix_state: MsixState,
    /// Masks for configuration space registers
    pub masks: Vec<RegisterMask>,
    /// Vm
    pub vm: Arc<KvmVm>,
}

impl std::fmt::Debug for VfioDeviceBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VfioDeviceBundle")
            .field("config", &self.config)
            .field("sbdf", &self.sbdf)
            .finish()
    }
}

macro_rules! handle_bar_access {
    ($state:expr, $device:expr, $base:expr, $offset:expr, $data:expr,
     $table_fn:ident, $pba_fn:ident, $region_method:ident) => {{
        let mut name = "----";
        let mut handled = false;
        let data_start = $offset;
        let data_end = $offset + $data.len() as u64;
        for hole in $state.bar_hole_infos.iter() {
            if hole.gpa == $base {
                if hole.usage.contains(BarHoleInfoUsage::TABLE) {
                    let (t_off, t_size) = $state.cap.table_range();
                    let t_start = offset_from_lower_host_page(t_off);
                    let t_end = t_start + t_size;
                    if t_start <= data_start && data_end <= t_end {
                        $state.config.$table_fn($offset - t_start, $data);
                        handled = true;
                        name = "MsiTable";
                        break;
                    }
                    // Reject partial overlap with table.
                    // This should not happen in normal operations, but malicious
                    // driver can try this.
                    // In this case it should be fine to ignore the access all together
                    if data_start < t_end && t_start < data_end {
                        handled = true;
                        break;
                    }
                }

                if hole.usage.contains(BarHoleInfoUsage::PBA) {
                    let (p_off, p_size) = $state.cap.pba_range();
                    let p_start = offset_from_lower_host_page(p_off);
                    let p_end = p_start + p_size;
                    if p_start <= data_start && data_end <= p_end {
                        $state.config.$pba_fn($offset - p_start, $data);
                        handled = true;
                        name = "PbaTable";
                        break;
                    }
                    // Reject partial overlap with pba.
                    // This should not happen in normal operations, but malicious
                    // driver can try this.
                    // In this case it should be fine to ignore the access all together
                    if data_start < p_end && p_start < data_end {
                        handled = true;
                        break;
                    }
                }

                let (region_idx, hole_off_in_region) =
                    if hole.usage.contains(BarHoleInfoUsage::TABLE) {
                        (
                            $state.cap.table_bir(),
                            align_down_host_page($state.cap.table_offset() as u64),
                        )
                    } else {
                        (
                            $state.cap.pba_bir(),
                            align_down_host_page($state.cap.pba_offset() as u64),
                        )
                    };
                let in_region_off = hole_off_in_region + $offset;
                let region_size = $device.get_region_size(region_idx as u32);
                if in_region_off + ($data.len() as u64) <= region_size {
                    $device.$region_method(region_idx as u32, $data, in_region_off);
                } else {
                    // Again, if access is partially out of the region boundaries
                    // just ignore it
                }
                handled = true;
                break;
            }
        }
        (name, handled)
    }};
}

// This should only serve BARs
impl BusDevice for VfioDeviceBundle {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        let (name, handled) = handle_bar_access!(
            self.msix_state,
            self.device,
            base,
            offset,
            data,
            read_table,
            read_pba,
            region_read
        );
        if !handled {
            warn!(
                "[{}] BusDevice::read not handled: base: {base:#x} offset: {offset:#x}",
                self.config.id
            );
            data.fill(0);
        }
        trace!(
            "[{}] base: {base:<#10x} offset: {offset:<#5x} data: {data:<4?} name: {name} handled: \
             {handled}",
            self.config.id,
        );
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let (name, handled) = handle_bar_access!(
            self.msix_state,
            self.device,
            base,
            offset,
            data,
            write_table,
            write_pba,
            region_write
        );
        if !handled {
            warn!(
                "[{}] BusDevice::write not handled: base: {base:#x} offset: {offset:#x}",
                self.config.id
            );
        }
        trace!(
            "[{}] base: {base:<#10x} offset: {offset:<#5x} data: {data:<4?} table_name: {name}, \
             handled: {handled}",
            self.config.id
        );
        None
    }
}

// This should only serve config space
impl PciDevice for VfioDeviceBundle {
    fn write_config_register(
        &mut self,
        reg_idx: u16,
        offset: u8,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        let mut name = "----";
        let mut handled: bool = false;

        if BAR0_REG_IDX <= reg_idx && reg_idx < BAR0_REG_IDX + u16::from(NUM_BAR_REGS) {
            // reg_idx is in [BAR0_REG, BAR0_REG+NUM_BAR_REGS), so the difference is 0..5.
            #[allow(clippy::cast_possible_truncation)]
            let bar_idx = (reg_idx - BAR0_REG_IDX) as u8;
            // offset is within a 4-byte PCI config register (0..3).
            self.bars.write(bar_idx, offset, data);
            name = "BAR";
            handled = true;
        } else if reg_idx == u16::from(self.msix_state.register) {
            // offset is within a 4-byte PCI config register (0..3).
            self.msix_state.config.write_msg_ctl_register(offset, data);
            name = "MSIX_CAP";
            // Don't set `handled` since we need to passthrough write
            // to the msg_ctl register to the device, so it will enable Msix
            // interrupts
        }
        let config_offset = reg_idx * 4 + u16::from(offset);
        if !handled {
            self.device
                .region_write(VFIO_PCI_CONFIG_REGION_INDEX, data, u64::from(config_offset));
        }
        trace!(
            "[{}] reg: {reg_idx:>3}({config_offset:>#6x}) data: {data:<4?} name: {name}",
            self.config.id
        );
        None
    }
    fn read_config_register(&mut self, reg_idx: u16) -> u32 {
        let mut name = "----";
        let config_offset = reg_idx as u64 * 4;
        let mut result: u32 = 0;
        if BAR0_REG_IDX <= reg_idx && reg_idx < BAR0_REG_IDX + u16::from(NUM_BAR_REGS) {
            // reg_idx is in [BAR0_REG, BAR0_REG+NUM_BAR_REGS), so the difference is 0..5.
            #[allow(clippy::cast_possible_truncation)]
            let bar_idx = (reg_idx - BAR0_REG_IDX) as u8;
            self.bars.read(bar_idx, 0, result.as_mut_bytes());
            name = "BAR";
        } else {
            self.device.region_read(
                VFIO_PCI_CONFIG_REGION_INDEX,
                result.as_mut_bytes(),
                config_offset,
            );
            if reg_idx == u16::from(self.msix_state.register) {
                result = (result & !(1 << 31 | 1 << 30))
                    | ((self.msix_state.config.enabled as u32) << 31)
                    | ((self.msix_state.config.masked as u32) << 30);
                name = "MSIX_CAP";
            }
            for mask in self.masks.iter() {
                if mask.register == reg_idx {
                    result = (result & mask.mask) | mask.value;
                    name = "MASK";
                    break;
                }
            }
        }
        trace!(
            "[{}] reg: {reg_idx:>3}({config_offset:>#6x}) data: {:<4?} name: {name}",
            self.config.id,
            result.as_bytes()
        );
        result
    }
}

#[allow(clippy::type_complexity)]
fn vfio_device_get_pci_capabilities(
    device: &VfioDevice,
) -> Result<(Option<(MsixCap, u8)>, Vec<RegisterMask>), VfioError> {
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

        // 7.5.3.1 PCI Express Capability List Register
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
                        // 7.7.2 MSI-X Capability and Table Structure
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
            _ => {}
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

            // 7.7.3.1 Secondary PCI Express Extended Capability Header
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
                PciExpressCapabilityId::AlternativeRoutingIdentificationInterpretation
                | PciExpressCapabilityId::ResizeableBar
                | PciExpressCapabilityId::SingleRootIoVirtualization => {
                    debug!(
                        "Found cap to be masked at register: {register}({current_cap_offset:#x})"
                    );
                    masks.push(RegisterMask {
                        register,
                        mask: 0xffff_0000,
                        value: 0x0000_0000,
                    })
                }
                _ => {}
            }
        }
    }
    Ok((msix_cap_and_register, masks))
}

fn vfio_device_get_single_bar_info(
    device: &VfioDevice,
    bar_idx: u8,
) -> Result<(u32, u32), VfioError> {
    // 7.5.1.2.1 Base Address Registers
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
    Ok((value, size))
}

fn vfio_device_allocate_bars(
    device: &VfioDevice,
    resource_allocator: &mut ResourceAllocator,
) -> Result<Bars, VfioError> {
    let mut bars = Bars::default();
    let mut bar_idx = 0;
    while bar_idx < NUM_BAR_REGS {
        let (bar_info, mut lower_size) = vfio_device_get_single_bar_info(device, bar_idx)?;

        let is_io_bar = bar_info & PCI_CONFIG_IO_BAR != 0;
        let is_64_bits = bar_info & PCI_CONFIG_MEMORY_BAR_64BIT != 0;
        let is_prefetchable = bar_info & PCI_CONFIG_BAR_PREFETCHABLE != 0;

        if is_64_bits && bar_idx == NUM_BAR_REGS - 1 {
            warn!("BAR{bar_idx} is last BAR but marked as 64bit. Skipping");
            break;
        }

        let size = if is_io_bar {
            lower_size &= !0b11;
            u64::from(decode_32_bits_bar_size(lower_size))
        } else if !is_64_bits {
            lower_size &= !0b1111;
            u64::from(decode_32_bits_bar_size(lower_size))
        } else {
            lower_size &= !0b1111;
            let (_, upper_size) = vfio_device_get_single_bar_info(device, bar_idx + 1)?;
            decode_64_bits_bar_size(upper_size, lower_size)
        };
        if size != 0 {
            fn calculate_alignment(size: u64) -> u64 {
                // 7.5.1.2.1 Base Address Registers
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
                gpa = resource_allocator
                    .mmio64_memory
                    .allocate(size, alignment, AllocPolicy::FirstMatch)
                    .map_err(|_| VfioError::BarAllocation)?
                    .start();
                bars.set_bar_64(idx, gpa, size, is_prefetchable.into());
            } else {
                let alignment = calculate_alignment(size);
                gpa = resource_allocator
                    .mmio32_memory
                    .allocate(size, alignment, AllocPolicy::FirstMatch)
                    .map_err(|_| VfioError::BarAllocation)?
                    .start();
                assert!(gpa < u64::from(u32::MAX));
                assert!(size < u64::from(u32::MAX));
                #[allow(clippy::cast_possible_truncation)]
                let gpa = gpa as u32;
                #[allow(clippy::cast_possible_truncation)]
                let size = size as u32;
                bars.set_bar_32(idx, gpa, size, is_prefetchable.into());
            }
            debug!(
                "BAR{bar_idx} gpa: [{:#x}..{:#x}] size: {size:>#10x} io_bar: {is_io_bar} 64bits: \
                 {is_64_bits} prefetchable: {is_prefetchable}",
                gpa,
                gpa + size
            );
        } else {
            debug!(
                "BAR{bar_idx} size: {size:>#10x} io_bar: {is_io_bar} 64bits: {is_64_bits} \
                 prefetchable: {is_prefetchable}"
            );
        }
        if is_64_bits {
            bar_idx += 1;
        }
        bar_idx += 1;
    }
    Ok(bars)
}

fn deallocate_bars(resource_allocator: &mut ResourceAllocator, bars: &Bars) {
    let mut bar_idx = 0;
    while bar_idx < NUM_BAR_REGS {
        if bars.bars[bar_idx as usize].used() {
            let start = bars.get_bar_addr(bar_idx);
            let size = bars.get_bar_size(bar_idx);
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

/// Intermediate type to store areas needed to be mmaped for the device
#[derive(Debug, Clone, Copy)]
struct BarArea {
    /// BAR gpa
    bar_gpa: u64,
    /// Offset into VFIO region
    region_offset: u64,
    /// Offset within BAR
    offset: u64,
    /// Size
    size: u64,
    /// Prot flags
    prot: i32,
}

/// Calculate areas needed to be mmaped for the device BARs including any BAR holes caused
/// by MSI-X table/pba
fn calculate_bar_areas(
    bars: &Bars,
    region_infos: &[VfioRegionInfo],
    msix_cap: Option<&MsixCap>,
) -> Result<(Vec<BarArea>, ArrayVec<BarHoleInfo, 2>), VfioError> {
    // There are 6 BARs with maximum of 2 holes in one or two of them
    // The only reasons to use Vec instead of ArrayVec here is because this vector can be populated
    // from the `sparse_mmap_cap` which can contiains different number of areas.
    // But in any case the size here is limited by the `nr_areas` field in the
    // `vfio_region_info_cap_sparse_mmap` struct. This field has type of `u32`.
    let mut areas = Vec::with_capacity(8);
    let mut bar_hole_infos = ArrayVec::<BarHoleInfo, 2>::new();
    let mut bar_idx: u8 = 0;
    while bar_idx < NUM_BAR_REGS {
        let bar_gpa = bars.get_bar_addr(bar_idx);
        if bar_gpa != 0 {
            let region_info = &region_infos[bar_idx as usize];
            let mut has_msix_mappable = false;
            let mut sparse_mmap_cap = None;
            for cap in region_info.caps.iter() {
                match cap {
                    VfioRegionInfoCap::SparseMmap(cap) => sparse_mmap_cap = Some(cap),
                    VfioRegionInfoCap::MsixMappable => has_msix_mappable = true,
                    _ => {}
                }
            }
            let mut contain_msix_table: bool = false;
            let mut msix_table_offset = 0;
            let mut msix_table_size = 0;

            let mut contain_msix_pba: bool = false;
            let mut msix_pba_offset = 0;
            let mut msix_pba_size = 0;

            if let Some(msix_cap) = msix_cap {
                contain_msix_table = bar_idx == msix_cap.table_bir();
                if contain_msix_table {
                    let (offset, size) = msix_cap.table_range();
                    let offset_in_hole = offset_from_lower_host_page(offset);

                    msix_table_offset = align_down_host_page(offset);
                    msix_table_size = align_up_host_page(offset_in_hole + size);

                    if msix_table_offset
                        .checked_add(msix_table_size)
                        .is_none_or(|end| end > region_info.size)
                    {
                        return Err(VfioError::MsixTableOutOfRange(
                            bar_idx,
                            msix_table_offset,
                            msix_table_size,
                            region_info.size,
                        ));
                    }

                    debug!(
                        "BAR{} msix_table hole: [{:#x}..{:#x}] actual table: [{:#x} ..{:#x}]",
                        bar_idx,
                        bar_gpa + msix_table_offset,
                        bar_gpa + msix_table_offset + msix_table_size,
                        bar_gpa + offset_in_hole,
                        bar_gpa + offset_in_hole + size,
                    );

                    let info = BarHoleInfo {
                        gpa: bar_gpa + msix_table_offset,
                        size: msix_table_size,
                        usage: BarHoleInfoUsage::TABLE,
                    };
                    bar_hole_infos.push(info);
                }

                contain_msix_pba = bar_idx == msix_cap.pba_bir();
                if contain_msix_pba {
                    let (offset, size) = msix_cap.pba_range();
                    let offset_in_hole = offset_from_lower_host_page(offset);

                    msix_pba_offset = align_down_host_page(offset);
                    msix_pba_size = align_up_host_page(offset_in_hole + size);

                    if msix_pba_offset
                        .checked_add(msix_pba_size)
                        .is_none_or(|end| end > region_info.size)
                    {
                        return Err(VfioError::MsixPbaOutOfRange(
                            bar_idx,
                            msix_pba_offset,
                            msix_pba_size,
                            region_info.size,
                        ));
                    }

                    debug!(
                        "BAR{} pba_table hole: [{:#x} ..{:#x}] actual table: [{:#x} ..{:#x}]",
                        bar_idx,
                        bar_gpa + msix_pba_offset,
                        bar_gpa + msix_pba_offset + msix_pba_size,
                        bar_gpa + offset_in_hole,
                        bar_gpa + offset_in_hole + size,
                    );

                    let pba_gpa = bar_gpa + msix_pba_offset;
                    // The table hole, if present, was just pushed above, so
                    // the PBA hole can only coincide with the last entry.
                    // Merge into it so we don't register the same MMIO range
                    // twice.
                    if let Some(last) = bar_hole_infos.last_mut()
                        && last.gpa == pba_gpa
                    {
                        last.usage |= BarHoleInfoUsage::PBA;
                        // In case PBA table is weirdly located at the page boundary which forces
                        // the size to become 2 pages instead of 1, just extend the region
                        last.size = last.size.max(msix_pba_size);
                    } else {
                        let info = BarHoleInfo {
                            gpa: pba_gpa,
                            size: msix_pba_size,
                            usage: BarHoleInfoUsage::PBA,
                        };
                        bar_hole_infos.push(info);
                    }
                }
            }

            if (contain_msix_table || contain_msix_pba)
                && !has_msix_mappable
                && sparse_mmap_cap.is_none()
            {
                debug!(
                    "BAR{} contains msix_table: {} msix_pba: {}, but mappable is {} and \
                     sparse_mmap_cap is {}. Skipping",
                    bar_idx,
                    contain_msix_table,
                    contain_msix_pba,
                    has_msix_mappable,
                    sparse_mmap_cap.is_some()
                );
            } else {
                let can_mmap = region_info.flags & VFIO_REGION_INFO_FLAG_MMAP != 0;
                if can_mmap || sparse_mmap_cap.is_some() {
                    let mut prot = 0;
                    if region_info.flags & VFIO_REGION_INFO_FLAG_READ != 0 {
                        prot |= libc::PROT_READ;
                    }
                    if region_info.flags & VFIO_REGION_INFO_FLAG_WRITE != 0 {
                        prot |= libc::PROT_WRITE;
                    }
                    let region_size = region_info.size;

                    if let Some(cap) = sparse_mmap_cap {
                        for area in cap.areas.iter() {
                            if area
                                .offset
                                .checked_add(area.size)
                                .is_none_or(|end| end > region_size)
                            {
                                return Err(VfioError::SparseMmapAreaOutOfRange(
                                    bar_idx,
                                    area.offset,
                                    area.size,
                                    region_size,
                                ));
                            }
                            areas.push(BarArea {
                                bar_gpa,
                                region_offset: region_info.offset,
                                offset: area.offset,
                                size: area.size,
                                prot,
                            });
                        }
                    } else if has_msix_mappable {
                        let mut first_gap_offset = msix_table_offset;
                        let mut first_gap_size = msix_table_size;
                        let mut second_gap_offset = msix_pba_offset;
                        let mut second_gap_size = msix_pba_size;
                        if second_gap_offset < first_gap_offset {
                            second_gap_offset = msix_table_offset;
                            second_gap_size = msix_table_size;
                            first_gap_offset = msix_pba_offset;
                            first_gap_size = msix_pba_size;
                        }
                        let mut offset = 0;
                        if first_gap_size != 0 {
                            let area_size = first_gap_offset - offset;
                            if area_size != 0 {
                                areas.push(BarArea {
                                    bar_gpa,
                                    region_offset: region_info.offset,
                                    offset,
                                    size: area_size,
                                    prot,
                                });
                            }
                            offset = first_gap_offset + first_gap_size;
                        }
                        if second_gap_size != 0 {
                            if offset < second_gap_offset {
                                let area_size = second_gap_offset - offset;
                                if area_size != 0 {
                                    areas.push(BarArea {
                                        bar_gpa,
                                        region_offset: region_info.offset,
                                        offset,
                                        size: area_size,
                                        prot,
                                    });
                                }
                            }
                            offset = offset.max(second_gap_offset + second_gap_size);
                        }
                        let area_size = region_size - offset;
                        if area_size != 0 {
                            areas.push(BarArea {
                                bar_gpa,
                                region_offset: region_info.offset,
                                offset,
                                size: area_size,
                                prot,
                            });
                        }
                    } else {
                        areas.push(BarArea {
                            bar_gpa,
                            region_offset: region_info.offset,
                            offset: 0,
                            size: region_size,
                            prot,
                        });
                    }
                }
            }
        }
        if bars.bars[bar_idx as usize].is_64bit() {
            bar_idx += 1;
        }
        bar_idx += 1;
    }
    Ok((areas, bar_hole_infos))
}

/// Establish DMA mapping of the Dram region of the guest memory with the vfio container
pub fn dma_map_guest_memory(
    container: &VfioContainer,
    guest_memory: &GuestMemoryMmap,
) -> Result<(), VfioError> {
    for (i, region) in guest_memory.iter().enumerate() {
        if region.region_type == GuestRegionType::Dram {
            let region = &region.inner;
            let hva = region.as_ptr();
            let iova = region.start_addr().0;
            let size = region.size();
            debug!(
                "DMA map guest memory: [{:#x}..{:#x}]",
                iova,
                iova + size as u64
            );
            // SAFETY: all arguments are from the existing guest memory region
            // After this operation, virtual memory will have a pinned physical pages backing it
            if let Err(e) = unsafe { container.vfio_dma_map(iova, size, hva) } {
                // Try to remove DMA mapping if anything fails. If unmap also fails, just log it
                // since there is nothing we can do about it.
                // Since the failed region is at index 'i', we only care about [0..i) regions
                for region in guest_memory.iter().take(i) {
                    if region.region_type == GuestRegionType::Dram {
                        let iova = region.start_addr().0;
                        let size = region.size();
                        if let Err(ee) = container.vfio_dma_unmap(iova, size) {
                            error!("Failed to unmap DMA from guest memory: {ee}");
                        }
                    }
                }
                return Err(VfioError::VfioIoctls(e));
            }
        }
    }
    Ok(())
}

/// Tear down DMA mapping of the Dram guest memory from the vfio container
pub fn dma_unmap_guest_memory(container: &VfioContainer, guest_memory: &GuestMemoryMmap) {
    for region in guest_memory.iter() {
        if region.region_type == GuestRegionType::Dram {
            let iova = region.start_addr().0;
            let size = region.size();
            if let Err(ee) = container.vfio_dma_unmap(iova, size) {
                error!("Failed to unmap DMA from guest memory: {ee}");
            }
        }
    }
}

fn map_bar_mapping(
    container: &VfioContainer,
    device: &VfioDevice,
    vm: &KvmVm,
    area: &BarArea,
    slot: u32,
) -> Result<BarMapping, VfioError> {
    // SAFETY: FFI call to mmap with valid fd and offset. The returned pointer is checked
    // against MAP_FAILED before use.
    let hva_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            #[allow(clippy::cast_possible_truncation)]
            {
                area.size as usize
            },
            area.prot,
            libc::MAP_SHARED,
            device.as_raw_fd(),
            #[allow(clippy::cast_possible_wrap)]
            {
                (area.region_offset + area.offset) as i64
            },
        )
    };

    if hva_ptr == libc::MAP_FAILED {
        return Err(VfioError::Mmap);
    }

    let iova = area.bar_gpa + area.offset;
    let size = area.size;
    let hva = hva_ptr as u64;

    let kvm_memory_region = kvm_userspace_memory_region {
        slot,
        flags: 0,
        guest_phys_addr: iova,
        memory_size: size,
        userspace_addr: hva,
    };
    if let Err(e) = vm.set_user_memory_region(kvm_memory_region) {
        // SAFETY: hva_ptr was returned by a successful mmap call above with the given size.
        let r = unsafe { libc::munmap(hva_ptr.cast(), u64_to_usize(size)) };
        if r < 0 {
            error!(
                "Error on unmapping host memory on VFIO device creation failure: {r:?}. \
                 Continuing with other regions removal."
            );
        }
        return Err(VfioError::SetUserMemoryRegion(e.to_string()));
    }

    // NOTE: the `vfio_dma_map` always maps with `VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE`
    // which does not respect the `region_info.flags`/`area.prot`.
    if let Err(e) =
        // SAFETY: hva_ptr was returned by a successful mmap call with the given size.
        unsafe { container.vfio_dma_map(iova, u64_to_usize(size), hva_ptr.cast::<u8>()) }
    {
        let kvm_memory_region = kvm_userspace_memory_region {
            slot,
            flags: 0,
            guest_phys_addr: iova,
            memory_size: 0,
            userspace_addr: hva,
        };
        if let Err(ee) = vm.set_user_memory_region(kvm_memory_region) {
            error!(
                "Error on removing KVM region on VFIO device creation failure: {ee:?}. Continuing \
                 with other regions removal."
            );
        }
        // SAFETY: hva_ptr was returned by a successful mmap call with the given size.
        let r = unsafe { libc::munmap(hva_ptr.cast(), u64_to_usize(size)) };
        if r < 0 {
            error!(
                "Error on unmapping host memory on VFIO device creation failure: {r:?}. \
                 Continuing with other regions removal."
            );
        }
        return Err(e.into());
    }
    Ok(BarMapping {
        slot,
        iova,
        size,
        hva,
    })
}

fn unmap_bar_mapping(container: &VfioContainer, vm: &KvmVm, mapping: &BarMapping) {
    let kvm_memory_region = kvm_userspace_memory_region {
        slot: mapping.slot,
        flags: 0,
        guest_phys_addr: mapping.iova,
        memory_size: 0,
        userspace_addr: mapping.hva,
    };
    if let Err(ee) = vm.set_user_memory_region(kvm_memory_region) {
        error!(
            "Error on removing KVM region on VFIO device creation failure: {ee:?}. Continuing \
             with other regions removal."
        );
    }

    if let Err(ee) = container.vfio_dma_unmap(mapping.iova, u64_to_usize(mapping.size)) {
        error!(
            "Error on unmapping DMA region on VFIO device creation failure: {ee:?}. Continuing \
             with other regions removal."
        );
    }

    // SAFETY: host_addr was obtained from a successful mmap call with the given size.
    let r = unsafe { libc::munmap(mapping.hva as *mut libc::c_void, u64_to_usize(mapping.size)) };
    if r < 0 {
        error!(
            "Error on unmapping host memory on VFIO device creation failure: {r:?}. Continuing \
             with other regions removal."
        );
    }
}

// There is no direct access to `regions` in `VfioDevice`, so need to work around this
fn extract_bar_region_infos(device: &VfioDevice) -> Vec<VfioRegionInfo> {
    (0..NUM_BAR_REGS as u32)
        .map(|i| VfioRegionInfo {
            flags: device.get_region_flags(i),
            size: device.get_region_size(i),
            offset: device.get_region_offset(i),
            caps: device.get_region_caps(i),
        })
        .collect()
}

/// Create KVM_DEV_TYPE_VFIO device
fn create_kvm_vfio_device(vm: &KvmVm) -> Result<kvm_ioctls::DeviceFd, VfioError> {
    let mut vfio_dev = kvm_create_device {
        type_: kvm_device_type_KVM_DEV_TYPE_VFIO,
        fd: 0,
        flags: 0,
    };
    vm.fd()
        .create_device(&mut vfio_dev)
        .map_err(VfioError::KVMCreateVfioDevice)
}

/// Create a VfioContainer wrapper around both KVM vfio device and VFIO container
pub fn init_kvm_vfio_device_and_vfio_container(
    vm: &KvmVm,
) -> Result<Arc<VfioContainer>, VfioError> {
    let kvm_device_fd = create_kvm_vfio_device(vm)?;
    let device_fd = VfioDeviceFd::new_from_kvm(kvm_device_fd);
    let container = VfioContainer::new(Some(Arc::new(device_fd)))?;
    Ok(Arc::new(container))
}

#[allow(clippy::type_complexity)]
fn prepare_vfio_device(
    container: &Arc<VfioContainer>,
    vm: &Arc<KvmVm>,
    sysfs_path: &Path,
    sbdf: PciSBDF,
) -> Result<
    (
        VfioDevice,
        Bars,
        Vec<BarMapping>,
        MsixState,
        Vec<RegisterMask>,
    ),
    VfioError,
> {
    let device = VfioDevice::new(
        sysfs_path,
        container.clone() as Arc<dyn vfio_ioctls::VfioOps>,
    )?;
    device.reset();

    let (msix_cap_and_register, masks) = vfio_device_get_pci_capabilities(&device)?;

    // Only devices with MSI-X cap and irqs are supported
    let Some((msix_cap, msix_register)) = msix_cap_and_register else {
        return Err(VfioError::NoMsixIrq);
    };
    let Some(msix_irq_info) = device.get_irq_info(VFIO_PCI_MSIX_IRQ_INDEX) else {
        return Err(VfioError::NoMsixIrq);
    };

    // SAFETY: maximum msix table size is 1 << 11 = 2048 (it has 10 bits int the control register
    // and encoded as N - 1)
    // This fits into u16 without issues
    #[allow(clippy::cast_possible_truncation)]
    let msix_num = msix_irq_info.count as u16;
    let msix_vectors =
        KvmVm::create_msix_group(vm.clone(), msix_num).map_err(VfioError::MsixConfig)?;
    let msix_config = MsixConfig::new(Arc::new(msix_vectors), sbdf);

    // We set VFIO irqs here on device setup. There is no reason to add additional tracking
    // for driver MSIx configuration since those are handled by the MsixState.
    // If anything after this call fails, we don't need to do anything since the kernel will
    // clean up these irqs when `device` file will be closed.
    let fds: Vec<&EventFd> = msix_config
        .vectors
        .vectors
        .iter()
        .map(|v| &v.event_fd)
        .collect();
    device.enable_msix(fds)?;

    let bars = {
        let mut resource_allocator_lock = vm.resource_allocator();
        let resource_allocator = resource_allocator_lock.deref_mut();
        vfio_device_allocate_bars(&device, resource_allocator)?
    };

    let bar_region_infos = extract_bar_region_infos(&device);
    let (areas, bar_hole_infos) = match calculate_bar_areas(
        &bars,
        &bar_region_infos,
        msix_cap_and_register.as_ref().map(|(v, _)| v),
    ) {
        Ok(v) => v,
        Err(e) => {
            let mut resource_allocator_lock = vm.resource_allocator();
            let resource_allocator = resource_allocator_lock.deref_mut();
            deallocate_bars(resource_allocator, &bars);
            return Err(e);
        }
    };
    let first_area_slot = match vm.next_kvm_slot(
        // SAFETY: areas.len() is bound to fit in u32
        #[allow(clippy::cast_possible_truncation)]
        {
            areas.len() as u32
        },
    ) {
        Some(v) => v,
        None => {
            let mut resource_allocator_lock = vm.resource_allocator();
            let resource_allocator = resource_allocator_lock.deref_mut();
            deallocate_bars(resource_allocator, &bars);
            return Err(VfioError::KvmSlot);
        }
    };

    // Same as with areas, usually there only should be 6 BARs and one of them can be split into 3
    // regions
    let mut bar_mappings = Vec::with_capacity(8);
    for (i, area) in areas.iter().enumerate() {
        match map_bar_mapping(
            container,
            &device,
            vm.as_ref(),
            area,
            first_area_slot + {
                // TODO i can fit into u32, but the sum might not. But the propability that this
                // should ever happen is 0, so this should be ok.
                #[allow(clippy::cast_possible_truncation)]
                {
                    i as u32
                }
            },
        ) {
            Ok(mapping) => {
                debug!(
                    "BAR area{} kvm gpa: [{:#x} ..{:#x}]",
                    i,
                    mapping.iova,
                    mapping.iova + mapping.size
                );
                bar_mappings.push(mapping);
            }
            Err(e) => {
                let mut resource_allocator_lock = vm.resource_allocator();
                let resource_allocator = resource_allocator_lock.deref_mut();
                deallocate_bars(resource_allocator, &bars);

                for mapping in bar_mappings.iter() {
                    unmap_bar_mapping(container, vm.as_ref(), mapping);
                }
                return Err(e);
            }
        }
    }

    let msix_state = MsixState {
        register: msix_register,
        cap: msix_cap,
        bar_hole_infos,
        config: msix_config,
    };
    Ok((device, bars, bar_mappings, msix_state, masks))
}

/// This will open a VFIO device, attach it's group both to the KVM VFIO device and to the VFIO
/// container. It will setup MSIx irqs and BAR DMAs.
pub fn init_vfio_device(
    container: &Arc<VfioContainer>,
    vm: &Arc<KvmVm>,
    config: VfioConfig,
    sbdf: PciSBDF,
) -> Result<Arc<Mutex<VfioDeviceBundle>>, VfioError> {
    let sysfs_path = config.sbdf.sysfs_path();
    debug!("Opening device at path: {}", sysfs_path);
    let (device, bars, bar_mappings, msix_state, masks) =
        prepare_vfio_device(container, vm, Path::new(&sysfs_path), sbdf)?;

    let vfio_device_bundle = Arc::new(Mutex::new(VfioDeviceBundle {
        config,
        sbdf,
        device,
        bars,
        bar_mappings,
        msix_state,
        masks,
        vm: vm.clone(),
    }));

    for hole in vfio_device_bundle
        .lock()
        .unwrap()
        .msix_state
        .bar_hole_infos
        .iter()
    {
        vm.common
            .mmio_bus
            .insert(vfio_device_bundle.clone(), hole.gpa, hole.size)
            // SAFETY: the hole gpa and size were allocated from internal allocator. we must never
            // receive overlapping regions from it.
            .unwrap();
    }
    Ok(vfio_device_bundle)
}

/// Performs cleanup of all VFIO device resources allocated by `init_vfio_device`
pub fn deinit_vfio_device(container: &Arc<VfioContainer>, vm: &KvmVm, device: &VfioDeviceBundle) {
    for hole in device.msix_state.bar_hole_infos.iter() {
        vm.common.mmio_bus.remove(hole.gpa, hole.size).unwrap();
    }
    for mapping in device.bar_mappings.iter() {
        unmap_bar_mapping(container, vm, mapping);
    }

    device.device.reset();

    let mut resource_allocator_lock = vm.resource_allocator();
    let resource_allocator = resource_allocator_lock.deref_mut();
    deallocate_bars(resource_allocator, &device.bars);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::configuration::BarPrefetchable;

    fn make_region(size: u64, caps: Vec<VfioRegionInfoCap>) -> VfioRegionInfo {
        let flags = if size != 0 {
            VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE | VFIO_REGION_INFO_FLAG_MMAP
        } else {
            0
        };
        VfioRegionInfo {
            flags,
            size,
            offset: 0,
            caps,
        }
    }

    #[test]
    fn test_calculate_bar_areas_no_msix() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x4000_0000_0000, 0x10_0000, BarPrefetchable::No);
        let region_infos = [make_region(0x10_0000, vec![])];

        let (areas, holes) = calculate_bar_areas(&bars, &region_infos, None).unwrap();
        assert_eq!(areas.len(), 1);
        assert_eq!(areas[0].bar_gpa, 0x4000_0000_0000);
        assert_eq!(areas[0].size, 0x10_0000);
        assert_eq!(areas[0].offset, 0);
        assert!(holes.is_empty());
    }

    #[test]
    fn test_calculate_bar_areas_msix_table_and_pba_different_bars() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x4000_0000_0000, 0x10_0000, BarPrefetchable::No);
        bars.set_bar_64(2, 0x4000_0010_0000, 0x1_0000, BarPrefetchable::No);

        let region_infos = [
            make_region(0x10_0000, vec![VfioRegionInfoCap::MsixMappable]),
            // BAR 0 is 64-bit so slot 1 is its high half and is never indexed.
            make_region(0, vec![]),
            make_region(0x1_0000, vec![VfioRegionInfoCap::MsixMappable]),
        ];

        let msix_cap = MsixCap::new(0, 32, 0, 2, 0);

        let (areas, holes) = calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();
        assert_eq!(holes.len(), 2);
        assert!(!areas.is_empty());
    }

    #[test]
    fn test_calculate_bar_areas_msix_table_and_pba_same_bar() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x4000_0000_0000, 0x10_0000, BarPrefetchable::No);

        let region_infos = [make_region(
            0x10_0000,
            vec![VfioRegionInfoCap::MsixMappable],
        )];

        let msix_cap = MsixCap::new(0, 32, 0, 0, 0x1000);

        let (areas, holes) = calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();
        assert_eq!(holes.len(), 2);
        // Table hole [0x0..0x1000), PBA hole [0x1000..0x2000), one area after both.
        assert_eq!(areas.len(), 1);
        assert_eq!(areas[0].offset, 0x2000);
        assert_eq!(areas[0].size, 0x10_0000 - 0x2000);
    }

    #[test]
    fn test_calculate_bar_areas_sparse_mmap() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x4000_0000_0000, 0x10_0000, BarPrefetchable::No);

        let sparse_areas = vec![
            VfioRegionSparseMmapArea {
                offset: 0,
                size: 0x8_0000,
            },
            VfioRegionSparseMmapArea {
                offset: 0xC_0000,
                size: 0x4_0000,
            },
        ];
        let region_infos = [make_region(
            0x10_0000,
            vec![VfioRegionInfoCap::SparseMmap(VfioRegionInfoCapSparseMmap {
                areas: sparse_areas,
            })],
        )];

        let msix_cap = MsixCap::new(0, 32, 0x8_0000, 0, 0xB_0000);

        let (areas, _holes) = calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();
        assert_eq!(areas.len(), 2);
        assert_eq!(areas[0].offset, 0);
        assert_eq!(areas[0].size, 0x8_0000);
        assert_eq!(areas[1].offset, 0xC_0000);
        assert_eq!(areas[1].size, 0x4_0000);
    }

    #[test]
    fn test_calculate_bar_areas_zero_size_bar() {
        let bars = Bars::default();
        let region_infos: [VfioRegionInfo; 0] = [];

        let (areas, holes) = calculate_bar_areas(&bars, &region_infos, None).unwrap();
        assert!(areas.is_empty());
        assert!(holes.is_empty());
    }

    #[test]
    fn test_calculate_bar_areas_overlapping_msix_holes() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x4000_0000_0000, 0x10_0000, BarPrefetchable::No);

        let region_infos = [make_region(
            0x10_0000,
            vec![VfioRegionInfoCap::MsixMappable],
        )];

        // Both tables create the same hole [0x0..0x1000)
        let msix_cap = MsixCap::new(0, 32, 0x0, 0, 0x200);
        let (areas, holes) = calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();

        assert_eq!(areas.len(), 1);
        assert_eq!(areas[0].offset, 0x1000);
        assert_eq!(areas[0].size, 0x10_0000 - 0x1000);

        assert_eq!(holes.len(), 1);
        assert_eq!(
            holes[0].usage,
            BarHoleInfoUsage::TABLE | BarHoleInfoUsage::PBA
        );
    }

    /// Table and PBA share the same starting page (so the same hole `gpa`),
    /// but the PBA contents straddle the page boundary, so its host-page-
    /// aligned size is larger than the table's. The two holes must merge
    /// into one - taking the larger size - otherwise `init_vfio_device`
    /// would panic on `mmio_bus.insert` for an overlapping range.
    #[test]
    fn test_calculate_bar_areas_same_gpa_different_size_msix_holes() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x4000_0000_0000, 0x10_0000, BarPrefetchable::No);

        let region_infos = [make_region(
            0x10_0000,
            vec![VfioRegionInfoCap::MsixMappable],
        )];

        // table at offset 0, 128 entries (0x800 bytes) -> hole [0x0, 0x1000)
        // PBA at offset 0xff8, 16 bytes -> straddles 0x1000 -> hole [0x0, 0x2000)
        // Same gpa (bar_gpa + 0), different sizes.
        let msix_cap = MsixCap::new(0, 128, 0, 0, 0xff8);

        let (areas, holes) = calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();

        // One merged hole, sized to the larger of the two (PBA's 0x2000).
        assert_eq!(holes.len(), 1);
        assert_eq!(holes[0].gpa, 0x4000_0000_0000);
        assert_eq!(holes[0].size, 0x2000);
        assert_eq!(
            holes[0].usage,
            BarHoleInfoUsage::TABLE | BarHoleInfoUsage::PBA
        );

        // One area covering the BAR after the merged hole.
        assert_eq!(areas.len(), 1);
        assert_eq!(areas[0].offset, 0x2000);
        assert_eq!(areas[0].size, 0x10_0000 - 0x2000);
    }

    /// MSI-X table claimed at the very end of the BAR. The page-aligned hole
    /// would extend past `region_size` and the gap arithmetic would underflow.
    /// `calculate_bar_areas` must reject this with `MsixTableOutOfRange`
    /// instead of proceeding with corrupted offsets.
    #[test]
    fn test_calculate_bar_areas_msix_table_past_region_end() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x4000_0000_0000, 0x4000, BarPrefetchable::No);

        let region_infos = [make_region(0x4000, vec![VfioRegionInfoCap::MsixMappable])];

        // table at offset 0x3ff8, 1 entry (16 bytes). The page-aligned hole is
        // [0x3000, 0x5000) (offset 0x3000, size 0x2000), whose end 0x5000 is
        // past the BAR's region_size of 0x4000.
        let msix_cap = MsixCap::new(0, 1, 0x3ff8, 0, 0);

        let err = calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap_err();
        assert!(matches!(
            err,
            VfioError::MsixTableOutOfRange(0, 0x3000, 0x2000, 0x4000)
        ));
    }

    /// MSI-X PBA claimed past the end of the BAR - same underflow risk as the
    /// table case but on the PBA path.
    #[test]
    fn test_calculate_bar_areas_msix_pba_past_region_end() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x4000_0000_0000, 0x4000, BarPrefetchable::No);

        let region_infos = [make_region(0x4000, vec![VfioRegionInfoCap::MsixMappable])];

        // PBA at offset 0x4000 (= region_size), 1 entry. The page-aligned hole is
        // [0x4000, 0x5000) (offset 0x4000, size 0x1000), whose end 0x5000 is past
        // region_size 0x4000.
        let msix_cap = MsixCap::new(0, 1, 0, 0, 0x4000);

        let err = calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap_err();
        assert!(matches!(
            err,
            VfioError::MsixPbaOutOfRange(0, 0x4000, 0x1000, 0x4000)
        ));
    }

    /// A sparse mmap area extending past the region end must also be rejected.
    #[test]
    fn test_calculate_bar_areas_sparse_mmap_area_past_region_end() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x4000_0000_0000, 0x4000, BarPrefetchable::No);

        let sparse_areas = vec![VfioRegionSparseMmapArea {
            offset: 0x3000,
            size: 0x2000, // 0x3000 + 0x2000 = 0x5000, past region_size 0x4000
        }];
        let region_infos = [make_region(
            0x4000,
            vec![VfioRegionInfoCap::SparseMmap(VfioRegionInfoCapSparseMmap {
                areas: sparse_areas,
            })],
        )];

        let err = calculate_bar_areas(&bars, &region_infos, None).unwrap_err();
        assert!(matches!(
            err,
            VfioError::SparseMmapAreaOutOfRange(0, 0x3000, 0x2000, 0x4000)
        ));
    }

    /// MSI-X table offset+size that overflows u64 on addition must also be
    /// rejected, not silently wrap.
    #[test]
    fn test_calculate_bar_areas_msix_table_offset_overflow() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x4000_0000_0000, 0x4000, BarPrefetchable::No);

        let region_infos = [make_region(0x4000, vec![VfioRegionInfoCap::MsixMappable])];

        // MsixCap stores table_offset in 32 bits, so it cannot itself overflow.
        // But the masked-off table_offset is 0xffff_fff8; with 32 entries the
        // table_range size = 32 * 16 = 0x200, end = 0x1_0000_01f8, past region_size.
        let msix_cap = MsixCap::new(0, 32, 0xffff_fff8, 0, 0);

        let err = calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap_err();
        assert!(matches!(err, VfioError::MsixTableOutOfRange(0, _, _, _)));
    }

    #[derive(Debug, Default)]
    struct MockMsixConfig {
        table_read: Option<(u64, usize)>,
        table_write: Option<(u64, Vec<u8>)>,
        pba_read: Option<(u64, usize)>,
        pba_write: Option<(u64, Vec<u8>)>,
    }

    impl MockMsixConfig {
        fn read_table(&mut self, offset: u64, data: &mut [u8]) {
            assert!(
                self.table_read.is_none(),
                "read_table called more than once"
            );
            self.table_read = Some((offset, data.len()));
            data.fill(0xAA);
        }
        fn write_table(&mut self, offset: u64, data: &[u8]) {
            assert!(
                self.table_write.is_none(),
                "write_table called more than once"
            );
            self.table_write = Some((offset, data.to_vec()));
        }
        fn read_pba(&mut self, offset: u64, data: &mut [u8]) {
            assert!(self.pba_read.is_none(), "read_pba called more than once");
            self.pba_read = Some((offset, data.len()));
            data.fill(0xBB);
        }
        fn write_pba(&mut self, offset: u64, data: &[u8]) {
            assert!(self.pba_write.is_none(), "write_pba called more than once");
            self.pba_write = Some((offset, data.to_vec()));
        }
    }

    #[derive(Debug)]
    struct MockVfioDevice {
        region_size: u64,
        read: Option<(u32, u64, usize)>,
        write: Option<(u32, u64, Vec<u8>)>,
    }

    impl MockVfioDevice {
        fn new(region_size: u64) -> Self {
            Self {
                region_size,
                read: None,
                write: None,
            }
        }
        fn get_region_size(&self, _index: u32) -> u64 {
            self.region_size
        }
        fn region_read(&mut self, index: u32, data: &mut [u8], offset: u64) {
            assert!(self.read.is_none(), "region_read called more than once");
            self.read = Some((index, offset, data.len()));
            data.fill(0xCC);
        }
        fn region_write(&mut self, index: u32, data: &[u8], offset: u64) {
            assert!(self.write.is_none(), "region_write called more than once");
            self.write = Some((index, offset, data.to_vec()));
        }
    }

    struct MockMsixState {
        bar_hole_infos: ArrayVec<BarHoleInfo, 2>,
        cap: MsixCap,
        config: MockMsixConfig,
    }

    fn drive_read(
        state: &mut MockMsixState,
        device: &mut MockVfioDevice,
        base: u64,
        offset: u64,
        data: &mut [u8],
    ) -> (&'static str, bool) {
        handle_bar_access!(
            state,
            device,
            base,
            offset,
            data,
            read_table,
            read_pba,
            region_read
        )
    }

    fn drive_write(
        state: &mut MockMsixState,
        device: &mut MockVfioDevice,
        base: u64,
        offset: u64,
        data: &[u8],
    ) -> (&'static str, bool) {
        handle_bar_access!(
            state,
            device,
            base,
            offset,
            data,
            write_table,
            write_pba,
            region_write
        )
    }

    const BAR_GPA: u64 = 0x4000_0000_0000;
    const REGION_SIZE: u64 = 0x10_0000;

    /// Hole-only-table at the start of the BAR. 4-entry table at offset 0
    /// (= 64 bytes). Hole spans the page [0x0..0x1000).
    fn state_table_only() -> MockMsixState {
        let cap = MsixCap::new(0, 4, 0, 0, 0x800);
        let mut bar_hole_infos = ArrayVec::new();
        bar_hole_infos.push(BarHoleInfo {
            gpa: BAR_GPA,
            size: 0x1000,
            usage: BarHoleInfoUsage::TABLE,
        });
        MockMsixState {
            bar_hole_infos,
            cap,
            config: MockMsixConfig::default(),
        }
    }

    /// Hole-only-PBA at the start of the BAR. PBA at offset 0x100, 8 bytes
    /// (one word for a 4-entry table). Hole spans the page [0x0..0x1000).
    fn state_pba_only() -> MockMsixState {
        let cap = MsixCap::new(0, 4, 0x800, 0, 0x100);
        let mut bar_hole_infos = ArrayVec::new();
        bar_hole_infos.push(BarHoleInfo {
            gpa: BAR_GPA,
            size: 0x1000,
            usage: BarHoleInfoUsage::PBA,
        });
        MockMsixState {
            bar_hole_infos,
            cap,
            config: MockMsixConfig::default(),
        }
    }

    /// Merged hole: table at offset 0 (4 entries = 64 bytes) and PBA at
    /// offset 0x200 (8 bytes), both in the same host page -> single hole
    /// [0x0..0x1000) flagged as TABLE|PBA.
    fn state_merged() -> MockMsixState {
        let cap = MsixCap::new(0, 4, 0, 0, 0x200);
        let mut bar_hole_infos = ArrayVec::new();
        bar_hole_infos.push(BarHoleInfo {
            gpa: BAR_GPA,
            size: 0x1000,
            usage: BarHoleInfoUsage::TABLE | BarHoleInfoUsage::PBA,
        });
        MockMsixState {
            bar_hole_infos,
            cap,
            config: MockMsixConfig::default(),
        }
    }

    #[test]
    fn test_handle_bar_access_table_inside_table_range() {
        // Read at offset 0x10 (second table entry, vector ctl).
        let mut state = state_table_only();
        let mut device = MockVfioDevice::new(REGION_SIZE);
        let mut data = [0u8; 4];
        let (name, handled) = drive_read(&mut state, &mut device, BAR_GPA, 0x10, &mut data);
        assert!(handled);
        assert_eq!(name, "MsiTable");
        assert_eq!(data, [0xAA, 0xAA, 0xAA, 0xAA]);
        assert_eq!(state.config.table_read, Some((0x10, 4)));
        assert!(device.read.is_none());
    }

    #[test]
    fn test_handle_bar_access_table_outside_table_range_forwards_to_device() {
        // Table is 64 bytes (4 entries). Access at offset 0x100 is in the
        // hole padding -> forward to device region.
        let mut state = state_table_only();
        let mut device = MockVfioDevice::new(REGION_SIZE);
        let mut data = [0u8; 4];
        let (_name, handled) = drive_read(&mut state, &mut device, BAR_GPA, 0x100, &mut data);
        assert!(handled);
        assert_eq!(data, [0xCC, 0xCC, 0xCC, 0xCC]);
        assert!(state.config.table_read.is_none());
        // table_bir = 0, in_region_offset = (0 - 0) + 0x100 = 0x100.
        assert_eq!(device.read, Some((0, 0x100, 4)));
    }

    #[test]
    fn test_handle_bar_access_pba_inside_pba_range() {
        // PBA at offset 0x100, size 8. Access at 0x100 -> handled by PBA.
        // Relative offset passed to read_pba is access_offset - pba_start = 0.
        let mut state = state_pba_only();
        let mut device = MockVfioDevice::new(REGION_SIZE);
        let mut data = [0u8; 4];
        let (name, handled) = drive_read(&mut state, &mut device, BAR_GPA, 0x100, &mut data);
        assert!(handled);
        assert_eq!(name, "PbaTable");
        assert_eq!(data, [0xBB, 0xBB, 0xBB, 0xBB]);
        assert_eq!(state.config.pba_read, Some((0, 4)));
        assert!(device.read.is_none());
    }

    #[test]
    fn test_handle_bar_access_pba_outside_pba_range_forwards_to_device() {
        // Hole [0x0..0x1000), PBA [0x100..0x108). Access at 0x800 forwards.
        let mut state = state_pba_only();
        let mut device = MockVfioDevice::new(REGION_SIZE);
        let mut data = [0u8; 4];
        let (_name, handled) = drive_read(&mut state, &mut device, BAR_GPA, 0x800, &mut data);
        assert!(handled);
        assert_eq!(device.read, Some((0, 0x800, 4)));
    }

    #[test]
    fn test_handle_bar_access_merged_hits_table() {
        // Merged hole. Access at 0x10 -> table.
        let mut state = state_merged();
        let mut device = MockVfioDevice::new(REGION_SIZE);
        let mut data = [0u8; 4];
        let (name, handled) = drive_read(&mut state, &mut device, BAR_GPA, 0x10, &mut data);
        assert!(handled);
        assert_eq!(name, "MsiTable");
        assert_eq!(state.config.table_read, Some((0x10, 4)));
        assert!(state.config.pba_read.is_none());
    }

    #[test]
    fn test_handle_bar_access_merged_hits_pba() {
        // Merged hole. Access at 0x200 -> PBA. Relative offset = 0.
        let mut state = state_merged();
        let mut device = MockVfioDevice::new(REGION_SIZE);
        let mut data = [0u8; 4];
        let (name, handled) = drive_read(&mut state, &mut device, BAR_GPA, 0x200, &mut data);
        assert!(handled);
        assert_eq!(name, "PbaTable");
        assert!(state.config.table_read.is_none());
        assert_eq!(state.config.pba_read, Some((0, 4)));
    }

    #[test]
    fn test_handle_bar_access_merged_padding_forwards_to_device() {
        // Merged hole padding (between PBA end at 0x208 and page end 0x1000).
        let mut state = state_merged();
        let mut device = MockVfioDevice::new(REGION_SIZE);
        let mut data = [0u8; 4];
        let (_name, handled) = drive_read(&mut state, &mut device, BAR_GPA, 0x800, &mut data);
        assert!(handled);
        assert_eq!(device.read, Some((0, 0x800, 4)));
    }

    #[test]
    fn test_handle_bar_access_unrelated_base_is_unhandled() {
        // base != hole.gpa -> handled stays false.
        let mut state = state_table_only();
        let mut device = MockVfioDevice::new(REGION_SIZE);
        let mut data = [0u8; 4];
        let (_name, handled) = drive_read(&mut state, &mut device, BAR_GPA + 0x1000, 0, &mut data);
        assert!(!handled);
        assert!(state.config.table_read.is_none());
        assert!(device.read.is_none());
    }

    #[test]
    fn test_handle_bar_access_write_table() {
        let mut state = state_table_only();
        let mut device = MockVfioDevice::new(REGION_SIZE);
        let buf = [1u8, 2, 3, 4];
        let (name, handled) = drive_write(&mut state, &mut device, BAR_GPA, 0, &buf);
        assert!(handled);
        assert_eq!(name, "MsiTable");
        assert_eq!(state.config.table_write, Some((0, vec![1, 2, 3, 4])));
    }

    #[test]
    fn test_handle_bar_access_write_pba_padding_forwards_to_device() {
        // PBA-padding write -> forwarded to device region_write.
        let mut state = state_pba_only();
        let mut device = MockVfioDevice::new(REGION_SIZE);
        let buf = [9u8, 8, 7, 6];
        let (_name, handled) = drive_write(&mut state, &mut device, BAR_GPA, 0x800, &buf);
        assert!(handled);
        assert_eq!(device.write, Some((0, 0x800, vec![9, 8, 7, 6])));
    }

    #[test]
    fn test_handle_bar_access_forward_beyond_region_size_is_dropped() {
        // Region is 0x100 bytes; access at 0x800 in the hole padding is
        // past region_size -> device call must be skipped.
        let mut state = state_table_only();
        let mut device = MockVfioDevice::new(0x100);
        let mut data = [0u8; 4];
        let (_name, handled) = drive_read(&mut state, &mut device, BAR_GPA, 0x800, &mut data);
        assert!(handled);
        assert!(device.read.is_none());
        assert!(state.config.table_read.is_none());
    }
}
