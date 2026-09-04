// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// TODO remove this once all code is used
#![allow(dead_code)]

use std::ops::DerefMut;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use arrayvec::ArrayVec;
use bitflags::bitflags;
use kvm_bindings::{KVM_MEM_READONLY, kvm_userspace_memory_region};
use vfio_bindings::bindings::vfio::*;
pub use vfio_ioctls::{
    VfioContainer, VfioDevice as InternalVfioDevice, VfioDeviceFd, VfioRegionInfoCap,
    VfioRegionInfoCapSparseMmap, VfioRegionSparseMmapArea,
};
use vm_allocator::{AllocPolicy, RangeInclusive};
use zerocopy::IntoBytes;

use crate::arch::host_page_size;
use crate::logger::{debug, error, warn};
use crate::pci::configuration::{
    Bars, NUM_BAR_REGS, decode_32_bits_bar_size, decode_64_bits_bar_size,
};
use crate::pci::msix::MsixCap;
use crate::pci::{PciCapabilityId, PciExpressCapabilityId};
use crate::utils::{
    align_down_host_page, align_up_host_page, is_host_page_aligned, offset_from_lower_host_page,
    u64_to_usize, usize_to_u64,
};
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vm::{KvmVm, VmError};

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
    /// Mmap failed: {0:?}
    Mmap(std::io::Error),
    /// Failed to set KVM user memory region: {0}
    SetUserMemoryRegion(VmError),
    /// vfio-ioctls crate error: {0}
    VfioIoctls(#[from] vfio_ioctls::VfioError),
    /// BAR{0} MSI-X table at offset {1:#x} size {2:#x} does not fit in region of size {3:#x}
    MsixTableOutOfRange(u8, u64, u64, u64),
    /// BAR{0} MSI-X PBA at offset {1:#x} size {2:#x} does not fit in region of size {3:#x}
    MsixPbaOutOfRange(u8, u64, u64, u64),
    /// BAR{0} sparse mmap area at offset {1:#x} size {2:#x} does not fit in region of size {3:#x}
    SparseMmapAreaOutOfRange(u8, u64, u64, u64),
    /// BAR{0} sparse mmap area at gpa {1:#x} size {2:#x} overlaps MSI-X at gpa {3:#x} size {4:#x}
    SparseMmapAreaOverlapsEmulatedArea(u8, u64, u64, u64, u64),
}

bitflags! {
    /// Type of the area in the bar. A single area can contain both
    /// the MSI-X table and PBA when their host-page-aligned ranges overlap.
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    struct VfioBarEmulatedAreaUsageFlags: u8 {
        /// The area contains MSIx table
        const MSIX_TABLE = 1 << 0;
        /// The area contains MSIx pba
        const MSIX_PBA = 1 << 1;
    }
}

/// Description of the area within some BAR where all reads/writes are emulated.
/// These are used for emulation of reads/writes to the MSIx table/pba.
#[derive(Debug, Copy, Clone)]
struct VfioBarEmulatedArea {
    bar_idx: u8,
    in_bar_offset: u64,
    gpa: u64,
    size: u64,
    usage: VfioBarEmulatedAreaUsageFlags,
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

/// Information about the bar mapping
#[derive(Debug, Copy, Clone)]
struct VfioBarMapping {
    kvm_slot: u32,
    gpa: u64,
    size: u64,
    hva: u64,
}

/// Wrapper type to automate dropping
struct VfioBarMappings {
    mappings: Vec<VfioBarMapping>,
    vm: Arc<KvmVm>,
}

impl VfioBarMappings {
    /// Create new VfioBarMappings
    fn new(
        vm: Arc<KvmVm>,
        areas: &[VfioBarMappableArea],
        device: &InternalVfioDevice,
        first_area_slot: u32,
    ) -> Result<VfioBarMappings, VfioError> {
        let mut mappings = Vec::with_capacity(areas.len());
        for (i, area) in areas.iter().enumerate() {
            // `areas` length is bound by `u32`. See `vfio_calculate_bar_areas` comment.
            #[allow(clippy::cast_possible_truncation)]
            let i = i as u32;
            match vfio_map_bar_mapping(device, vm.as_ref(), area, first_area_slot + i) {
                Ok(mapping) => {
                    debug!(
                        "BAR area{} kvm gpa: [{:#x} ..{:#x}]",
                        i,
                        mapping.gpa,
                        mapping.gpa + mapping.size
                    );
                    mappings.push(mapping);
                }
                Err(e) => {
                    for mapping in mappings.iter() {
                        vfio_unmap_bar_mapping(vm.as_ref(), mapping);
                    }
                    return Err(e);
                }
            }
        }
        Ok(Self { mappings, vm })
    }
}

impl Drop for VfioBarMappings {
    fn drop(&mut self) {
        for mapping in self.mappings.iter() {
            vfio_unmap_bar_mapping(self.vm.as_ref(), mapping);
        }
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

/// Internal type to store vfio region info from the kernel
#[derive(Debug, Clone)]
struct VfioRegionInfo {
    flags: u32,
    size: u64,
    offset: u64,
    caps: Vec<VfioRegionInfoCap>,
}

/// Internal type to store areas needed to be mmaped for the device
#[derive(Debug, Clone, Copy)]
struct VfioBarMappableArea {
    gpa: u64,
    /// Offset to use when mmapping the vfio device fd in order to get the needed part of the
    /// region/BAR
    vfio_fd_offset: u64,
    size: u64,
    prot: i32,
}

/// Check if ranges overlap each other (touching does not count)
fn vfio_ranges_overlap(start_a: u64, size_a: u64, start_b: u64, size_b: u64) -> bool {
    start_a.max(start_b) < (start_a + size_a).min(start_b + size_b)
}

/// Add an emulated area to the `emulated_areas` array while checking for the overlap with possible
/// area already present in the array. Currently emulated areas are only used for MSIx table or pba,
/// so the max length of the array is 2.
fn vfio_add_emulated_area(
    bar_idx: u8,
    bar_gpa: u64,
    usage_flag: VfioBarEmulatedAreaUsageFlags,
    host_aligned_offset: u64,
    host_aligned_size: u64,
    emulated_areas: &mut ArrayVec<VfioBarEmulatedArea, 2>,
) {
    debug!(
        "BAR{} {:?} emulated area: [{:#x}..{:#x}]",
        bar_idx,
        usage_flag,
        bar_gpa + host_aligned_offset,
        bar_gpa + host_aligned_offset + host_aligned_size,
    );

    let new_area = VfioBarEmulatedArea {
        bar_idx,
        in_bar_offset: host_aligned_offset,
        gpa: bar_gpa + host_aligned_offset,
        size: host_aligned_size,
        usage: usage_flag,
    };

    match emulated_areas.last_mut() {
        Some(last_area)
            if vfio_ranges_overlap(last_area.gpa, last_area.size, new_area.gpa, new_area.size) =>
        {
            assert_eq!(last_area.bar_idx, bar_idx);
            let end = (last_area.gpa + last_area.size).max(new_area.gpa + new_area.size);
            last_area.usage |= new_area.usage;
            last_area.in_bar_offset = last_area.in_bar_offset.min(new_area.in_bar_offset);
            last_area.gpa = last_area.gpa.min(new_area.gpa);
            last_area.size = end - last_area.gpa;
        }
        _ => emulated_areas.push(new_area),
    }
}

/// Calculate different areas of BARs of a device:
/// - mmapable areas will be `mmap`ed and passed through directly to the guest without any emulation
///   on our side
/// - emulated area will not be given to the guest and so all guest accesses to them will cause
///   KVMExits which we will emulate
///
/// Emulated areas are only used for MSIx table and pba
///
/// As an example, a single BAR can be split into this arrangement:
///
/// [ mmapped area ][ emulated MSIx table area ][ mmapped area ][ emulated MSIx pba area ]
///
/// where each `area` is host page aligned.
///
/// In reality MSIx table/pba most likely will reside inside one shared emulated area
fn vfio_calculate_bar_areas(
    bars: &Bars,
    region_infos: &[VfioRegionInfo; NUM_BAR_REGS as usize],
    msix_cap: Option<&MsixCap>,
) -> Result<(Vec<VfioBarMappableArea>, ArrayVec<VfioBarEmulatedArea, 2>), VfioError> {
    // There are 6 BARs with maximum of 2 emulated_areas, so the maximum number of mappable areas
    // is 8, The only reasons to use `Vec` instead of `ArrayVec` here is because this vector can be
    // populated from the `sparse_mmap_cap` which can contain a different number of areas. But
    // in any case the size here is limited by the `nr_areas` field in the
    // `vfio_region_info_cap_sparse_mmap` struct. This field has the `u32` type.
    let mut mmappable_areas = Vec::with_capacity(8);
    let mut emulated_areas = ArrayVec::<VfioBarEmulatedArea, 2>::new();
    let mut bar_idx: u8 = 0;
    while bar_idx < NUM_BAR_REGS {
        if bars.bars[bar_idx as usize].used() {
            let bar_gpa = bars.get_bar_addr(bar_idx);
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
                    let (offset, size) = msix_cap.table_bar_offset_and_size();
                    // Since original `offset` and `size` are `u32` and `u16`, their addition
                    // cannot overflow when widened to `u64`;
                    let (offset, size) = (offset as u64, size as u64);
                    let offset_in_area = offset_from_lower_host_page(offset);

                    msix_table_offset = align_down_host_page(offset);
                    msix_table_size = align_up_host_page(offset_in_area + size);

                    if region_info.size < offset + size {
                        return Err(VfioError::MsixTableOutOfRange(
                            bar_idx,
                            offset,
                            size,
                            region_info.size,
                        ));
                    }

                    vfio_add_emulated_area(
                        bar_idx,
                        bar_gpa,
                        VfioBarEmulatedAreaUsageFlags::MSIX_TABLE,
                        msix_table_offset,
                        msix_table_size,
                        &mut emulated_areas,
                    );
                }

                contain_msix_pba = bar_idx == msix_cap.pba_bir();
                if contain_msix_pba {
                    let (offset, size) = msix_cap.pba_bar_offset_and_size();
                    // Since original `offset` and `size` are `u32` and `u16`, their addition
                    // cannot overflow when widened to `u64`;
                    let (offset, size) = (offset as u64, size as u64);
                    let offset_in_area = offset_from_lower_host_page(offset);

                    msix_pba_offset = align_down_host_page(offset);
                    msix_pba_size = align_up_host_page(offset_in_area + size);

                    if region_info.size < offset + size {
                        return Err(VfioError::MsixPbaOutOfRange(
                            bar_idx,
                            offset,
                            size,
                            region_info.size,
                        ));
                    }

                    vfio_add_emulated_area(
                        bar_idx,
                        bar_gpa,
                        VfioBarEmulatedAreaUsageFlags::MSIX_PBA,
                        msix_pba_offset,
                        msix_pba_size,
                        &mut emulated_areas,
                    );
                }
            }

            if (contain_msix_table || contain_msix_pba)
                && !has_msix_mappable
                && sparse_mmap_cap.is_none()
            {
                // Theoretically this can happen if BAR only contains MSIx table/pba, but even in
                // that case it is fine to skip it since we would already handle MSIx areas.
                debug!(
                    "BAR{} contains msix_table: {} msix_pba: {}, but it is not mappable and \
                     kernel did not provide sparse_mmap_cap. Skipping",
                    bar_idx, contain_msix_table, contain_msix_pba,
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

                    // TODO: currently if host page size is bigger than the BAR size, we would fail
                    // at the stage where we set KVM memory region since the region will be
                    // smaller than the host page size and KVM checks for this.
                    // In the future we need to update this code to widen areas to page
                    // boundaries if possible. It should be done here and not in the mapping
                    // function since it is more suited for this.
                    if let Some(cap) = sparse_mmap_cap {
                        for area in cap.areas.iter() {
                            // Even though these are kernel provided values, do additional
                            // sanity checks.
                            if area
                                .offset
                                .checked_add(area.size)
                                .is_none_or(|end| region_size < end)
                                || area.size == 0
                                || !is_host_page_aligned(area.offset)
                                || !is_host_page_aligned(area.size)
                            {
                                return Err(VfioError::SparseMmapAreaOutOfRange(
                                    bar_idx,
                                    area.offset,
                                    area.size,
                                    region_size,
                                ));
                            }
                            // The kernel is expected to exclude the MSI-X table/pba from the
                            // sparse mmap areas. If it did not, `mmap`ing the area would pass
                            // the MSI-X table/pba through to the guest while we also emulate
                            // it, which would let the guest program interrupts directly.
                            let gpa = bar_gpa + area.offset;
                            for emulated_area in emulated_areas.iter() {
                                if vfio_ranges_overlap(
                                    gpa,
                                    area.size,
                                    emulated_area.gpa,
                                    emulated_area.size,
                                ) {
                                    return Err(VfioError::SparseMmapAreaOverlapsEmulatedArea(
                                        bar_idx,
                                        gpa,
                                        area.size,
                                        emulated_area.gpa,
                                        emulated_area.size,
                                    ));
                                }
                            }
                            mmappable_areas.push(VfioBarMappableArea {
                                gpa,
                                vfio_fd_offset: region_info.offset + area.offset,
                                size: area.size,
                                prot,
                            });
                        }
                    } else if has_msix_mappable {
                        // There can only be maximum of 2 gaps/emulated_areas in the BAR,
                        // so the maximum number of mmappable areas is 3.
                        //
                        // First we sort gaps by the starting offset and then
                        // we go from left to right (low offset to high offset) and areas between
                        // gaps.
                        //
                        // The most advanced case will look like this:
                        //
                        // region start                               region end
                        //      [ area ][ gap ][ area ][ gap ][ last area ]
                        //     low                                       high
                        //
                        let mut gaps = [
                            (msix_table_offset, msix_table_size),
                            (msix_pba_offset, msix_pba_size),
                        ];
                        gaps.sort_unstable_by_key(|(offset, _)| *offset);

                        let mut offset = 0;
                        for (gap_offset, gap_size) in gaps {
                            if gap_size != 0 && offset < gap_offset {
                                let area_size = gap_offset - offset;
                                if area_size != 0 {
                                    mmappable_areas.push(VfioBarMappableArea {
                                        gpa: bar_gpa + offset,
                                        vfio_fd_offset: region_info.offset + offset,
                                        size: area_size,
                                        prot,
                                    });
                                }
                            }
                            offset = offset.max(gap_offset + gap_size);
                        }
                        let last_area_size = region_size - offset;
                        if last_area_size != 0 {
                            mmappable_areas.push(VfioBarMappableArea {
                                gpa: bar_gpa + offset,
                                vfio_fd_offset: region_info.offset + offset,
                                size: last_area_size,
                                prot,
                            });
                        }
                    } else {
                        mmappable_areas.push(VfioBarMappableArea {
                            gpa: bar_gpa,
                            vfio_fd_offset: region_info.offset,
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
    Ok((mmappable_areas, emulated_areas))
}

/// Mmaps the area of the device BAR and creates a sets the KVM memory region for it, giving guest
/// direct access to that memory.
fn vfio_map_bar_mapping(
    device: &InternalVfioDevice,
    vm: &KvmVm,
    area: &VfioBarMappableArea,
    slot: u32,
) -> Result<VfioBarMapping, VfioError> {
    // SAFETY: FFI call to mmap with valid fd and offset. The returned pointer is checked
    // against MAP_FAILED before use.
    let hva_ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            u64_to_usize(area.size),
            area.prot,
            libc::MAP_SHARED,
            device.as_raw_fd(),
            #[allow(clippy::cast_possible_wrap)]
            {
                area.vfio_fd_offset as libc::off_t
            },
        )
    };

    if hva_ptr == libc::MAP_FAILED {
        return Err(VfioError::Mmap(std::io::Error::last_os_error()));
    }

    let gpa = area.gpa;
    let size = area.size;
    let hva = hva_ptr as u64;

    let kvm_flags = if (area.prot & libc::PROT_WRITE) == 0 {
        KVM_MEM_READONLY
    } else {
        0
    };
    let kvm_memory_region = kvm_userspace_memory_region {
        slot,
        flags: kvm_flags,
        guest_phys_addr: gpa,
        memory_size: size,
        userspace_addr: hva,
    };
    if let Err(e) = vm.set_user_memory_region(kvm_memory_region) {
        // SAFETY: hva_ptr was returned by a successful mmap call above with the given size.
        let r = unsafe { libc::munmap(hva_ptr.cast(), u64_to_usize(size)) };
        if r < 0 {
            error!(
                "Error on unmapping host memory on VFIO device creation failure: {:?}. Continuing \
                 with other regions removal.",
                std::io::Error::last_os_error()
            );
        }
        return Err(VfioError::SetUserMemoryRegion(e));
    }

    // We don't establish DMA mappings for BARs yet since we don't support PTP yet. Device can
    // access their own memory without DMA.

    Ok(VfioBarMapping {
        kvm_slot: slot,
        gpa,
        size,
        hva,
    })
}

/// Removes the KVM memory region and unmaps the corresponding virtual address space
fn vfio_unmap_bar_mapping(vm: &KvmVm, mapping: &VfioBarMapping) {
    let kvm_memory_region = kvm_userspace_memory_region {
        slot: mapping.kvm_slot,
        flags: 0,
        guest_phys_addr: mapping.gpa,
        memory_size: 0,
        userspace_addr: mapping.hva,
    };
    if let Err(ee) = vm.set_user_memory_region(kvm_memory_region) {
        error!(
            "Error on removing KVM region for BAR in a VFIO device: {ee:?}. Continuing with other \
             regions removal."
        );
    }

    // SAFETY: host_addr was obtained from a successful mmap call with the given size.
    let r = unsafe { libc::munmap(mapping.hva as *mut libc::c_void, u64_to_usize(mapping.size)) };
    if r < 0 {
        error!(
            "Error on unmapping host memory for BAR in a VFIO device: {:?}. Continuing with other \
             regions removal.",
            std::io::Error::last_os_error()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::configuration::{
        BarPrefetchable, encode_32_bits_bar_size, encode_64_bits_bar_size,
    };

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

    fn dummy_region_info(size: u64, caps: Vec<VfioRegionInfoCap>) -> VfioRegionInfo {
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

    fn dummy_region_infos<const N: usize>(
        entries: [VfioRegionInfo; N],
    ) -> [VfioRegionInfo; NUM_BAR_REGS as usize] {
        let mut infos: [VfioRegionInfo; NUM_BAR_REGS as usize] =
            std::array::from_fn(|_| dummy_region_info(0, vec![]));
        for (i, info) in entries.into_iter().enumerate() {
            infos[i] = info;
        }
        infos
    }

    #[test]
    fn test_vfio_calculate_bar_areas_no_bars_or_region_infos() {
        let bars = Bars::default();
        let region_infos = dummy_region_infos([]);

        let (areas, emulated_areas) = vfio_calculate_bar_areas(&bars, &region_infos, None).unwrap();
        assert!(areas.is_empty());
        assert!(emulated_areas.is_empty());
    }

    #[test]
    fn test_vfio_calculate_bar_areas_no_emulated_areas() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x1000, 0x1000, BarPrefetchable::No);
        bars.set_bar_64(2, 0x2000, 0x1000, BarPrefetchable::No);
        let region_infos = dummy_region_infos([
            // BAR 0
            dummy_region_info(0x1000, vec![]),
            dummy_region_info(0x0, vec![]),
            // BAR 1
            dummy_region_info(0x1000, vec![VfioRegionInfoCap::MsixMappable]),
        ]);

        let (areas, emulated_areas) = vfio_calculate_bar_areas(&bars, &region_infos, None).unwrap();

        assert_eq!(areas.len(), 2);
        assert_eq!(areas[0].gpa, 0x1000);
        assert_eq!(areas[0].size, 0x1000);
        assert_eq!(areas[0].vfio_fd_offset, 0);
        assert_eq!(areas[1].gpa, 0x2000);
        assert_eq!(areas[1].size, 0x1000);
        assert_eq!(areas[1].vfio_fd_offset, 0);

        assert!(emulated_areas.is_empty());
    }

    #[test]
    fn test_vfio_calculate_bar_areas_msix_table_and_pba_in_different_bars() {
        // BARs are just one page long, so emulated areas take them
        {
            let mut bars = Bars::default();
            bars.set_bar_64(0, 0x1000, 0x1000, BarPrefetchable::No);
            bars.set_bar_64(2, 0x2000, 0x1000, BarPrefetchable::No);

            let region_infos = dummy_region_infos([
                // BAR 0
                dummy_region_info(0x1000, vec![VfioRegionInfoCap::MsixMappable]),
                dummy_region_info(0, vec![]),
                // BAR 1
                dummy_region_info(0x1000, vec![VfioRegionInfoCap::MsixMappable]),
            ]);

            let msix_cap = MsixCap::new(0, 32, 0, 2, 0);

            let (areas, emulated_areas) =
                vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();

            assert_eq!(areas.len(), 0);

            assert_eq!(emulated_areas.len(), 2);
            assert_eq!(emulated_areas[0].gpa, 0x1000);
            assert_eq!(emulated_areas[0].size, 0x1000);
            assert_eq!(
                emulated_areas[0].usage,
                VfioBarEmulatedAreaUsageFlags::MSIX_TABLE
            );
            assert_eq!(emulated_areas[1].gpa, 0x2000);
            assert_eq!(emulated_areas[1].size, 0x1000);
            assert_eq!(
                emulated_areas[1].usage,
                VfioBarEmulatedAreaUsageFlags::MSIX_PBA
            );
        }

        // BARs are multiple pages, so emulated areas leave some space
        {
            let mut bars = Bars::default();
            bars.set_bar_64(0, 0x1000, 0x2000, BarPrefetchable::No);
            bars.set_bar_64(2, 0x3000, 0x2000, BarPrefetchable::No);

            let region_infos = dummy_region_infos([
                // BAR 0
                dummy_region_info(0x2000, vec![VfioRegionInfoCap::MsixMappable]),
                dummy_region_info(0, vec![]),
                // BAR 1
                dummy_region_info(0x2000, vec![VfioRegionInfoCap::MsixMappable]),
            ]);

            let msix_cap = MsixCap::new(0, 32, 0, 2, 0);

            let (areas, emulated_areas) =
                vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();

            assert_eq!(areas.len(), 2);
            assert_eq!(areas[0].gpa, 0x2000);
            assert_eq!(areas[0].size, 0x1000);
            assert_eq!(areas[0].vfio_fd_offset, 0x1000);
            assert_eq!(areas[1].gpa, 0x4000);
            assert_eq!(areas[1].size, 0x1000);
            assert_eq!(areas[1].vfio_fd_offset, 0x1000);

            assert_eq!(emulated_areas.len(), 2);
            assert_eq!(emulated_areas[0].gpa, 0x1000);
            assert_eq!(emulated_areas[0].size, 0x1000);
            assert_eq!(
                emulated_areas[0].usage,
                VfioBarEmulatedAreaUsageFlags::MSIX_TABLE
            );
            assert_eq!(emulated_areas[1].gpa, 0x3000);
            assert_eq!(emulated_areas[1].size, 0x1000);
            assert_eq!(
                emulated_areas[1].usage,
                VfioBarEmulatedAreaUsageFlags::MSIX_PBA
            );
        }
    }

    #[test]
    fn test_vfio_calculate_bar_areas_sparse_mmap() {
        // All good sparse areas
        {
            let mut bars = Bars::default();
            bars.set_bar_64(0, 0x1000, 0x4000, BarPrefetchable::No);

            let sparse_areas = vec![
                VfioRegionSparseMmapArea {
                    offset: 0,
                    size: 0x1000,
                },
                VfioRegionSparseMmapArea {
                    offset: 0x2000,
                    size: 0x1000,
                },
            ];
            let region_infos = dummy_region_infos([dummy_region_info(
                0x4000,
                vec![VfioRegionInfoCap::SparseMmap(VfioRegionInfoCapSparseMmap {
                    areas: sparse_areas,
                })],
            )]);

            let (areas, emulated_areas) =
                vfio_calculate_bar_areas(&bars, &region_infos, None).unwrap();

            assert_eq!(areas.len(), 2);
            assert_eq!(areas[0].gpa, 0x1000);
            assert_eq!(areas[0].vfio_fd_offset, 0);
            assert_eq!(areas[0].size, 0x1000);
            assert_eq!(areas[1].gpa, 0x3000);
            assert_eq!(areas[1].vfio_fd_offset, 0x2000);
            assert_eq!(areas[1].size, 0x1000);

            assert!(emulated_areas.is_empty());
        }

        // Overflow
        {
            let mut bars = Bars::default();
            bars.set_bar_64(0, 0x1000, 0x4000, BarPrefetchable::No);

            let sparse_areas = vec![
                VfioRegionSparseMmapArea {
                    offset: 0,
                    size: 0x1000,
                },
                VfioRegionSparseMmapArea {
                    offset: 0x2000,
                    // This one is outside the region
                    size: 0x3000,
                },
            ];
            let region_infos = dummy_region_infos([dummy_region_info(
                0x4000,
                vec![VfioRegionInfoCap::SparseMmap(VfioRegionInfoCapSparseMmap {
                    areas: sparse_areas,
                })],
            )]);

            vfio_calculate_bar_areas(&bars, &region_infos, None).unwrap_err();
        }

        // Unaligned
        {
            let mut bars = Bars::default();
            bars.set_bar_64(0, 0x1000, 0x4000, BarPrefetchable::No);

            let sparse_areas = vec![
                VfioRegionSparseMmapArea {
                    offset: 0,
                    size: 0x1000,
                },
                VfioRegionSparseMmapArea {
                    offset: 0x2000,
                    // Unaligned
                    size: 0x3001,
                },
            ];
            let region_infos = dummy_region_infos([dummy_region_info(
                0x4000,
                vec![VfioRegionInfoCap::SparseMmap(VfioRegionInfoCapSparseMmap {
                    areas: sparse_areas,
                })],
            )]);

            vfio_calculate_bar_areas(&bars, &region_infos, None).unwrap_err();
        }
    }

    #[test]
    fn test_vfio_ranges_overlap() {
        // Same range
        assert!(vfio_ranges_overlap(0x1000, 0x1000, 0x1000, 0x1000));
        // Partial overlap in both directions
        assert!(vfio_ranges_overlap(0x1000, 0x2000, 0x2000, 0x2000));
        assert!(vfio_ranges_overlap(0x2000, 0x2000, 0x1000, 0x2000));
        // Fully contained in both directions
        assert!(vfio_ranges_overlap(0x1000, 0x4000, 0x2000, 0x1000));
        assert!(vfio_ranges_overlap(0x2000, 0x1000, 0x1000, 0x4000));
        // Adjacent ranges do not overlap
        assert!(!vfio_ranges_overlap(0x1000, 0x1000, 0x2000, 0x1000));
        assert!(!vfio_ranges_overlap(0x2000, 0x1000, 0x1000, 0x1000));
        // Disjoint ranges do not overlap
        assert!(!vfio_ranges_overlap(0x1000, 0x1000, 0x3000, 0x1000));
        // Empty ranges do not overlap anything, even when inside the other range
        assert!(!vfio_ranges_overlap(0x1000, 0x1000, 0x1800, 0));
        assert!(!vfio_ranges_overlap(0x1800, 0, 0x1000, 0x1000));
    }

    #[test]
    fn test_vfio_add_emulated_area_no_overlap() {
        let mut emulated_areas = ArrayVec::<VfioBarEmulatedArea, 2>::new();

        vfio_add_emulated_area(
            0,
            0x1000,
            VfioBarEmulatedAreaUsageFlags::MSIX_TABLE,
            0,
            0x1000,
            &mut emulated_areas,
        );

        vfio_add_emulated_area(
            0,
            0x1000,
            VfioBarEmulatedAreaUsageFlags::MSIX_PBA,
            0x1000,
            0x1000,
            &mut emulated_areas,
        );

        assert_eq!(emulated_areas.len(), 2);
        assert_eq!(emulated_areas[0].bar_idx, 0);
        assert_eq!(emulated_areas[0].in_bar_offset, 0);
        assert_eq!(emulated_areas[0].gpa, 0x1000);
        assert_eq!(emulated_areas[0].size, 0x1000);
        assert_eq!(
            emulated_areas[0].usage,
            VfioBarEmulatedAreaUsageFlags::MSIX_TABLE
        );
        assert_eq!(emulated_areas[1].bar_idx, 0);
        assert_eq!(emulated_areas[1].in_bar_offset, 0x1000);
        assert_eq!(emulated_areas[1].gpa, 0x2000);
        assert_eq!(emulated_areas[1].size, 0x1000);
        assert_eq!(
            emulated_areas[1].usage,
            VfioBarEmulatedAreaUsageFlags::MSIX_PBA
        );
    }

    #[test]
    #[should_panic]
    fn test_vfio_add_emulated_area_overlap_different_bar_ids() {
        let mut emulated_areas = ArrayVec::<VfioBarEmulatedArea, 2>::new();

        vfio_add_emulated_area(
            0,
            0x1000,
            VfioBarEmulatedAreaUsageFlags::MSIX_TABLE,
            0x1000,
            0x1000,
            &mut emulated_areas,
        );

        vfio_add_emulated_area(
            1,
            0x1000,
            VfioBarEmulatedAreaUsageFlags::MSIX_PBA,
            0,
            0x2000,
            &mut emulated_areas,
        );
    }

    #[test]
    fn test_vfio_add_emulated_area_overlap() {
        let mut emulated_areas = ArrayVec::<VfioBarEmulatedArea, 2>::new();

        vfio_add_emulated_area(
            0,
            0x1000,
            VfioBarEmulatedAreaUsageFlags::MSIX_TABLE,
            0x1000,
            0x1000,
            &mut emulated_areas,
        );

        vfio_add_emulated_area(
            0,
            0x1000,
            VfioBarEmulatedAreaUsageFlags::MSIX_PBA,
            0,
            0x2000,
            &mut emulated_areas,
        );

        assert_eq!(emulated_areas.len(), 1);
        assert_eq!(emulated_areas[0].bar_idx, 0);
        assert_eq!(emulated_areas[0].in_bar_offset, 0);
        assert_eq!(emulated_areas[0].gpa, 0x1000);
        assert_eq!(emulated_areas[0].size, 0x2000);
        assert_eq!(
            emulated_areas[0].usage,
            VfioBarEmulatedAreaUsageFlags::MSIX_TABLE | VfioBarEmulatedAreaUsageFlags::MSIX_PBA
        );
    }

    #[test]
    fn test_vfio_calculate_bar_areas_sparse_mmap_overlaps_msix() {
        // Sparse area exactly covers the MSI-X table emulated area
        {
            let mut bars = Bars::default();
            bars.set_bar_64(0, 0x1000, 0x4000, BarPrefetchable::No);

            // Table in BAR0 at offset 0 -> emulated area [0x0, 0x1000) -> gpa [0x1000, 0x2000)
            // PBA is in BAR1, which is never visited, so it creates no emulated area.
            let msix_cap = MsixCap::new(0, 32, 0, 1, 0);

            let sparse_areas = vec![VfioRegionSparseMmapArea {
                offset: 0,
                size: 0x1000,
            }];
            let region_infos = dummy_region_infos([dummy_region_info(
                0x4000,
                vec![VfioRegionInfoCap::SparseMmap(VfioRegionInfoCapSparseMmap {
                    areas: sparse_areas,
                })],
            )]);

            let err = vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap_err();
            assert!(
                matches!(
                    err,
                    VfioError::SparseMmapAreaOverlapsEmulatedArea(
                        0, 0x1000, 0x1000, 0x1000, 0x1000
                    )
                ),
                "{err:?}"
            );
        }

        // Sparse area partially overlaps the MSI-X pba emulated area
        {
            let mut bars = Bars::default();
            bars.set_bar_64(0, 0x1000, 0x4000, BarPrefetchable::No);

            // PBA in BAR0 at offset 0x2000 -> emulated area [0x2000, 0x3000) -> gpa [0x3000,
            // 0x4000) Table is in BAR1, which is never visited, so it creates no
            // emulated area.
            let msix_cap = MsixCap::new(1, 32, 0, 0, 0x2000);

            // Covers region [0x1000, 0x3000) -> gpa [0x2000, 0x4000), so only the second half
            // of it overlaps the pba emulated area.
            let sparse_areas = vec![VfioRegionSparseMmapArea {
                offset: 0x1000,
                size: 0x2000,
            }];
            let region_infos = dummy_region_infos([dummy_region_info(
                0x4000,
                vec![VfioRegionInfoCap::SparseMmap(VfioRegionInfoCapSparseMmap {
                    areas: sparse_areas,
                })],
            )]);

            let err = vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap_err();
            assert!(
                matches!(
                    err,
                    VfioError::SparseMmapAreaOverlapsEmulatedArea(
                        0, 0x2000, 0x2000, 0x3000, 0x1000
                    )
                ),
                "{err:?}"
            );
        }

        // Sparse areas correctly exclude both the MSI-X table and pba emulated_areas
        {
            let mut bars = Bars::default();
            bars.set_bar_64(0, 0x1000, 0x4000, BarPrefetchable::No);

            // Table at offset 0x1000 -> emulated area [0x1000, 0x2000) -> gpa [0x2000, 0x3000)
            // PBA   at offset 0x2000 -> emulated area [0x2000, 0x3000) -> gpa [0x3000, 0x4000)
            let msix_cap = MsixCap::new(0, 32, 0x1000, 0, 0x2000);

            let sparse_areas = vec![
                VfioRegionSparseMmapArea {
                    offset: 0,
                    size: 0x1000,
                },
                VfioRegionSparseMmapArea {
                    offset: 0x3000,
                    size: 0x1000,
                },
            ];
            let region_infos = dummy_region_infos([dummy_region_info(
                0x4000,
                vec![VfioRegionInfoCap::SparseMmap(VfioRegionInfoCapSparseMmap {
                    areas: sparse_areas,
                })],
            )]);

            let (areas, emulated_areas) =
                vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();

            assert_eq!(areas.len(), 2);
            assert_eq!(areas[0].gpa, 0x1000);
            assert_eq!(areas[0].vfio_fd_offset, 0);
            assert_eq!(areas[0].size, 0x1000);
            assert_eq!(areas[1].gpa, 0x4000);
            assert_eq!(areas[1].vfio_fd_offset, 0x3000);
            assert_eq!(areas[1].size, 0x1000);

            // The table and pba emulated_areas are adjacent, so they stay separate areas
            assert_eq!(emulated_areas.len(), 2);
            assert_eq!(emulated_areas[0].gpa, 0x2000);
            assert_eq!(emulated_areas[0].size, 0x1000);
            assert_eq!(
                emulated_areas[0].usage,
                VfioBarEmulatedAreaUsageFlags::MSIX_TABLE
            );
            assert_eq!(emulated_areas[1].gpa, 0x3000);
            assert_eq!(emulated_areas[1].size, 0x1000);
            assert_eq!(
                emulated_areas[1].usage,
                VfioBarEmulatedAreaUsageFlags::MSIX_PBA
            );
        }
    }

    #[test]
    fn test_vfio_calculate_bar_areas_msix_table_and_pba_in_the_same_bar() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x1000, 0x2000, BarPrefetchable::No);

        let region_infos = dummy_region_infos([dummy_region_info(
            0x2000,
            vec![VfioRegionInfoCap::MsixMappable],
        )]);

        let msix_cap = MsixCap::new(0, 32, 0, 0, 0x1000);

        let (areas, emulated_areas) =
            vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();

        assert!(areas.is_empty());

        assert_eq!(emulated_areas.len(), 2);
        assert_eq!(emulated_areas[0].gpa, 0x1000);
        assert_eq!(emulated_areas[0].size, 0x1000);
        assert_eq!(
            emulated_areas[0].usage,
            VfioBarEmulatedAreaUsageFlags::MSIX_TABLE
        );
        assert_eq!(emulated_areas[1].gpa, 0x2000);
        assert_eq!(emulated_areas[1].size, 0x1000);
        assert_eq!(
            emulated_areas[1].usage,
            VfioBarEmulatedAreaUsageFlags::MSIX_PBA
        );
    }

    #[test]
    fn test_vfio_calculate_bar_areas_overlapping_msix_emulated_areas() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x1000, 0x2000, BarPrefetchable::No);

        let region_infos = dummy_region_infos([dummy_region_info(
            0x2000,
            vec![VfioRegionInfoCap::MsixMappable],
        )]);

        // Both tables create the same emulated area [0x0..0x1000)
        let msix_cap = MsixCap::new(0, 32, 0x0, 0, 0x200);
        let (areas, emulated_areas) =
            vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();

        assert_eq!(areas.len(), 1);
        assert_eq!(areas[0].gpa, 0x2000);
        assert_eq!(areas[0].size, 0x1000);
        assert_eq!(areas[0].vfio_fd_offset, 0x1000);

        assert_eq!(emulated_areas.len(), 1);
        assert_eq!(emulated_areas[0].gpa, 0x1000);
        assert_eq!(emulated_areas[0].size, 0x1000);
        assert_eq!(
            emulated_areas[0].usage,
            VfioBarEmulatedAreaUsageFlags::MSIX_TABLE | VfioBarEmulatedAreaUsageFlags::MSIX_PBA
        );
    }

    /// Table and PBA share the same starting page (so the same emulated area `gpa`),
    /// but the PBA contents straddle the page boundary, so its host-page-
    /// aligned size is larger than the table's. The two emulated_areas must merge
    /// into one.
    #[test]
    fn test_vfio_calculate_bar_areas_same_gpa_different_size_msix_emulated_areas() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x1000, 0x2000, BarPrefetchable::No);

        let region_infos = dummy_region_infos([dummy_region_info(
            0x2000,
            vec![VfioRegionInfoCap::MsixMappable],
        )]);

        // table at offset 0, 128 entries (0x800 bytes) -> emulated area [0x0, 0x1000)
        // PBA at offset 0xff8, 16 bytes -> straddles 0x1000 -> emulated area [0x0, 0x2000)
        // Same gpa (bar_gpa + 0), different sizes.
        let msix_cap = MsixCap::new(0, 128, 0, 0, 0xff8);

        let (areas, emulated_areas) =
            vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();

        // No space for areas, all taken by emulated_areas
        assert!(areas.is_empty());

        assert_eq!(emulated_areas.len(), 1);
        assert_eq!(emulated_areas[0].gpa, 0x1000);
        assert_eq!(emulated_areas[0].size, 0x2000);
        assert_eq!(
            emulated_areas[0].usage,
            VfioBarEmulatedAreaUsageFlags::MSIX_TABLE | VfioBarEmulatedAreaUsageFlags::MSIX_PBA
        );
    }

    #[test]
    fn test_vfio_calculate_bar_areas_msix_table_past_region_end() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x1000, 0x1000, BarPrefetchable::No);

        let region_infos = dummy_region_infos([dummy_region_info(
            0x1000,
            vec![VfioRegionInfoCap::MsixMappable],
        )]);

        // end of the table at offset 0xff8 with size of 16 will land outside 0x1000 region
        let msix_cap = MsixCap::new(0, 1, 0xff8, 0, 0);

        let err = vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap_err();
        assert!(matches!(
            err,
            VfioError::MsixTableOutOfRange(0, 0xff8, 16, 0x1000)
        ));
    }

    #[test]
    fn test_vfio_calculate_bar_areas_msix_pba_past_region_end() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x1000, 0x1000, BarPrefetchable::No);

        let region_infos = dummy_region_infos([dummy_region_info(
            0x1000,
            vec![VfioRegionInfoCap::MsixMappable],
        )]);

        // end of the pba at offset 0xff8 with size of 16 will land outside 0x1000 region
        let msix_cap = MsixCap::new(0, 128, 0, 0, 0xff8);

        let err = vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap_err();
        assert!(matches!(
            err,
            VfioError::MsixPbaOutOfRange(0, 0xff8, 16, 0x1000)
        ));
    }
}
