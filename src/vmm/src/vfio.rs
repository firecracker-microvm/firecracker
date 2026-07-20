// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ops::DerefMut;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Barrier, Mutex};

use arrayvec::ArrayVec;
use bitflags::bitflags;
use kvm_bindings::kvm_userspace_memory_region;
use vfio_bindings::bindings::vfio::*;
pub use vfio_ioctls::{
    VfioContainer, VfioDevice as InternalVfioDevice, VfioDeviceFd, VfioRegionInfoCap,
    VfioRegionInfoCapSparseMmap, VfioRegionSparseMmapArea,
};
use vm_allocator::{AllocPolicy, RangeInclusive};
use vm_memory::{GuestMemoryBackend, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;
use zerocopy::IntoBytes;

use crate::arch::host_page_size;
use crate::logger::{debug, error, warn};
use crate::pci::configuration::{
    BAR0_REG_IDX, Bars, NUM_BAR_REGS, ROM_BAR_REG, decode_32_bits_bar_size, decode_64_bits_bar_size,
};
use crate::pci::msix::{MsixCap, MsixConfig};
use crate::pci::{PciCapabilityId, PciDevice, PciExpressCapabilityId, PciSBDF};
use crate::utils::{
    align_down_host_page, align_up_host_page, is_host_page_aligned, offset_from_lower_host_page,
    u64_to_usize, usize_to_u64,
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

bitflags! {
    /// Type of the hole in the bar. A single hole can contain both
    /// the MSI-X table and PBA when their host-page-aligned ranges overlap.
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct VfioBarHoleUsageFlags: u8 {
        /// The hole contains MSIx table
        const TABLE = 1 << 0;
        /// The hole contains MSIx pba
        const PBA = 1 << 1;
    }
}

/// Information about the location of the hole in the bar
#[derive(Debug, Copy, Clone)]
pub struct VfioBarHoleInfo {
    /// Guest location of the hole
    pub gpa: u64,
    /// Size of the hole
    pub size: u64,
    /// What does the hole contain
    pub usage: VfioBarHoleUsageFlags,
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

/// Information about the bar mapping
#[derive(Debug, Copy, Clone)]
pub struct VfioBarMapping {
    /// KVM slot assigned to the mapping
    pub slot: u32,
    /// Guest physical address
    pub iova: u64,
    /// Size
    pub size: u64,
    /// Host virtual address
    pub hva: u64,
}

/// Wrapper type to automate dropping
pub struct VfioBarMappings {
    /// mappings
    pub mappings: Vec<VfioBarMapping>,
    /// container
    pub container: Arc<VfioContainer>,
    /// vm
    pub vm: Arc<KvmVm>,
}

impl std::fmt::Debug for VfioBarMappings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VfioBarMappings")
            .field("mappings", &self.mappings)
            .finish()
    }
}

impl VfioBarMappings {
    /// New VfioBarMappings
    fn new(
        container: Arc<VfioContainer>,
        vm: Arc<KvmVm>,
        areas: &[BarArea],
        device: &InternalVfioDevice,
        first_area_slot: u32,
    ) -> Result<VfioBarMappings, VfioError> {
        let mut mappings = Vec::with_capacity(areas.len());
        for (i, area) in areas.iter().enumerate() {
            // `areas` length is bound by `u32`. See `vfio_calculate_bar_areas` comment.
            #[allow(clippy::cast_possible_truncation)]
            let i = i as u32;
            match vfio_map_bar_mapping(
                container.as_ref(),
                device,
                vm.as_ref(),
                area,
                first_area_slot + i,
            ) {
                Ok(mapping) => {
                    debug!(
                        "BAR area{} kvm gpa: [{:#x} ..{:#x}]",
                        i,
                        mapping.iova,
                        mapping.iova + mapping.size
                    );
                    mappings.push(mapping);
                }
                Err(e) => {
                    for mapping in mappings.iter() {
                        vfio_unmap_bar_mapping(container.as_ref(), vm.as_ref(), mapping);
                    }
                    return Err(e);
                }
            }
        }
        Ok(Self {
            mappings,
            container,
            vm,
        })
    }
}

impl Drop for VfioBarMappings {
    fn drop(&mut self) {
        for mapping in self.mappings.iter() {
            vfio_unmap_bar_mapping(self.container.as_ref(), self.vm.as_ref(), mapping);
        }
    }
}

/// Container for everything MSIx related
#[derive(Debug)]
pub struct VfioMsixState {
    /// Register idx where the capability is in the configuration space
    pub register: u8,
    /// The actual capability (without first 2 bytes)
    pub cap: MsixCap,
    /// Info about Table and Pba holes
    pub bar_hole_infos: ArrayVec<VfioBarHoleInfo, 2>,
    /// Config
    pub config: MsixConfig,
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

/// The VFIO device information
pub struct VfioDevice {
    /// Configuration with which the device was created
    pub config: VfioConfig,
    /// SBDF of the device in the configuration space
    pub sbdf: PciSBDF,
    /// Device
    pub device: InternalVfioDevice,
    /// Information about BARs
    pub bars: VfioBars,
    /// DMA mapped BARs
    pub bar_mappings: VfioBarMappings,
    /// MSIx state
    pub msix_state: VfioMsixState,
    /// Masks for configuration space registers
    pub masks: Vec<VfioRegisterMask>,
    /// Vm
    pub vm: Arc<KvmVm>,
}

impl std::fmt::Debug for VfioDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VfioDeviceBundle")
            .field("config", &self.config)
            .field("sbdf", &self.sbdf)
            .finish()
    }
}

impl VfioDevice {
    /// New VfioDevice
    pub fn new(
        container: &Arc<VfioContainer>,
        vm: &Arc<KvmVm>,
        config: VfioConfig,
        sbdf: PciSBDF,
    ) -> Result<Arc<Mutex<VfioDevice>>, VfioError> {
        vfio_init_device(container, vm, config, sbdf)
    }
}

impl Drop for VfioDevice {
    fn drop(&mut self) {
        vfio_deinit_device(self);
    }
}

enum HandleBarAccessResult {
    PartialOverlap,
    MsixTable(u64),
    MsixPba(u64),
    Device(u8, u64),
}
fn vfio_handle_bar_access(
    bar_hole_infos: &[VfioBarHoleInfo],
    msix_cap: &MsixCap,
    base: u64,
    offset: u64,
    data_len: u64,
) -> HandleBarAccessResult {
    let data_start = offset;
    let data_end = offset + data_len;
    for hole in bar_hole_infos.iter() {
        if hole.gpa == base {
            if hole.usage.contains(VfioBarHoleUsageFlags::TABLE) {
                let (t_off, t_size) = msix_cap.table_bar_offset_and_size();
                let t_start = offset_from_lower_host_page(t_off);
                let t_end = t_start + t_size;
                if t_start <= data_start && data_end <= t_end {
                    return HandleBarAccessResult::MsixTable(offset - t_start);
                }
                // Reject partial overlap with table.
                // This should not happen in normal operations, but malicious
                // driver can try this.
                // In this case it should be fine to ignore the access all together
                if data_start < t_end && t_start < data_end {
                    return HandleBarAccessResult::PartialOverlap;
                }
            }

            if hole.usage.contains(VfioBarHoleUsageFlags::PBA) {
                let (p_off, p_size) = msix_cap.pba_bar_offset_and_size();
                let p_start = offset_from_lower_host_page(p_off);
                let p_end = p_start + p_size;
                if p_start <= data_start && data_end <= p_end {
                    return HandleBarAccessResult::MsixPba(offset - p_start);
                }
                // Reject partial overlap with pba.
                // This should not happen in normal operations, but malicious
                // driver can try this.
                // In this case it should be fine to ignore the access all together
                if data_start < p_end && p_start < data_end {
                    return HandleBarAccessResult::PartialOverlap;
                }
            }

            let (region_idx, hole_off_in_region) =
                if hole.usage.contains(VfioBarHoleUsageFlags::TABLE) {
                    (
                        msix_cap.table_bir(),
                        align_down_host_page(msix_cap.table_offset() as u64),
                    )
                } else {
                    (
                        msix_cap.pba_bir(),
                        align_down_host_page(msix_cap.pba_offset() as u64),
                    )
                };
            let in_region_off = hole_off_in_region + offset;
            return HandleBarAccessResult::Device(region_idx, in_region_off);
        }
    }
    // SAFETY: if this is ever reached it would mean we have a bug in the code that adds BarHoles
    // as regions into the MmioBus.
    unreachable!()
}

// This should only serve BARs
impl BusDevice for VfioDevice {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        match vfio_handle_bar_access(
            &self.msix_state.bar_hole_infos,
            &self.msix_state.cap,
            base,
            offset,
            usize_to_u64(data.len()),
        ) {
            HandleBarAccessResult::PartialOverlap => {
                warn!(
                    "[{}] BusDevice::read ignoring read with partial overlap: base: {base:#x} \
                     offset: {offset:#x}",
                    self.config.id
                );
                data.fill(0);
            }
            HandleBarAccessResult::MsixTable(offset) => {
                self.msix_state.config.read_table(offset, data);
            }
            HandleBarAccessResult::MsixPba(offset) => {
                self.msix_state.config.read_pba(offset, data);
            }
            HandleBarAccessResult::Device(region_idx, in_region_off) => {
                let region_size = self.device.get_region_size(region_idx as u32);
                if in_region_off + (data.len() as u64) <= region_size {
                    self.device
                        .region_read(region_idx as u32, data, in_region_off);
                } else {
                    // If access is partially out of the region boundaries
                    // just ignore it
                }
            }
        }
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        match vfio_handle_bar_access(
            &self.msix_state.bar_hole_infos,
            &self.msix_state.cap,
            base,
            offset,
            usize_to_u64(data.len()),
        ) {
            HandleBarAccessResult::PartialOverlap => {
                warn!(
                    "[{}] BusDevice::write ignoring write with partial overlap: base: {base:#x} \
                     offset: {offset:#x}",
                    self.config.id
                );
            }
            HandleBarAccessResult::MsixTable(offset) => {
                self.msix_state.config.write_table(offset, data);
            }
            HandleBarAccessResult::MsixPba(offset) => {
                self.msix_state.config.write_pba(offset, data);
            }
            HandleBarAccessResult::Device(region_idx, in_region_off) => {
                let region_size = self.device.get_region_size(region_idx as u32);
                if in_region_off + (data.len() as u64) <= region_size {
                    self.device
                        .region_write(region_idx as u32, data, in_region_off);
                } else {
                    // If access is partially out of the region boundaries
                    // just ignore it
                }
            }
        }
        None
    }
}

// This should only serve config space
impl PciDevice for VfioDevice {
    fn write_config_register(
        &mut self,
        reg_idx: u16,
        offset: u8,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        let mut handled: bool = false;
        if BAR0_REG_IDX <= reg_idx && reg_idx < BAR0_REG_IDX + u16::from(NUM_BAR_REGS) {
            // reg_idx is in [BAR0_REG, BAR0_REG+NUM_BAR_REGS), so the difference is 0..5.
            #[allow(clippy::cast_possible_truncation)]
            let bar_idx = (reg_idx - BAR0_REG_IDX) as u8;
            // offset is within a 4-byte PCI config register (0..3).
            self.bars.bars.write(bar_idx, offset, data);
            handled = true;
        } else if reg_idx == ROM_BAR_REG {
            // We don's support ROM BAR
            handled = true;
            warn!(
                "[{}] PciDevice::write_config_register ignoring write to the ROM BAR: offset: \
                 {offset:#x}",
                self.config.id
            );
        } else if reg_idx == u16::from(self.msix_state.register) {
            // offset is within a 4-byte PCI config register (0..3).
            self.msix_state.config.write_msg_ctl_register(offset, data);
            // Don't set `handled` since we need to passthrough write
            // to the msg_ctl register to the device, so it will enable Msix
            // interrupts
        } else {
            // If we mask some registers, there is no reason to allow writing to them
            for mask in self.masks.iter() {
                if mask.register == reg_idx {
                    handled = true;
                    break;
                }
            }
        }
        let config_offset = reg_idx * 4 + u16::from(offset);
        if !handled {
            self.device
                .region_write(VFIO_PCI_CONFIG_REGION_INDEX, data, u64::from(config_offset));
        }
        None
    }
    fn read_config_register(&mut self, reg_idx: u16) -> u32 {
        let config_offset = reg_idx as u64 * 4;
        let mut result: u32 = 0;
        if BAR0_REG_IDX <= reg_idx && reg_idx < BAR0_REG_IDX + u16::from(NUM_BAR_REGS) {
            // reg_idx is in [BAR0_REG, BAR0_REG+NUM_BAR_REGS), so the difference is 0..5.
            #[allow(clippy::cast_possible_truncation)]
            let bar_idx = (reg_idx - BAR0_REG_IDX) as u8;
            self.bars.bars.read(bar_idx, 0, result.as_mut_bytes());
        } else if reg_idx == ROM_BAR_REG {
            // We don's support ROM BAR
            warn!(
                "[{}] PciDevice::read_config_register ignoring read to the ROM BAR",
                self.config.id
            );
        } else {
            self.device.region_read(
                VFIO_PCI_CONFIG_REGION_INDEX,
                result.as_mut_bytes(),
                config_offset,
            );
            if reg_idx == u16::from(self.msix_state.register) {
                // Since we emulate the MsixCap, we need to set the Mask and Msix enable bits to
                // values we have, and not what device has.
                let msg_ctl = self.msix_state.config.as_msg_ctl();
                result &= 0x0000ffff;
                result |= u32::from(msg_ctl) << 16;
            }
            for mask in self.masks.iter() {
                if mask.register == reg_idx {
                    result = (result & mask.mask) | mask.value;
                    break;
                }
            }
        }
        result
    }
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
fn vfio_calculate_bar_areas(
    bars: &Bars,
    region_infos: &[VfioRegionInfo],
    msix_cap: Option<&MsixCap>,
) -> Result<(Vec<BarArea>, ArrayVec<VfioBarHoleInfo, 2>), VfioError> {
    // There are 6 BARs with maximum of 2 holes in one or two of them
    // The only reasons to use Vec instead of ArrayVec here is because this vector can be populated
    // from the `sparse_mmap_cap` which can contiains different number of areas.
    // But in any case the size here is limited by the `nr_areas` field in the
    // `vfio_region_info_cap_sparse_mmap` struct. This field has type of `u32`.
    let mut areas = Vec::with_capacity(8);
    let mut bar_hole_infos = ArrayVec::<VfioBarHoleInfo, 2>::new();
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
                    let (offset, size) = msix_cap.table_bar_offset_and_size();
                    let offset_in_hole = offset_from_lower_host_page(offset);

                    msix_table_offset = align_down_host_page(offset);
                    msix_table_size = align_up_host_page(offset_in_hole + size);

                    if msix_table_offset
                        .checked_add(msix_table_size)
                        .is_none_or(|end| region_info.size < end)
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

                    let info = VfioBarHoleInfo {
                        gpa: bar_gpa + msix_table_offset,
                        size: msix_table_size,
                        usage: VfioBarHoleUsageFlags::TABLE,
                    };
                    bar_hole_infos.push(info);
                }

                contain_msix_pba = bar_idx == msix_cap.pba_bir();
                if contain_msix_pba {
                    let (offset, size) = msix_cap.pba_bar_offset_and_size();
                    let offset_in_hole = offset_from_lower_host_page(offset);

                    msix_pba_offset = align_down_host_page(offset);
                    msix_pba_size = align_up_host_page(offset_in_hole + size);

                    if msix_pba_offset
                        .checked_add(msix_pba_size)
                        .is_none_or(|end| region_info.size < end)
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
                        last.usage |= VfioBarHoleUsageFlags::PBA;
                        // In case PBA table is weirdly located at the page boundary which forces
                        // the size to become 2 pages instead of 1, just extend the region
                        last.size = last.size.max(msix_pba_size);
                    } else {
                        let info = VfioBarHoleInfo {
                            gpa: pba_gpa,
                            size: msix_pba_size,
                            usage: VfioBarHoleUsageFlags::PBA,
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
                                .is_none_or(|end| region_size < end)
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
pub fn vfio_dma_map_guest_memory(
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
pub fn vfio_dma_unmap_guest_memory(container: &VfioContainer, guest_memory: &GuestMemoryMmap) {
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

fn vfio_map_bar_mapping(
    container: &VfioContainer,
    device: &InternalVfioDevice,
    vm: &KvmVm,
    area: &BarArea,
    slot: u32,
) -> Result<VfioBarMapping, VfioError> {
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
    Ok(VfioBarMapping {
        slot,
        iova,
        size,
        hva,
    })
}

fn vfio_unmap_bar_mapping(container: &VfioContainer, vm: &KvmVm, mapping: &VfioBarMapping) {
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

#[allow(clippy::type_complexity)]
fn vfio_prepare_device(
    container: &Arc<VfioContainer>,
    vm: &Arc<KvmVm>,
    sysfs_path: &Path,
    sbdf: PciSBDF,
) -> Result<
    (
        InternalVfioDevice,
        VfioBars,
        VfioBarMappings,
        VfioMsixState,
        Vec<VfioRegisterMask>,
    ),
    VfioError,
> {
    let device = InternalVfioDevice::new(
        sysfs_path,
        container.clone() as Arc<dyn vfio_ioctls::VfioOps>,
    )?;
    device.reset();

    let (msix_cap_and_register, masks) = vfio_device_get_pci_capabilities(&device);

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

    let bars = VfioBars::new(&device, vm.clone())?;

    // There is no direct access to `regions` in `VfioDevice`, so need to work around this
    let bar_region_infos: [VfioRegionInfo; NUM_BAR_REGS as usize] = std::array::from_fn(|i| {
        #[allow(clippy::cast_possible_truncation)]
        VfioRegionInfo {
            flags: device.get_region_flags(i as u32),
            size: device.get_region_size(i as u32),
            offset: device.get_region_offset(i as u32),
            caps: device.get_region_caps(i as u32),
        }
    });

    let (areas, bar_hole_infos) = vfio_calculate_bar_areas(
        &bars.bars,
        &bar_region_infos,
        msix_cap_and_register.as_ref().map(|(v, _)| v),
    )?;

    let Some(first_area_slot) = vm.next_kvm_slot(
        // SAFETY: areas.len() is bound to fit in u32
        #[allow(clippy::cast_possible_truncation)]
        {
            areas.len() as u32
        },
    ) else {
        return Err(VfioError::KvmSlot);
    };

    let bar_mappings = VfioBarMappings::new(
        container.clone(),
        vm.clone(),
        &areas,
        &device,
        first_area_slot,
    )?;

    let msix_state = VfioMsixState {
        register: msix_register,
        cap: msix_cap,
        bar_hole_infos,
        config: msix_config,
    };
    Ok((device, bars, bar_mappings, msix_state, masks))
}

/// This will open a VFIO device, attach it's group both to the KVM VFIO device and to the VFIO
/// container. It will setup MSIx irqs and BAR DMAs.
fn vfio_init_device(
    container: &Arc<VfioContainer>,
    vm: &Arc<KvmVm>,
    config: VfioConfig,
    sbdf: PciSBDF,
) -> Result<Arc<Mutex<VfioDevice>>, VfioError> {
    let sysfs_path = format!(
        "/sys/bus/pci/devices/{:04x}:{:02x}:{:02x}.{:x}",
        config.sbdf.segment(),
        config.sbdf.bus(),
        config.sbdf.device(),
        config.sbdf.function()
    );
    debug!("Opening device at path: {}", sysfs_path);
    let (device, bars, bar_mappings, msix_state, masks) =
        vfio_prepare_device(container, vm, Path::new(&sysfs_path), sbdf)?;

    let vfio_device = Arc::new(Mutex::new(VfioDevice {
        config,
        sbdf,
        device,
        bars,
        bar_mappings,
        msix_state,
        masks,
        vm: vm.clone(),
    }));

    for hole in vfio_device.lock().unwrap().msix_state.bar_hole_infos.iter() {
        vm.common
            .mmio_bus
            .insert(vfio_device.clone(), hole.gpa, hole.size)
            // SAFETY: the hole gpa and size were allocated from internal allocator. we must never
            // receive overlapping regions from it.
            .unwrap();
    }
    Ok(vfio_device)
}

/// Performs device reset and removes emulated regions from the mmio_bus.
fn vfio_deinit_device(device: &VfioDevice) {
    device.device.reset();

    for hole in device.msix_state.bar_hole_infos.iter() {
        device
            .vm
            .common
            .mmio_bus
            .remove(hole.gpa, hole.size)
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pci::configuration::{
        BarPrefetchable, encode_32_bits_bar_size, encode_64_bits_bar_size,
    };

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

    #[test]
    fn test_calculate_bar_areas_no_bars_or_region_infos() {
        let bars = Bars::default();
        let region_infos: [VfioRegionInfo; 0] = [];

        let (areas, holes) = vfio_calculate_bar_areas(&bars, &region_infos, None).unwrap();
        assert!(areas.is_empty());
        assert!(holes.is_empty());
    }

    #[test]
    fn test_calculate_bar_areas_no_holes() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x1000, 0x1000, BarPrefetchable::No);
        bars.set_bar_64(2, 0x2000, 0x1000, BarPrefetchable::No);
        let region_infos = [
            // BAR 0
            dummy_region_info(0x1000, vec![]),
            dummy_region_info(0x0, vec![]),
            // BAR 1
            dummy_region_info(0x1000, vec![VfioRegionInfoCap::MsixMappable]),
        ];

        let (areas, holes) = vfio_calculate_bar_areas(&bars, &region_infos, None).unwrap();

        assert_eq!(areas.len(), 2);
        assert_eq!(areas[0].bar_gpa, 0x1000);
        assert_eq!(areas[0].size, 0x1000);
        assert_eq!(areas[0].offset, 0);
        assert_eq!(areas[1].bar_gpa, 0x2000);
        assert_eq!(areas[1].size, 0x1000);
        assert_eq!(areas[1].offset, 0);

        assert!(holes.is_empty());
    }

    #[test]
    fn test_calculate_bar_areas_msix_table_and_pba_in_different_bars() {
        // BARs are just one page long, so hole take them
        {
            let mut bars = Bars::default();
            bars.set_bar_64(0, 0x1000, 0x1000, BarPrefetchable::No);
            bars.set_bar_64(2, 0x2000, 0x1000, BarPrefetchable::No);

            let region_infos = [
                // BAR 0
                dummy_region_info(0x1000, vec![VfioRegionInfoCap::MsixMappable]),
                dummy_region_info(0, vec![]),
                // BAR 1
                dummy_region_info(0x1000, vec![VfioRegionInfoCap::MsixMappable]),
            ];

            let msix_cap = MsixCap::new(0, 32, 0, 2, 0);

            let (areas, holes) =
                vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();

            assert_eq!(areas.len(), 0);

            assert_eq!(holes.len(), 2);
            assert_eq!(holes[0].gpa, 0x1000);
            assert_eq!(holes[0].size, 0x1000);
            assert_eq!(holes[0].usage, VfioBarHoleUsageFlags::TABLE);
            assert_eq!(holes[1].gpa, 0x2000);
            assert_eq!(holes[1].size, 0x1000);
            assert_eq!(holes[1].usage, VfioBarHoleUsageFlags::PBA);
        }

        // BARs are multiple pages, so hole leave some space
        {
            let mut bars = Bars::default();
            bars.set_bar_64(0, 0x1000, 0x2000, BarPrefetchable::No);
            bars.set_bar_64(2, 0x3000, 0x2000, BarPrefetchable::No);

            let region_infos = [
                // BAR 0
                dummy_region_info(0x2000, vec![VfioRegionInfoCap::MsixMappable]),
                dummy_region_info(0, vec![]),
                // BAR 1
                dummy_region_info(0x2000, vec![VfioRegionInfoCap::MsixMappable]),
            ];

            let msix_cap = MsixCap::new(0, 32, 0, 2, 0);

            let (areas, holes) =
                vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();

            assert_eq!(areas.len(), 2);
            assert_eq!(areas[0].bar_gpa, 0x1000);
            assert_eq!(areas[0].size, 0x1000);
            assert_eq!(areas[0].offset, 0x1000);
            assert_eq!(areas[1].bar_gpa, 0x3000);
            assert_eq!(areas[1].size, 0x1000);
            assert_eq!(areas[1].offset, 0x1000);

            assert_eq!(holes.len(), 2);
            assert_eq!(holes[0].gpa, 0x1000);
            assert_eq!(holes[0].size, 0x1000);
            assert_eq!(holes[0].usage, VfioBarHoleUsageFlags::TABLE);
            assert_eq!(holes[1].gpa, 0x3000);
            assert_eq!(holes[1].size, 0x1000);
            assert_eq!(holes[1].usage, VfioBarHoleUsageFlags::PBA);
        }
    }

    #[test]
    fn test_calculate_bar_areas_sparse_mmap() {
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
            let region_infos = [dummy_region_info(
                0x4000,
                vec![VfioRegionInfoCap::SparseMmap(VfioRegionInfoCapSparseMmap {
                    areas: sparse_areas,
                })],
            )];

            let (areas, holes) = vfio_calculate_bar_areas(&bars, &region_infos, None).unwrap();

            assert_eq!(areas.len(), 2);
            assert_eq!(areas[0].offset, 0);
            assert_eq!(areas[0].size, 0x1000);
            assert_eq!(areas[1].offset, 0x2000);
            assert_eq!(areas[1].size, 0x1000);

            assert!(holes.is_empty());
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
            let region_infos = [dummy_region_info(
                0x4000,
                vec![VfioRegionInfoCap::SparseMmap(VfioRegionInfoCapSparseMmap {
                    areas: sparse_areas,
                })],
            )];

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
            let region_infos = [dummy_region_info(
                0x4000,
                vec![VfioRegionInfoCap::SparseMmap(VfioRegionInfoCapSparseMmap {
                    areas: sparse_areas,
                })],
            )];

            vfio_calculate_bar_areas(&bars, &region_infos, None).unwrap_err();
        }
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

    #[test]
    fn test_calculate_bar_areas_msix_table_and_pba_in_the_same_bar() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x1000, 0x2000, BarPrefetchable::No);

        let region_infos = [dummy_region_info(
            0x2000,
            vec![VfioRegionInfoCap::MsixMappable],
        )];

        let msix_cap = MsixCap::new(0, 32, 0, 0, 0x1000);

        let (areas, holes) =
            vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();

        assert!(areas.is_empty());

        assert_eq!(holes.len(), 2);
        assert_eq!(holes[0].gpa, 0x1000);
        assert_eq!(holes[0].size, 0x1000);
        assert_eq!(holes[0].usage, VfioBarHoleUsageFlags::TABLE);
        assert_eq!(holes[1].gpa, 0x2000);
        assert_eq!(holes[1].size, 0x1000);
        assert_eq!(holes[1].usage, VfioBarHoleUsageFlags::PBA);
    }

    #[test]
    fn test_calculate_bar_areas_overlapping_msix_holes() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x1000, 0x2000, BarPrefetchable::No);

        let region_infos = [dummy_region_info(
            0x2000,
            vec![VfioRegionInfoCap::MsixMappable],
        )];

        // Both tables create the same hole [0x0..0x1000)
        let msix_cap = MsixCap::new(0, 32, 0x0, 0, 0x200);
        let (areas, holes) =
            vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();

        assert_eq!(areas.len(), 1);
        assert_eq!(areas[0].bar_gpa, 0x1000);
        assert_eq!(areas[0].size, 0x1000);
        assert_eq!(areas[0].offset, 0x1000);

        assert_eq!(holes.len(), 1);
        assert_eq!(holes[0].gpa, 0x1000);
        assert_eq!(holes[0].size, 0x1000);
        assert_eq!(
            holes[0].usage,
            VfioBarHoleUsageFlags::TABLE | VfioBarHoleUsageFlags::PBA
        );
    }

    /// Table and PBA share the same starting page (so the same hole `gpa`),
    /// but the PBA contents straddle the page boundary, so its host-page-
    /// aligned size is larger than the table's. The two holes must merge
    /// into one.
    #[test]
    fn test_calculate_bar_areas_same_gpa_different_size_msix_holes() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x1000, 0x2000, BarPrefetchable::No);

        let region_infos = [dummy_region_info(
            0x2000,
            vec![VfioRegionInfoCap::MsixMappable],
        )];

        // table at offset 0, 128 entries (0x800 bytes) -> hole [0x0, 0x1000)
        // PBA at offset 0xff8, 16 bytes -> straddles 0x1000 -> hole [0x0, 0x2000)
        // Same gpa (bar_gpa + 0), different sizes.
        let msix_cap = MsixCap::new(0, 128, 0, 0, 0xff8);

        let (areas, holes) =
            vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap();

        // No space for areas, all taken by holes
        assert!(areas.is_empty());

        assert_eq!(holes.len(), 1);
        assert_eq!(holes[0].gpa, 0x1000);
        assert_eq!(holes[0].size, 0x2000);
        assert_eq!(
            holes[0].usage,
            VfioBarHoleUsageFlags::TABLE | VfioBarHoleUsageFlags::PBA
        );
    }

    #[test]
    fn test_calculate_bar_areas_msix_table_past_region_end() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x1000, 0x1000, BarPrefetchable::No);

        let region_infos = [dummy_region_info(
            0x1000,
            vec![VfioRegionInfoCap::MsixMappable],
        )];

        // The page-aligned hole is [0x1000, 0x3000) which is outside [0x1000, 0x2000) BAR range
        let msix_cap = MsixCap::new(0, 1, 0xff8, 0, 0);

        let err = vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap_err();
        assert!(matches!(
            err,
            VfioError::MsixTableOutOfRange(0, 0x0, 0x2000, 0x1000)
        ));
    }

    #[test]
    fn test_calculate_bar_areas_msix_pba_past_region_end() {
        let mut bars = Bars::default();
        bars.set_bar_64(0, 0x1000, 0x1000, BarPrefetchable::No);

        let region_infos = [dummy_region_info(
            0x1000,
            vec![VfioRegionInfoCap::MsixMappable],
        )];

        // The page-aligned hole is [0x1000, 0x3000) which is outside [0x1000, 0x2000) BAR range
        let msix_cap = MsixCap::new(0, 128, 0, 0, 0xffe);

        let err = vfio_calculate_bar_areas(&bars, &region_infos, Some(&msix_cap)).unwrap_err();
        assert!(matches!(
            err,
            VfioError::MsixPbaOutOfRange(0, 0x0, 0x2000, 0x1000)
        ));
    }

    const BAR_GPA: u64 = 0x1000;

    fn holes_table_only() -> ArrayVec<VfioBarHoleInfo, 2> {
        let mut holes = ArrayVec::new();
        holes.push(VfioBarHoleInfo {
            gpa: BAR_GPA,
            size: 0x1000,
            usage: VfioBarHoleUsageFlags::TABLE,
        });
        holes
    }

    fn holes_pba_only() -> ArrayVec<VfioBarHoleInfo, 2> {
        let mut holes = ArrayVec::new();
        holes.push(VfioBarHoleInfo {
            gpa: BAR_GPA,
            size: 0x1000,
            usage: VfioBarHoleUsageFlags::PBA,
        });
        holes
    }

    fn holes_merged() -> ArrayVec<VfioBarHoleInfo, 2> {
        let mut holes = ArrayVec::new();
        holes.push(VfioBarHoleInfo {
            gpa: BAR_GPA,
            size: 0x1000,
            usage: VfioBarHoleUsageFlags::TABLE | VfioBarHoleUsageFlags::PBA,
        });
        holes
    }

    #[test]
    fn test_handle_bar_access_table_inside_table_range() {
        let holes = holes_table_only();
        let cap = MsixCap::new(0, 4, 0, 0, 0x800);
        let result = vfio_handle_bar_access(&holes, &cap, BAR_GPA, 0x10, 4);
        assert!(matches!(result, HandleBarAccessResult::MsixTable(0x10)));
    }

    #[test]
    fn test_handle_bar_access_table_outside_table_range_forwards_to_device() {
        let holes = holes_table_only();
        let cap = MsixCap::new(0, 4, 0, 0, 0x800);
        let result = vfio_handle_bar_access(&holes, &cap, BAR_GPA, 0x100, 4);
        assert!(matches!(result, HandleBarAccessResult::Device(0, 0x100)));
    }

    #[test]
    fn test_handle_bar_access_pba_inside_pba_range() {
        let holes = holes_pba_only();
        let cap = MsixCap::new(0, 4, 0x800, 0, 0x100);
        let result = vfio_handle_bar_access(&holes, &cap, BAR_GPA, 0x100, 4);
        assert!(matches!(result, HandleBarAccessResult::MsixPba(0)));
    }

    #[test]
    fn test_handle_bar_access_pba_outside_pba_range_forwards_to_device() {
        let holes = holes_pba_only();
        let cap = MsixCap::new(0, 4, 0x800, 0, 0x100);
        let result = vfio_handle_bar_access(&holes, &cap, BAR_GPA, 0x800, 4);
        assert!(matches!(result, HandleBarAccessResult::Device(0, 0x800)));
    }

    #[test]
    fn test_handle_bar_access_merged_hits_table() {
        let holes = holes_merged();
        let cap = MsixCap::new(0, 4, 0, 0, 0x200);
        let result = vfio_handle_bar_access(&holes, &cap, BAR_GPA, 0x10, 4);
        assert!(matches!(result, HandleBarAccessResult::MsixTable(0x10)));
    }

    #[test]
    fn test_handle_bar_access_merged_hits_pba() {
        let holes = holes_merged();
        let cap = MsixCap::new(0, 4, 0, 0, 0x200);
        let result = vfio_handle_bar_access(&holes, &cap, BAR_GPA, 0x200, 4);
        assert!(matches!(result, HandleBarAccessResult::MsixPba(0)));
    }

    #[test]
    fn test_handle_bar_access_merged_padding_forwards_to_device() {
        let holes = holes_merged();
        let cap = MsixCap::new(0, 4, 0, 0, 0x200);
        let result = vfio_handle_bar_access(&holes, &cap, BAR_GPA, 0x800, 4);
        assert!(matches!(result, HandleBarAccessResult::Device(0, 0x800)));
    }

    #[test]
    fn test_handle_bar_access_partial_overlap_table_start() {
        let holes = holes_table_only();
        let cap = MsixCap::new(0, 4, 0x100, 0, 0x800);
        let result = vfio_handle_bar_access(&holes, &cap, BAR_GPA, 0xfe, 4);
        assert!(matches!(result, HandleBarAccessResult::PartialOverlap));
    }

    #[test]
    fn test_handle_bar_access_partial_overlap_table_end() {
        let holes = holes_table_only();
        let cap = MsixCap::new(0, 4, 0, 0, 0x800);
        let result = vfio_handle_bar_access(&holes, &cap, BAR_GPA, 0x3e, 4);
        assert!(matches!(result, HandleBarAccessResult::PartialOverlap));
    }

    #[test]
    fn test_handle_bar_access_partial_overlap_pba_start() {
        let holes = holes_pba_only();
        let cap = MsixCap::new(0, 4, 0x800, 0, 0x100);
        let result = vfio_handle_bar_access(&holes, &cap, BAR_GPA, 0xfe, 4);
        assert!(matches!(result, HandleBarAccessResult::PartialOverlap));
    }

    #[test]
    fn test_handle_bar_access_partial_overlap_pba_end() {
        let holes = holes_pba_only();
        let cap = MsixCap::new(0, 4, 0x800, 0, 0x100);
        let result = vfio_handle_bar_access(&holes, &cap, BAR_GPA, 0x106, 4);
        assert!(matches!(result, HandleBarAccessResult::PartialOverlap));
    }

    #[test]
    #[should_panic(expected = "unreachable")]
    fn test_handle_bar_access_unrelated_base_panics() {
        let holes = holes_table_only();
        let cap = MsixCap::new(0, 4, 0, 0, 0x800);
        let _ = vfio_handle_bar_access(&holes, &cap, BAR_GPA + 0x1000, 0, 4);
    }
}
