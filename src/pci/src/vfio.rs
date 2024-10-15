// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//

use core::fmt;
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fmt::{Debug, Formatter};
use std::io;
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;
use std::sync::{Arc, Barrier, Mutex};

use anyhow::{anyhow, Error};
use byteorder::{ByteOrder, LittleEndian};
use kvm_ioctls::VmFd;
use libc::{sysconf, _SC_PAGESIZE};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use vfio_bindings::bindings::vfio::*;
use vfio_ioctls::{
    VfioContainer, VfioDevice, VfioIrq, VfioRegionInfoCap, VfioRegionSparseMmapArea,
};
use vm_system_allocator::page_size::{
    align_page_size_down, align_page_size_up, is_4k_aligned, is_4k_multiple, is_page_size_aligned,
};
use vm_system_allocator::{AddressAllocator, SystemAllocator};
use vm_device::dma_mapping::ExternalDmaMapping;
use vm_device::interrupt::{
    InterruptIndex, InterruptManager, InterruptSourceGroup, MsiIrqGroupConfig,
};
use vm_device::Resource;
use vm_memory::{Address, GuestAddress, GuestAddressSpace, GuestMemory, GuestUsize};
use vmm_sys_util::eventfd::EventFd;

use crate::msi::{MsiConfigState, MSI_CONFIG_ID};
use crate::msix::MsixConfigState;
use crate::{
    msi_num_enabled_vectors, BarReprogrammingParams, MsiCap, MsiConfig, MsixCap, MsixConfig,
    PciBarConfiguration, PciBarPrefetchable, PciBarRegionType, PciBdf, PciCapabilityId,
    PciClassCode, PciConfiguration, PciDevice, PciDeviceError, PciExpressCapabilityId,
    PciHeaderType, PciSubclass, MSIX_CONFIG_ID, MSIX_TABLE_ENTRY_SIZE, PCI_CONFIGURATION_ID,
};

pub use kvm_bindings::kvm_userspace_memory_region as MemoryRegion;

pub(crate) const VFIO_COMMON_ID: &str = "vfio_common";

#[derive(Debug, Error)]
pub enum VfioPciError {
    #[error("Failed to create user memory region: {0}")]
    MapRegionGuest(#[source] Error),
    #[error("Failed to DMA map: {0}")]
    DmaMap(#[source] vfio_ioctls::VfioError),
    #[error("Failed to DMA unmap: {0}")]
    DmaUnmap(#[source] vfio_ioctls::VfioError),
    #[error("Failed to enable INTx: {0}")]
    EnableIntx(#[source] VfioError),
    #[error("Failed to enable MSI: {0}")]
    EnableMsi(#[source] VfioError),
    #[error("Failed to enable MSI-x: {0}")]
    EnableMsix(#[source] VfioError),
    #[error("Failed to mmap the area")]
    MmapArea,
    #[error("Failed to notifier's eventfd")]
    MissingNotifier,
    #[error("Invalid region alignment")]
    RegionAlignment,
    #[error("Invalid region size")]
    RegionSize,
    #[error("Failed to retrieve MsiConfigState: {0}")]
    RetrieveMsiConfigState(#[source] anyhow::Error),
    #[error("Failed to retrieve MsixConfigState: {0}")]
    RetrieveMsixConfigState(#[source] anyhow::Error),
    #[error("Failed to retrieve PciConfigurationState: {0}")]
    RetrievePciConfigurationState(#[source] anyhow::Error),
    #[error("Failed to retrieve VfioCommonState: {0}")]
    RetrieveVfioCommonState(#[source] anyhow::Error),
}

#[derive(Copy, Clone)]
enum PciVfioSubclass {
    VfioSubclass = 0xff,
}

impl PciSubclass for PciVfioSubclass {
    fn get_register_value(&self) -> u8 {
        *self as u8
    }
}

enum InterruptUpdateAction {
    EnableMsi,
    DisableMsi,
    EnableMsix,
    DisableMsix,
}

#[derive(Serialize, Deserialize)]
struct IntxState {
    enabled: bool,
}

pub(crate) struct VfioIntx {
    interrupt_source_group: Arc<dyn InterruptSourceGroup>,
    enabled: bool,
}

#[derive(Serialize, Deserialize)]
struct MsiState {
    cap: MsiCap,
    cap_offset: u32,
}

pub(crate) struct VfioMsi {
    pub(crate) cfg: MsiConfig,
    cap_offset: u32,
    interrupt_source_group: Arc<dyn InterruptSourceGroup>,
}

impl VfioMsi {
    fn update(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        let old_enabled = self.cfg.enabled();

        self.cfg.update(offset, data);

        let new_enabled = self.cfg.enabled();

        if !old_enabled && new_enabled {
            return Some(InterruptUpdateAction::EnableMsi);
        }

        if old_enabled && !new_enabled {
            return Some(InterruptUpdateAction::DisableMsi);
        }

        None
    }
}

#[derive(Serialize, Deserialize)]
struct MsixState {
    cap: MsixCap,
    cap_offset: u32,
    bdf: u32,
}

pub(crate) struct VfioMsix {
    pub(crate) bar: MsixConfig,
    cap: MsixCap,
    cap_offset: u32,
    interrupt_source_group: Arc<dyn InterruptSourceGroup>,
}

impl VfioMsix {
    fn update(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        let old_enabled = self.bar.enabled();

        // Update "Message Control" word
        if offset == 2 && data.len() == 2 {
            self.bar.set_msg_ctl(LittleEndian::read_u16(data));
        }

        let new_enabled = self.bar.enabled();

        if !old_enabled && new_enabled {
            return Some(InterruptUpdateAction::EnableMsix);
        }

        if old_enabled && !new_enabled {
            return Some(InterruptUpdateAction::DisableMsix);
        }

        None
    }

    fn table_accessed(&self, bar_index: u32, offset: u64) -> bool {
        let table_offset: u64 = u64::from(self.cap.table_offset());
        let table_size: u64 = u64::from(self.cap.table_size()) * (MSIX_TABLE_ENTRY_SIZE as u64);
        let table_bir: u32 = self.cap.table_bir();

        bar_index == table_bir && offset >= table_offset && offset < table_offset + table_size
    }
}

pub(crate) struct Interrupt {
    pub(crate) intx: Option<VfioIntx>,
    pub(crate) msi: Option<VfioMsi>,
    pub(crate) msix: Option<VfioMsix>,
}

impl Interrupt {
    fn update_msi(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        if let Some(ref mut msi) = &mut self.msi {
            let action = msi.update(offset, data);
            return action;
        }

        None
    }

    fn update_msix(&mut self, offset: u64, data: &[u8]) -> Option<InterruptUpdateAction> {
        if let Some(ref mut msix) = &mut self.msix {
            let action = msix.update(offset, data);
            return action;
        }

        None
    }

    fn accessed(&self, offset: u64) -> Option<(PciCapabilityId, u64)> {
        if let Some(msi) = &self.msi {
            if offset >= u64::from(msi.cap_offset)
                && offset < u64::from(msi.cap_offset) + msi.cfg.size()
            {
                return Some((
                    PciCapabilityId::MessageSignalledInterrupts,
                    u64::from(msi.cap_offset),
                ));
            }
        }

        if let Some(msix) = &self.msix {
            if offset == u64::from(msix.cap_offset) {
                return Some((PciCapabilityId::MsiX, u64::from(msix.cap_offset)));
            }
        }

        None
    }

    fn msix_table_accessed(&self, bar_index: u32, offset: u64) -> bool {
        if let Some(msix) = &self.msix {
            return msix.table_accessed(bar_index, offset);
        }

        false
    }

    fn msix_write_table(&mut self, offset: u64, data: &[u8]) {
        if let Some(ref mut msix) = &mut self.msix {
            let offset = offset - u64::from(msix.cap.table_offset());
            msix.bar.write_table(offset, data)
        }
    }

    fn msix_read_table(&self, offset: u64, data: &mut [u8]) {
        if let Some(msix) = &self.msix {
            let offset = offset - u64::from(msix.cap.table_offset());
            msix.bar.read_table(offset, data)
        }
    }

    pub(crate) fn intx_in_use(&self) -> bool {
        if let Some(intx) = &self.intx {
            return intx.enabled;
        }

        false
    }
}

#[derive(Copy, Clone)]
pub struct UserMemoryRegion {
    pub slot: u32,
    pub start: u64,
    pub size: u64,
    pub host_addr: u64,
}

#[derive(Clone)]
pub struct MmioRegion {
    pub start: GuestAddress,
    pub length: GuestUsize,
    pub(crate) type_: PciBarRegionType,
    pub(crate) index: u32,
    pub(crate) user_memory_regions: Vec<UserMemoryRegion>,
}

trait MmioRegionRange {
    fn check_range(&self, guest_addr: u64, size: u64) -> bool;
    fn find_user_address(&self, guest_addr: u64) -> Result<u64, io::Error>;
}

impl MmioRegionRange for Vec<MmioRegion> {
    // Check if a guest address is within the range of mmio regions
    fn check_range(&self, guest_addr: u64, size: u64) -> bool {
        for region in self.iter() {
            let Some(guest_addr_end) = guest_addr.checked_add(size) else {
                return false;
            };
            let Some(region_end) = region.start.raw_value().checked_add(region.length) else {
                return false;
            };
            if guest_addr >= region.start.raw_value() && guest_addr_end <= region_end {
                return true;
            }
        }
        false
    }

    // Locate the user region address for a guest address within all mmio regions
    fn find_user_address(&self, guest_addr: u64) -> Result<u64, io::Error> {
        for region in self.iter() {
            for user_region in region.user_memory_regions.iter() {
                if guest_addr >= user_region.start
                    && guest_addr < user_region.start + user_region.size
                {
                    return Ok(user_region.host_addr + (guest_addr - user_region.start));
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("unable to find user address: 0x{guest_addr:x}"),
        ))
    }
}

#[derive(Debug, Error)]
pub enum VfioError {
    #[error("Kernel VFIO error: {0}")]
    KernelVfio(#[source] vfio_ioctls::VfioError),
}

pub(crate) trait Vfio: Send + Sync {
    fn read_config_byte(&self, offset: u32) -> u8 {
        let mut data: [u8; 1] = [0];
        self.read_config(offset, &mut data);
        data[0]
    }

    fn read_config_word(&self, offset: u32) -> u16 {
        let mut data: [u8; 2] = [0, 0];
        self.read_config(offset, &mut data);
        u16::from_le_bytes(data)
    }

    fn read_config_dword(&self, offset: u32) -> u32 {
        let mut data: [u8; 4] = [0, 0, 0, 0];
        self.read_config(offset, &mut data);
        u32::from_le_bytes(data)
    }

    fn write_config_dword(&self, offset: u32, buf: u32) {
        let data: [u8; 4] = buf.to_le_bytes();
        self.write_config(offset, &data)
    }

    fn read_config(&self, offset: u32, data: &mut [u8]) {
        self.region_read(VFIO_PCI_CONFIG_REGION_INDEX, offset.into(), data.as_mut());
    }

    fn write_config(&self, offset: u32, data: &[u8]) {
        self.region_write(VFIO_PCI_CONFIG_REGION_INDEX, offset.into(), data)
    }

    fn enable_msi(&self, fds: Vec<&EventFd>) -> Result<(), VfioError> {
        self.enable_irq(VFIO_PCI_MSI_IRQ_INDEX, fds)
    }

    fn disable_msi(&self) -> Result<(), VfioError> {
        self.disable_irq(VFIO_PCI_MSI_IRQ_INDEX)
    }

    fn enable_msix(&self, fds: Vec<&EventFd>) -> Result<(), VfioError> {
        self.enable_irq(VFIO_PCI_MSIX_IRQ_INDEX, fds)
    }

    fn disable_msix(&self) -> Result<(), VfioError> {
        self.disable_irq(VFIO_PCI_MSIX_IRQ_INDEX)
    }

    fn region_read(&self, _index: u32, _offset: u64, _data: &mut [u8]) {
        unimplemented!()
    }

    fn region_write(&self, _index: u32, _offset: u64, _data: &[u8]) {
        unimplemented!()
    }

    fn get_irq_info(&self, _irq_index: u32) -> Option<VfioIrq> {
        unimplemented!()
    }

    fn enable_irq(&self, _irq_index: u32, _event_fds: Vec<&EventFd>) -> Result<(), VfioError> {
        unimplemented!()
    }

    fn disable_irq(&self, _irq_index: u32) -> Result<(), VfioError> {
        unimplemented!()
    }

    fn unmask_irq(&self, _irq_index: u32) -> Result<(), VfioError> {
        unimplemented!()
    }
}

struct VfioDeviceWrapper {
    device: Arc<VfioDevice>,
}

impl VfioDeviceWrapper {
    fn new(device: Arc<VfioDevice>) -> Self {
        Self { device }
    }
}

impl Vfio for VfioDeviceWrapper {
    fn region_read(&self, index: u32, offset: u64, data: &mut [u8]) {
        self.device.region_read(index, data, offset)
    }

    fn region_write(&self, index: u32, offset: u64, data: &[u8]) {
        self.device.region_write(index, data, offset)
    }

    fn get_irq_info(&self, irq_index: u32) -> Option<VfioIrq> {
        self.device.get_irq_info(irq_index).copied()
    }

    fn enable_irq(&self, irq_index: u32, event_fds: Vec<&EventFd>) -> Result<(), VfioError> {
        self.device
            .enable_irq(irq_index, event_fds)
            .map_err(VfioError::KernelVfio)
    }

    fn disable_irq(&self, irq_index: u32) -> Result<(), VfioError> {
        self.device
            .disable_irq(irq_index)
            .map_err(VfioError::KernelVfio)
    }

    fn unmask_irq(&self, irq_index: u32) -> Result<(), VfioError> {
        self.device
            .unmask_irq(irq_index)
            .map_err(VfioError::KernelVfio)
    }
}

#[derive(Serialize, Deserialize)]
struct VfioCommonState {
    intx_state: Option<IntxState>,
    msi_state: Option<MsiState>,
    msix_state: Option<MsixState>,
}

pub(crate) struct ConfigPatch {
    mask: u32,
    patch: u32,
}

pub(crate) struct VfioCommon {
    pub(crate) configuration: PciConfiguration,
    pub(crate) mmio_regions: Vec<MmioRegion>,
    pub(crate) interrupt: Interrupt,
    pub(crate) msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
    pub(crate) legacy_interrupt_group: Option<Arc<dyn InterruptSourceGroup>>,
    pub(crate) vfio_wrapper: Arc<dyn Vfio>,
    pub(crate) patches: HashMap<usize, ConfigPatch>,
    x_nv_gpudirect_clique: Option<u8>,
}

impl VfioCommon {
    pub(crate) fn new(
        msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        legacy_interrupt_group: Option<Arc<dyn InterruptSourceGroup>>,
        vfio_wrapper: Arc<dyn Vfio>,
        subclass: &dyn PciSubclass,
        bdf: PciBdf,
        x_nv_gpudirect_clique: Option<u8>,
    ) -> Result<Self, VfioPciError> {
        let pci_configuration_state = None;

        let configuration = PciConfiguration::new(
            0,
            0,
            0,
            PciClassCode::Other,
            subclass,
            None,
            PciHeaderType::Device,
            0,
            0,
            None,
            pci_configuration_state,
        );

        let mut vfio_common = VfioCommon {
            mmio_regions: Vec::new(),
            configuration,
            interrupt: Interrupt {
                intx: None,
                msi: None,
                msix: None,
            },
            msi_interrupt_manager,
            legacy_interrupt_group,
            vfio_wrapper,
            patches: HashMap::new(),
            x_nv_gpudirect_clique,
        };

        let state: Option<VfioCommonState> = None;
        let msi_state = None;
        let msix_state = None;

        if let Some(state) = state.as_ref() {
            vfio_common.set_state(state, msi_state, msix_state)?;
        } else {
            vfio_common.parse_capabilities(bdf);
            vfio_common.initialize_legacy_interrupt()?;
        }

        Ok(vfio_common)
    }

    /// In case msix table offset is not page size aligned, we need do some fixup to achieve it.
    /// Because we don't want the MMIO RW region and trap region overlap each other.
    fn fixup_msix_region(&mut self, bar_id: u32, region_size: u64) -> u64 {
        if let Some(msix) = self.interrupt.msix.as_mut() {
            let msix_cap = &mut msix.cap;

            // Suppose table_bir equals to pba_bir here. Am I right?
            let (table_offset, table_size) = msix_cap.table_range();
            if is_page_size_aligned(table_offset) || msix_cap.table_bir() != bar_id {
                return region_size;
            }

            let (pba_offset, pba_size) = msix_cap.pba_range();
            let msix_sz = align_page_size_up(table_size + pba_size);
            // Expand region to hold RW and trap region which both page size aligned
            let size = std::cmp::max(region_size * 2, msix_sz * 2);
            // let table starts from the middle of the region
            msix_cap.table_set_offset((size / 2) as u32);
            msix_cap.pba_set_offset((size / 2 + pba_offset - table_offset) as u32);

            size
        } else {
            // MSI-X not supported for this device
            region_size
        }
    }

    // The `allocator` argument is unused on `aarch64`
    #[allow(unused_variables)]
    pub(crate) fn allocate_bars(
        &mut self,
        allocator: &Arc<Mutex<SystemAllocator>>,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
        resources: Option<Vec<Resource>>,
    ) -> Result<Vec<PciBarConfiguration>, PciDeviceError> {
        let mut bars = Vec::new();
        let mut bar_id = VFIO_PCI_BAR0_REGION_INDEX;

        // Going through all regular regions to compute the BAR size.
        // We're not saving the BAR address to restore it, because we
        // are going to allocate a guest address for each BAR and write
        // that new address back.
        while bar_id < VFIO_PCI_CONFIG_REGION_INDEX {
            let mut region_size: u64 = 0;
            let mut region_type = PciBarRegionType::Memory32BitRegion;
            let mut prefetchable = PciBarPrefetchable::NotPrefetchable;
            let mut flags: u32 = 0;

            let mut restored_bar_addr = None;
            if let Some(resources) = &resources {
                for resource in resources {
                    if let Resource::PciBar {
                        index,
                        base,
                        size,
                        type_,
                        ..
                    } = resource
                    {
                        if *index == bar_id as usize {
                            restored_bar_addr = Some(GuestAddress(*base));
                            region_size = *size;
                            region_type = PciBarRegionType::from(*type_);
                            break;
                        }
                    }
                }
                if restored_bar_addr.is_none() {
                    bar_id += 1;
                    continue;
                }
            } else {
                let bar_offset = if bar_id == VFIO_PCI_ROM_REGION_INDEX {
                    (PCI_ROM_EXP_BAR_INDEX * 4) as u32
                } else {
                    PCI_CONFIG_BAR_OFFSET + bar_id * 4
                };

                // First read flags
                flags = self.vfio_wrapper.read_config_dword(bar_offset);

                // Is this an IO BAR?
                let io_bar = if bar_id != VFIO_PCI_ROM_REGION_INDEX {
                    matches!(flags & PCI_CONFIG_IO_BAR, PCI_CONFIG_IO_BAR)
                } else {
                    false
                };

                // Is this a 64-bit BAR?
                let is_64bit_bar = if bar_id != VFIO_PCI_ROM_REGION_INDEX {
                    matches!(
                        flags & PCI_CONFIG_MEMORY_BAR_64BIT,
                        PCI_CONFIG_MEMORY_BAR_64BIT
                    )
                } else {
                    false
                };

                if matches!(
                    flags & PCI_CONFIG_BAR_PREFETCHABLE,
                    PCI_CONFIG_BAR_PREFETCHABLE
                ) {
                    prefetchable = PciBarPrefetchable::Prefetchable
                };

                // To get size write all 1s
                self.vfio_wrapper
                    .write_config_dword(bar_offset, 0xffff_ffff);

                // And read back BAR value. The device will write zeros for bits it doesn't care about
                let mut lower = self.vfio_wrapper.read_config_dword(bar_offset);

                if io_bar {
                    // Mask flag bits (lowest 2 for I/O bars)
                    lower &= !0b11;

                    // BAR is not enabled
                    if lower == 0 {
                        bar_id += 1;
                        continue;
                    }

                    // IO BAR
                    region_type = PciBarRegionType::IoRegion;

                    // Invert bits and add 1 to calculate size
                    region_size = (!lower + 1) as u64;
                } else if is_64bit_bar {
                    // 64 bits Memory BAR
                    region_type = PciBarRegionType::Memory64BitRegion;

                    // Query size of upper BAR of 64-bit BAR
                    let upper_offset: u32 = PCI_CONFIG_BAR_OFFSET + (bar_id + 1) * 4;
                    self.vfio_wrapper
                        .write_config_dword(upper_offset, 0xffff_ffff);
                    let upper = self.vfio_wrapper.read_config_dword(upper_offset);

                    let mut combined_size = u64::from(upper) << 32 | u64::from(lower);

                    // Mask out flag bits (lowest 4 for memory bars)
                    combined_size &= !0b1111;

                    // BAR is not enabled
                    if combined_size == 0 {
                        bar_id += 1;
                        continue;
                    }

                    // Invert and add 1 to to find size
                    region_size = !combined_size + 1;
                } else {
                    region_type = PciBarRegionType::Memory32BitRegion;

                    // Mask out flag bits (lowest 4 for memory bars)
                    lower &= !0b1111;

                    if lower == 0 {
                        bar_id += 1;
                        continue;
                    }

                    // Invert and add 1 to to find size
                    region_size = (!lower + 1) as u64;
                }
            }

            let bar_addr = match region_type {
                PciBarRegionType::IoRegion => {
                    #[cfg(not(target_arch = "x86_64"))]
                    unimplemented!();

                    // The address needs to be 4 bytes aligned.
                    #[cfg(target_arch = "x86_64")]
                    allocator
                        .lock()
                        .unwrap()
                        .allocate_io_addresses(restored_bar_addr, region_size, Some(0x4))
                        .ok_or(PciDeviceError::IoAllocationFailed(region_size))?
                }
                PciBarRegionType::Memory32BitRegion => {
                    // BAR allocation must be naturally aligned
                    mmio32_allocator
                        .allocate(restored_bar_addr, region_size, Some(region_size))
                        .ok_or(PciDeviceError::IoAllocationFailed(region_size))?
                }
                PciBarRegionType::Memory64BitRegion => {
                    // We need do some fixup to keep MMIO RW region and msix cap region page size
                    // aligned.
                    region_size = self.fixup_msix_region(bar_id, region_size);
                    mmio64_allocator
                        .allocate(
                            restored_bar_addr,
                            region_size,
                            Some(std::cmp::max(
                                // SAFETY: FFI call. Trivially safe.
                                unsafe { sysconf(_SC_PAGESIZE) as GuestUsize },
                                region_size,
                            )),
                        )
                        .ok_or(PciDeviceError::IoAllocationFailed(region_size))?
                }
            };

            // We can now build our BAR configuration block.
            let bar = PciBarConfiguration::default()
                .set_index(bar_id as usize)
                .set_address(bar_addr.raw_value())
                .set_size(region_size)
                .set_region_type(region_type)
                .set_prefetchable(prefetchable);

            if bar_id == VFIO_PCI_ROM_REGION_INDEX {
                self.configuration
                    .add_pci_rom_bar(&bar, flags & 0x1)
                    .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr.raw_value(), e))?;
            } else {
                self.configuration
                    .add_pci_bar(&bar)
                    .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr.raw_value(), e))?;
            }

            bars.push(bar);
            self.mmio_regions.push(MmioRegion {
                start: bar_addr,
                length: region_size,
                type_: region_type,
                index: bar_id,
                user_memory_regions: Vec::new(),
            });

            bar_id += 1;
            if region_type == PciBarRegionType::Memory64BitRegion {
                bar_id += 1;
            }
        }

        Ok(bars)
    }

    // The `allocator` argument is unused on `aarch64`
    #[allow(unused_variables)]
    pub(crate) fn free_bars(
        &mut self,
        allocator: &mut SystemAllocator,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
    ) -> Result<(), PciDeviceError> {
        for region in self.mmio_regions.iter() {
            match region.type_ {
                PciBarRegionType::IoRegion => {
                    #[cfg(target_arch = "x86_64")]
                    allocator.free_io_addresses(region.start, region.length);
                    #[cfg(not(target_arch = "x86_64"))]
                    error!("I/O region is not supported");
                }
                PciBarRegionType::Memory32BitRegion => {
                    mmio32_allocator.free(region.start, region.length);
                }
                PciBarRegionType::Memory64BitRegion => {
                    mmio64_allocator.free(region.start, region.length);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn parse_msix_capabilities(&mut self, cap: u8) -> MsixCap {
        let msg_ctl = self.vfio_wrapper.read_config_word((cap + 2).into());

        let table = self.vfio_wrapper.read_config_dword((cap + 4).into());

        let pba = self.vfio_wrapper.read_config_dword((cap + 8).into());

        MsixCap {
            msg_ctl,
            table,
            pba,
        }
    }

    pub(crate) fn initialize_msix(
        &mut self,
        msix_cap: MsixCap,
        cap_offset: u32,
        bdf: PciBdf,
        state: Option<MsixConfigState>,
    ) {
        let interrupt_source_group = self
            .msi_interrupt_manager
            .create_group(MsiIrqGroupConfig {
                base: 0,
                count: msix_cap.table_size() as InterruptIndex,
            })
            .unwrap();

        let msix_config = MsixConfig::new(
            msix_cap.table_size(),
            interrupt_source_group.clone(),
            bdf.into(),
            state,
        )
        .unwrap();

        self.interrupt.msix = Some(VfioMsix {
            bar: msix_config,
            cap: msix_cap,
            cap_offset,
            interrupt_source_group,
        });
    }

    pub(crate) fn parse_msi_capabilities(&mut self, cap: u8) -> u16 {
        self.vfio_wrapper.read_config_word((cap + 2).into())
    }

    pub(crate) fn initialize_msi(
        &mut self,
        msg_ctl: u16,
        cap_offset: u32,
        state: Option<MsiConfigState>,
    ) {
        let interrupt_source_group = self
            .msi_interrupt_manager
            .create_group(MsiIrqGroupConfig {
                base: 0,
                count: msi_num_enabled_vectors(msg_ctl) as InterruptIndex,
            })
            .unwrap();

        let msi_config = MsiConfig::new(msg_ctl, interrupt_source_group.clone(), state).unwrap();

        self.interrupt.msi = Some(VfioMsi {
            cfg: msi_config,
            cap_offset,
            interrupt_source_group,
        });
    }

    pub(crate) fn get_msix_cap_idx(&self) -> Option<usize> {
        let mut cap_next = self
            .vfio_wrapper
            .read_config_byte(PCI_CONFIG_CAPABILITY_OFFSET);

        while cap_next != 0 {
            let cap_id = self.vfio_wrapper.read_config_byte(cap_next.into());
            if PciCapabilityId::from(cap_id) == PciCapabilityId::MsiX {
                return Some(cap_next as usize);
            } else {
                cap_next = self.vfio_wrapper.read_config_byte((cap_next + 1).into());
            }
        }

        None
    }

    pub(crate) fn parse_capabilities(&mut self, bdf: PciBdf) {
        let mut cap_iter = self
            .vfio_wrapper
            .read_config_byte(PCI_CONFIG_CAPABILITY_OFFSET);

        let mut pci_express_cap_found = false;
        let mut power_management_cap_found = false;

        while cap_iter != 0 {
            let cap_id = self.vfio_wrapper.read_config_byte(cap_iter.into());

            match PciCapabilityId::from(cap_id) {
                PciCapabilityId::MessageSignalledInterrupts => {
                    if let Some(irq_info) = self.vfio_wrapper.get_irq_info(VFIO_PCI_MSI_IRQ_INDEX) {
                        if irq_info.count > 0 {
                            // Parse capability only if the VFIO device
                            // supports MSI.
                            let msg_ctl = self.parse_msi_capabilities(cap_iter);
                            self.initialize_msi(msg_ctl, cap_iter as u32, None);
                        }
                    }
                }
                PciCapabilityId::MsiX => {
                    if let Some(irq_info) = self.vfio_wrapper.get_irq_info(VFIO_PCI_MSIX_IRQ_INDEX)
                    {
                        if irq_info.count > 0 {
                            // Parse capability only if the VFIO device
                            // supports MSI-X.
                            let msix_cap = self.parse_msix_capabilities(cap_iter);
                            self.initialize_msix(msix_cap, cap_iter as u32, bdf, None);
                        }
                    }
                }
                PciCapabilityId::PciExpress => pci_express_cap_found = true,
                PciCapabilityId::PowerManagement => power_management_cap_found = true,
                _ => {}
            };

            let cap_next = self.vfio_wrapper.read_config_byte((cap_iter + 1).into());
            if cap_next == 0 {
                break;
            }

            cap_iter = cap_next;
        }

        if let Some(clique_id) = self.x_nv_gpudirect_clique {
            self.add_nv_gpudirect_clique_cap(cap_iter, clique_id);
        }

        if pci_express_cap_found && power_management_cap_found {
            self.parse_extended_capabilities();
        }
    }

    fn add_nv_gpudirect_clique_cap(&mut self, cap_iter: u8, clique_id: u8) {
        // Turing, Ampere, Hopper, and Lovelace GPUs have dedicated space
        // at 0xD4 for this capability.
        let cap_offset = 0xd4u32;

        let reg_idx = (cap_iter / 4) as usize;
        self.patches.insert(
            reg_idx,
            ConfigPatch {
                mask: 0x0000_ff00,
                patch: cap_offset << 8,
            },
        );

        let reg_idx = (cap_offset / 4) as usize;
        self.patches.insert(
            reg_idx,
            ConfigPatch {
                mask: 0xffff_ffff,
                patch: 0x50080009u32,
            },
        );
        self.patches.insert(
            reg_idx + 1,
            ConfigPatch {
                mask: 0xffff_ffff,
                patch: u32::from(clique_id) << 19 | 0x5032,
            },
        );
    }

    fn parse_extended_capabilities(&mut self) {
        let mut current_offset = PCI_CONFIG_EXTENDED_CAPABILITY_OFFSET;

        loop {
            let ext_cap_hdr = self.vfio_wrapper.read_config_dword(current_offset);

            let cap_id: u16 = (ext_cap_hdr & 0xffff) as u16;
            let cap_next: u16 = ((ext_cap_hdr >> 20) & 0xfff) as u16;

            match PciExpressCapabilityId::from(cap_id) {
                PciExpressCapabilityId::AlternativeRoutingIdentificationInterpretation
                | PciExpressCapabilityId::ResizeableBar
                | PciExpressCapabilityId::SingleRootIoVirtualization => {
                    let reg_idx = (current_offset / 4) as usize;
                    self.patches.insert(
                        reg_idx,
                        ConfigPatch {
                            mask: 0x0000_ffff,
                            patch: PciExpressCapabilityId::NullCapability as u32,
                        },
                    );
                }
                _ => {}
            }

            if cap_next == 0 {
                break;
            }

            current_offset = cap_next.into();
        }
    }

    pub(crate) fn enable_intx(&mut self) -> Result<(), VfioPciError> {
        if let Some(intx) = &mut self.interrupt.intx {
            if !intx.enabled {
                if let Some(eventfd) = intx.interrupt_source_group.notifier(0) {
                    self.vfio_wrapper
                        .enable_irq(VFIO_PCI_INTX_IRQ_INDEX, vec![&eventfd])
                        .map_err(VfioPciError::EnableIntx)?;

                    intx.enabled = true;
                } else {
                    return Err(VfioPciError::MissingNotifier);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn disable_intx(&mut self) {
        if let Some(intx) = &mut self.interrupt.intx {
            if intx.enabled {
                if let Err(e) = self.vfio_wrapper.disable_irq(VFIO_PCI_INTX_IRQ_INDEX) {
                    error!("Could not disable INTx: {}", e);
                } else {
                    intx.enabled = false;
                }
            }
        }
    }

    pub(crate) fn enable_msi(&self) -> Result<(), VfioPciError> {
        if let Some(msi) = &self.interrupt.msi {
            let mut irq_fds: Vec<EventFd> = Vec::new();
            for i in 0..msi.cfg.num_enabled_vectors() {
                if let Some(eventfd) = msi.interrupt_source_group.notifier(i as InterruptIndex) {
                    irq_fds.push(eventfd);
                } else {
                    return Err(VfioPciError::MissingNotifier);
                }
            }

            self.vfio_wrapper
                .enable_msi(irq_fds.iter().collect())
                .map_err(VfioPciError::EnableMsi)?;
        }

        Ok(())
    }

    pub(crate) fn disable_msi(&self) {
        if let Err(e) = self.vfio_wrapper.disable_msi() {
            error!("Could not disable MSI: {}", e);
        }
    }

    pub(crate) fn enable_msix(&self) -> Result<(), VfioPciError> {
        if let Some(msix) = &self.interrupt.msix {
            let mut irq_fds: Vec<EventFd> = Vec::new();
            for i in 0..msix.bar.table_entries.len() {
                if let Some(eventfd) = msix.interrupt_source_group.notifier(i as InterruptIndex) {
                    irq_fds.push(eventfd);
                } else {
                    return Err(VfioPciError::MissingNotifier);
                }
            }

            self.vfio_wrapper
                .enable_msix(irq_fds.iter().collect())
                .map_err(VfioPciError::EnableMsix)?;
        }

        Ok(())
    }

    pub(crate) fn disable_msix(&self) {
        if let Err(e) = self.vfio_wrapper.disable_msix() {
            error!("Could not disable MSI-X: {}", e);
        }
    }

    pub(crate) fn initialize_legacy_interrupt(&mut self) -> Result<(), VfioPciError> {
        if let Some(irq_info) = self.vfio_wrapper.get_irq_info(VFIO_PCI_INTX_IRQ_INDEX) {
            if irq_info.count == 0 {
                // A count of 0 means the INTx IRQ is not supported, therefore
                // it shouldn't be initialized.
                return Ok(());
            }
        }

        if let Some(interrupt_source_group) = self.legacy_interrupt_group.clone() {
            self.interrupt.intx = Some(VfioIntx {
                interrupt_source_group,
                enabled: false,
            });

            self.enable_intx()?;
        }

        Ok(())
    }

    pub(crate) fn update_msi_capabilities(
        &mut self,
        offset: u64,
        data: &[u8],
    ) -> Result<(), VfioPciError> {
        match self.interrupt.update_msi(offset, data) {
            Some(InterruptUpdateAction::EnableMsi) => {
                // Disable INTx before we can enable MSI
                self.disable_intx();
                self.enable_msi()?;
            }
            Some(InterruptUpdateAction::DisableMsi) => {
                // Fallback onto INTx when disabling MSI
                self.disable_msi();
                self.enable_intx()?;
            }
            _ => {}
        }

        Ok(())
    }

    pub(crate) fn update_msix_capabilities(
        &mut self,
        offset: u64,
        data: &[u8],
    ) -> Result<(), VfioPciError> {
        match self.interrupt.update_msix(offset, data) {
            Some(InterruptUpdateAction::EnableMsix) => {
                // Disable INTx before we can enable MSI-X
                self.disable_intx();
                self.enable_msix()?;
            }
            Some(InterruptUpdateAction::DisableMsix) => {
                // Fallback onto INTx when disabling MSI-X
                self.disable_msix();
                self.enable_intx()?;
            }
            _ => {}
        }

        Ok(())
    }

    pub(crate) fn find_region(&self, addr: u64) -> Option<MmioRegion> {
        for region in self.mmio_regions.iter() {
            if addr >= region.start.raw_value()
                && addr < region.start.unchecked_add(region.length).raw_value()
            {
                return Some(region.clone());
            }
        }
        None
    }

    fn make_user_memory_region(
        slot: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        readonly: bool,
        log_dirty_pages: bool,
    ) -> MemoryRegion {
        use kvm_bindings::{KVM_MEM_LOG_DIRTY_PAGES, KVM_MEM_READONLY};
        MemoryRegion {
            slot,
            guest_phys_addr,
            memory_size,
            userspace_addr,
            flags: if readonly { KVM_MEM_READONLY } else { 0 }
                | if log_dirty_pages {
                    KVM_MEM_LOG_DIRTY_PAGES
                } else {
                    0
                },
        }
    }

    pub(crate) fn read_bar(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        let addr = base + offset;
        if let Some(region) = self.find_region(addr) {
            let offset = addr - region.start.raw_value();

            if self.interrupt.msix_table_accessed(region.index, offset) {
                self.interrupt.msix_read_table(offset, data);
            } else {
                self.vfio_wrapper.region_read(region.index, offset, data);
            }
        }

        // INTx EOI
        // The guest reading from the BAR potentially means the interrupt has
        // been received and can be acknowledged.
        if self.interrupt.intx_in_use() {
            if let Err(e) = self.vfio_wrapper.unmask_irq(VFIO_PCI_INTX_IRQ_INDEX) {
                error!("Failed unmasking INTx IRQ: {}", e);
            }
        }
    }

    pub(crate) fn write_bar(
        &mut self,
        base: u64,
        offset: u64,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        let addr = base + offset;
        if let Some(region) = self.find_region(addr) {
            let offset = addr - region.start.raw_value();

            // If the MSI-X table is written to, we need to update our cache.
            if self.interrupt.msix_table_accessed(region.index, offset) {
                self.interrupt.msix_write_table(offset, data);
            } else {
                self.vfio_wrapper.region_write(region.index, offset, data);
            }
        }

        // INTx EOI
        // The guest writing to the BAR potentially means the interrupt has
        // been received and can be acknowledged.
        if self.interrupt.intx_in_use() {
            if let Err(e) = self.vfio_wrapper.unmask_irq(VFIO_PCI_INTX_IRQ_INDEX) {
                error!("Failed unmasking INTx IRQ: {}", e);
            }
        }

        None
    }

    pub(crate) fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        // When the guest wants to write to a BAR, we trap it into
        // our local configuration space. We're not reprogramming
        // VFIO device.
        if (PCI_CONFIG_BAR0_INDEX..PCI_CONFIG_BAR0_INDEX + BAR_NUMS).contains(&reg_idx)
            || reg_idx == PCI_ROM_EXP_BAR_INDEX
        {
            // We keep our local cache updated with the BARs.
            // We'll read it back from there when the guest is asking
            // for BARs (see read_config_register()).
            self.configuration
                .write_config_register(reg_idx, offset, data);
            return None;
        }

        let reg = (reg_idx * PCI_CONFIG_REGISTER_SIZE) as u64;

        // If the MSI or MSI-X capabilities are accessed, we need to
        // update our local cache accordingly.
        // Depending on how the capabilities are modified, this could
        // trigger a VFIO MSI or MSI-X toggle.
        if let Some((cap_id, cap_base)) = self.interrupt.accessed(reg) {
            let cap_offset: u64 = reg - cap_base + offset;
            match cap_id {
                PciCapabilityId::MessageSignalledInterrupts => {
                    if let Err(e) = self.update_msi_capabilities(cap_offset, data) {
                        error!("Could not update MSI capabilities: {}", e);
                    }
                }
                PciCapabilityId::MsiX => {
                    if let Err(e) = self.update_msix_capabilities(cap_offset, data) {
                        error!("Could not update MSI-X capabilities: {}", e);
                    }
                }
                _ => {}
            }
        }

        // Make sure to write to the device's PCI config space after MSI/MSI-X
        // interrupts have been enabled/disabled. In case of MSI, when the
        // interrupts are enabled through VFIO (using VFIO_DEVICE_SET_IRQS),
        // the MSI Enable bit in the MSI capability structure found in the PCI
        // config space is disabled by default. That's why when the guest is
        // enabling this bit, we first need to enable the MSI interrupts with
        // VFIO through VFIO_DEVICE_SET_IRQS ioctl, and only after we can write
        // to the device region to update the MSI Enable bit.
        self.vfio_wrapper.write_config((reg + offset) as u32, data);

        None
    }

    pub(crate) fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        // When reading the BARs, we trap it and return what comes
        // from our local configuration space. We want the guest to
        // use that and not the VFIO device BARs as it does not map
        // with the guest address space.
        if (PCI_CONFIG_BAR0_INDEX..PCI_CONFIG_BAR0_INDEX + BAR_NUMS).contains(&reg_idx)
            || reg_idx == PCI_ROM_EXP_BAR_INDEX
        {
            return self.configuration.read_reg(reg_idx);
        }

        if let Some(id) = self.get_msix_cap_idx() {
            let msix = self.interrupt.msix.as_mut().unwrap();
            if reg_idx * 4 == id + 4 {
                return msix.cap.table;
            } else if reg_idx * 4 == id + 8 {
                return msix.cap.pba;
            }
        }

        // Since we don't support passing multi-functions devices, we should
        // mask the multi-function bit, bit 7 of the Header Type byte on the
        // register 3.
        let mask = if reg_idx == PCI_HEADER_TYPE_REG_INDEX {
            0xff7f_ffff
        } else {
            0xffff_ffff
        };

        // The config register read comes from the VFIO device itself.
        let mut value = self.vfio_wrapper.read_config_dword((reg_idx * 4) as u32) & mask;

        if let Some(config_patch) = self.patches.get(&reg_idx) {
            value = (value & !config_patch.mask) | config_patch.patch;
        }

        value
    }

    fn state(&self) -> VfioCommonState {
        let intx_state = self.interrupt.intx.as_ref().map(|intx| IntxState {
            enabled: intx.enabled,
        });

        let msi_state = self.interrupt.msi.as_ref().map(|msi| MsiState {
            cap: msi.cfg.cap,
            cap_offset: msi.cap_offset,
        });

        let msix_state = self.interrupt.msix.as_ref().map(|msix| MsixState {
            cap: msix.cap,
            cap_offset: msix.cap_offset,
            bdf: msix.bar.devid,
        });

        VfioCommonState {
            intx_state,
            msi_state,
            msix_state,
        }
    }

    fn set_state(
        &mut self,
        state: &VfioCommonState,
        msi_state: Option<MsiConfigState>,
        msix_state: Option<MsixConfigState>,
    ) -> Result<(), VfioPciError> {
        if let (Some(intx), Some(interrupt_source_group)) =
            (&state.intx_state, self.legacy_interrupt_group.clone())
        {
            self.interrupt.intx = Some(VfioIntx {
                interrupt_source_group,
                enabled: false,
            });

            if intx.enabled {
                self.enable_intx()?;
            }
        }

        if let Some(msi) = &state.msi_state {
            self.initialize_msi(msi.cap.msg_ctl, msi.cap_offset, msi_state);
        }

        if let Some(msix) = &state.msix_state {
            self.initialize_msix(msix.cap, msix.cap_offset, msix.bdf.into(), msix_state);
        }

        Ok(())
    }
}

/// VfioPciDevice represents a VFIO PCI device.
/// This structure implements the BusDevice and PciDevice traits.
///
/// A VfioPciDevice is bound to a VfioDevice and is also a PCI device.
/// The VMM creates a VfioDevice, then assigns it to a VfioPciDevice,
/// which then gets added to the PCI bus.
pub struct VfioPciDevice {
    id: String,
    vm: Arc<Mutex<VmFd>>,
    device: Arc<VfioDevice>,
    container: Arc<VfioContainer>,
    common: VfioCommon,
    iommu_attached: bool,
    memory_slot: Arc<dyn Fn() -> u32 + Send + Sync>,
}

impl Debug for VfioPciDevice {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("VfioPciDevice")
            .finish()
    }
}

impl VfioPciDevice {
    /// Constructs a new Vfio Pci device for the given Vfio device
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        vm: Arc<Mutex<VmFd>>,
        device: VfioDevice,
        container: Arc<VfioContainer>,
        msi_interrupt_manager: Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        legacy_interrupt_group: Option<Arc<dyn InterruptSourceGroup>>,
        iommu_attached: bool,
        bdf: PciBdf,
        memory_slot: Arc<dyn Fn() -> u32 + Send + Sync>,
        x_nv_gpudirect_clique: Option<u8>,
    ) -> Result<Self, VfioPciError> {
        let device = Arc::new(device);
        device.reset();

        let vfio_wrapper = VfioDeviceWrapper::new(Arc::clone(&device));

        let common = VfioCommon::new(
            msi_interrupt_manager,
            legacy_interrupt_group,
            Arc::new(vfio_wrapper) as Arc<dyn Vfio>,
            &PciVfioSubclass::VfioSubclass,
            bdf,
            x_nv_gpudirect_clique,
        )?;

        let vfio_pci_device = VfioPciDevice {
            id,
            vm: vm.clone(),
            device,
            container,
            common,
            iommu_attached,
            memory_slot,
        };

        Ok(vfio_pci_device)
    }

    pub fn iommu_attached(&self) -> bool {
        self.iommu_attached
    }

    fn generate_sparse_areas(
        caps: &[VfioRegionInfoCap],
        region_index: u32,
        region_start: u64,
        region_size: u64,
        vfio_msix: Option<&VfioMsix>,
    ) -> Result<Vec<VfioRegionSparseMmapArea>, VfioPciError> {
        for cap in caps {
            match cap {
                VfioRegionInfoCap::SparseMmap(sparse_mmap) => return Ok(sparse_mmap.areas.clone()),
                VfioRegionInfoCap::MsixMappable => {
                    if !is_4k_aligned(region_start) {
                        error!(
                            "Region start address 0x{:x} must be at least aligned on 4KiB",
                            region_start
                        );
                        return Err(VfioPciError::RegionAlignment);
                    }
                    if !is_4k_multiple(region_size) {
                        error!(
                            "Region size 0x{:x} must be at least a multiple of 4KiB",
                            region_size
                        );
                        return Err(VfioPciError::RegionSize);
                    }

                    // In case the region contains the MSI-X vectors table or
                    // the MSI-X PBA table, we must calculate the subregions
                    // around them, leading to a list of sparse areas.
                    // We want to make sure we will still trap MMIO accesses
                    // to these MSI-X specific ranges. If these region don't align
                    // with pagesize, we can achieve it by enlarging its range.
                    //
                    // Using a BtreeMap as the list provided through the iterator is sorted
                    // by key. This ensures proper split of the whole region.
                    let mut inter_ranges = BTreeMap::new();
                    if let Some(msix) = vfio_msix {
                        if region_index == msix.cap.table_bir() {
                            let (offset, size) = msix.cap.table_range();
                            let offset = align_page_size_down(offset);
                            let size = align_page_size_up(size);
                            inter_ranges.insert(offset, size);
                        }
                        if region_index == msix.cap.pba_bir() {
                            let (offset, size) = msix.cap.pba_range();
                            let offset = align_page_size_down(offset);
                            let size = align_page_size_up(size);
                            inter_ranges.insert(offset, size);
                        }
                    }

                    let mut sparse_areas = Vec::new();
                    let mut current_offset = 0;
                    for (range_offset, range_size) in inter_ranges {
                        if range_offset > current_offset {
                            sparse_areas.push(VfioRegionSparseMmapArea {
                                offset: current_offset,
                                size: range_offset - current_offset,
                            });
                        }
                        current_offset = align_page_size_down(range_offset + range_size);
                    }

                    if region_size > current_offset {
                        sparse_areas.push(VfioRegionSparseMmapArea {
                            offset: current_offset,
                            size: region_size - current_offset,
                        });
                    }

                    return Ok(sparse_areas);
                }
                _ => {}
            }
        }

        // In case no relevant capabilities have been found, create a single
        // sparse area corresponding to the entire MMIO region.
        Ok(vec![VfioRegionSparseMmapArea {
            offset: 0,
            size: region_size,
        }])
    }

    /// Map MMIO regions into the guest, and avoid VM exits when the guest tries
    /// to reach those regions.
    ///
    /// # Arguments
    ///
    /// * `vm` - The VM object. It is used to set the VFIO MMIO regions
    ///          as user memory regions.
    /// * `mem_slot` - The closure to return a memory slot.
    pub fn map_mmio_regions(&mut self) -> Result<(), VfioPciError> {
        let fd = self.device.as_raw_fd();


        for region in self.common.mmio_regions.iter_mut() {
            let region_flags = self.device.get_region_flags(region.index);
            if region_flags & VFIO_REGION_INFO_FLAG_MMAP != 0 {
                let mut prot = 0;
                if region_flags & VFIO_REGION_INFO_FLAG_READ != 0 {
                    prot |= libc::PROT_READ;
                }
                if region_flags & VFIO_REGION_INFO_FLAG_WRITE != 0 {
                    prot |= libc::PROT_WRITE;
                }

                // Retrieve the list of capabilities found on the region
                let caps = if region_flags & VFIO_REGION_INFO_FLAG_CAPS != 0 {
                    self.device.get_region_caps(region.index)
                } else {
                    Vec::new()
                };

                // Don't try to mmap the region if it contains MSI-X table or
                // MSI-X PBA subregion, and if we couldn't find MSIX_MAPPABLE
                // in the list of supported capabilities.
                if let Some(msix) = self.common.interrupt.msix.as_ref() {
                    if (region.index == msix.cap.table_bir() || region.index == msix.cap.pba_bir())
                        && !caps.contains(&VfioRegionInfoCap::MsixMappable)
                    {
                        continue;
                    }
                }

                let mmap_size = self.device.get_region_size(region.index);
                let mmap_offset = self.device.get_region_offset(region.index);

                let sparse_areas = Self::generate_sparse_areas(
                    &caps,
                    region.index,
                    region.start.0,
                    mmap_size,
                    self.common.interrupt.msix.as_ref(),
                )?;

                for area in sparse_areas.iter() {
                    // SAFETY: FFI call with correct arguments
                    let host_addr = unsafe {
                        libc::mmap(
                            null_mut(),
                            area.size as usize,
                            prot,
                            libc::MAP_SHARED,
                            fd,
                            mmap_offset as libc::off_t + area.offset as libc::off_t,
                        )
                    };

                    if host_addr == libc::MAP_FAILED {
                        error!(
                            "Could not mmap sparse area (offset = 0x{:x}, size = 0x{:x}): {}",
                            area.offset,
                            area.size,
                            std::io::Error::last_os_error()
                        );
                        return Err(VfioPciError::MmapArea);
                    }

                    if !is_page_size_aligned(area.size) || !is_page_size_aligned(area.offset) {
                        warn!(
                            "Could not mmap sparse area that is not page size aligned (offset = 0x{:x}, size = 0x{:x})",
                            area.offset,
                            area.size,
                            );
                        return Ok(());
                    }

                    let user_memory_region = UserMemoryRegion {
                        slot: (self.memory_slot)(),
                        start: region.start.0 + area.offset,
                        size: area.size,
                        host_addr: host_addr as u64,
                    };

                    region.user_memory_regions.push(user_memory_region);

                    let mem_region = VfioCommon::make_user_memory_region(
                        user_memory_region.slot,
                        user_memory_region.start,
                        user_memory_region.size,
                        user_memory_region.host_addr,
                        false,
                        false,
                    );

                    unsafe {
                        self.vm.lock().expect("Poisoned lock")
                            .set_user_memory_region(mem_region)
                            .map_err(|e| VfioPciError::MapRegionGuest(e.into()))?;
                    }

                    if !self.iommu_attached {
                        self.container
                            .vfio_dma_map(
                                user_memory_region.start,
                                user_memory_region.size,
                                user_memory_region.host_addr,
                            )
                            .map_err(VfioPciError::DmaMap)?;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn unmap_mmio_regions(&mut self) {
        for region in self.common.mmio_regions.iter() {
            for user_memory_region in region.user_memory_regions.iter() {
                // Unmap from vfio container
                if !self.iommu_attached {
                    if let Err(e) = self
                        .container
                        .vfio_dma_unmap(user_memory_region.start, user_memory_region.size)
                    {
                        error!("Could not unmap mmio region from vfio container: {}", e);
                    }
                }

                // Remove region
                let r = VfioCommon::make_user_memory_region(
                    user_memory_region.slot,
                    user_memory_region.start,
                    user_memory_region.size,
                    user_memory_region.host_addr,
                    false,
                    false,
                );

                if let Err(e) = unsafe { self.vm.lock().expect("Poisoned lock").set_user_memory_region(r) } {
                    error!("Could not remove the userspace memory region: {}", e);
                }

                // SAFETY: FFI call with correct arguments
                let ret = unsafe {
                    libc::munmap(
                        user_memory_region.host_addr as *mut libc::c_void,
                        user_memory_region.size as usize,
                    )
                };
                if ret != 0 {
                    error!(
                        "Could not unmap region {}, error:{}",
                        region.index,
                        io::Error::last_os_error()
                    );
                }
            }
        }
    }

    pub fn dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<(), VfioPciError> {
        if !self.iommu_attached {
            self.container
                .vfio_dma_map(iova, size, user_addr)
                .map_err(VfioPciError::DmaMap)?;
        }

        Ok(())
    }

    pub fn dma_unmap(&self, iova: u64, size: u64) -> Result<(), VfioPciError> {
        if !self.iommu_attached {
            self.container
                .vfio_dma_unmap(iova, size)
                .map_err(VfioPciError::DmaUnmap)?;
        }

        Ok(())
    }

    pub fn mmio_regions(&self) -> Vec<MmioRegion> {
        self.common.mmio_regions.clone()
    }
}

impl Drop for VfioPciDevice {
    fn drop(&mut self) {
        self.unmap_mmio_regions();

        if let Some(msix) = &self.common.interrupt.msix {
            if msix.bar.enabled() {
                self.common.disable_msix();
            }
        }

        if let Some(msi) = &self.common.interrupt.msi {
            if msi.cfg.enabled() {
                self.common.disable_msi()
            }
        }

        if self.common.interrupt.intx_in_use() {
            self.common.disable_intx();
        }
    }
}

impl VfioPciDevice {
    pub fn bus_read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(base, offset, data)
    }

    pub fn bus_write(&mut self, base: u64, offset: u64, data: &[u8]) {
        self.write_bar(base, offset, data);
        ()
    }
}

// First BAR offset in the PCI config space.
const PCI_CONFIG_BAR_OFFSET: u32 = 0x10;
// Capability register offset in the PCI config space.
const PCI_CONFIG_CAPABILITY_OFFSET: u32 = 0x34;
// Extended capabilities register offset in the PCI config space.
const PCI_CONFIG_EXTENDED_CAPABILITY_OFFSET: u32 = 0x100;
// IO BAR when first BAR bit is 1.
const PCI_CONFIG_IO_BAR: u32 = 0x1;
// 64-bit memory bar flag.
const PCI_CONFIG_MEMORY_BAR_64BIT: u32 = 0x4;
// Prefetchable BAR bit
const PCI_CONFIG_BAR_PREFETCHABLE: u32 = 0x8;
// PCI config register size (4 bytes).
const PCI_CONFIG_REGISTER_SIZE: usize = 4;
// Number of BARs for a PCI device
const BAR_NUMS: usize = 6;
// PCI Header Type register index
const PCI_HEADER_TYPE_REG_INDEX: usize = 3;
// First BAR register index
const PCI_CONFIG_BAR0_INDEX: usize = 4;
// PCI ROM expansion BAR register index
const PCI_ROM_EXP_BAR_INDEX: usize = 12;

impl PciDevice for VfioPciDevice {
    fn allocate_bars(
        &mut self,
        allocator: &Arc<Mutex<SystemAllocator>>,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
        resources: Option<Vec<Resource>>,
    ) -> Result<Vec<PciBarConfiguration>, PciDeviceError> {
        self.common
            .allocate_bars(allocator, mmio32_allocator, mmio64_allocator, resources)
    }

    fn free_bars(
        &mut self,
        allocator: &mut SystemAllocator,
        mmio32_allocator: &mut AddressAllocator,
        mmio64_allocator: &mut AddressAllocator,
    ) -> Result<(), PciDeviceError> {
        self.common
            .free_bars(allocator, mmio32_allocator, mmio64_allocator)
    }

    fn write_config_register(
        &mut self,
        reg_idx: usize,
        offset: u64,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        self.common.write_config_register(reg_idx, offset, data)
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        self.common.read_config_register(reg_idx)
    }

    fn detect_bar_reprogramming(
        &mut self,
        reg_idx: usize,
        data: &[u8],
    ) -> Option<BarReprogrammingParams> {
        self.common
            .configuration
            .detect_bar_reprogramming(reg_idx, data)
    }

    fn read_bar(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.common.read_bar(base, offset, data)
    }

    fn write_bar(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.common.write_bar(base, offset, data)
    }

    fn move_bar(&mut self, old_base: u64, new_base: u64) -> Result<(), io::Error> {
        for region in self.common.mmio_regions.iter_mut() {
            if region.start.raw_value() == old_base {
                region.start = GuestAddress(new_base);

                for user_memory_region in region.user_memory_regions.iter_mut() {
                    // Remove old region
                    let old_mem_region = VfioCommon::make_user_memory_region(
                        user_memory_region.slot,
                        user_memory_region.start,
                        user_memory_region.size,
                        user_memory_region.host_addr,
                        false,
                        false,
                    );

                    unsafe { self.vm.lock().expect("Poisoned lock").set_user_memory_region(old_mem_region) }
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                    // Update the user memory region with the correct start address.
                    if new_base > old_base {
                        user_memory_region.start += new_base - old_base;
                    } else {
                        user_memory_region.start -= old_base - new_base;
                    }

                    // Insert new region
                    let new_mem_region = VfioCommon::make_user_memory_region(
                        user_memory_region.slot,
                        user_memory_region.start,
                        user_memory_region.size,
                        user_memory_region.host_addr,
                        false,
                        false,
                    );

                    unsafe { self.vm.lock().expect("Poisoned lock").set_user_memory_region(new_mem_region) }
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
            }
        }

        Ok(())
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        Some(self.id.clone())
    }
}

/// This structure implements the ExternalDmaMapping trait. It is meant to
/// be used when the caller tries to provide a way to update the mappings
/// associated with a specific VFIO container.
pub struct VfioDmaMapping<M: GuestAddressSpace> {
    container: Arc<VfioContainer>,
    memory: Arc<M>,
    mmio_regions: Arc<Mutex<Vec<MmioRegion>>>,
}

impl<M: GuestAddressSpace> VfioDmaMapping<M> {
    /// Create a DmaMapping object.
    /// # Parameters
    /// * `container`: VFIO container object.
    /// * `memory`: guest memory to mmap.
    /// * `mmio_regions`: mmio_regions to mmap.
    pub fn new(
        container: Arc<VfioContainer>,
        memory: Arc<M>,
        mmio_regions: Arc<Mutex<Vec<MmioRegion>>>,
    ) -> Self {
        VfioDmaMapping {
            container,
            memory,
            mmio_regions,
        }
    }
}

impl<M: GuestAddressSpace + Sync + Send> ExternalDmaMapping for VfioDmaMapping<M> {
    fn map(&self, iova: u64, gpa: u64, size: u64) -> std::result::Result<(), io::Error> {
        let mem = self.memory.memory();
        let guest_addr = GuestAddress(gpa);
        let user_addr = if mem.check_range(guest_addr, size as usize) {
            match mem.get_host_address(guest_addr) {
                Ok(t) => t as u64,
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("unable to retrieve user address for gpa 0x{gpa:x} from guest memory region: {e}")
                    ));
                }
            }
        } else if self.mmio_regions.lock().unwrap().check_range(gpa, size) {
            self.mmio_regions.lock().unwrap().find_user_address(gpa)?
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("failed to locate guest address 0x{gpa:x} in guest memory"),
            ));
        };

        self.container
            .vfio_dma_map(iova, size, user_addr)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "failed to map memory for VFIO container, \
                         iova 0x{iova:x}, gpa 0x{gpa:x}, size 0x{size:x}: {e:?}"
                    ),
                )
            })
    }

    fn unmap(&self, iova: u64, size: u64) -> std::result::Result<(), io::Error> {
        self.container.vfio_dma_unmap(iova, size).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "failed to unmap memory for VFIO container, \
                     iova 0x{iova:x}, size 0x{size:x}: {e:?}"
                ),
            )
        })
    }
}
