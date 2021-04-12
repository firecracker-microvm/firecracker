// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use crate::{
    msi_num_enabled_vectors, BarReprogrammingParams, MsiConfig, MsixCap, MsixConfig,
    PciBarConfiguration, PciBarRegionType, PciCapabilityId, PciClassCode, PciConfiguration,
    PciDevice, PciDeviceError, PciHeaderType, PciSubclass, MSIX_TABLE_ENTRY_SIZE,
};

use byteorder::{ByteOrder, LittleEndian};
use kvm_ioctls::VmFd;
use std::any::Any;
use std::fmt::{Debug, Formatter};
use std::os::unix::io::AsRawFd;
use std::ptr::null_mut;
use std::sync::{Arc, Barrier, Mutex};
use std::{fmt, io, result};
use vfio_bindings::bindings::vfio::*;
use vfio_ioctls::{VfioContainer, VfioDevice, VfioError};

use vm_device::interrupt::{
    InterruptIndex, InterruptManager, InterruptSourceGroup,
    MsiIrqGroupConfig
};

use vm_memory::{Address, GuestAddress, GuestUsize};
use vmm_sys_util::eventfd::EventFd;
use vm_system_allocator::SystemAllocator;

pub use kvm_bindings::kvm_userspace_memory_region as MemoryRegion;

use log::error;

#[derive(Debug)]
pub enum VfioPciError {
    AllocateGsi,
    DmaMap(VfioError),
    DmaUnmap(VfioError),
    EnableIntx(VfioError),
    EnableMsi(VfioError),
    EnableMsix(VfioError),
    EventFd(io::Error),
    InterruptSourceGroupCreate(io::Error),
    // IrqFd(hypervisor::HypervisorVmError),
    MapRegionGuest(anyhow::Error),
    MissingNotifier,
    MsiNotConfigured,
    MsixNotConfigured,
    NewVfioPciDevice,
}
pub type Result<T> = std::result::Result<T, VfioPciError>;

impl fmt::Display for VfioPciError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VfioPciError::AllocateGsi => write!(f, "failed to allocate GSI"),
            VfioPciError::DmaMap(e) => write!(f, "failed to DMA map: {}", e),
            VfioPciError::DmaUnmap(e) => write!(f, "failed to DMA unmap: {}", e),
            VfioPciError::EnableIntx(e) => write!(f, "failed to enable INTx: {}", e),
            VfioPciError::EnableMsi(e) => write!(f, "failed to enable MSI: {}", e),
            VfioPciError::EnableMsix(e) => write!(f, "failed to enable MSI-X: {}", e),
            VfioPciError::EventFd(e) => write!(f, "failed to create eventfd: {}", e),
            VfioPciError::InterruptSourceGroupCreate(e) => {
                write!(f, "failed to create interrupt source group: {}", e)
            }
            VfioPciError::MapRegionGuest(e) => {
                write!(f, "failed to map VFIO PCI region into guest: {}", e)
            }
            VfioPciError::MissingNotifier => write!(f, "failed to notifier's eventfd"),
            VfioPciError::MsiNotConfigured => write!(f, "MSI interrupt not yet configured"),
            VfioPciError::MsixNotConfigured => write!(f, "MSI-X interrupt not yet configured"),
            VfioPciError::NewVfioPciDevice => write!(f, "failed to create VFIO PCI device"),
        }
    }
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

struct VfioIntx {
    interrupt_source_group: Arc<Box<dyn InterruptSourceGroup>>,
    enabled: bool,
}

struct VfioMsi {
    cfg: MsiConfig,
    cap_offset: u32,
    interrupt_source_group: Arc<Box<dyn InterruptSourceGroup>>,
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

struct VfioMsix {
    bar: MsixConfig,
    cap: MsixCap,
    cap_offset: u32,
    interrupt_source_group: Arc<Box<dyn InterruptSourceGroup>>,
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

struct Interrupt {
    intx: Option<VfioIntx>,
    msi: Option<VfioMsi>,
    msix: Option<VfioMsix>,
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

    fn intx_in_use(&self) -> bool {
        if let Some(intx) = &self.intx {
            return intx.enabled;
        }

        false
    }
}


#[derive(Copy, Clone)]
pub struct MmioRegion {
    pub start: GuestAddress,
    pub length: GuestUsize,
    type_: PciBarRegionType,
    index: u32,
    mem_slot: Option<u32>,
    pub host_addr: Option<u64>,
    mmap_size: Option<usize>,
}

struct VfioPciConfig {
    device: Arc<VfioDevice>,
}

impl VfioPciConfig {
    fn new(device: Arc<VfioDevice>) -> Self {
        VfioPciConfig { device }
    }

    fn read_config_byte(&self, offset: u32) -> u8 {
        let mut data: [u8; 1] = [0];
        self.device
            .region_read(VFIO_PCI_CONFIG_REGION_INDEX, data.as_mut(), offset.into());

        data[0]
    }

    fn read_config_word(&self, offset: u32) -> u16 {
        let mut data: [u8; 2] = [0, 0];
        self.device
            .region_read(VFIO_PCI_CONFIG_REGION_INDEX, data.as_mut(), offset.into());

        u16::from_le_bytes(data)
    }

    fn read_config_dword(&self, offset: u32) -> u32 {
        let mut data: [u8; 4] = [0, 0, 0, 0];
        self.device
            .region_read(VFIO_PCI_CONFIG_REGION_INDEX, data.as_mut(), offset.into());

        u32::from_le_bytes(data)
    }

    fn write_config_dword(&self, buf: u32, offset: u32) {
        let data: [u8; 4] = buf.to_le_bytes();
        self.device
            .region_write(VFIO_PCI_CONFIG_REGION_INDEX, &data, offset.into())
    }
}

/// VfioPciDevice represents a VFIO PCI device.
/// This structure implements the BusDevice and PciDevice traits.
///
/// A VfioPciDevice is bound to a VfioDevice and is also a PCI device.
/// The VMM creates a VfioDevice, then assigns it to a VfioPciDevice,
/// which then gets added to the PCI bus.
pub struct VfioPciDevice {
    vm: Arc<Mutex<VmFd>>,
    device: Arc<VfioDevice>,
    container: Arc<VfioContainer>,
    vfio_pci_configuration: VfioPciConfig,
    configuration: PciConfiguration,
    mmio_regions: Vec<MmioRegion>,
    interrupt: Interrupt,
    iommu_attached: bool,
}

impl Debug for VfioPciDevice {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("VfioPciDevice")
            .finish()
    }
}

impl VfioPciDevice {
    /// Constructs a new Vfio Pci device for the given Vfio device
    pub fn new(
        vm: Arc<Mutex<VmFd>>,
        device: VfioDevice,
        container: Arc<VfioContainer>,
        msi_interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
        legacy_interrupt_group: Option<Arc<Box<dyn InterruptSourceGroup>>>,
        iommu_attached: bool,
    ) -> Result<Self> {
        let device = Arc::new(device);
        device.reset();

        let configuration = PciConfiguration::new(
            0,
            0,
            0,
            PciClassCode::Other,
            &PciVfioSubclass::VfioSubclass,
            None,
            PciHeaderType::Device,
            0,
            0,
            None,
        );

        let vfio_pci_configuration = VfioPciConfig::new(Arc::clone(&device));

        let mut vfio_pci_device = VfioPciDevice {
            vm: Arc::clone(&vm),
            device,
            container,
            configuration,
            vfio_pci_configuration,
            mmio_regions: Vec::new(),
            interrupt: Interrupt {
                intx: None,
                msi: None,
                msix: None,
            },
            iommu_attached,
        };

        vfio_pci_device.parse_capabilities(msi_interrupt_manager);
        
        vfio_pci_device.initialize_legacy_interrupt(legacy_interrupt_group)?;

        Ok(vfio_pci_device)
    }

    fn enable_intx(&mut self) -> Result<()> {
        if let Some(intx) = &mut self.interrupt.intx {
            if !intx.enabled {
                if let Some(eventfd) = intx.interrupt_source_group.notifier(0) {
                    self.device
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

    fn disable_intx(&mut self) {
        if let Some(intx) = &mut self.interrupt.intx {
            if intx.enabled {
                if let Err(e) = self.device.disable_irq(VFIO_PCI_INTX_IRQ_INDEX) {
                    error!("Could not disable INTx: {}", e);
                } else {
                    intx.enabled = false;
                }
            }
        }
    }

    fn enable_msi(&self) -> Result<()> {
        if let Some(msi) = &self.interrupt.msi {
            let mut irq_fds: Vec<EventFd> = Vec::new();
            for i in 0..msi.cfg.num_enabled_vectors() {
                if let Some(eventfd) = msi.interrupt_source_group.notifier(i as InterruptIndex) {
                    irq_fds.push(eventfd);
                } else {
                    return Err(VfioPciError::MissingNotifier);
                }
            }

            self.device
                .enable_msi(irq_fds.iter().collect())
                .map_err(VfioPciError::EnableMsi)?;
        }

        Ok(())
    }

    fn disable_msi(&self) {
        if let Err(e) = self.device.disable_msi() {
            error!("Could not disable MSI: {}", e);
        }
    }

    fn enable_msix(&self) -> Result<()> {
        if let Some(msix) = &self.interrupt.msix {
            let mut irq_fds: Vec<EventFd> = Vec::new();
            for i in 0..msix.bar.table_entries.len() {
                if let Some(eventfd) = msix.interrupt_source_group.notifier(i as InterruptIndex) {
                    irq_fds.push(eventfd);
                } else {
                    return Err(VfioPciError::MissingNotifier);
                }
            }

            self.device
                .enable_msix(irq_fds.iter().collect())
                .map_err(VfioPciError::EnableMsix)?;
        }

        Ok(())
    }

    fn disable_msix(&self) {
        if let Err(e) = self.device.disable_msix() {
            error!("Could not disable MSI-X: {}", e);
        }
    }

    fn initialize_legacy_interrupt(
        &mut self,
        legacy_interrupt_group: Option<Arc<Box<dyn InterruptSourceGroup>>>,
    ) -> Result<()> {
        if let Some(irq_info) = self.device.get_irq_info(VFIO_PCI_INTX_IRQ_INDEX) {
            if irq_info.count == 0 {
                error!("Device does not want legacy IRQ");
                // A count of 0 means the INTx IRQ is not supported, therefore
                // it shouldn't be initialized.
                return Ok(());
            }
        }
        if let Some(interrupt_source_group) = legacy_interrupt_group {
            self.interrupt.intx = Some(
                VfioIntx {
                interrupt_source_group,
                enabled: false,
            });
        }

        self.enable_intx()?;

        Ok(())
    }

    fn parse_msix_capabilities(
        &mut self,
        cap: u8,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
    ) {
        let msg_ctl = self
            .vfio_pci_configuration
            .read_config_word((cap + 2).into());

        let table = self
            .vfio_pci_configuration
            .read_config_dword((cap + 4).into());

        let pba = self
            .vfio_pci_configuration
            .read_config_dword((cap + 8).into());

        let msix_cap = MsixCap {
            msg_ctl,
            table,
            pba,
        };

        let interrupt_source_group = interrupt_manager
            .create_group(MsiIrqGroupConfig {
                base: 0,
                count: msix_cap.table_size() as InterruptIndex,
            })
            .unwrap();

        let msix_config = MsixConfig::new(msix_cap.table_size(), interrupt_source_group.clone(), 0);

        self.interrupt.msix = Some(VfioMsix {
            bar: msix_config,
            cap: msix_cap,
            cap_offset: cap.into(),
            interrupt_source_group,
        });
    }

    fn parse_msi_capabilities(
        &mut self,
        cap: u8,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
    ) {
        let msg_ctl = self
            .vfio_pci_configuration
            .read_config_word((cap + 2).into());

        let interrupt_source_group = interrupt_manager
            .create_group(MsiIrqGroupConfig {
                base: 0,
                count: msi_num_enabled_vectors(msg_ctl) as InterruptIndex,
            })
            .unwrap();

        let msi_config = MsiConfig::new(msg_ctl, interrupt_source_group.clone());

        self.interrupt.msi = Some(VfioMsi {
            cfg: msi_config,
            cap_offset: cap.into(),
            interrupt_source_group,
        });
    }

    fn parse_capabilities(
        &mut self,
        interrupt_manager: &Arc<dyn InterruptManager<GroupConfig = MsiIrqGroupConfig>>,
    ) {
        let mut cap_next = self
            .vfio_pci_configuration
            .read_config_byte(PCI_CONFIG_CAPABILITY_OFFSET);

        while cap_next != 0 {
            let cap_id = self
                .vfio_pci_configuration
                .read_config_byte(cap_next.into());

            match PciCapabilityId::from(cap_id) {
                PciCapabilityId::MessageSignalledInterrupts => {
                    if let Some(irq_info) = self.device.get_irq_info(VFIO_PCI_MSI_IRQ_INDEX) {
                        if irq_info.count > 0 {
                            // Parse capability only if the VFIO device
                            // supports MSI.
                            self.parse_msi_capabilities(cap_next, interrupt_manager);
                        }
                    }
                }
                PciCapabilityId::MsiX => {
                    if let Some(irq_info) = self.device.get_irq_info(VFIO_PCI_MSIX_IRQ_INDEX) {
                        if irq_info.count > 0 {
                            // Parse capability only if the VFIO device
                            // supports MSI-X.
                            self.parse_msix_capabilities(cap_next, interrupt_manager);
                        }
                    }
                }
                _ => {}
            };

            cap_next = self
                .vfio_pci_configuration
                .read_config_byte((cap_next + 1).into());
        }
    }

    fn update_msi_capabilities(&mut self, offset: u64, data: &[u8]) -> Result<()> {
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

    fn update_msix_capabilities(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        match self.interrupt.update_msix(offset, data) {
            Some(InterruptUpdateAction::EnableMsix) => {
                // Disable INTx before we can enable MSI-X
                self.disable_intx();
                self.enable_msix()?;

                error!("MSIX enabled.")
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

    fn find_region(&self, addr: u64) -> Option<MmioRegion> {
        for region in self.mmio_regions.iter() {
            // error!("Finding region {:x} vs {:x} len {:x}", addr, region.start.raw_value(), region.length);
            if addr >= region.start.raw_value()
                && addr < region.start.unchecked_add(region.length).raw_value()
            {
                return Some(*region);
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
    /// Map MMIO regions into the guest, and avoid VM exits when the guest tries
    /// to reach those regions.
    ///
    /// # Arguments
    ///
    /// * `vm` - The VM object. It is used to set the VFIO MMIO regions
    ///          as user memory regions.
    /// * `mem_slot` - The closure to return a memory slot.
    pub fn map_mmio_regions(&mut self) -> Result<()> {
        let fd = self.device.as_raw_fd();
        let mut slot = 2;

        error!("Mmap mmio regions count {}", self.mmio_regions.len());
        for region in self.mmio_regions.iter_mut() {
            // We want to skip the mapping of the BAR containing the MSI-X
            // table even if it is mappable. The reason is we need to trap
            // any access to the MSI-X table and update the GSI routing
            // accordingly.
            if let Some(msix) = &self.interrupt.msix {
                if region.index == msix.cap.table_bir() || region.index == msix.cap.pba_bir() {
                    continue;
                }
            }
            let region_flags = self.device.get_region_flags(region.index);
            if region_flags & VFIO_REGION_INFO_FLAG_MMAP != 0 {
                let mut prot = 0;
                if region_flags & VFIO_REGION_INFO_FLAG_READ != 0 {
                    prot |= libc::PROT_READ;
                }
                if region_flags & VFIO_REGION_INFO_FLAG_WRITE != 0 {
                    prot |= libc::PROT_WRITE;
                }
                let mmap_offset = self.device.get_region_offset(region.index);
                let mmap_size = self.device.get_region_size(region.index);
                
                let offset = self.device.get_region_offset(region.index) + mmap_offset;
                error!(
                    "VFIO region {}, offset {:x}, size {:x}",
                    region.index, offset, mmap_size
                );
                let host_addr = unsafe {
                    libc::mmap(
                        null_mut(),
                        mmap_size as usize,
                        prot,
                        libc::MAP_SHARED,
                        fd,
                        offset as libc::off_t,
                    )
                };

                if host_addr == libc::MAP_FAILED {
                    error!(
                        "Could not mmap regions, error:{}",
                        io::Error::last_os_error()
                    );
                    continue;
                }

                error!(
                    "Mmap slot {} gpa {:x} size {} hva {:x}",
                    slot,
                    region.start.raw_value() + mmap_offset,
                    mmap_size as u64,
                    host_addr as u64
                );

                let mem_region = Self::make_user_memory_region(
                    slot,
                    region.start.raw_value() + mmap_offset,
                    mmap_size as u64,
                    host_addr as u64,
                    false,
                    false,
                );

                unsafe {
                    self.vm.lock().expect("Poisoned lock")
                        .set_user_memory_region(mem_region)
                        .map_err(|e| VfioPciError::MapRegionGuest(e.into()))?;
                }

                // self.container.vfio_dma_map(
                //     region.start.raw_value() + mmap_offset,
                //     mmap_size,
                //     host_addr as u64
                // ).unwrap();

                // Update the region with memory mapped info.
                region.mem_slot = Some(slot);
                region.host_addr = Some(host_addr as u64);
                region.mmap_size = Some(mmap_size as usize);

                slot += 1;
            }
        }

        Ok(())
    }

    pub fn unmap_mmio_regions(&mut self) {
        for region in self.mmio_regions.iter() {
            if let (Some(host_addr), Some(mmap_size), Some(mem_slot)) =
                (region.host_addr, region.mmap_size, region.mem_slot)
            {
                let mmap_offset = self.device.get_region_offset(region.index);

                // Remove region
                let r = Self::make_user_memory_region(
                    mem_slot,
                    region.start.raw_value() + mmap_offset,
                    0,
                    host_addr as u64,
                    false,
                    false,
                );

                if let Err(e) = unsafe { self.vm.lock().expect("Poisoned lock").set_user_memory_region(r) } {
                    error!("Could not remove the userspace memory region: {}", e);
                }

                let ret = unsafe { libc::munmap(host_addr as *mut libc::c_void, mmap_size) };
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

    pub fn dma_map(&self, iova: u64, size: u64, user_addr: u64) -> Result<()> {
        if !self.iommu_attached {
            self.container
                .vfio_dma_map(iova, size, user_addr)
                .map_err(VfioPciError::DmaMap)?;
        }
        Ok(())
    }

    pub fn dma_unmap(&self, iova: u64, size: u64) -> Result<()> {
        if !self.iommu_attached {
            self.container
                .vfio_dma_unmap(iova, size)
                .map_err(VfioPciError::DmaUnmap)?;
        }

        Ok(())
    }

    pub fn mmio_regions(&self) -> Vec<MmioRegion> {
        self.mmio_regions.clone()
    }

    pub fn bus_read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(base, offset, data);
    }

    pub fn bus_write(&mut self, base: u64, offset: u64, data: &[u8]) {
        self.write_bar(base, offset, data);
    }
}

impl Drop for VfioPciDevice {
    fn drop(&mut self) {
        self.unmap_mmio_regions();

        if self.interrupt.intx_in_use() {
            self.disable_intx();
        }
    }
}


// First BAR offset in the PCI config space.
const PCI_CONFIG_BAR_OFFSET: u32 = 0x10;
// Capability register offset in the PCI config space.
const PCI_CONFIG_CAPABILITY_OFFSET: u32 = 0x34;
// IO BAR when first BAR bit is 1.
const PCI_CONFIG_IO_BAR: u32 = 0x1;
// Memory BAR flags (lower 4 bits).
const PCI_CONFIG_MEMORY_BAR_FLAG_MASK: u32 = 0xf;
// 64-bit memory bar flag.
const PCI_CONFIG_MEMORY_BAR_64BIT: u32 = 0x4;
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
        allocator: &mut SystemAllocator,
    ) -> std::result::Result<Vec<(GuestAddress, GuestUsize, PciBarRegionType)>, PciDeviceError>
    {
        let mut ranges = Vec::new();
        let mut bar_id = VFIO_PCI_BAR0_REGION_INDEX as u32;

        // Going through all regular regions to compute the BAR size.
        // We're not saving the BAR address to restore it, because we
        // are going to allocate a guest address for each BAR and write
        // that new address back.
        while bar_id < VFIO_PCI_CONFIG_REGION_INDEX {
            let mut lsb_size: u32 = 0xffff_ffff;
            let mut msb_size = 0;
            let mut region_size: u64;
            let bar_addr: GuestAddress;

            // Read the BAR size (Starts by all 1s to the BAR)
            let bar_offset = if bar_id == VFIO_PCI_ROM_REGION_INDEX {
                (PCI_ROM_EXP_BAR_INDEX * 4) as u32
            } else {
                PCI_CONFIG_BAR_OFFSET + bar_id * 4
            };

            self.vfio_pci_configuration
                .write_config_dword(lsb_size, bar_offset);
            lsb_size = self.vfio_pci_configuration.read_config_dword(bar_offset);

            // We've just read the BAR size back. Or at least its LSB.
            let lsb_flag = lsb_size & PCI_CONFIG_MEMORY_BAR_FLAG_MASK;

            if lsb_size == 0 {
                bar_id += 1;
                continue;
            }

            // Is this an IO BAR?
            let io_bar = if bar_id != VFIO_PCI_ROM_REGION_INDEX {
                matches!(lsb_flag & PCI_CONFIG_IO_BAR, PCI_CONFIG_IO_BAR)
            } else {
                false
            };

            // Is this a 64-bit BAR?
            let is_64bit_bar = if bar_id != VFIO_PCI_ROM_REGION_INDEX {
                matches!(
                    lsb_flag & PCI_CONFIG_MEMORY_BAR_64BIT,
                    PCI_CONFIG_MEMORY_BAR_64BIT
                )
            } else {
                false
            };

            // By default, the region type is 32 bits memory BAR.
            let mut region_type = PciBarRegionType::Memory32BitRegion;

            if io_bar {
                #[cfg(target_arch = "x86_64")]
                {
                    // IO BAR
                    region_type = PciBarRegionType::IoRegion;

                    // Clear first bit.
                    lsb_size &= 0xffff_fffc;

                    // Find the first bit that's set to 1.
                    let first_bit = lsb_size.trailing_zeros();
                    region_size = 2u64.pow(first_bit);
                    // We need to allocate a guest PIO address range for that BAR.
                    // The address needs to be 4 bytes aligned.
                    bar_addr = allocator
                        .allocate_io_addresses(None, region_size, Some(0x4))
                        .ok_or(PciDeviceError::IoAllocationFailed(region_size))?;
                }
                #[cfg(target_arch = "aarch64")]
                unimplemented!()
            } else {
                if is_64bit_bar {
                    // 64 bits Memory BAR
                    region_type = PciBarRegionType::Memory64BitRegion;

                    msb_size = 0xffff_ffff;
                    let msb_bar_offset: u32 = PCI_CONFIG_BAR_OFFSET + (bar_id + 1) * 4;

                    self.vfio_pci_configuration
                        .write_config_dword(msb_size, msb_bar_offset);

                    msb_size = self
                        .vfio_pci_configuration
                        .read_config_dword(msb_bar_offset);
                }

                // Clear the first four bytes from our LSB.
                lsb_size &= 0xffff_fff0;

                region_size = u64::from(msb_size);
                region_size <<= 32;
                region_size |= u64::from(lsb_size);

                // Find the first that's set to 1.
                let first_bit = region_size.trailing_zeros();
                region_size = 2u64.pow(first_bit);

                // We need to allocate a guest MMIO address range for that BAR.
                // In case the BAR is mappable directly, this means it might be
                // set as user memory region, which expects to deal with 4K
                // pages. Therefore, the alignment has to be set accordingly.
                let bar_alignment = if (bar_id == VFIO_PCI_ROM_REGION_INDEX)
                    || (self.device.get_region_flags(bar_id) & VFIO_REGION_INFO_FLAG_MMAP != 0)
                {
                    // 4K alignment
                    0x1000
                } else {
                    // Default 16 bytes alignment
                    0x10
                };
                if is_64bit_bar {
                    bar_addr = allocator
                        .allocate_mmio_addresses(None, region_size, Some(bar_alignment))
                        .ok_or(PciDeviceError::IoAllocationFailed(region_size))?;
                } else {
                    bar_addr = allocator
                        .allocate_mmio_hole_addresses(None, region_size, Some(bar_alignment))
                        .ok_or(PciDeviceError::IoAllocationFailed(region_size))?;
                }
            }

            let reg_idx = if bar_id == VFIO_PCI_ROM_REGION_INDEX {
                PCI_ROM_EXP_BAR_INDEX
            } else {
                bar_id as usize
            };

            // We can now build our BAR configuration block.
            let config = PciBarConfiguration::default()
                .set_register_index(reg_idx)
                .set_address(bar_addr.raw_value())
                .set_size(region_size)
                .set_region_type(region_type);

            if bar_id == VFIO_PCI_ROM_REGION_INDEX {
                self.configuration
                    .add_pci_rom_bar(&config, lsb_flag & 0x1)
                    .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr.raw_value(), e))?;
            } else {
                self.configuration
                    .add_pci_bar(&config)
                    .map_err(|e| PciDeviceError::IoRegistrationFailed(bar_addr.raw_value(), e))?;
            }

            error!("Bar addr: {:?}", bar_addr);
            ranges.push((bar_addr, region_size, region_type));
            self.mmio_regions.push(MmioRegion {
                start: bar_addr,
                length: region_size,
                type_: region_type,
                index: bar_id as u32,
                mem_slot: None,
                host_addr: None,
                mmap_size: None,
            });
        

            bar_id += 1;
            if is_64bit_bar {
                bar_id += 1;
            }
        }

        Ok(ranges)
    }

    fn free_bars(
        &mut self,
        allocator: &mut SystemAllocator,
    ) -> std::result::Result<(), PciDeviceError> {
        for region in self.mmio_regions.iter() {
            match region.type_ {
                PciBarRegionType::IoRegion => {
                    #[cfg(target_arch = "x86_64")]
                    allocator.free_io_addresses(region.start, region.length);
                    #[cfg(target_arch = "aarch64")]
                    error!("I/O region is not supported");
                }
                PciBarRegionType::Memory32BitRegion => {
                    allocator.free_mmio_hole_addresses(region.start, region.length);
                }
                PciBarRegionType::Memory64BitRegion => {
                    allocator.free_mmio_addresses(region.start, region.length);
                }
            }
        }
        Ok(())
    }

    fn write_config_register(
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
        self.device
            .region_write(VFIO_PCI_CONFIG_REGION_INDEX, data, reg + offset);

        None
    }

    fn read_config_register(&mut self, reg_idx: usize) -> u32 {
        // When reading the BARs, we trap it and return what comes
        // from our local configuration space. We want the guest to
        // use that and not the VFIO device BARs as it does not map
        // with the guest address space.
        if (PCI_CONFIG_BAR0_INDEX..PCI_CONFIG_BAR0_INDEX + BAR_NUMS).contains(&reg_idx)
            || reg_idx == PCI_ROM_EXP_BAR_INDEX
        {
            return self.configuration.read_reg(reg_idx);
        }

        // Since we don't support passing multi-functions devices, we should
        // mask the multi-function bit, bit 7 of the Header Type byte on the
        // register 3.
        let mask = if reg_idx == PCI_HEADER_TYPE_REG_INDEX {
            0xff7f_ffffu32
        } else {
            0xffff_ffffu32
        };

        // The config register read comes from the VFIO device itself.
        self.vfio_pci_configuration
            .read_config_dword((reg_idx * 4) as u32)
            & mask
    }

    fn detect_bar_reprogramming(
        &mut self,
        reg_idx: usize,
        data: &[u8],
    ) -> Option<BarReprogrammingParams> {
        self.configuration.detect_bar_reprogramming(reg_idx, data)
    }

    fn read_bar(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        let addr = base + offset;
        if let Some(region) = self.find_region(addr) {
            let offset = addr - region.start.raw_value();

            if self.interrupt.msix_table_accessed(region.index, offset) {
                self.interrupt.msix_read_table(offset, data);
            } else {
                self.device.region_read(region.index, data, offset);
            }
        }

        // INTx EOI
        // The guest reading from the BAR potentially means the interrupt has
        // been received and can be acknowledged.
        if self.interrupt.intx_in_use() {
            if let Err(e) = self.device.unmask_irq(VFIO_PCI_INTX_IRQ_INDEX) {
                error!("Failed unmasking INTx IRQ: {}", e);
            }
        }
    }

    fn write_bar(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        let addr = base + offset;
        if let Some(region) = self.find_region(addr) {
            let offset = addr - region.start.raw_value();

            // If the MSI-X table is written to, we need to update our cache.
            if self.interrupt.msix_table_accessed(region.index, offset) {
                self.interrupt.msix_write_table(offset, data);
            } else {
                self.device.region_write(region.index, data, offset);
            }
        }

        // INTx EOI
        // The guest writing to the BAR potentially means the interrupt has
        // been received and can be acknowledged.
        if self.interrupt.intx_in_use() {
            if let Err(e) = self.device.unmask_irq(VFIO_PCI_INTX_IRQ_INDEX) {
                error!("Failed unmasking INTx IRQ: {}", e);
            }
        }

        None
    }

    fn move_bar(&mut self, old_base: u64, new_base: u64) -> result::Result<(), io::Error> {
        for region in self.mmio_regions.iter_mut() {
            if region.start.raw_value() == old_base {
                region.start = GuestAddress(new_base);

                if let Some(mem_slot) = region.mem_slot {
                    if let Some(host_addr) = region.host_addr {
                        let mmap_offset = self.device.get_region_offset(region.index);
                        let mmap_size = self.device.get_region_size(region.index);

                        // Remove old region
                        let old_mem_region = Self::make_user_memory_region(
                            mem_slot,
                            old_base + mmap_offset,
                            0,
                            host_addr as u64,
                            false,
                            false,
                        );

                        unsafe { self.vm.lock().expect("Poisoned lock")
                            .set_user_memory_region(old_mem_region)
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                        }

                        // Insert new region
                        let new_mem_region = Self::make_user_memory_region(
                            mem_slot,
                            new_base + mmap_offset,
                            mmap_size as u64,
                            host_addr as u64,
                            false,
                            false,
                        );

                        unsafe { self.vm.lock().expect("Poisoned lock")
                            .set_user_memory_region(new_mem_region)
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}