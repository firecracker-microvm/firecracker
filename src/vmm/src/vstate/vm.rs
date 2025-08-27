// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(target_arch = "x86_64")]
use kvm_bindings::KVM_IRQCHIP_IOAPIC;
use kvm_bindings::{
    KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI, KVM_MEM_LOG_DIRTY_PAGES, KVM_MSI_VALID_DEVID,
    KvmIrqRouting, kvm_irq_routing_entry, kvm_userspace_memory_region,
};
use kvm_ioctls::VmFd;
use log::{debug, error};
use pci::DeviceRelocation;
use serde::{Deserialize, Serialize};
use vm_device::interrupt::{
    InterruptIndex, InterruptSourceConfig, InterruptSourceGroup, MsiIrqSourceConfig,
};
use vmm_sys_util::errno;
use vmm_sys_util::eventfd::EventFd;

pub use crate::arch::{ArchVm as Vm, ArchVmError, VmState};
use crate::arch::{GSI_MSI_END, host_page_size};
use crate::logger::info;
use crate::persist::CreateSnapshotError;
use crate::snapshot::Persist;
use crate::utils::u64_to_usize;
use crate::vmm_config::snapshot::SnapshotType;
use crate::vstate::memory::{
    Address, GuestMemory, GuestMemoryExtension, GuestMemoryMmap, GuestMemoryRegion, GuestRegionMmap,
};
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vcpu::VcpuError;
use crate::{DirtyBitmap, Vcpu, mem_size_mib};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Errors related with Firecracker interrupts
pub enum InterruptError {
    /// Error allocating resources: {0}
    Allocator(#[from] vm_allocator::Error),
    /// EventFd error: {0}
    EventFd(std::io::Error),
    /// FamStruct error: {0}
    FamStruct(#[from] vmm_sys_util::fam::Error),
    /// KVM error: {0}
    Kvm(#[from] kvm_ioctls::Error),
}

#[derive(Debug, Serialize, Deserialize)]
/// A struct representing an interrupt line used by some device of the microVM
pub struct RoutingEntry {
    entry: kvm_irq_routing_entry,
    masked: bool,
}

/// Type that describes an allocated interrupt
#[derive(Debug)]
pub struct MsiVector {
    /// GSI used for this vector
    pub gsi: u32,
    /// EventFd used for this vector
    pub event_fd: EventFd,
    /// Flag determining whether the vector is enabled
    pub enabled: AtomicBool,
}

impl MsiVector {
    /// Create a new [`MsiVector`] of a particular type
    pub fn new(gsi: u32, enabled: bool) -> Result<MsiVector, InterruptError> {
        Ok(MsiVector {
            gsi,
            event_fd: EventFd::new(libc::EFD_NONBLOCK).map_err(InterruptError::EventFd)?,
            enabled: AtomicBool::new(enabled),
        })
    }
}

impl MsiVector {
    /// Enable vector
    fn enable(&self, vmfd: &VmFd) -> Result<(), errno::Error> {
        if !self.enabled.load(Ordering::Acquire) {
            vmfd.register_irqfd(&self.event_fd, self.gsi)?;
            self.enabled.store(true, Ordering::Release);
        }

        Ok(())
    }

    /// Disable vector
    fn disable(&self, vmfd: &VmFd) -> Result<(), errno::Error> {
        if self.enabled.load(Ordering::Acquire) {
            vmfd.unregister_irqfd(&self.event_fd, self.gsi)?;
            self.enabled.store(false, Ordering::Release);
        }

        Ok(())
    }
}

#[derive(Debug)]
/// MSI interrupts created for a VirtIO device
pub struct MsiVectorGroup {
    vm: Arc<Vm>,
    irq_routes: Vec<MsiVector>,
}

impl MsiVectorGroup {
    /// Returns the number of vectors in this group
    pub fn num_vectors(&self) -> u16 {
        // It is safe to unwrap here. We are creating `MsiVectorGroup` objects through the
        // `Vm::create_msix_group` where the argument for the number of `irq_routes` is a `u16`.
        u16::try_from(self.irq_routes.len()).unwrap()
    }
}

impl<'a> Persist<'a> for MsiVectorGroup {
    type State = Vec<u32>;
    type ConstructorArgs = Arc<Vm>;
    type Error = InterruptError;

    fn save(&self) -> Self::State {
        // We don't save the "enabled" state of the MSI interrupt. PCI devices store the MSI-X
        // configuration and make sure that the vector is enabled during the restore path if it was
        // initially enabled
        self.irq_routes.iter().map(|route| route.gsi).collect()
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        let mut irq_routes = Vec::with_capacity(state.len());

        for gsi in state {
            irq_routes.push(MsiVector::new(*gsi, false)?);
        }

        Ok(MsiVectorGroup {
            vm: constructor_args,
            irq_routes,
        })
    }
}

impl InterruptSourceGroup for MsiVectorGroup {
    fn enable(&self) -> vm_device::interrupt::Result<()> {
        for route in &self.irq_routes {
            route.enable(&self.vm.common.fd)?;
        }

        Ok(())
    }

    fn disable(&self) -> vm_device::interrupt::Result<()> {
        for route in &self.irq_routes {
            route.disable(&self.vm.common.fd)?;
        }

        Ok(())
    }

    fn trigger(&self, index: InterruptIndex) -> vm_device::interrupt::Result<()> {
        self.notifier(index)
            .ok_or_else(|| {
                std::io::Error::other(format!("trigger: invalid interrupt index {index}"))
            })?
            .write(1)
    }

    fn notifier(&self, index: InterruptIndex) -> Option<&EventFd> {
        self.irq_routes
            .get(index as usize)
            .map(|route| &route.event_fd)
    }

    fn update(
        &self,
        index: InterruptIndex,
        config: InterruptSourceConfig,
        masked: bool,
        set_gsi: bool,
    ) -> vm_device::interrupt::Result<()> {
        let msi_config = match config {
            InterruptSourceConfig::LegacyIrq(_) => {
                return Err(std::io::Error::other(
                    "MSI-x update: invalid configuration type",
                ));
            }
            InterruptSourceConfig::MsiIrq(config) => config,
        };

        if let Some(route) = self.irq_routes.get(index as usize) {
            // When an interrupt is masked the GSI will not be passed to KVM through
            // KVM_SET_GSI_ROUTING. So, call [`disable()`] to unregister the interrupt file
            // descriptor before passing the interrupt routes to KVM
            if masked {
                route.disable(&self.vm.common.fd)?;
            }

            self.vm.register_msi(route, masked, msi_config)?;
            if set_gsi {
                self.vm
                    .set_gsi_routes()
                    .map_err(|err| std::io::Error::other(format!("MSI-X update: {err}")))?
            }

            // Assign KVM_IRQFD after KVM_SET_GSI_ROUTING to avoid
            // panic on kernel which does not have commit a80ced6ea514
            // (KVM: SVM: fix panic on out-of-bounds guest IRQ).
            if !masked {
                route.enable(&self.vm.common.fd)?;
            }

            return Ok(());
        }

        Err(std::io::Error::other(format!(
            "MSI-X update: invalid vector index {index}"
        )))
    }

    fn set_gsi(&self) -> vm_device::interrupt::Result<()> {
        self.vm
            .set_gsi_routes()
            .map_err(|err| std::io::Error::other(format!("MSI-X update: {err}")))
    }
}

/// Architecture independent parts of a VM.
#[derive(Debug)]
pub struct VmCommon {
    /// The KVM file descriptor used to access this Vm.
    pub fd: VmFd,
    max_memslots: u32,
    /// The guest memory of this Vm.
    pub guest_memory: GuestMemoryMmap,
    /// Interrupts used by Vm's devices
    pub interrupts: Mutex<HashMap<u32, RoutingEntry>>,
    /// Allocator for VM resources
    pub resource_allocator: Mutex<ResourceAllocator>,
    /// MMIO bus
    pub mmio_bus: Arc<vm_device::Bus>,
}

/// Errors associated with the wrappers over KVM ioctls.
/// Needs `rustfmt::skip` to make multiline comments work
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmError {
    /// Cannot set the memory regions: {0}
    SetUserMemoryRegion(kvm_ioctls::Error),
    /// Failed to create VM: {0}
    CreateVm(kvm_ioctls::Error),
    /// Failed to get KVM's dirty log: {0}
    GetDirtyLog(kvm_ioctls::Error),
    /// {0}
    Arch(#[from] ArchVmError),
    /// Error during eventfd operations: {0}
    EventFd(std::io::Error),
    /// Failed to create vcpu: {0}
    CreateVcpu(VcpuError),
    /// The number of configured slots is bigger than the maximum reported by KVM: {0}
    NotEnoughMemorySlots(u32),
    /// Memory Error: {0}
    VmMemory(#[from] vm_memory::Error),
    /// Error calling mincore: {0}
    Mincore(vmm_sys_util::errno::Error),
    /// ResourceAllocator error: {0}
    ResourceAllocator(#[from] vm_allocator::Error)
}

/// Contains Vm functions that are usable across CPU architectures
impl Vm {
    /// Create a KVM VM
    pub fn create_common(kvm: &crate::vstate::kvm::Kvm) -> Result<VmCommon, VmError> {
        // It is known that KVM_CREATE_VM occasionally fails with EINTR on heavily loaded machines
        // with many VMs.
        //
        // The behavior itself that KVM_CREATE_VM can return EINTR is intentional. This is because
        // the KVM_CREATE_VM path includes mm_take_all_locks() that is CPU intensive and all CPU
        // intensive syscalls should check for pending signals and return EINTR immediately to allow
        // userland to remain interactive.
        // https://lists.nongnu.org/archive/html/qemu-devel/2014-01/msg01740.html
        //
        // However, it is empirically confirmed that, even though there is no pending signal,
        // KVM_CREATE_VM returns EINTR.
        // https://lore.kernel.org/qemu-devel/8735e0s1zw.wl-maz@kernel.org/
        //
        // To mitigate it, QEMU does an infinite retry on EINTR that greatly improves reliabiliy:
        // - https://github.com/qemu/qemu/commit/94ccff133820552a859c0fb95e33a539e0b90a75
        // - https://github.com/qemu/qemu/commit/bbde13cd14ad4eec18529ce0bf5876058464e124
        //
        // Similarly, we do retries up to 5 times. Although Firecracker clients are also able to
        // retry, they have to start Firecracker from scratch. Doing retries in Firecracker makes
        // recovery faster and improves reliability.
        const MAX_ATTEMPTS: u32 = 5;
        let mut attempt = 1;
        let fd = loop {
            match kvm.fd.create_vm() {
                Ok(fd) => break fd,
                Err(e) if e.errno() == libc::EINTR && attempt < MAX_ATTEMPTS => {
                    info!("Attempt #{attempt} of KVM_CREATE_VM returned EINTR");
                    // Exponential backoff (1us, 2us, 4us, and 8us => 15us in total)
                    std::thread::sleep(std::time::Duration::from_micros(2u64.pow(attempt - 1)));
                }
                Err(e) => return Err(VmError::CreateVm(e)),
            }

            attempt += 1;
        };

        Ok(VmCommon {
            fd,
            max_memslots: kvm.max_nr_memslots(),
            guest_memory: GuestMemoryMmap::default(),
            interrupts: Mutex::new(HashMap::with_capacity(GSI_MSI_END as usize + 1)),
            resource_allocator: Mutex::new(ResourceAllocator::new()),
            mmio_bus: Arc::new(vm_device::Bus::new()),
        })
    }

    /// Creates the specified number of [`Vcpu`]s.
    ///
    /// The returned [`EventFd`] is written to whenever any of the vcpus exit.
    pub fn create_vcpus(&mut self, vcpu_count: u8) -> Result<(Vec<Vcpu>, EventFd), VmError> {
        self.arch_pre_create_vcpus(vcpu_count)?;

        let exit_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmError::EventFd)?;

        let mut vcpus = Vec::with_capacity(vcpu_count as usize);
        for cpu_idx in 0..vcpu_count {
            let exit_evt = exit_evt.try_clone().map_err(VmError::EventFd)?;
            let vcpu = Vcpu::new(cpu_idx, self, exit_evt).map_err(VmError::CreateVcpu)?;
            vcpus.push(vcpu);
        }

        self.arch_post_create_vcpus(vcpu_count)?;

        Ok((vcpus, exit_evt))
    }

    /// Register a list of new memory regions to this [`Vm`].
    pub fn register_memory_regions(
        &mut self,
        regions: Vec<GuestRegionMmap>,
    ) -> Result<(), VmError> {
        for region in regions {
            self.register_memory_region(region)?
        }

        Ok(())
    }

    /// Register a new memory region to this [`Vm`].
    pub fn register_memory_region(&mut self, region: GuestRegionMmap) -> Result<(), VmError> {
        let next_slot = self
            .guest_memory()
            .num_regions()
            .try_into()
            .expect("Number of existing memory regions exceeds u32::MAX");
        if self.common.max_memslots <= next_slot {
            return Err(VmError::NotEnoughMemorySlots(self.common.max_memslots));
        }

        let flags = if region.bitmap().is_some() {
            KVM_MEM_LOG_DIRTY_PAGES
        } else {
            0
        };

        let memory_region = kvm_userspace_memory_region {
            slot: next_slot,
            guest_phys_addr: region.start_addr().raw_value(),
            memory_size: region.len(),
            userspace_addr: region.as_ptr() as u64,
            flags,
        };

        let new_guest_memory = self.common.guest_memory.insert_region(Arc::new(region))?;

        // SAFETY: Safe because the fd is a valid KVM file descriptor.
        unsafe {
            self.fd()
                .set_user_memory_region(memory_region)
                .map_err(VmError::SetUserMemoryRegion)?;
        }

        self.common.guest_memory = new_guest_memory;

        Ok(())
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    pub fn fd(&self) -> &VmFd {
        &self.common.fd
    }

    /// Gets a reference to this [`Vm`]'s [`GuestMemoryMmap`] object
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.common.guest_memory
    }

    /// Gets a mutable reference to this [`Vm`]'s [`ResourceAllocator`] object
    pub fn resource_allocator(&self) -> MutexGuard<'_, ResourceAllocator> {
        self.common
            .resource_allocator
            .lock()
            .expect("Poisoned lock")
    }

    /// Resets the KVM dirty bitmap for each of the guest's memory regions.
    pub fn reset_dirty_bitmap(&self) {
        self.guest_memory()
            .iter()
            .zip(0u32..)
            .for_each(|(region, slot)| {
                let _ = self.fd().get_dirty_log(slot, u64_to_usize(region.len()));
            });
    }

    /// Retrieves the KVM dirty bitmap for each of the guest's memory regions.
    pub fn get_dirty_bitmap(&self) -> Result<DirtyBitmap, VmError> {
        self.guest_memory()
            .iter()
            .zip(0u32..)
            .map(|(region, slot)| {
                let bitmap = match region.bitmap() {
                    Some(_) => self
                        .fd()
                        .get_dirty_log(slot, u64_to_usize(region.len()))
                        .map_err(VmError::GetDirtyLog)?,
                    None => mincore_bitmap(region)?,
                };
                Ok((slot, bitmap))
            })
            .collect()
    }

    /// Takes a snapshot of the virtual machine running inside the given [`Vmm`] and saves it to
    /// `mem_file_path`.
    ///
    /// If `snapshot_type` is [`SnapshotType::Diff`], and `mem_file_path` exists and is a snapshot
    /// file of matching size, then the diff snapshot will be directly merged into the existing
    /// snapshot. Otherwise, existing files are simply overwritten.
    pub(crate) fn snapshot_memory_to_file(
        &self,
        mem_file_path: &Path,
        snapshot_type: SnapshotType,
    ) -> Result<(), CreateSnapshotError> {
        use self::CreateSnapshotError::*;

        // Need to check this here, as we create the file in the line below
        let file_existed = mem_file_path.exists();

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(mem_file_path)
            .map_err(|err| MemoryBackingFile("open", err))?;

        // Determine what size our total memory area is.
        let mem_size_mib = mem_size_mib(self.guest_memory());
        let expected_size = mem_size_mib * 1024 * 1024;

        if file_existed {
            let file_size = file
                .metadata()
                .map_err(|e| MemoryBackingFile("get_metadata", e))?
                .len();

            // Here we only truncate the file if the size mismatches.
            // - For full snapshots, the entire file's contents will be overwritten anyway. We have
            //   to avoid truncating here to deal with the edge case where it represents the
            //   snapshot file from which this very microVM was loaded (as modifying the memory file
            //   would be reflected in the mmap of the file, meaning a truncate operation would zero
            //   out guest memory, and thus corrupt the VM).
            // - For diff snapshots, we want to merge the diff layer directly into the file.
            if file_size != expected_size {
                file.set_len(0)
                    .map_err(|err| MemoryBackingFile("truncate", err))?;
            }
        }

        // Set the length of the file to the full size of the memory area.
        file.set_len(expected_size)
            .map_err(|e| MemoryBackingFile("set_length", e))?;

        match snapshot_type {
            SnapshotType::Diff => {
                let dirty_bitmap = self.get_dirty_bitmap()?;
                self.guest_memory().dump_dirty(&mut file, &dirty_bitmap)?;
            }
            SnapshotType::Full => {
                self.guest_memory().dump(&mut file)?;
                self.reset_dirty_bitmap();
                self.guest_memory().reset_dirty();
            }
        };

        file.flush()
            .map_err(|err| MemoryBackingFile("flush", err))?;
        file.sync_all()
            .map_err(|err| MemoryBackingFile("sync_all", err))
    }

    /// Register a device IRQ
    pub fn register_irq(&self, fd: &EventFd, gsi: u32) -> Result<(), errno::Error> {
        self.common.fd.register_irqfd(fd, gsi)?;

        let mut entry = kvm_irq_routing_entry {
            gsi,
            type_: KVM_IRQ_ROUTING_IRQCHIP,
            ..Default::default()
        };
        #[cfg(target_arch = "x86_64")]
        {
            entry.u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC;
        }
        #[cfg(target_arch = "aarch64")]
        {
            entry.u.irqchip.irqchip = 0;
        }
        entry.u.irqchip.pin = gsi;

        self.common
            .interrupts
            .lock()
            .expect("Poisoned lock")
            .insert(
                gsi,
                RoutingEntry {
                    entry,
                    masked: false,
                },
            );
        Ok(())
    }

    /// Register an MSI device interrupt
    pub fn register_msi(
        &self,
        route: &MsiVector,
        masked: bool,
        config: MsiIrqSourceConfig,
    ) -> Result<(), errno::Error> {
        let mut entry = kvm_irq_routing_entry {
            gsi: route.gsi,
            type_: KVM_IRQ_ROUTING_MSI,
            ..Default::default()
        };
        entry.u.msi.address_lo = config.low_addr;
        entry.u.msi.address_hi = config.high_addr;
        entry.u.msi.data = config.data;

        if self.common.fd.check_extension(kvm_ioctls::Cap::MsiDevid) {
            // According to KVM documentation:
            // https://docs.kernel.org/virt/kvm/api.html#kvm-set-gsi-routing
            //
            // if the capability is set, we need to set the flag and provide a valid unique device
            // ID. "For PCI, this is usually a BDF identifier in the lower 16 bits".
            //
            // The layout of `config.devid` is:
            //
            // |---- 16 bits ----|-- 8 bits --|-- 5 bits --|-- 3 bits --|
            // |      segment    |     bus    |   device   |  function  |
            //
            // For the time being, we are using a single PCI segment and a single bus per segment
            // so just passing config.devid should be fine.
            entry.flags = KVM_MSI_VALID_DEVID;
            entry.u.msi.__bindgen_anon_1.devid = config.devid;
        }

        self.common
            .interrupts
            .lock()
            .expect("Poisoned lock")
            .insert(route.gsi, RoutingEntry { entry, masked });

        Ok(())
    }

    /// Create a group of MSI-X interrupts
    pub fn create_msix_group(vm: Arc<Vm>, count: u16) -> Result<MsiVectorGroup, InterruptError> {
        debug!("Creating new MSI group with {count} vectors");
        let mut irq_routes = Vec::with_capacity(count as usize);
        for gsi in vm
            .resource_allocator()
            .allocate_gsi_msi(count as u32)?
            .iter()
        {
            irq_routes.push(MsiVector::new(*gsi, false)?);
        }

        Ok(MsiVectorGroup { vm, irq_routes })
    }

    /// Set GSI routes to KVM
    pub fn set_gsi_routes(&self) -> Result<(), InterruptError> {
        let entries = self.common.interrupts.lock().expect("Poisoned lock");
        let mut routes = KvmIrqRouting::new(0)?;

        for entry in entries.values() {
            if entry.masked {
                continue;
            }
            routes.push(entry.entry)?;
        }

        self.common.fd.set_gsi_routing(&routes)?;
        Ok(())
    }
}

/// Use `mincore(2)` to overapproximate the dirty bitmap for the given memslot. To be used
/// if a diff snapshot is requested, but dirty page tracking wasn't enabled.
fn mincore_bitmap(region: &GuestRegionMmap) -> Result<Vec<u64>, VmError> {
    // TODO: Once Host 5.10 goes out of support, we can make this more robust and work on
    // swap-enabled systems, by doing mlock2(MLOCK_ONFAULT)/munlock() in this function (to
    // force swapped-out pages to get paged in, so that mincore will consider them incore).
    // However, on AMD (m6a/m7a) 5.10, doing so introduces a 100%/30ms regression to snapshot
    // creation, even if swap is disabled, so currently it cannot be done.

    // Mincore always works at PAGE_SIZE granularity, even if the VMA we are dealing with
    // is a hugetlbfs VMA (e.g. to report a single hugepage as "present", mincore will
    // give us 512 4k markers with the lowest bit set).
    let page_size = host_page_size();
    let mut mincore_bitmap = vec![0u8; u64_to_usize(region.len()) / page_size];
    let mut bitmap = vec![0u64; (u64_to_usize(region.len()) / page_size).div_ceil(64)];

    // SAFETY: The safety invariants of GuestRegionMmap ensure that region.as_ptr() is a valid
    // userspace mapping of size region.len() bytes. The bitmap has exactly one byte for each
    // page in this userspace mapping. Note that mincore does not operate on bitmaps like
    // KVM_MEM_LOG_DIRTY_PAGES, but rather it uses 8 bits per page (e.g. 1 byte), setting the
    // least significant bit to 1 if the page corresponding to a byte is in core (available in
    // the page cache and resolvable via just a minor page fault).
    let r = unsafe {
        libc::mincore(
            region.as_ptr().cast::<libc::c_void>(),
            u64_to_usize(region.len()),
            mincore_bitmap.as_mut_ptr(),
        )
    };

    if r != 0 {
        return Err(VmError::Mincore(vmm_sys_util::errno::Error::last()));
    }

    for (page_idx, b) in mincore_bitmap.iter().enumerate() {
        bitmap[page_idx / 64] |= (*b as u64 & 0x1) << (page_idx as u64 % 64);
    }

    Ok(bitmap)
}

impl DeviceRelocation for Vm {
    fn move_bar(
        &self,
        _old_base: u64,
        _new_base: u64,
        _len: u64,
        _pci_dev: &mut dyn pci::PciDevice,
        _region_type: pci::PciBarRegionType,
    ) -> Result<(), std::io::Error> {
        error!("pci: device relocation not supported");
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use vm_device::interrupt::{InterruptSourceConfig, LegacyIrqSourceConfig};
    use vm_memory::GuestAddress;
    use vm_memory::mmap::MmapRegionBuilder;

    use super::*;
    #[cfg(target_arch = "x86_64")]
    use crate::snapshot::Snapshot;
    use crate::test_utils::single_region_mem_raw;
    use crate::utils::mib_to_bytes;
    use crate::vstate::kvm::Kvm;
    use crate::vstate::memory::GuestRegionMmap;

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm() -> (Kvm, Vm) {
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        let vm = Vm::new(&kvm).expect("Cannot create new vm");
        (kvm, vm)
    }

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm_with_memory(mem_size: usize) -> (Kvm, Vm) {
        let (kvm, mut vm) = setup_vm();
        let gm = single_region_mem_raw(mem_size);
        vm.register_memory_regions(gm).unwrap();
        (kvm, vm)
    }

    #[test]
    fn test_new() {
        // Testing with a valid /dev/kvm descriptor.
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        Vm::new(&kvm).unwrap();
    }

    #[test]
    fn test_register_memory_regions() {
        let (_, mut vm) = setup_vm();

        // Trying to set a memory region with a size that is not a multiple of GUEST_PAGE_SIZE
        // will result in error.
        let gm = single_region_mem_raw(0x10);
        let res = vm.register_memory_regions(gm);
        assert_eq!(
            res.unwrap_err().to_string(),
            "Cannot set the memory regions: Invalid argument (os error 22)"
        );

        let gm = single_region_mem_raw(0x1000);
        let res = vm.register_memory_regions(gm);
        res.unwrap();
    }

    #[test]
    fn test_too_many_regions() {
        let (kvm, mut vm) = setup_vm();
        let max_nr_regions = kvm.max_nr_memslots();

        // SAFETY: valid mmap parameters
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                0x1000,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };

        assert_ne!(ptr, libc::MAP_FAILED);

        for i in 0..=max_nr_regions {
            // SAFETY: we assert above that the ptr is valid, and the size matches what we passed to
            // mmap
            let region = unsafe {
                MmapRegionBuilder::new(0x1000)
                    .with_raw_mmap_pointer(ptr.cast())
                    .build()
                    .unwrap()
            };

            let region = GuestRegionMmap::new(region, GuestAddress(i as u64 * 0x1000)).unwrap();

            let res = vm.register_memory_region(region);

            if max_nr_regions <= i {
                assert!(
                    matches!(res, Err(VmError::NotEnoughMemorySlots(v)) if v == max_nr_regions),
                    "{:?} at iteration {}",
                    res,
                    i
                );
            } else {
                res.unwrap_or_else(|_| {
                    panic!(
                        "to be able to insert more regions in iteration {i} - max_nr_memslots: \
                         {max_nr_regions} - num_regions: {}",
                        vm.guest_memory().num_regions()
                    )
                });
            }
        }
    }

    #[test]
    fn test_create_vcpus() {
        let vcpu_count = 2;
        let (_, mut vm) = setup_vm_with_memory(mib_to_bytes(128));

        let (vcpu_vec, _) = vm.create_vcpus(vcpu_count).unwrap();

        assert_eq!(vcpu_vec.len(), vcpu_count as usize);
    }

    fn enable_irqchip(vm: &mut Vm) {
        #[cfg(target_arch = "x86_64")]
        vm.setup_irqchip().unwrap();
        #[cfg(target_arch = "aarch64")]
        vm.setup_irqchip(1).unwrap();
    }

    fn create_msix_group(vm: &Arc<Vm>) -> MsiVectorGroup {
        Vm::create_msix_group(vm.clone(), 4).unwrap()
    }

    #[test]
    fn test_msi_vector_group_new() {
        let (_, vm) = setup_vm_with_memory(mib_to_bytes(128));
        let vm = Arc::new(vm);
        let msix_group = create_msix_group(&vm);
        assert_eq!(msix_group.num_vectors(), 4);
    }

    #[test]
    fn test_msi_vector_group_enable_disable() {
        let (_, mut vm) = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);
        let msix_group = create_msix_group(&vm);

        // Initially all vectors are disabled
        for route in &msix_group.irq_routes {
            assert!(!route.enabled.load(Ordering::Acquire))
        }

        // Enable works
        msix_group.enable().unwrap();
        for route in &msix_group.irq_routes {
            assert!(route.enabled.load(Ordering::Acquire));
        }
        // Enabling an enabled group doesn't error out
        msix_group.enable().unwrap();

        // Disable works
        msix_group.disable().unwrap();
        for route in &msix_group.irq_routes {
            assert!(!route.enabled.load(Ordering::Acquire))
        }
        // Disabling a disabled group doesn't error out
    }

    #[test]
    fn test_msi_vector_group_trigger() {
        let (_, mut vm) = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);

        let vm = Arc::new(vm);
        let msix_group = create_msix_group(&vm);

        // We can now trigger all vectors
        for i in 0..4 {
            msix_group.trigger(i).unwrap()
        }

        // We can't trigger an invalid vector
        msix_group.trigger(4).unwrap_err();
    }

    #[test]
    fn test_msi_vector_group_notifier() {
        let (_, vm) = setup_vm_with_memory(mib_to_bytes(128));
        let vm = Arc::new(vm);
        let msix_group = create_msix_group(&vm);

        for i in 0..4 {
            assert!(msix_group.notifier(i).is_some());
        }

        assert!(msix_group.notifier(4).is_none());
    }

    #[test]
    fn test_msi_vector_group_update_wrong_config() {
        let (_, vm) = setup_vm_with_memory(mib_to_bytes(128));
        let vm = Arc::new(vm);
        let msix_group = create_msix_group(&vm);
        let irq_config = LegacyIrqSourceConfig { irqchip: 0, pin: 0 };
        msix_group
            .update(0, InterruptSourceConfig::LegacyIrq(irq_config), true, true)
            .unwrap_err();
    }

    #[test]
    fn test_msi_vector_group_update_invalid_vector() {
        let (_, mut vm) = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);
        let msix_group = create_msix_group(&vm);
        let config = InterruptSourceConfig::MsiIrq(MsiIrqSourceConfig {
            high_addr: 0x42,
            low_addr: 0x12,
            data: 0x12,
            devid: 0xafa,
        });
        msix_group.update(0, config, true, true).unwrap();
        msix_group.update(4, config, true, true).unwrap_err();
    }

    #[test]
    fn test_msi_vector_group_update() {
        let (_, mut vm) = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);
        assert!(vm.common.interrupts.lock().unwrap().is_empty());
        let msix_group = create_msix_group(&vm);

        // Set some configuration for the vectors. Initially all are masked
        let mut config = MsiIrqSourceConfig {
            high_addr: 0x42,
            low_addr: 0x13,
            data: 0x12,
            devid: 0xafa,
        };
        for i in 0..4 {
            config.data = 0x12 * i;
            msix_group
                .update(i, InterruptSourceConfig::MsiIrq(config), true, false)
                .unwrap();
        }

        // All vectors should be disabled
        for vector in &msix_group.irq_routes {
            assert!(!vector.enabled.load(Ordering::Acquire));
        }

        for i in 0..4 {
            let gsi = crate::arch::GSI_MSI_START + i;
            let interrupts = vm.common.interrupts.lock().unwrap();
            let kvm_route = interrupts.get(&gsi).unwrap();
            assert!(kvm_route.masked);
            assert_eq!(kvm_route.entry.gsi, gsi);
            assert_eq!(kvm_route.entry.type_, KVM_IRQ_ROUTING_MSI);
            // SAFETY: because we know we setup MSI routes.
            unsafe {
                assert_eq!(kvm_route.entry.u.msi.address_hi, 0x42);
                assert_eq!(kvm_route.entry.u.msi.address_lo, 0x13);
                assert_eq!(kvm_route.entry.u.msi.data, 0x12 * i);
            }
        }

        // Simply enabling the vectors should not update the registered IRQ routes
        msix_group.enable().unwrap();
        for i in 0..4 {
            let gsi = crate::arch::GSI_MSI_START + i;
            let interrupts = vm.common.interrupts.lock().unwrap();
            let kvm_route = interrupts.get(&gsi).unwrap();
            assert!(kvm_route.masked);
            assert_eq!(kvm_route.entry.gsi, gsi);
            assert_eq!(kvm_route.entry.type_, KVM_IRQ_ROUTING_MSI);
            // SAFETY: because we know we setup MSI routes.
            unsafe {
                assert_eq!(kvm_route.entry.u.msi.address_hi, 0x42);
                assert_eq!(kvm_route.entry.u.msi.address_lo, 0x13);
                assert_eq!(kvm_route.entry.u.msi.data, 0x12 * i);
            }
        }

        // Updating the config of a vector should enable its route (and only its route)
        config.data = 0;
        msix_group
            .update(0, InterruptSourceConfig::MsiIrq(config), false, true)
            .unwrap();
        for i in 0..4 {
            let gsi = crate::arch::GSI_MSI_START + i;
            let interrupts = vm.common.interrupts.lock().unwrap();
            let kvm_route = interrupts.get(&gsi).unwrap();
            assert_eq!(kvm_route.masked, i != 0);
            assert_eq!(kvm_route.entry.gsi, gsi);
            assert_eq!(kvm_route.entry.type_, KVM_IRQ_ROUTING_MSI);
            // SAFETY: because we know we setup MSI routes.
            unsafe {
                assert_eq!(kvm_route.entry.u.msi.address_hi, 0x42);
                assert_eq!(kvm_route.entry.u.msi.address_lo, 0x13);
                assert_eq!(kvm_route.entry.u.msi.data, 0x12 * i);
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_msi_vector_group_set_gsi_without_ioapic() {
        // Setting GSI routes without IOAPIC setup should fail on x86. Apparently, it doesn't fail
        // on Aarch64
        let (_, vm) = setup_vm_with_memory(mib_to_bytes(128));
        let vm = Arc::new(vm);
        let msix_group = create_msix_group(&vm);
        let err = msix_group.set_gsi().unwrap_err();
        assert_eq!(
            format!("{err}"),
            "MSI-X update: KVM error: Invalid argument (os error 22)"
        );
    }

    #[test]
    fn test_msi_vector_group_set_gsi() {
        let (_, mut vm) = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);
        let msix_group = create_msix_group(&vm);

        msix_group.set_gsi().unwrap();
    }

    #[test]
    fn test_msi_vector_group_persistence() {
        let (_, mut vm) = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);
        let msix_group = create_msix_group(&vm);

        msix_group.enable().unwrap();
        let state = msix_group.save();
        let restored_group = MsiVectorGroup::restore(vm, &state).unwrap();

        assert_eq!(msix_group.num_vectors(), restored_group.num_vectors());
        // Even if an MSI group is enabled, we don't save it as such. During restoration, the PCI
        // transport will make sure the correct config is set for the vectors and enable them
        // accordingly.
        for (id, vector) in msix_group.irq_routes.iter().enumerate() {
            let new_vector = &restored_group.irq_routes[id];
            assert_eq!(vector.gsi, new_vector.gsi);
            assert!(!new_vector.enabled.load(Ordering::Acquire));
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_restore_state_resource_allocator() {
        use vm_allocator::AllocPolicy;

        let mut snapshot_data = vec![0u8; 10000];
        let (_, mut vm) = setup_vm_with_memory(0x1000);
        vm.setup_irqchip().unwrap();

        // Allocate a GSI and some memory and make sure they are still allocated after restore
        let (gsi, range) = {
            let mut resource_allocator = vm.resource_allocator();

            let gsi = resource_allocator.allocate_gsi_msi(1).unwrap()[0];
            let range = resource_allocator
                .allocate_32bit_mmio_memory(1024, 1024, AllocPolicy::FirstMatch)
                .unwrap();
            (gsi, range)
        };

        let state = vm.save_state().unwrap();
        Snapshot::new(state)
            .save(&mut snapshot_data.as_mut_slice())
            .unwrap();

        let restored_state: VmState = Snapshot::load_without_crc_check(snapshot_data.as_slice())
            .unwrap()
            .data;
        vm.restore_state(&restored_state).unwrap();

        let mut resource_allocator = vm.resource_allocator();
        let gsi_new = resource_allocator.allocate_gsi_msi(1).unwrap()[0];
        assert_eq!(gsi + 1, gsi_new);

        resource_allocator
            .allocate_32bit_mmio_memory(1024, 1024, AllocPolicy::ExactMatch(range))
            .unwrap_err();
        let range_new = resource_allocator
            .allocate_32bit_mmio_memory(1024, 1024, AllocPolicy::FirstMatch)
            .unwrap();
        assert_eq!(range + 1024, range_new);
    }
}
