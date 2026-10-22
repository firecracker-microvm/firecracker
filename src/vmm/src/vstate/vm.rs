// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Cursor, Seek, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};

#[cfg(target_arch = "x86_64")]
use kvm_bindings::KVM_IRQCHIP_IOAPIC;
use kvm_bindings::{
    KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI, KVM_MSI_VALID_DEVID, KvmIrqRouting,
    kvm_irq_routing_entry, kvm_userspace_memory_region,
};
use kvm_ioctls::VmFd;
use serde::{Deserialize, Serialize};
use userfaultfd::Uffd;
use vm_memory::bitmap::BitmapSlice;
use vm_memory::{GuestMemoryBackend, VolatileMemoryError, VolatileSlice, WriteVolatile};
use vmm_sys_util::errno;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::terminal::Terminal;

use crate::arch::{GSI_MSI_END, host_page_size};
pub use crate::arch::{KvmVm, KvmVmError, VmState};
use crate::logger::{debug, info};
use crate::pci::PciSBDF;
use crate::pci::msix::MsixTableEntry;
use crate::persist::CreateSnapshotError;
use crate::vmm_config::machine_config::HugePageConfig;
use crate::vmm_config::snapshot::SnapshotType;
use crate::vstate::bus::Bus;
use crate::vstate::interrupts::{InterruptError, MsixVector, MsixVectorGroup};
use crate::vstate::kvm::Kvm;
use crate::vstate::memory::{
    self, GuestMemoryExtension, GuestMemoryMmap, GuestMemoryRegion, GuestMemoryState,
    GuestRegionMmap, GuestRegionMmapExt, MemoryError,
};
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vcpu::{StartThreadedError, VcpuError, VcpuHandle};
use crate::{DirtyBitmap, Vcpu, mem_size_mib};

/// Error type for [`KvmVm::start_vcpus`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum StartVcpusError {
    /// Failed to set terminal mode: {0}
    SetTerminalMode(#[from] vmm_sys_util::errno::Error),
    /// Vcpu handle error: {0}
    VcpuHandle(#[from] StartThreadedError),
}

#[derive(Debug, Serialize, Deserialize)]
/// A struct representing an interrupt line used by some device of the microVM
pub struct RoutingEntry {
    entry: kvm_irq_routing_entry,
    masked: bool,
}

/// Architecture independent parts of a VM.
#[derive(Debug)]
pub struct VmCommon {
    /// The KVM file descriptor used to access this KvmVm.
    pub fd: VmFd,
    max_memslots: u32,
    /// The guest memory of this KvmVm.
    pub guest_memory: GuestMemoryMmap,
    next_kvm_slot: AtomicU32,
    /// Interrupts used by KvmVm's devices
    pub interrupts: Mutex<HashMap<u32, RoutingEntry>>,
    /// Allocator for VM resources
    pub resource_allocator: Mutex<ResourceAllocator>,
    /// MMIO bus
    pub mmio_bus: Arc<Bus>,
    /// The global KVM state (fd + capabilities).
    pub kvm: Kvm,
    /// Userfaultfd kept open for snapshot restore.
    pub uffd: Option<Uffd>,
    /// Handles to vCPU threads.
    pub vcpus_handles: Mutex<Vec<VcpuHandle>>,
    /// Event fd written to by vCPUs on exit.
    pub vcpus_exit_evt: EventFd,
    /// Test-only countdown that forces the Nth-next `set_user_memory_region` call to fail, used
    /// to exercise partial-failure handling. 0 means never fail.
    #[cfg(test)]
    fail_set_user_memory_region_in: AtomicU32,
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
    Arch(#[from] KvmVmError),
    /// Error during eventfd operations: {0}
    EventFd(std::io::Error),
    /// Failed to create vcpu: {0}
    CreateVcpu(VcpuError),
    /// The number of configured slots is bigger than the maximum reported by KVM: {0}
    NotEnoughMemorySlots(u32),
    /// Failed to add a memory region: {0}
    InsertRegion(#[from] vm_memory::GuestRegionCollectionError),
    /// Error calling mincore: {0}
    Mincore(vmm_sys_util::errno::Error),
    /// ResourceAllocator error: {0}
    ResourceAllocator(#[from] vm_allocator::Error),
    /// MemoryError error: {0}
    MemoryError(#[from] MemoryError),
}

/// VM abstraction: either a KVM-based VM or (in the future) a Nitro Enclave.
#[derive(Debug)]
pub enum Vm {
    /// KVM-backed virtual machine.
    Kvm(Arc<KvmVm>),
}

impl Vm {
    /// Returns the name of the VM type.
    pub fn type_name(&self) -> &'static str {
        match self {
            Vm::Kvm(_) => "Kvm",
        }
    }

    /// Returns a reference to the inner KVM VM, or `None` if this is not a KVM VM.
    pub fn as_kvm(&self) -> Option<&Arc<KvmVm>> {
        match self {
            Vm::Kvm(v) => Some(v),
        }
    }
}

/// Contains KvmVm functions that are usable across CPU architectures
impl KvmVm {
    /// Create a KVM VM
    pub fn create_common(kvm: Kvm) -> Result<VmCommon, VmError> {
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

        let vcpus_exit_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmError::EventFd)?;

        Ok(VmCommon {
            fd,
            max_memslots: kvm.max_nr_memslots(),
            guest_memory: GuestMemoryMmap::default(),
            next_kvm_slot: AtomicU32::new(0),
            interrupts: Mutex::new(HashMap::with_capacity(GSI_MSI_END as usize + 1)),
            resource_allocator: Mutex::new(ResourceAllocator::new()),
            mmio_bus: Arc::new(Bus::new()),
            kvm,
            uffd: None,
            vcpus_handles: Mutex::new(Vec::new()),
            vcpus_exit_evt,
            #[cfg(test)]
            fail_set_user_memory_region_in: AtomicU32::new(0),
        })
    }

    /// Creates the specified number of [`Vcpu`]s.
    ///
    /// Each vCPU gets a clone of the `vcpus_exit_evt` EventFd stored on this KvmVm.
    pub fn create_vcpus(&mut self, vcpu_count: u8) -> Result<Vec<Vcpu>, VmError> {
        self.arch_pre_create_vcpus(vcpu_count)?;

        let mut vcpus = Vec::with_capacity(vcpu_count as usize);
        for cpu_idx in 0..vcpu_count {
            let exit_evt = self
                .vcpus_exit_evt()
                .try_clone()
                .map_err(VmError::EventFd)?;
            let vcpu = Vcpu::new(cpu_idx, self, exit_evt).map_err(VmError::CreateVcpu)?;
            vcpus.push(vcpu);
        }

        self.arch_post_create_vcpus(vcpu_count)?;

        Ok(vcpus)
    }

    /// Returns a reference to the [`Kvm`] instance.
    pub fn kvm(&self) -> &Kvm {
        &self.common.kvm
    }

    /// Returns a reference to the vCPU exit [`EventFd`].
    pub fn vcpus_exit_evt(&self) -> &EventFd {
        &self.common.vcpus_exit_evt
    }

    /// Returns a locked reference to the vCPU handles.
    pub fn vcpus_handles(&self) -> MutexGuard<'_, Vec<VcpuHandle>> {
        self.common.vcpus_handles.lock().expect("Poisoned lock")
    }

    /// Sets the userfaultfd (used during snapshot restore).
    pub fn set_uffd(&mut self, uffd: Option<Uffd>) {
        self.common.uffd = uffd;
    }

    /// Starts the microVM vCPUs.
    ///
    /// Sets the terminal to raw/non-blocking mode, then spawns a thread per vCPU
    /// and stores the resulting handles. The barrier is used to synchronize TLS
    /// initialization across all vCPU threads before returning.
    pub fn start_vcpus(
        self: &Arc<Self>,
        mut vcpus: Vec<Vcpu>,
        vcpu_seccomp_filter: Arc<crate::seccomp::BpfProgram>,
    ) -> Result<(), StartVcpusError> {
        let vcpu_count = vcpus.len();
        let barrier = Arc::new(Barrier::new(vcpu_count + 1));

        let stdin = std::io::stdin().lock();
        stdin.set_raw_mode().inspect_err(|&err| {
            crate::logger::warn!("Cannot set raw mode for the terminal. {:?}", err);
        })?;
        stdin.set_non_block(true).inspect_err(|&err| {
            crate::logger::warn!("Cannot set non block for the terminal. {:?}", err);
        })?;

        let mut handles = self.vcpus_handles();
        handles.reserve(vcpu_count);
        for mut vcpu in vcpus.drain(..) {
            vcpu.set_mmio_bus(self.common.mmio_bus.clone());
            #[cfg(target_arch = "x86_64")]
            vcpu.kvm_vcpu.set_pio_bus(self.pio_bus.clone());

            handles.push(vcpu.start_threaded(
                self,
                vcpu_seccomp_filter.clone(),
                barrier.clone(),
            )?);
        }
        drop(handles);
        barrier.wait();

        Ok(())
    }

    /// Sends a pause event to all vCPUs and waits for acknowledgement.
    pub fn pause_vcpus(&self) -> Result<(), crate::VmmError> {
        let mut handles = self.vcpus_handles();
        handles
            .iter_mut()
            .try_for_each(|handle| handle.send_event(crate::VcpuEvent::Pause))
            .map_err(|_| crate::VmmError::VcpuMessage)?;

        if handles
            .iter()
            .map(|handle| {
                handle
                    .response_receiver()
                    .recv_timeout(crate::RECV_TIMEOUT_SEC)
            })
            .any(|response| !matches!(response, Ok(crate::VcpuResponse::Paused)))
        {
            return Err(crate::VmmError::VcpuMessage);
        }
        Ok(())
    }

    /// Sends a resume event to all vCPUs and waits for acknowledgement.
    pub fn resume_vcpus(&self) -> Result<(), crate::VmmError> {
        let mut handles = self.vcpus_handles();
        handles
            .iter_mut()
            .try_for_each(|handle| handle.send_event(crate::VcpuEvent::Resume))
            .map_err(|_| crate::VmmError::VcpuMessage)?;

        if handles
            .iter()
            .map(|handle| {
                handle
                    .response_receiver()
                    .recv_timeout(crate::RECV_TIMEOUT_SEC)
            })
            .any(|response| !matches!(response, Ok(crate::VcpuResponse::Resumed)))
        {
            return Err(crate::VmmError::VcpuMessage);
        }
        Ok(())
    }

    /// Saves vCPU states by requesting each vCPU thread to serialize its state.
    pub fn save_vcpu_states(
        &self,
    ) -> Result<Vec<crate::vstate::vcpu::VcpuState>, crate::persist::MicrovmStateError> {
        use crate::persist::MicrovmStateError;

        let mut handles = self.vcpus_handles();
        for handle in handles.iter_mut() {
            handle
                .send_event(crate::VcpuEvent::SaveState)
                .map_err(MicrovmStateError::SignalVcpu)?;
        }

        let vcpu_responses = handles
            .iter()
            .map(|handle| {
                handle
                    .response_receiver()
                    .recv_timeout(crate::RECV_TIMEOUT_SEC)
            })
            .collect::<Result<Vec<crate::VcpuResponse>, _>>()
            .map_err(|_| MicrovmStateError::UnexpectedVcpuResponse)?;

        vcpu_responses
            .into_iter()
            .map(|response| match response {
                crate::VcpuResponse::SavedState(state) => Ok(*state),
                crate::VcpuResponse::Error(err) => Err(MicrovmStateError::SaveVcpuState(err)),
                crate::VcpuResponse::NotAllowed(reason) => {
                    Err(MicrovmStateError::NotAllowed(reason))
                }
                _ => Err(MicrovmStateError::UnexpectedVcpuResponse),
            })
            .collect()
    }

    /// Dumps CPU configuration from all vCPU threads.
    pub fn dump_cpu_config_states(
        &self,
    ) -> Result<Vec<crate::cpu_config::templates::CpuConfiguration>, crate::DumpCpuConfigError>
    {
        use crate::DumpCpuConfigError;

        let mut handles = self.vcpus_handles();
        for handle in handles.iter_mut() {
            handle
                .send_event(crate::VcpuEvent::DumpCpuConfig)
                .map_err(DumpCpuConfigError::SendEvent)?;
        }

        let vcpu_responses = handles
            .iter()
            .map(|handle| {
                handle
                    .response_receiver()
                    .recv_timeout(crate::RECV_TIMEOUT_SEC)
            })
            .collect::<Result<Vec<crate::VcpuResponse>, _>>()
            .map_err(|_| DumpCpuConfigError::UnexpectedResponse)?;

        vcpu_responses
            .into_iter()
            .map(|response| match response {
                crate::VcpuResponse::DumpedCpuConfig(cpu_config) => Ok(*cpu_config),
                crate::VcpuResponse::Error(err) => Err(DumpCpuConfigError::DumpCpuConfig(err)),
                crate::VcpuResponse::NotAllowed(reason) => {
                    Err(DumpCpuConfigError::NotAllowed(reason))
                }
                _ => Err(DumpCpuConfigError::UnexpectedResponse),
            })
            .collect()
    }

    /// Sends finish events to all vCPU threads and joins them.
    pub fn shutdown_vcpus(&self) {
        let mut handles = self.vcpus_handles();
        for (idx, handle) in handles.iter_mut().enumerate() {
            if let Err(err) = handle.send_event(crate::VcpuEvent::Finish) {
                crate::logger::error!("Failed to send VcpuEvent::Finish to vCPU {}: {}", idx, err);
            }
        }
        // Join the vCPU threads by running VcpuHandle::drop().
        handles.clear();
    }

    /// Reserves the next `slot_cnt` contiguous kvm slot ids and returns the first one
    pub fn next_kvm_slot(&self, slot_cnt: u32) -> Option<u32> {
        let next = self
            .common
            .next_kvm_slot
            .fetch_add(slot_cnt, Ordering::Relaxed);
        if self.common.max_memslots <= next {
            None
        } else {
            Some(next)
        }
    }

    pub(crate) fn set_user_memory_region(
        &self,
        region: kvm_userspace_memory_region,
    ) -> Result<(), VmError> {
        #[cfg(test)]
        if self.common.fail_set_user_memory_region_in.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |n| (n > 0).then(|| n - 1),
        ) == Ok(1)
        {
            return Err(VmError::SetUserMemoryRegion(kvm_ioctls::Error::new(
                libc::ENOMEM,
            )));
        }
        // SAFETY: Safe because the fd is a valid KVM file descriptor.
        unsafe {
            self.fd()
                .set_user_memory_region(region)
                .map_err(VmError::SetUserMemoryRegion)
        }
    }

    /// Test-only: arm the fault injector so the `n`th subsequent call to
    /// [`Self::set_user_memory_region`] fails (n == 1 fails the very next call).
    #[cfg(test)]
    pub(crate) fn fail_next_set_user_memory_region(&self, n: u32) {
        self.common
            .fail_set_user_memory_region_in
            .store(n, Ordering::Relaxed);
    }

    fn register_memory_region(&mut self, region: Arc<GuestRegionMmapExt>) -> Result<(), VmError> {
        let new_guest_memory = self
            .common
            .guest_memory
            .insert_region(Arc::clone(&region))?;

        region
            .slots()
            .try_for_each(|(ref slot, plugged)| match plugged {
                // if the slot is plugged, add it to kvm user memory regions
                true => self.set_user_memory_region(slot.into()),
                // if the slot is not plugged, protect accesses to it
                false => slot.protect(true).map_err(VmError::MemoryError),
            })?;

        self.common.guest_memory = new_guest_memory;

        Ok(())
    }

    /// Register a list of new memory regions to this [`KvmVm`].
    pub fn register_dram_memory_regions(
        &mut self,
        regions: Vec<GuestRegionMmap>,
    ) -> Result<(), VmError> {
        for region in regions {
            let next_slot = self
                .next_kvm_slot(1)
                .ok_or(VmError::NotEnoughMemorySlots(self.common.max_memslots))?;

            let arcd_region =
                Arc::new(GuestRegionMmapExt::dram_from_mmap_region(region, next_slot));

            self.register_memory_region(arcd_region)?
        }

        Ok(())
    }

    /// Register a new hotpluggable region to this [`KvmVm`].
    pub fn register_hotpluggable_memory_region(
        &mut self,
        region: GuestRegionMmap,
        slot_size: usize,
    ) -> Result<(), VmError> {
        // caller should ensure the slot size divides the region length.
        assert!(region.len().is_multiple_of(slot_size as u64));
        let slot_cnt = (region.len() / (slot_size as u64))
            .try_into()
            .map_err(|_| VmError::NotEnoughMemorySlots(self.common.max_memslots))?;
        let slot_from = self
            .next_kvm_slot(slot_cnt)
            .ok_or(VmError::NotEnoughMemorySlots(self.common.max_memslots))?;
        let arcd_region = Arc::new(GuestRegionMmapExt::hotpluggable_from_mmap_region(
            region, slot_from, slot_size,
        ));

        self.register_memory_region(arcd_region)
    }

    /// Register a list of new memory regions to this [`KvmVm`].
    ///
    /// Note: regions and state.regions need to be in the same order.
    pub fn restore_memory_regions(
        &mut self,
        regions: Vec<GuestRegionMmap>,
        state: &GuestMemoryState,
    ) -> Result<(), VmError> {
        for (region, state) in regions.into_iter().zip(state.regions.iter()) {
            let slot_cnt = state
                .plugged
                .len()
                .try_into()
                .map_err(|_| VmError::NotEnoughMemorySlots(self.common.max_memslots))?;

            let next_slot = self
                .next_kvm_slot(slot_cnt)
                .ok_or(VmError::NotEnoughMemorySlots(self.common.max_memslots))?;

            let arcd_region = Arc::new(GuestRegionMmapExt::from_state(region, state, next_slot)?);

            self.register_memory_region(arcd_region)?
        }

        Ok(())
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    pub fn fd(&self) -> &VmFd {
        &self.common.fd
    }

    /// Gets a reference to this [`KvmVm`]'s [`GuestMemoryMmap`] object
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.common.guest_memory
    }

    /// Whether a vhost-user backend can map this VM's guest memory.
    ///
    /// Guest memory is a shared memfd mapping only when a vhost-user device is
    /// configured before boot. Otherwise it is anonymous, or a private mapping
    /// of a read-only snapshot file, which a backend cannot map at all.
    pub fn vhost_user_memory_shareable(&self) -> bool {
        // Never empty after boot, so `all` cannot pass vacuously.
        self.guest_memory()
            .iter()
            .all(|r| r.is_shared() && r.file_offset().is_some())
    }

    /// Gets a mutable reference to this [`KvmVm`]'s [`ResourceAllocator`] object
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
            .flat_map(|region| region.plugged_slots())
            .for_each(|mem_slot| {
                let _ = self.fd().get_dirty_log(mem_slot.slot, mem_slot.slice.len());
            });
    }

    /// Retrieves the KVM dirty bitmap for each of the guest's memory regions.
    pub fn get_dirty_bitmap(&self) -> Result<DirtyBitmap, VmError> {
        self.guest_memory()
            .iter()
            .flat_map(|region| region.plugged_slots())
            .map(|mem_slot| {
                let bitmap = match mem_slot.slice.bitmap() {
                    Some(_) => self
                        .fd()
                        .get_dirty_log(mem_slot.slot, mem_slot.slice.len())
                        .map_err(VmError::GetDirtyLog)?,
                    None => mincore_bitmap(
                        mem_slot.slice.ptr_guard_mut().as_ptr(),
                        mem_slot.slice.len(),
                    )?,
                };
                Ok((mem_slot.slot, bitmap))
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
        sync_snapshot_files: bool,
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

        let file_size = file
            .metadata()
            .map_err(|e| MemoryBackingFile("get_metadata", e))?
            .len();

        let hugetlbfs_page_size = memory::hugetlbfs_page_size(&file)?;
        if let Some(page_size) = hugetlbfs_page_size {
            // hugetlbfs does not report holes, so a separate diff layer cannot tell unchanged pages
            // from zero pages. A diff must be merged into an existing memory file instead.
            if snapshot_type == SnapshotType::Diff && !(file_existed && file_size == expected_size)
            {
                return Err(HugetlbfsDiffLayer);
            }
            memory::validate_snapshot_file_page_size(
                Some(page_size),
                HugePageConfig::Hugetlbfs2M,
                &self.guest_memory().describe().regions(),
            )?;
            // hugetlbfs files are written through a shared writable mapping, which requires a
            // file descriptor open for both reading and writing. Keep the existing write-only
            // behavior for regular snapshot files.
            file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(mem_file_path)
                .map_err(|err| MemoryBackingFile("open_read_write", err))?;
        }

        if file_existed {
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

        if let Some(page_size) = hugetlbfs_page_size {
            self.snapshot_memory_via_mmap(&file, expected_size, snapshot_type, page_size)?;
        } else {
            self.dump_memory(&mut file, snapshot_type)?;
            file.flush()
                .map_err(|err| MemoryBackingFile("flush", err))?;
        }
        if sync_snapshot_files {
            file.sync_all()
                .map_err(|err| MemoryBackingFile("sync_all", err))?;
        }
        Ok(())
    }

    /// Writes all of guest memory ([`SnapshotType::Full`]) or only its dirty pages
    /// ([`SnapshotType::Diff`]) to `writer`, laid out as a snapshot memory file.
    fn dump_memory<W: WriteVolatile + Seek>(
        &self,
        writer: &mut W,
        snapshot_type: SnapshotType,
    ) -> Result<(), CreateSnapshotError> {
        match snapshot_type {
            SnapshotType::Diff => {
                let dirty_bitmap = self.get_dirty_bitmap()?;
                self.guest_memory().dump_dirty(writer, &dirty_bitmap)?;
            }
            SnapshotType::Full => {
                self.guest_memory().dump(writer)?;
                self.reset_dirty_bitmap();
                self.guest_memory().reset_dirty();
            }
        }
        Ok(())
    }

    /// Writes guest memory into a hugetlbfs snapshot file through a temporary shared mapping,
    /// since hugetlbfs does not implement `write(2)`.
    ///
    /// A full snapshot leaves zero huge pages as holes, punching them in case the file is reused,
    /// so the file only takes pool pages for memory the guest holds.
    fn snapshot_memory_via_mmap(
        &self,
        file: &std::fs::File,
        size: u64,
        snapshot_type: SnapshotType,
        page_size: usize,
    ) -> Result<(), CreateSnapshotError> {
        use self::CreateSnapshotError::*;

        let size = usize::try_from(size).map_err(|_| MemoryError::OffsetTooLarge)?;

        // MAP_NORESERVE: hugetlbfs would otherwise reserve huge pages for the whole file, including
        // its holes. `HugetlbfsWriter` allocates the pages it writes instead.
        // SAFETY: `file` is open for reading and writing, its length was set to `size`, `size` is
        // non-zero and page-aligned, and the mapping is checked against `MAP_FAILED` before use.
        let destination = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_NORESERVE,
                file.as_raw_fd(),
                0,
            )
        };
        if destination == libc::MAP_FAILED {
            return Err(MemoryBackingFile("mmap", std::io::Error::last_os_error()));
        }

        let dump_result = {
            // SAFETY: `destination` is a writable mapping of exactly `size` bytes. Firecracker's
            // guest-memory size is bounded below `isize::MAX`, and this slice does not outlive the
            // mapping or alias any other Rust reference.
            let destination =
                unsafe { std::slice::from_raw_parts_mut(destination.cast::<u8>(), size) };
            let mut destination = HugetlbfsWriter {
                file,
                page_size: page_size as u64,
                mapping: Cursor::new(destination),
            };
            match snapshot_type {
                SnapshotType::Diff => self.dump_memory(&mut destination, snapshot_type),
                SnapshotType::Full => self
                    .guest_memory()
                    .dump_skipping_zero_chunks(&mut destination, page_size, |offset, len| {
                        punch_hole(file, offset, len)
                    })
                    .map(|()| {
                        self.reset_dirty_bitmap();
                        self.guest_memory().reset_dirty();
                    })
                    .map_err(CreateSnapshotError::from),
            }
        };

        // SAFETY: `destination` and `size` describe the successful mapping above, and all Rust
        // references into the mapping were dropped at the end of the block above.
        let unmap_result = unsafe { libc::munmap(destination, size) };

        dump_result?;
        if unmap_result != 0 {
            return Err(MemoryBackingFile("munmap", std::io::Error::last_os_error()));
        }

        Ok(())
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
        route: &MsixVector,
        table_entry: &MsixTableEntry,
        pci_sbdf: PciSBDF,
    ) -> Result<(), errno::Error> {
        let mut entry = kvm_irq_routing_entry {
            gsi: route.gsi,
            type_: KVM_IRQ_ROUTING_MSI,
            ..Default::default()
        };
        entry.u.msi.address_lo = table_entry.msg_addr_lo;
        entry.u.msi.address_hi = table_entry.msg_addr_hi;
        entry.u.msi.data = table_entry.msg_data;

        if self.common.fd.check_extension(kvm_ioctls::Cap::MsiDevid) {
            entry.flags = KVM_MSI_VALID_DEVID;
            entry.u.msi.__bindgen_anon_1.devid = pci_sbdf.into();
        }

        self.common
            .interrupts
            .lock()
            .expect("Poisoned lock")
            .insert(
                route.gsi,
                RoutingEntry {
                    entry,
                    masked: table_entry.masked(),
                },
            );

        Ok(())
    }

    /// Create a group of MSI-X interrupts
    pub fn create_msix_group(
        vm: Arc<KvmVm>,
        count: u16,
    ) -> Result<MsixVectorGroup, InterruptError> {
        debug!("Creating new MSI group with {count} vectors");
        let mut vectors = Vec::with_capacity(count as usize);
        for gsi in vm
            .resource_allocator()
            .allocate_gsi_msi(count as u32)?
            .iter()
        {
            vectors.push(MsixVector::new(*gsi, false)?);
        }

        Ok(MsixVectorGroup { vm, vectors })
    }

    /// Set GSI routes to KVM
    pub fn set_gsi_routes(&self) -> Result<(), InterruptError> {
        let entries = self.common.interrupts.lock().expect("Poisoned lock");
        let unmasked = entries.values().filter(|e| !e.masked).count();
        let mut routes = KvmIrqRouting::new(unmasked)?;
        for (slot, entry) in entries.values().filter(|e| !e.masked).enumerate() {
            routes.as_mut_slice()[slot] = entry.entry;
        }

        self.common.fd.set_gsi_routing(&routes)?;
        Ok(())
    }
}

/// Use `mincore(2)` to overapproximate the dirty bitmap for the given memslot. To be used
/// if a diff snapshot is requested, but dirty page tracking wasn't enabled.
fn mincore_bitmap(addr: *mut u8, len: usize) -> Result<Vec<u64>, VmError> {
    // TODO: Once Host 5.10 goes out of support, we can make this more robust and work on
    // swap-enabled systems, by doing mlock2(MLOCK_ONFAULT)/munlock() in this function (to
    // force swapped-out pages to get paged in, so that mincore will consider them incore).
    // However, on AMD (m6a/m7a) 5.10, doing so introduces a 100%/30ms regression to snapshot
    // creation, even if swap is disabled, so currently it cannot be done.

    // Mincore always works at PAGE_SIZE granularity, even if the VMA we are dealing with
    // is a hugetlbfs VMA (e.g. to report a single hugepage as "present", mincore will
    // give us 512 4k markers with the lowest bit set).
    let page_size = host_page_size();
    let mut mincore_bitmap = vec![0u8; len / page_size];
    let mut bitmap = vec![0u64; (len / page_size).div_ceil(64)];

    // SAFETY: The safety invariants of GuestRegionMmap ensure that region.as_ptr() is a valid
    // userspace mapping of size region.len() bytes. The bitmap has exactly one byte for each
    // page in this userspace mapping. Note that mincore does not operate on bitmaps like
    // KVM_MEM_LOG_DIRTY_PAGES, but rather it uses 8 bits per page (e.g. 1 byte), setting the
    // least significant bit to 1 if the page corresponding to a byte is in core (available in
    // the page cache and resolvable via just a minor page fault).
    let r = unsafe { libc::mincore(addr.cast(), len, mincore_bitmap.as_mut_ptr()) };

    if r != 0 {
        return Err(VmError::Mincore(vmm_sys_util::errno::Error::last()));
    }

    for (page_idx, b) in mincore_bitmap.iter().enumerate() {
        bitmap[page_idx / 64] |= (*b as u64 & 0x1) << (page_idx as u64 % 64);
    }

    Ok(bitmap)
}

/// Calls `fallocate(2)` on `len` bytes of `file` at `offset`, keeping its size.
fn fallocate(
    file: &std::fs::File,
    mode: libc::c_int,
    offset: u64,
    len: u64,
) -> std::io::Result<()> {
    let offset = libc::off_t::try_from(offset).map_err(std::io::Error::other)?;
    let len = libc::off_t::try_from(len).map_err(std::io::Error::other)?;
    // SAFETY: `file` owns a valid file descriptor, and `fallocate` only changes its allocation.
    let ret = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            mode | libc::FALLOC_FL_KEEP_SIZE,
            offset,
            len,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Deallocates `len` bytes of `file` at `offset`, keeping its size, so the range reads as zeros.
fn punch_hole(file: &std::fs::File, offset: u64, len: usize) -> Result<(), MemoryError> {
    fallocate(file, libc::FALLOC_FL_PUNCH_HOLE, offset, len as u64).map_err(MemoryError::PunchHole)
}

/// Writes into a `MAP_NORESERVE` shared mapping of a hugetlbfs file.
///
/// Writing to a huge page that the pool cannot provide would raise `SIGBUS`, so each write first
/// allocates the pages it covers, which fails with `ENOSPC` instead.
struct HugetlbfsWriter<'a> {
    file: &'a std::fs::File,
    page_size: u64,
    mapping: Cursor<&'a mut [u8]>,
}

impl WriteVolatile for HugetlbfsWriter<'_> {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        buf: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        let len = self.mapping.get_ref().len() as u64;
        let start = self.mapping.position().min(len);
        let end = start.saturating_add(buf.len() as u64).min(len);
        let aligned_start = start - start % self.page_size;
        let aligned_end = end.div_ceil(self.page_size) * self.page_size;
        if aligned_end > aligned_start {
            fallocate(self.file, 0, aligned_start, aligned_end - aligned_start)
                .map_err(VolatileMemoryError::IOError)?;
        }
        self.mapping.write_volatile(buf)
    }
}

impl Seek for HugetlbfsWriter<'_> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.mapping.seek(pos)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::assert_matches;
    use std::sync::atomic::Ordering;

    use vm_memory::GuestAddress;

    use super::*;
    use crate::arch;
    use crate::pci::PciSBDF;
    use crate::pci::msix::MsixTableEntry;
    use crate::snapshot::Persist;
    use crate::test_utils::single_region_mem_raw;
    use crate::utils::mib_to_bytes;
    use crate::vmm_config::machine_config::HugePageConfig;
    use crate::vstate::kvm::Kvm;
    use crate::vstate::memory::anonymous;

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm() -> KvmVm {
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        KvmVm::new(kvm).expect("Cannot create new vm")
    }

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm_with_memory(mem_size: usize) -> KvmVm {
        let mut vm = setup_vm();
        let gm = single_region_mem_raw(mem_size);
        vm.register_dram_memory_regions(gm).unwrap();
        vm
    }

    #[test]
    fn test_vhost_user_memory_shareable() {
        // Anonymous: what a VM booted without a vhost-user device gets.
        let vm = setup_vm_with_memory(mib_to_bytes(128));
        assert!(!vm.vhost_user_memory_shareable());

        // memfd-backed: what a VM configured with a vhost-user block before boot
        // gets.
        let mut vm = setup_vm();
        let regions = arch::arch_memory_regions(mib_to_bytes(128));
        let total: u64 = regions.iter().map(|&(_, size)| size as u64).sum();
        let gm = crate::vstate::memory::MemfdBacking::new(total, HugePageConfig::None)
            .unwrap()
            .allocate(&regions, false, HugePageConfig::None)
            .unwrap();
        vm.register_dram_memory_regions(gm).unwrap();
        assert!(vm.vhost_user_memory_shareable());

        // A snapshot file is mapped private: it has a descriptor and must still be
        // rejected.
        let mut vm = setup_vm();
        let file = vmm_sys_util::tempfile::TempFile::new().unwrap().into_file();
        let regions = arch::arch_memory_regions(mib_to_bytes(128));
        let total: u64 = regions.iter().map(|&(_, size)| size as u64).sum();
        file.set_len(total).unwrap();
        let gm = crate::vstate::memory::snapshot_file(file, &regions, false, HugePageConfig::None)
            .unwrap();
        vm.register_dram_memory_regions(gm).unwrap();
        assert!(!vm.vhost_user_memory_shareable());
    }

    #[test]
    fn test_new() {
        // Testing with a valid /dev/kvm descriptor.
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        KvmVm::new(kvm).unwrap();
    }

    #[test]
    fn test_register_memory_regions() {
        let mut vm = setup_vm();

        // Trying to set a memory region with a size that is not a multiple of GUEST_PAGE_SIZE
        // will result in error.
        let gm = single_region_mem_raw(0x10);
        let res = vm.register_dram_memory_regions(gm);
        assert_eq!(
            res.unwrap_err().to_string(),
            "Cannot set the memory regions: Invalid argument (os error 22)"
        );

        let gm = single_region_mem_raw(0x1000);
        let res = vm.register_dram_memory_regions(gm);
        res.unwrap();
    }

    #[test]
    fn test_too_many_regions() {
        let mut vm = setup_vm();
        let max_nr_regions = vm.kvm().max_nr_memslots();

        for i in 0..=max_nr_regions {
            let regions = anonymous(
                &[(GuestAddress(i as u64 * 0x1000), 0x1000)],
                false,
                HugePageConfig::None,
            )
            .unwrap();
            assert_eq!(regions.len(), 1);

            let res = vm.register_dram_memory_regions(regions);

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
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));

        let vcpu_vec = vm.create_vcpus(vcpu_count).unwrap();

        assert_eq!(vcpu_vec.len(), vcpu_count as usize);
    }

    fn enable_irqchip(vm: &mut KvmVm) {
        #[cfg(target_arch = "x86_64")]
        vm.setup_irqchip().unwrap();
        #[cfg(target_arch = "aarch64")]
        vm.setup_irqchip(1).unwrap();
    }

    #[test]
    fn test_msi_vector_group_new() {
        let vm = setup_vm_with_memory(mib_to_bytes(128));
        let vm = Arc::new(vm);
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();
        assert_eq!(msix_group.num_vectors(), 4);
    }

    /// Enable all vectors MSI-X vector group
    pub fn enable_all_vectors(vector_group: &MsixVectorGroup) {
        for route in &vector_group.vectors {
            route.enable(&vector_group.vm.common.fd).unwrap();
        }
    }

    #[test]
    fn test_msi_vector_group_disable() {
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();

        // Initially all vectors are disabled
        for route in &msix_group.vectors {
            assert!(!route.enabled.load(Ordering::Acquire))
        }
        // Enabling vectors
        enable_all_vectors(&msix_group);

        // Disable works
        msix_group.disable().unwrap();
        for route in &msix_group.vectors {
            assert!(!route.enabled.load(Ordering::Acquire))
        }
        // Disabling a disabled group doesn't error out
    }

    #[test]
    fn test_msi_vector_group_trigger() {
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);

        let vm = Arc::new(vm);
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();

        // We can now trigger all vectors
        for i in 0..4 {
            msix_group.trigger(i).unwrap()
        }

        // We can't trigger an invalid vector
        msix_group.trigger(4).unwrap_err();
    }

    #[test]
    fn test_msi_vector_group_notifier() {
        let vm = setup_vm_with_memory(mib_to_bytes(128));
        let vm = Arc::new(vm);
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();

        for i in 0..4 {
            assert!(msix_group.notifier(i).is_some());
        }

        assert!(msix_group.notifier(4).is_none());
    }

    #[test]
    fn test_msi_vector_group_update_invalid_vector() {
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();
        let sbdf = PciSBDF::from(0xafa);
        let config = MsixTableEntry {
            msg_addr_hi: 0x42,
            msg_addr_lo: 0x12,
            msg_data: 0x12,
            // Masked
            vector_ctl: 0x1,
        };
        msix_group.update(0, &config, sbdf).unwrap();
        assert_matches!(
            msix_group.update(4, &config, sbdf),
            Err(InterruptError::InvalidVectorIndex(4)),
        );
    }

    #[test]
    fn test_msi_vector_group_update() {
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);
        assert!(vm.common.interrupts.lock().unwrap().is_empty());
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();
        let pci_sbdf = PciSBDF::from(0xafa);

        // Set some configuration for the vectors. Initially all are masked
        let configs: [_; 4] = std::array::from_fn(|idx| MsixTableEntry {
            msg_addr_hi: 0x42,
            msg_addr_lo: 0x13,
            msg_data: 0x12 * u32::try_from(idx).unwrap(),
            vector_ctl: 0x1, // Masked
        });
        msix_group.update_batched(&configs, pci_sbdf).unwrap();

        // All vectors should be disabled
        for vector in &msix_group.vectors {
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
        enable_all_vectors(&msix_group);
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
            assert!(
                msix_group.vectors[i as usize]
                    .enabled
                    .load(Ordering::Acquire)
            );
        }
        msix_group.disable().unwrap();

        let unmasked0 = MsixTableEntry {
            vector_ctl: 0x0, // un-masked
            ..configs[0].clone()
        };
        let unmasked1 = MsixTableEntry {
            vector_ctl: 0x0, // un-masked
            ..configs[1].clone()
        };
        // `update` and `register` will update the in-memory GSI config of its route (and only its route)
        msix_group.update(0, &unmasked0, pci_sbdf).unwrap();
        msix_group.register(1, &unmasked1, pci_sbdf).unwrap();
        for i in 0..4 {
            let gsi = crate::arch::GSI_MSI_START + i;
            let interrupts = vm.common.interrupts.lock().unwrap();
            let kvm_route = interrupts.get(&gsi).unwrap();
            assert_eq!(kvm_route.masked, i >= 2);
            assert_eq!(kvm_route.entry.gsi, gsi);
            assert_eq!(kvm_route.entry.type_, KVM_IRQ_ROUTING_MSI);
            // SAFETY: because we know we setup MSI routes.
            unsafe {
                assert_eq!(kvm_route.entry.u.msi.address_hi, 0x42);
                assert_eq!(kvm_route.entry.u.msi.address_lo, 0x13);
                assert_eq!(kvm_route.entry.u.msi.data, 0x12 * i);
            }
            // However, only `update` (first vector) will actually enable be enabled
            assert_eq!(
                msix_group.vectors[i as usize]
                    .enabled
                    .load(Ordering::Acquire),
                i == 0,
            );
        }
    }

    #[test]
    fn test_msi_vector_group_persistence() {
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();

        enable_all_vectors(&msix_group);
        let state = msix_group.save();

        // On the real restore path the allocator state omits MSI GSIs before devices replay
        // their allocations. Mimic that here so `restore` can re-claim the saved GSIs.
        let allocator_state = vm.resource_allocator().save();
        *vm.resource_allocator() = ResourceAllocator::restore((), &allocator_state).unwrap();
        let restored_group = MsixVectorGroup::restore(vm.clone(), &state).unwrap();

        assert_eq!(msix_group.num_vectors(), restored_group.num_vectors());
        // Even if an MSI group is enabled, we don't save it as such. During restoration, the PCI
        // transport will make sure the correct config is set for the vectors and enable them
        // accordingly.
        for (id, vector) in msix_group.vectors.iter().enumerate() {
            let new_vector = &restored_group.vectors[id];
            assert_eq!(vector.gsi, new_vector.gsi);
            assert!(!new_vector.enabled.load(Ordering::Acquire));
        }

        // Both groups own the same GSIs in this test so dropping both will result in panic. Resolve
        // this by simply forgetting about the restored version.
        std::mem::forget(restored_group);
    }

    #[test]
    fn test_msi_vector_group_restore_rejects_out_of_range_gsi() {
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);

        // A snapshot with a GSI outside the managed MSI range must be rejected rather than panic
        // when the GSI is later freed on drop.
        let tampered_state = vec![arch::GSI_MSI_END + 1];
        MsixVectorGroup::restore(vm.clone(), &tampered_state).unwrap_err();
    }

    #[test]
    fn test_msi_vector_group_drop_frees_gsis() {
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);

        let gsis_before = vm.resource_allocator().allocate_gsi_msi(1).unwrap();
        for id in gsis_before.iter() {
            vm.resource_allocator()
                .gsi_msi_allocator
                .free_id(*id)
                .unwrap();
        }

        // Allocating, configuring and dropping a group must leave the allocator and the routing
        // table in the same state as before.
        {
            let group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();
            let table_entry = MsixTableEntry {
                msg_addr_hi: 0x42,
                msg_addr_lo: 0x13,
                msg_data: 0x12,
                // Unmasked
                vector_ctl: 0x0,
            };
            let table_entries = vec![table_entry.clone(); 4];
            group
                .update_batched(&table_entries, PciSBDF::from(0xafa))
                .unwrap();
            assert_eq!(vm.common.interrupts.lock().unwrap().len(), 4);
        }

        assert!(vm.common.interrupts.lock().unwrap().is_empty());
        let gsis_after = vm.resource_allocator().allocate_gsi_msi(1).unwrap();
        assert_eq!(gsis_before, gsis_after);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_restore_state_resource_allocator() {
        use vm_allocator::AllocPolicy;

        let mut vm = setup_vm_with_memory(0x1000);
        vm.setup_irqchip().unwrap();

        // Allocate a GSI and some memory.
        let (gsi, range) = {
            let mut resource_allocator = vm.resource_allocator();

            let gsi = resource_allocator.allocate_gsi_msi(1).unwrap()[0];
            let range = resource_allocator
                .mmio32_memory
                .allocate(1024, 1024, AllocPolicy::FirstMatch)
                .unwrap();
            (gsi, range.start())
        };

        let state = vm.save_state().unwrap();
        let serialized_data = bitcode::serialize(&state).unwrap();

        let restored_state: VmState = bitcode::deserialize(&serialized_data).unwrap();
        vm.restore_state(&restored_state, false).unwrap();

        let mut resource_allocator = vm.resource_allocator();

        // The MSI GSI allocator is reset on restore (its allocations are replayed by the devices),
        // so the previously allocated GSI is free again and is the first one handed out.
        let gsi_new = resource_allocator.allocate_gsi_msi(1).unwrap()[0];
        assert_eq!(gsi, gsi_new);

        // Memory allocations, on the other hand, are restored from the serialized state, so the
        // range allocated before the snapshot is still reserved.
        resource_allocator
            .mmio32_memory
            .allocate(1024, 1024, AllocPolicy::ExactMatch(range))
            .unwrap_err();
        let range_new = resource_allocator
            .mmio32_memory
            .allocate(1024, 1024, AllocPolicy::FirstMatch)
            .unwrap();
        assert_eq!(range + 1024, range_new.start());
    }

    /// Returns a path for a new file on a 2 MiB hugetlbfs mount, if the host has one and at least
    /// `pages` free huge pages.
    fn hugetlbfs_snapshot_path(name: &str, pages: usize) -> Option<std::path::PathBuf> {
        if memory::tests::free_hugepages_2m() < pages {
            return None;
        }
        let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
        let mount = mounts
            .lines()
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            .find(|fields| {
                fields.len() > 3
                    && fields[2] == "hugetlbfs"
                    && fields[3].split(',').any(|option| option == "pagesize=2M")
            })?;
        Some(Path::new(mount[1]).join(format!("fc-test-{}-{name}", std::process::id())))
    }

    #[test]
    fn test_hugetlbfs_diff_snapshot_merges_into_existing_file() {
        use std::os::unix::fs::MetadataExt;

        use vm_memory::Bytes;

        let page_size = HugePageConfig::Hugetlbfs2M.page_size();
        let mem_size = 3 * page_size;
        // The full snapshot allocates two huge pages and leaves the third as a hole.
        let Some(path) = hugetlbfs_snapshot_path("diff-merge", 2) else {
            println!("Skipping: no 2 MiB hugetlbfs mount with two free huge pages");
            return;
        };
        let vm = setup_vm_with_memory(mem_size);

        // A separate diff layer is rejected.
        assert_matches!(
            vm.snapshot_memory_to_file(&path, SnapshotType::Diff, false),
            Err(CreateSnapshotError::HugetlbfsDiffLayer)
        );

        // Page 0 does not change after the full snapshot; page 1 does.
        vm.guest_memory().write(&[1; 8], GuestAddress(0)).unwrap();
        vm.guest_memory()
            .write(&[2; 8], GuestAddress(page_size as u64))
            .unwrap();
        vm.snapshot_memory_to_file(&path, SnapshotType::Full, false)
            .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().blocks() * 512,
            2 * page_size as u64
        );
        vm.guest_memory()
            .write(&[3; 8], GuestAddress(page_size as u64))
            .unwrap();

        // A diff merged into the full snapshot keeps unchanged memory and adds the changes.
        vm.snapshot_memory_to_file(&path, SnapshotType::Diff, false)
            .unwrap();
        let mut expected = vec![0; mem_size];
        expected[..8].copy_from_slice(&[1; 8]);
        expected[page_size..page_size + 8].copy_from_slice(&[3; 8]);
        assert!(std::fs::read(&path).unwrap() == expected);

        // A diff into a memory file of another size is rejected, and the file is left intact.
        let larger_vm = setup_vm_with_memory(2 * mem_size);
        assert_matches!(
            larger_vm.snapshot_memory_to_file(&path, SnapshotType::Diff, false),
            Err(CreateSnapshotError::HugetlbfsDiffLayer)
        );
        assert!(std::fs::read(&path).unwrap() == expected);

        std::fs::remove_file(&path).unwrap();
    }
}
