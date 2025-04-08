// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::FromRawFd;
use std::path::Path;
use std::sync::Arc;

use kvm_bindings::{
    KVM_MEMORY_ATTRIBUTE_PRIVATE, kvm_create_guest_memfd, kvm_memory_attributes,
    kvm_userspace_memory_region,
};
use kvm_ioctls::{Cap, VmFd};
use userfaultfd::{FeatureFlags, Uffd, UffdBuilder};
use vmm_sys_util::eventfd::EventFd;

pub use crate::arch::{ArchVm as Vm, ArchVmError, VmState};
use crate::arch::{Kvm, host_page_size};
use crate::logger::info;
use crate::persist::{CreateSnapshotError, GuestRegionUffdMapping};
use crate::utils::u64_to_usize;
use crate::vmm_config::snapshot::SnapshotType;
use crate::vstate::memory::{
    Bounce, GuestMemory, GuestMemoryExtension, GuestMemoryMmap, GuestMemoryRegion, GuestRegionMmap,
    KvmRegion,
};
use crate::vstate::vcpu::VcpuError;
use crate::{DirtyBitmap, Vcpu, mem_size_mib};

pub(crate) const KVM_GMEM_NO_DIRECT_MAP: u64 = 1;

/// Architecture independent parts of a VM.
#[derive(Debug)]
pub struct VmCommon {
    /// The KVM file descriptor used to access this Vm.
    pub fd: VmFd,
    max_memslots: usize,
    /// The guest memory of this Vm.
    pub guest_memory: GuestMemoryMmap,
    /// The swiotlb regions of this Vm.
    pub swiotlb_regions: GuestMemoryMmap,
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
    /// {0}
    Arch(#[from] ArchVmError),
    /// Error during eventfd operations: {0}
    EventFd(std::io::Error),
    /// Failed to create vcpu: {0}
    CreateVcpu(VcpuError),
    /// The number of configured slots is bigger than the maximum reported by KVM
    NotEnoughMemorySlots,
    /// Memory Error: {0}
    VmMemory(#[from] vm_memory::Error),
    /// Failure to create guest_memfd: {0}
    GuestMemfd(kvm_ioctls::Error),
    /// guest_memfd is not supported on this host kernel.
    GuestMemfdNotSupported,
    /// Failed to set memory attributes to private: {0}
    SetMemoryAttributes(kvm_ioctls::Error),
}

/// Contains Vm functions that are usable across CPU architectures
impl Vm {
    /// Create a KVM VM
    pub fn create_common(kvm: &Kvm, vm_type: Option<u64>) -> Result<VmCommon, VmError> {
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
            let vm_res = match vm_type {
                Some(r#type) => kvm.fd.create_vm_with_type(r#type),
                None => kvm.fd.create_vm(),
            };

            match vm_res {
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
            swiotlb_regions: GuestMemoryMmap::default(),
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

    /// Create a guest_memfd of the specified size
    pub fn create_guest_memfd(&self, size: usize, flags: u64) -> Result<File, VmError> {
        assert_eq!(
            size & (host_page_size() - 1),
            0,
            "guest_memfd size must be page aligned"
        );

        if !self.fd().check_extension(Cap::GuestMemfd) {
            return Err(VmError::GuestMemfdNotSupported);
        }

        let kvm_gmem = kvm_create_guest_memfd {
            size: size as u64,
            flags,
            ..Default::default()
        };

        self.fd()
            .create_guest_memfd(kvm_gmem)
            .map_err(VmError::GuestMemfd)
            // SAFETY: We know rawfd is a valid fd because create_guest_memfd didn't return an
            // error.
            .map(|rawfd| unsafe { File::from_raw_fd(rawfd) })
    }

    /// Register a list of new memory regions to this [`Vm`].
    pub fn register_memory_regions(
        &mut self,
        regions: Vec<GuestRegionMmap>,
        mmap_of_guest_memfd: bool,
    ) -> Result<(), VmError> {
        for region in regions {
            self.register_memory_region(region, mmap_of_guest_memfd)?
        }

        Ok(())
    }

    fn kvmify_region(
        &self,
        region: GuestRegionMmap,
        mmap_of_guest_memfd: bool,
    ) -> Result<KvmRegion, VmError> {
        let next_slot = self
            .guest_memory()
            .num_regions()
            .checked_add(self.swiotlb_regions().num_regions())
            .ok_or(VmError::NotEnoughMemorySlots)?
            .try_into()
            .map_err(|_| VmError::NotEnoughMemorySlots)?;

        if next_slot as usize >= self.common.max_memslots {
            return Err(VmError::NotEnoughMemorySlots);
        }

        let gmem_fo = if mmap_of_guest_memfd {
            assert!(
                region.file_offset().is_some(),
                "Requested to register guest_memfd to region that isn't mapping a guest_memfd in \
                 the first place!"
            );

            region.file_offset().cloned()
        } else {
            None
        };

        Ok(KvmRegion::from_mmap_region(region, next_slot, gmem_fo))
    }

    fn register_kvm_region(&mut self, region: &KvmRegion) -> Result<(), VmError> {
        if self.fd().check_extension(Cap::UserMemory2) {
            // SAFETY: Safe because the fd is a valid KVM file descriptor.
            unsafe {
                self.fd()
                    .set_user_memory_region2(*region.inner())
                    .map_err(VmError::SetUserMemoryRegion)?;
            }
        } else {
            // Something is seriously wrong if we manage to set these fields on a host that doesn't
            // even allow creation of guest_memfds!
            assert_eq!(region.inner().guest_memfd, 0);
            assert_eq!(region.inner().guest_memfd_offset, 0);

            // SAFETY: We are passing a valid memory region and operate on a valid KVM FD.
            unsafe {
                self.fd()
                    .set_user_memory_region(kvm_userspace_memory_region {
                        slot: region.inner().slot,
                        flags: region.inner().flags,
                        guest_phys_addr: region.inner().guest_phys_addr,
                        memory_size: region.inner().memory_size,
                        userspace_addr: region.inner().userspace_addr,
                    })
                    .map_err(VmError::SetUserMemoryRegion)?;
            }
        }

        Ok(())
    }

    /// Register a new memory region to this [`Vm`].
    pub fn register_memory_region(
        &mut self,
        region: GuestRegionMmap,
        mmap_of_guest_memfd: bool,
    ) -> Result<(), VmError> {
        let arcd_region = Arc::new(self.kvmify_region(region, mmap_of_guest_memfd)?);
        let new_guest_memory = self
            .common
            .guest_memory
            .insert_region(Arc::clone(&arcd_region))?;

        self.register_kvm_region(arcd_region.as_ref())?;

        self.common.guest_memory = new_guest_memory;
        Ok(())
    }

    /// Registers a new io memory region to this [`Vm`].
    pub fn register_swiotlb_region(&mut self, region: GuestRegionMmap) -> Result<(), VmError> {
        // swiotlb regions are never gmem backed - by definition they need to be accessible to the
        // host!
        let arcd_region = Arc::new(self.kvmify_region(region, false)?);
        let new_collection = self
            .common
            .swiotlb_regions
            .insert_region(Arc::clone(&arcd_region))?;

        self.register_kvm_region(arcd_region.as_ref())?;

        self.common.swiotlb_regions = new_collection;
        Ok(())
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    pub fn fd(&self) -> &VmFd {
        &self.common.fd
    }

    /// Gets a reference to this [`Vm`]'s [`GuestMemoryMmap`] object, which
    /// contains all non-swiotlb guest memory regions.
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.common.guest_memory
    }

    /// Returns a reference to the [`GuestMemoryMmap`] that I/O devices attached to this [`Vm`]
    /// have access to. If no I/O regions were registered, return the same as [`Vm::guest_memory`],
    /// otherwise returns the [`GuestMemoryMmap`] describing a specific swiotlb region.
    pub fn io_memory(&self) -> &GuestMemoryMmap {
        if self.has_swiotlb() {
            &self.common.swiotlb_regions
        } else {
            &self.common.guest_memory
        }
    }

    /// Gets a reference to the [`GuestMemoryMmap`] holding the swiotlb regions registered to
    /// this [`Vm`]. Unlike [`Vm::io_memory`], does not fall back to returning the
    /// [`GuestMemoryMmap`] of normal memory when no swiotlb regions were registered.
    pub fn swiotlb_regions(&self) -> &GuestMemoryMmap {
        &self.common.swiotlb_regions
    }

    /// Returns `true` iff any io memory regions where registered via [`Vm::register_io_region`].
    pub fn has_swiotlb(&self) -> bool {
        self.common.swiotlb_regions.num_regions() > 0
    }

    /// Sets the memory attributes on all guest_memfd-backed regions to private
    pub fn set_memory_private(&self) -> Result<(), VmError> {
        for region in self.guest_memory().iter() {
            if region.inner().guest_memfd != 0 {
                let attr = kvm_memory_attributes {
                    address: region.start_addr().0,
                    size: region.len(),
                    attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE as u64,
                    ..Default::default()
                };

                self.fd()
                    .set_memory_attributes(attr)
                    .map_err(VmError::SetMemoryAttributes)?
            }
        }

        Ok(())
    }

    /// Returns an iterator over all regions, normal and swiotlb.
    fn all_regions(&self) -> impl Iterator<Item = &KvmRegion> {
        self.guest_memory()
            .iter()
            .chain(self.common.swiotlb_regions.iter())
    }

    pub(crate) fn create_uffd(
        &self,
    ) -> Result<(Uffd, Vec<GuestRegionUffdMapping>), userfaultfd::Error> {
        let mut uffd_builder = UffdBuilder::new();
        let mut mappings = Vec::new();

        // We only make use of this if balloon devices are present, but we can enable it
        // unconditionally because the only place the kernel checks this is in a hook from
        // madvise, e.g. it doesn't actively change the behavior of UFFD, only passively.
        // Without balloon devices we never call madvise anyway, so no need to put this into
        // a conditional.
        uffd_builder.require_features(FeatureFlags::EVENT_REMOVE);

        let uffd = uffd_builder
            .close_on_exec(true)
            .non_blocking(true)
            .user_mode_only(false)
            .create()?;

        let mut offset = 0;

        for mem_region in self.common.guest_memory.iter() {
            uffd.register(
                mem_region.inner().userspace_addr as *mut libc::c_void,
                u64_to_usize(mem_region.len()),
            )?;
            mappings.push(GuestRegionUffdMapping {
                base_host_virt_addr: mem_region.inner().userspace_addr,
                size: u64_to_usize(mem_region.len()),
                offset,
                ..Default::default()
            });

            offset += mem_region.len();
        }

        Ok((uffd, mappings))
    }

    /// Resets the KVM dirty bitmap for each of the guest's memory regions.
    pub fn reset_dirty_bitmap(&self) {
        self.all_regions().for_each(|region| {
            let _ = self
                .fd()
                .get_dirty_log(region.inner().slot, u64_to_usize(region.len()));
        });
    }

    /// Retrieves the KVM dirty bitmap for each of the guest's memory regions.
    pub fn get_dirty_bitmap(&self) -> Result<DirtyBitmap, vmm_sys_util::errno::Error> {
        let mut bitmap: DirtyBitmap = HashMap::new();
        self.all_regions().try_for_each(|region| {
            self.fd()
                .get_dirty_log(region.inner().slot, u64_to_usize(region.len()))
                .map(|bitmap_region| _ = bitmap.insert(region.inner().slot, bitmap_region))
        })?;
        Ok(bitmap)
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
                self.guest_memory()
                    .dump_dirty(&mut file, &dirty_bitmap)
                    .and_then(|_| self.swiotlb_regions().dump_dirty(&mut file, &dirty_bitmap))?;
            }
            SnapshotType::Full => {
                let secret_hidden = self
                    .guest_memory()
                    .iter()
                    .any(|r| r.inner().guest_memfd != 0);
                self.guest_memory()
                    .dump(&mut Bounce(&file, secret_hidden))
                    .and_then(|_| self.swiotlb_regions().dump(&mut file))?;
                self.reset_dirty_bitmap();
                self.guest_memory().reset_dirty();
            }
        };

        file.flush()
            .map_err(|err| MemoryBackingFile("flush", err))?;
        file.sync_all()
            .map_err(|err| MemoryBackingFile("sync_all", err))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use vm_memory::GuestAddress;
    use vm_memory::mmap::MmapRegionBuilder;

    use super::*;
    use crate::test_utils::single_region_mem_raw;
    use crate::utils::mib_to_bytes;
    use crate::vmm_config::machine_config::HugePageConfig;
    use crate::vstate::kvm::Kvm;
    use crate::vstate::memory;
    use crate::vstate::memory::GuestRegionMmap;

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm() -> (Kvm, Vm) {
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        let vm = Vm::new(&kvm, None).expect("Cannot create new vm");
        (kvm, vm)
    }

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm_with_memory(mem_size: usize) -> (Kvm, Vm) {
        let (kvm, mut vm) = setup_vm();
        let gm = single_region_mem_raw(mem_size);
        vm.register_memory_regions(gm, false).unwrap();
        (kvm, vm)
    }

    #[test]
    fn test_new() {
        // Testing with a valid /dev/kvm descriptor.
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        Vm::new(&kvm, None).unwrap();
    }

    #[test]
    fn test_register_memory_regions() {
        let (_, mut vm) = setup_vm();

        // Trying to set a memory region with a size that is not a multiple of GUEST_PAGE_SIZE
        // will result in error.
        let gm = single_region_mem_raw(0x10);
        let res = vm.register_memory_regions(gm, false);
        assert_eq!(
            res.unwrap_err().to_string(),
            "Cannot set the memory regions: Invalid argument (os error 22)"
        );

        let gm = single_region_mem_raw(0x1000);
        let res = vm.register_memory_regions(gm, false);
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

            let res = vm.register_memory_region(region, false);

            if i >= max_nr_regions {
                assert!(
                    matches!(res, Err(VmError::NotEnoughMemorySlots)),
                    "{:?} at iteration {} - max_nr_memslots: {}",
                    res,
                    i,
                    max_nr_regions
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

    #[test]
    fn test_swiotlb() {
        let (_, mut vm) = setup_vm();
        let regions = [
            (GuestAddress(0), 0x1000),
            (GuestAddress(0x1000), 0x1000),
            (GuestAddress(0x2000), 0x1000),
        ];
        let mut regions =
            memory::anonymous(regions.into_iter(), false, HugePageConfig::None).unwrap();

        vm.register_memory_region(regions.remove(0), false).unwrap();
        vm.register_memory_region(regions.remove(0), false).unwrap();

        // Before we register any swiotlb regions, io_memory() should return the normal mem region
        assert_eq!(vm.guest_memory().num_regions(), 2);
        assert_eq!(vm.io_memory().num_regions(), 2);
        assert_eq!(vm.all_regions().count(), 2);
        assert_eq!(vm.swiotlb_regions().num_regions(), 0);
        assert!(!vm.has_swiotlb());

        vm.register_swiotlb_region(regions.remove(0)).unwrap();

        // After swiotlb region is returned, io_memory() should return only the swiotlb regions
        assert_eq!(vm.guest_memory().num_regions(), 2);
        assert_eq!(vm.io_memory().num_regions(), 1);
        assert_eq!(vm.all_regions().count(), 3);
        assert_eq!(vm.swiotlb_regions().num_regions(), 1);
        assert!(vm.has_swiotlb());

        // Test that kvm slot indices are not reused across different types of regions.
        assert_eq!(
            vm.all_regions().map(|r| r.inner().slot).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }
}
