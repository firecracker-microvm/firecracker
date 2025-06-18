// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::path::Path;
use std::sync::Arc;

use bincode::{Decode, Encode};
use kvm_bindings::{
    KVM_MEM_GUEST_MEMFD, KVM_MEM_LOG_DIRTY_PAGES, KVM_MEMORY_ATTRIBUTE_PRIVATE, KVMIO,
    kvm_create_guest_memfd, kvm_memory_attributes, kvm_userspace_memory_region,
};
use kvm_ioctls::{Cap, VmFd};
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl::ioctl_with_ref;
use vmm_sys_util::{ioctl_ioc_nr, ioctl_iow_nr};

pub use crate::arch::{ArchVm as Vm, ArchVmError, VmState};
use crate::arch::{VM_TYPE_FOR_SECRET_FREEDOM, host_page_size};
use crate::logger::info;
use crate::persist::CreateSnapshotError;
use crate::utils::u64_to_usize;
use crate::vmm_config::snapshot::SnapshotType;
use crate::vstate::memory::{
    Address, GuestMemory, GuestMemoryExtension, GuestMemoryMmap, GuestMemoryRegion,
    GuestRegionMmap, MaybeBounce,
};
use crate::vstate::vcpu::VcpuError;
use crate::{DirtyBitmap, Vcpu, mem_size_mib};

pub(crate) const KVM_GMEM_NO_DIRECT_MAP: u64 = 1;

/// KVM userfault information
#[derive(Copy, Clone, Decode, Default, Eq, PartialEq, Debug, Encode)]
pub struct UserfaultData {
    /// Flags
    pub flags: u64,
    /// Guest physical address
    pub gpa: u64,
    /// Size
    pub size: u64,
}

/// Errors associated with `UserfaultChannel`.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum UserfaultChannelError {
    /// Encode error {0}
    Encode(#[from] bincode::error::EncodeError),
    /// Decode error {0}
    Decode(#[from] bincode::error::DecodeError),
    /// IO error {0}
    IO(#[from] std::io::Error),
}

/// KVM userfault channel
#[derive(Debug)]
pub struct UserfaultChannel {
    /// Sender
    pub sender: File,
    /// Receiver
    pub receiver: File,
}

impl UserfaultChannel {
    fn bincode_config(&self) -> impl bincode::config::Config {
        bincode::config::standard().with_fixed_int_encoding()
    }

    /// Receive `UserfaultData` from the channel.
    pub fn send(&mut self, data: UserfaultData) -> Result<(), UserfaultChannelError> {
        let encoded_data = bincode::encode_to_vec(data, self.bincode_config())
            .map_err(UserfaultChannelError::Encode)?;

        self.sender.write_all(&encoded_data)?;

        Ok(())
    }

    /// Send `UserfaultData` to the channel.
    pub fn recv(&mut self) -> Result<UserfaultData, UserfaultChannelError> {
        let size = bincode::encode_to_vec(UserfaultData::default(), self.bincode_config())?.len();

        let mut encoded_data = vec![0u8; size as usize];
        self.receiver.read_exact(&mut encoded_data)?;

        bincode::decode_from_slice(&encoded_data, self.bincode_config())
            .map_err(UserfaultChannelError::Decode)
            .map(|(data, _)| data)
    }
}

fn pipe2(flags: libc::c_int) -> std::io::Result<(File, File)> {
    let mut fds = [0, 0];

    // SAFETY: pipe2() is safe to call with a valid mutable pointer to an array of 2 integers
    // The fds array is stack-allocated and lives for the entire unsafe block.
    let res = unsafe { libc::pipe2(fds.as_mut_ptr(), flags) };

    if res == 0 {
        Ok((
            // SAFETY: fds[0] contains a valid file descriptor for the read end of the pipe
            // We only convert successful pipe2() calls, and each fd is used exactly once.
            unsafe { File::from_raw_fd(fds[0]) },
            // SAFETY: fds[1] contains a valid file descriptor for the write end of the pipe
            // We only convert successful pipe2() calls, and each fd is used exactly once.
            unsafe { File::from_raw_fd(fds[1]) },
        ))
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Architecture independent parts of a VM.
#[derive(Debug)]
pub struct VmCommon {
    /// The KVM file descriptor used to access this Vm.
    pub fd: VmFd,
    max_memslots: usize,
    /// The guest memory of this Vm.
    pub guest_memory: GuestMemoryMmap,
    secret_free: bool,
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
    /// Failed to create a userfault channel: {0}
    UserfaultChannel(std::io::Error),
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

// Upstream `kvm_userspace_memory_region2` definition does not include `userfault_bitmap` field yet.
// TODO: revert to `kvm_userspace_memory_region2` from kvm-bindings
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
struct kvm_userspace_memory_region2 {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    guest_memfd_offset: u64,
    guest_memfd: u32,
    pad1: u32,
    userfault_bitmap: u64,
    pad2: [u64; 13],
}

type VcpuCreationResult = Result<(Vec<Vcpu>, EventFd, Option<Vec<UserfaultChannel>>), VmError>;

/// Contains Vm functions that are usable across CPU architectures
impl Vm {
    /// Create a KVM VM
    pub fn create_common(
        kvm: &crate::vstate::kvm::Kvm,
        secret_free: bool,
    ) -> Result<VmCommon, VmError> {
        if secret_free && !kvm.fd.check_extension(Cap::GuestMemfd) {
            return Err(VmError::GuestMemfdNotSupported);
        }

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
            let create_result = if secret_free && VM_TYPE_FOR_SECRET_FREEDOM.is_some() {
                kvm.fd
                    .create_vm_with_type(VM_TYPE_FOR_SECRET_FREEDOM.unwrap())
            } else {
                kvm.fd.create_vm()
            };

            match create_result {
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
            secret_free,
        })
    }

    fn create_userfault_channels(
        &self,
        secret_free: bool,
    ) -> Result<(Option<UserfaultChannel>, Option<UserfaultChannel>), std::io::Error> {
        if secret_free {
            let (receiver_vcpu_to_vm, sender_vcpu_to_vm) = pipe2(libc::O_NONBLOCK)?;
            let (receiver_vm_to_vcpu, sender_vm_to_vcpu) = pipe2(0)?;
            Ok((
                Some(UserfaultChannel {
                    sender: sender_vcpu_to_vm,
                    receiver: receiver_vm_to_vcpu,
                }),
                Some(UserfaultChannel {
                    sender: sender_vm_to_vcpu,
                    receiver: receiver_vcpu_to_vm,
                }),
            ))
        } else {
            Ok((None, None))
        }
    }

    /// Creates the specified number of [`Vcpu`]s.
    ///
    /// The returned [`EventFd`] is written to whenever any of the vcpus exit.
    pub fn create_vcpus(&mut self, vcpu_count: u8, secret_free: bool) -> VcpuCreationResult {
        self.arch_pre_create_vcpus(vcpu_count)?;

        let exit_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmError::EventFd)?;

        let mut vcpus = Vec::with_capacity(vcpu_count as usize);
        let mut userfault_channels = Vec::with_capacity(vcpu_count as usize);
        for cpu_idx in 0..vcpu_count {
            let exit_evt = exit_evt.try_clone().map_err(VmError::EventFd)?;

            let (vcpu_channel, vmm_channel) = self
                .create_userfault_channels(secret_free)
                .map_err(VmError::UserfaultChannel)?;

            let vcpu =
                Vcpu::new(cpu_idx, self, exit_evt, vcpu_channel).map_err(VmError::CreateVcpu)?;
            vcpus.push(vcpu);

            if secret_free {
                userfault_channels.push(vmm_channel.unwrap());
            }
        }

        self.arch_post_create_vcpus(vcpu_count)?;

        Ok((
            vcpus,
            exit_evt,
            if secret_free {
                Some(userfault_channels)
            } else {
                None
            },
        ))
    }

    /// Create a guest_memfd of the specified size
    pub fn create_guest_memfd(&self, size: usize, flags: u64) -> Result<File, VmError> {
        assert_eq!(
            size & (host_page_size() - 1),
            0,
            "guest_memfd size must be page aligned"
        );

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
        userfault_bitmap_memfd: Option<&File>,
    ) -> Result<(), VmError> {
        let addr = match userfault_bitmap_memfd {
            Some(file) => {
                // SAFETY: the arguments to mmap cannot cause any memory unsafety in the rust sense
                let addr = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        usize::try_from(file.metadata().unwrap().len())
                            .expect("userfault bitmap file size is too large"),
                        libc::PROT_WRITE,
                        libc::MAP_SHARED,
                        file.as_raw_fd(),
                        0,
                    )
                };

                if addr == libc::MAP_FAILED {
                    panic!(
                        "Failed to mmap userfault bitmap file: {}",
                        std::io::Error::last_os_error()
                    );
                }

                Some(addr as u64)
            }
            None => None,
        };

        for region in regions {
            self.register_memory_region(region, addr)?
        }

        Ok(())
    }

    // TODO: remove when userfault support is merged upstream
    fn set_user_memory_region2(
        &self,
        user_memory_region2: kvm_userspace_memory_region2,
    ) -> Result<(), VmError> {
        ioctl_iow_nr!(
            KVM_SET_USER_MEMORY_REGION2,
            KVMIO,
            0x49,
            kvm_userspace_memory_region2
        );

        #[allow(clippy::undocumented_unsafe_blocks)]
        let ret = unsafe {
            ioctl_with_ref(
                self.fd(),
                KVM_SET_USER_MEMORY_REGION2(),
                &user_memory_region2,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(VmError::SetUserMemoryRegion(kvm_ioctls::Error::last()))
        }
    }

    /// Register a new memory region to this [`Vm`].
    pub fn register_memory_region(
        &mut self,
        region: GuestRegionMmap,
        userfault_addr: Option<u64>,
    ) -> Result<(), VmError> {
        // TODO: take it from kvm-bindings when merged upstream
        const KVM_MEM_USERFAULT: u32 = 1 << 3;

        let next_slot = self
            .guest_memory()
            .num_regions()
            .try_into()
            .map_err(|_| VmError::NotEnoughMemorySlots)?;
        if next_slot as usize >= self.common.max_memslots {
            return Err(VmError::NotEnoughMemorySlots);
        }

        let mut flags = 0;
        if region.bitmap().is_some() {
            flags |= KVM_MEM_LOG_DIRTY_PAGES;
        }

        #[allow(clippy::cast_sign_loss)]
        let (guest_memfd, guest_memfd_offset) = if self.secret_free() {
            flags |= KVM_MEM_GUEST_MEMFD;

            let fo = region
                .file_offset()
                .expect("secret hidden VMs must mmap guest_memfd for memslots");

            (fo.file().as_raw_fd() as u32, fo.start())
        } else {
            (0, 0)
        };

        let userfault_bitmap = match userfault_addr {
            Some(addr) => {
                flags |= KVM_MEM_USERFAULT;

                let file_offset_start = region.file_offset().unwrap().start();
                let pages_offset = file_offset_start / (host_page_size() as u64);
                let bytes_offset = pages_offset / (u8::BITS as u64);
                addr + bytes_offset
            }
            None => 0,
        };

        let memory_region = kvm_userspace_memory_region2 {
            slot: next_slot,
            guest_phys_addr: region.start_addr().raw_value(),
            memory_size: region.len(),
            userspace_addr: region.as_ptr() as u64,
            flags,
            guest_memfd,
            guest_memfd_offset,
            userfault_bitmap,
            ..Default::default()
        };

        let new_guest_memory = self.common.guest_memory.insert_region(Arc::new(region))?;

        if self.fd().check_extension(Cap::UserMemory2) {
            self.set_user_memory_region2(memory_region)?;
        } else {
            // Something is seriously wrong if we manage to set these fields on a host that doesn't
            // even allow creation of guest_memfds!
            assert_eq!(memory_region.guest_memfd, 0);
            assert_eq!(memory_region.guest_memfd_offset, 0);
            assert_eq!(memory_region.flags & KVM_MEM_GUEST_MEMFD, 0);

            // SAFETY: We are passing a valid memory region and operate on a valid KVM FD.
            unsafe {
                self.fd()
                    .set_user_memory_region(kvm_userspace_memory_region {
                        slot: memory_region.slot,
                        flags: memory_region.flags,
                        guest_phys_addr: memory_region.guest_phys_addr,
                        memory_size: memory_region.memory_size,
                        userspace_addr: memory_region.userspace_addr,
                    })
                    .map_err(VmError::SetUserMemoryRegion)?;
            }
        }

        self.common.guest_memory = new_guest_memory;

        Ok(())
    }

    /// Whether this VM is secret free
    pub fn secret_free(&self) -> bool {
        self.common.secret_free
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    pub fn fd(&self) -> &VmFd {
        &self.common.fd
    }

    /// Gets a reference to this [`Vm`]'s [`GuestMemoryMmap`] object
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.common.guest_memory
    }

    /// Sets the memory attributes on all guest_memfd-backed regions to private
    pub fn set_memory_private(&self) -> Result<(), VmError> {
        if !self.secret_free() {
            return Ok(());
        }

        for region in self.guest_memory().iter() {
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

        Ok(())
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
    pub fn get_dirty_bitmap(&self) -> Result<DirtyBitmap, vmm_sys_util::errno::Error> {
        let mut bitmap: DirtyBitmap = HashMap::new();
        self.guest_memory()
            .iter()
            .zip(0u32..)
            .try_for_each(|(region, slot)| {
                self.fd()
                    .get_dirty_log(slot, u64_to_usize(region.len()))
                    .map(|bitmap_region| _ = bitmap.insert(slot, bitmap_region))
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
                self.guest_memory().dump_dirty(&mut file, &dirty_bitmap)?;
            }
            SnapshotType::Full => {
                self.guest_memory()
                    .dump(&mut MaybeBounce::new(file.as_fd(), self.secret_free()))?;
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
    use crate::vstate::kvm::Kvm;
    use crate::vstate::memory::GuestRegionMmap;

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm() -> (Kvm, Vm) {
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        let vm = Vm::new(&kvm, false).expect("Cannot create new vm");
        (kvm, vm)
    }

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm_with_memory(mem_size: usize) -> (Kvm, Vm) {
        let (kvm, mut vm) = setup_vm();
        let gm = single_region_mem_raw(mem_size);
        vm.register_memory_regions(gm, None).unwrap();
        (kvm, vm)
    }

    #[test]
    fn test_new() {
        // Testing with a valid /dev/kvm descriptor.
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        Vm::new(&kvm, false).unwrap();
    }

    #[test]
    fn test_new_secret_free() {
        let kvm = Kvm::new(vec![]).unwrap();

        if !kvm.fd.check_extension(Cap::GuestMemfd) {
            return;
        }

        Vm::new(&kvm, true)
            .expect("should be able to create secret free VMs if guest_memfd is supported");
    }

    #[test]
    fn test_register_memory_regions() {
        let (_, mut vm) = setup_vm();

        // Trying to set a memory region with a size that is not a multiple of GUEST_PAGE_SIZE
        // will result in error.
        let gm = single_region_mem_raw(0x10);
        let res = vm.register_memory_regions(gm, None);
        assert_eq!(
            res.unwrap_err().to_string(),
            "Cannot set the memory regions: Invalid argument (os error 22)"
        );

        let gm = single_region_mem_raw(0x1000);
        let res = vm.register_memory_regions(gm, None);
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

            let res = vm.register_memory_region(region, None);

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

        let (vcpu_vec, _, _) = vm.create_vcpus(vcpu_count, false).unwrap();

        assert_eq!(vcpu_vec.len(), vcpu_count as usize);
    }
}
