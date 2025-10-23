// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::ops::{Deref, DerefMut};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use kvm_bindings::{KVM_MEM_READONLY, kvm_userspace_memory_region};
use kvm_ioctls::VmFd;
use serde::{Deserialize, Serialize};
use vm_allocator::AllocPolicy;
use vm_memory::mmap::{MmapRegionBuilder, MmapRegionError};
use vm_memory::{GuestAddress, GuestMemoryError};
use vmm_sys_util::eventfd::EventFd;

use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ids::VIRTIO_ID_PMEM;
use crate::devices::virtio::pmem::PMEM_QUEUE_SIZE;
use crate::devices::virtio::pmem::metrics::{PmemMetrics, PmemMetricsPerDevice};
use crate::devices::virtio::queue::{DescriptorChain, InvalidAvailIdx, Queue, QueueError};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::logger::{IncMetric, error};
use crate::utils::{align_up, u64_to_usize};
use crate::vmm_config::pmem::PmemConfig;
use crate::vstate::memory::{ByteValued, Bytes, GuestMemoryMmap, GuestMmapRegion};
use crate::vstate::vm::VmError;
use crate::{Vm, impl_device_type};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PmemError {
    /// Cannot set the memory regions: {0}
    SetUserMemoryRegion(VmError),
    /// Unablet to allocate a KVM slot for the device
    NoKvmSlotAvailable,
    /// Error accessing backing file: {0}
    BackingFile(std::io::Error),
    /// Error backing file size is 0
    BackingFileZeroSize,
    /// Error with EventFd: {0}
    EventFd(std::io::Error),
    /// Unexpected read-only descriptor
    ReadOnlyDescriptor,
    /// Unexpected write-only descriptor
    WriteOnlyDescriptor,
    /// UnknownRequestType: {0}
    UnknownRequestType(u32),
    /// Descriptor chain too short
    DescriptorChainTooShort,
    /// Guest memory error: {0}
    GuestMemory(#[from] GuestMemoryError),
    /// Error handling the VirtIO queue: {0}
    Queue(#[from] QueueError),
    /// Error during obtaining the descriptor from the queue: {0}
    QueuePop(#[from] InvalidAvailIdx),
}

const VIRTIO_PMEM_REQ_TYPE_FLUSH: u32 = 0;
const SUCCESS: i32 = 0;
const FAILURE: i32 = -1;

#[derive(Debug, Default, Copy, Clone, Serialize, Deserialize)]
#[repr(C)]
pub struct ConfigSpace {
    // Physical address of the first byte of the persistent memory region.
    pub start: u64,
    // Length of the address range
    pub size: u64,
}

// SAFETY: `ConfigSpace` contains only PODs in `repr(c)`, without padding.
unsafe impl ByteValued for ConfigSpace {}

#[derive(Debug)]
pub struct Pmem {
    // VirtIO fields
    pub avail_features: u64,
    pub acked_features: u64,
    pub activate_event: EventFd,

    // Transport fields
    pub device_state: DeviceState,
    pub queues: Vec<Queue>,
    pub queue_events: Vec<EventFd>,

    // Pmem specific fields
    pub config_space: ConfigSpace,
    pub file: File,
    pub file_len: u64,
    pub mmap_ptr: u64,
    pub metrics: Arc<PmemMetrics>,

    pub config: PmemConfig,
}

impl Pmem {
    // Pmem devices need to have address and size to be
    // a multiple of 2MB
    pub const ALIGNMENT: u64 = 2 * 1024 * 1024;

    /// Create a new Pmem device with a backing file at `disk_image_path` path.
    pub fn new(config: PmemConfig) -> Result<Self, PmemError> {
        Self::new_with_queues(config, vec![Queue::new(PMEM_QUEUE_SIZE)])
    }

    /// Create a new Pmem device with a backing file at `disk_image_path` path using a pre-created
    /// set of queues.
    pub fn new_with_queues(config: PmemConfig, queues: Vec<Queue>) -> Result<Self, PmemError> {
        let (file, file_len, mmap_ptr, mmap_len) =
            Self::mmap_backing_file(&config.path_on_host, config.read_only)?;

        Ok(Self {
            avail_features: 1u64 << VIRTIO_F_VERSION_1,
            acked_features: 0u64,
            activate_event: EventFd::new(libc::EFD_NONBLOCK).map_err(PmemError::EventFd)?,
            device_state: DeviceState::Inactive,
            queues,
            queue_events: vec![EventFd::new(libc::EFD_NONBLOCK).map_err(PmemError::EventFd)?],
            config_space: ConfigSpace {
                start: 0,
                size: mmap_len,
            },
            file,
            file_len,
            mmap_ptr,
            metrics: PmemMetricsPerDevice::alloc(config.id.clone()),
            config,
        })
    }

    pub fn mmap_backing_file(
        path: &str,
        read_only: bool,
    ) -> Result<(File, u64, u64, u64), PmemError> {
        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(path)
            .map_err(PmemError::BackingFile)?;
        let file_len = file.metadata().unwrap().len();
        if (file_len == 0) {
            return Err(PmemError::BackingFileZeroSize);
        }

        let mut prot = libc::PROT_READ;
        if !read_only {
            prot |= libc::PROT_WRITE;
        }

        let mmap_len = align_up(file_len, Self::ALIGNMENT);
        let mmap_ptr = if (mmap_len == file_len) {
            // SAFETY: We are calling the system call with valid arguments and checking the returned
            // value
            unsafe {
                let r = libc::mmap(
                    std::ptr::null_mut(),
                    u64_to_usize(file_len),
                    prot,
                    libc::MAP_SHARED | libc::MAP_NORESERVE,
                    file.as_raw_fd(),
                    0,
                );
                if r == libc::MAP_FAILED {
                    return Err(PmemError::BackingFile(std::io::Error::last_os_error()));
                }
                r
            }
        } else {
            // SAFETY: We are calling system calls with valid arguments and checking returned
            // values
            //
            // The double mapping is done to ensure the underlying memory has the size of
            // `mmap_len` (wich is 2MB aligned as per `virtio-pmem` specification)
            // First mmap creates a mapping of `mmap_len` while second mmaps the actual
            // file on top. The remaining gap between the end of the mmaped file and
            // the actual end of the memory region is backed by PRIVATE | ANONYMOUS memory.
            unsafe {
                let mmap_ptr = libc::mmap(
                    std::ptr::null_mut(),
                    u64_to_usize(mmap_len),
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_NORESERVE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if mmap_ptr == libc::MAP_FAILED {
                    return Err(PmemError::BackingFile(std::io::Error::last_os_error()));
                }
                let r = libc::mmap(
                    mmap_ptr,
                    u64_to_usize(file_len),
                    prot,
                    libc::MAP_SHARED | libc::MAP_NORESERVE | libc::MAP_FIXED,
                    file.as_raw_fd(),
                    0,
                );
                if r == libc::MAP_FAILED {
                    return Err(PmemError::BackingFile(std::io::Error::last_os_error()));
                }
                mmap_ptr
            }
        };
        Ok((file, file_len, mmap_ptr as u64, mmap_len))
    }

    /// Allocate memory in past_mmio64 memory region
    pub fn alloc_region(&mut self, vm: &Vm) {
        let mut resource_allocator_lock = vm.resource_allocator();
        let resource_allocator = resource_allocator_lock.deref_mut();
        let addr = resource_allocator
            .past_mmio64_memory
            .allocate(
                self.config_space.size,
                Pmem::ALIGNMENT,
                AllocPolicy::FirstMatch,
            )
            .unwrap();
        self.config_space.start = addr.start();
    }

    /// Set user memory region in KVM
    pub fn set_mem_region(&mut self, vm: &Vm) -> Result<(), PmemError> {
        let next_slot = vm.next_kvm_slot(1).ok_or(PmemError::NoKvmSlotAvailable)?;
        let memory_region = kvm_userspace_memory_region {
            slot: next_slot,
            guest_phys_addr: self.config_space.start,
            memory_size: self.config_space.size,
            userspace_addr: self.mmap_ptr,
            flags: if self.config.read_only {
                KVM_MEM_READONLY
            } else {
                0
            },
        };

        vm.set_user_memory_region(memory_region)
            .map_err(PmemError::SetUserMemoryRegion)
    }

    fn handle_queue(&mut self) -> Result<(), PmemError> {
        // This is safe since we checked in the event handler that the device is activated.
        let active_state = self.device_state.active_state().unwrap();

        while let Some(head) = self.queues[0].pop()? {
            let add_result = match self.process_chain(head) {
                Ok(()) => self.queues[0].add_used(head.index, 4),
                Err(err) => {
                    error!("pmem: {err}");
                    self.metrics.event_fails.inc();
                    self.queues[0].add_used(head.index, 0)
                }
            };
            if let Err(err) = add_result {
                error!("pmem: {err}");
                self.metrics.event_fails.inc();
                break;
            }
        }
        self.queues[0].advance_used_ring_idx();

        if self.queues[0].prepare_kick() {
            active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|err| {
                    error!("pmem: {err}");
                    self.metrics.event_fails.inc();
                });
        }
        Ok(())
    }

    fn process_chain(&self, head: DescriptorChain) -> Result<(), PmemError> {
        // This is safe since we checked in the event handler that the device is activated.
        let active_state = self.device_state.active_state().unwrap();

        if head.is_write_only() {
            return Err(PmemError::WriteOnlyDescriptor);
        }
        let request: u32 = active_state.mem.read_obj(head.addr)?;
        if request != VIRTIO_PMEM_REQ_TYPE_FLUSH {
            return Err(PmemError::UnknownRequestType(request));
        }
        let Some(status_descriptor) = head.next_descriptor() else {
            return Err(PmemError::DescriptorChainTooShort);
        };
        if !status_descriptor.is_write_only() {
            return Err(PmemError::ReadOnlyDescriptor);
        }
        let mut result = SUCCESS;
        // SAFETY: We are calling the system call with valid arguments and checking the returned
        // value
        unsafe {
            let ret = libc::msync(
                self.mmap_ptr as *mut libc::c_void,
                u64_to_usize(self.file_len),
                libc::MS_SYNC,
            );
            if ret < 0 {
                error!("pmem: Unable to msync the file. Error: {}", ret);
                result = FAILURE;
            }
        }
        active_state.mem.write_obj(result, status_descriptor.addr)?;
        Ok(())
    }

    pub fn process_queue(&mut self) {
        self.metrics.queue_event_count.inc();
        if let Err(err) = self.queue_events[0].read() {
            error!("pmem: Failed to get queue event: {err:?}");
            self.metrics.event_fails.inc();
            return;
        }

        self.handle_queue().unwrap_or_else(|err| {
            error!("pmem: {err:?}");
            self.metrics.event_fails.inc();
        });
    }
}

impl VirtioDevice for Pmem {
    impl_device_type!(VIRTIO_ID_PMEM);

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device not activated")
            .interrupt
            .deref()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if let Some(config_space_bytes) = self.config_space.as_slice().get(u64_to_usize(offset)..) {
            let len = config_space_bytes.len().min(data.len());
            data[..len].copy_from_slice(&config_space_bytes[..len]);
        } else {
            error!("Failed to read config space");
            self.metrics.cfg_fails.inc();
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

        if self.activate_event.write(1).is_err() {
            self.metrics.activate_fails.inc();
            return Err(ActivateError::EventFd);
        }
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};

    #[test]
    fn test_from_config() {
        let config = PmemConfig {
            id: "1".into(),
            path_on_host: "not_a_path".into(),
            root_device: true,
            read_only: false,
        };
        assert!(matches!(
            Pmem::new(config).unwrap_err(),
            PmemError::BackingFile(_),
        ));

        let dummy_file = TempFile::new().unwrap();
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();
        let config = PmemConfig {
            id: "1".into(),
            path_on_host: dummy_path.clone(),
            root_device: true,
            read_only: false,
        };
        assert!(matches!(
            Pmem::new(config).unwrap_err(),
            PmemError::BackingFileZeroSize,
        ));

        dummy_file.as_file().set_len(0x20_0000);
        let config = PmemConfig {
            id: "1".into(),
            path_on_host: dummy_path,
            root_device: true,
            read_only: false,
        };
        Pmem::new(config).unwrap();
    }

    #[test]
    fn test_process_chain() {
        let dummy_file = TempFile::new().unwrap();
        dummy_file.as_file().set_len(0x20_0000);
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();
        let config = PmemConfig {
            id: "1".into(),
            path_on_host: dummy_path,
            root_device: true,
            read_only: false,
        };
        let mut pmem = Pmem::new(config).unwrap();

        let mem = default_mem();
        let interrupt = default_interrupt();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        pmem.queues[0] = vq.create_queue();
        pmem.activate(mem.clone(), interrupt).unwrap();

        // Valid request
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, VIRTQ_DESC_F_NEXT, 1);
            vq.avail.ring[1].set(1);
            vq.dtable[1].set(0x2000, 4, VIRTQ_DESC_F_WRITE, 0);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();
            mem.write_obj::<u32>(0x69, GuestAddress(0x2000)).unwrap();

            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            pmem.process_chain(head).unwrap();
            assert_eq!(mem.read_obj::<u32>(GuestAddress(0x2000)).unwrap(), 0);
        }

        // Invalid request type
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, VIRTQ_DESC_F_NEXT, 1);
            mem.write_obj::<u32>(0x69, GuestAddress(0x1000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            assert!(matches!(
                pmem.process_chain(head).unwrap_err(),
                PmemError::UnknownRequestType(0x69),
            ));
        }

        // Short chain request
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, 0, 1);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            assert!(matches!(
                pmem.process_chain(head).unwrap_err(),
                PmemError::DescriptorChainTooShort,
            ));
        }

        // Write only first descriptor
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT, 1);
            vq.avail.ring[1].set(1);
            vq.dtable[1].set(0x2000, 4, VIRTQ_DESC_F_WRITE, 0);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            assert!(matches!(
                pmem.process_chain(head).unwrap_err(),
                PmemError::WriteOnlyDescriptor,
            ));
        }

        // Read only second descriptor
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, VIRTQ_DESC_F_NEXT, 1);
            vq.avail.ring[1].set(1);
            vq.dtable[1].set(0x2000, 4, 0, 0);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            assert!(matches!(
                pmem.process_chain(head).unwrap_err(),
                PmemError::ReadOnlyDescriptor,
            ));
        }
    }
}
