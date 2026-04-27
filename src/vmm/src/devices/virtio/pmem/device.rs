// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use kvm_bindings::{KVM_MEM_READONLY, kvm_userspace_memory_region};
use serde::{Deserialize, Serialize};
use vm_allocator::{AllocPolicy, RangeInclusive};
use vm_memory::mmap::{MmapRegionBuilder, MmapRegionError};
use vm_memory::{GuestAddress, GuestMemoryError};
use vmm_sys_util::eventfd::EventFd;

use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::pmem::PMEM_QUEUE_SIZE;
use crate::devices::virtio::pmem::metrics::{PmemMetrics, PmemMetricsPerDevice};
use crate::devices::virtio::queue::{DescriptorChain, InvalidAvailIdx, Queue, QueueError};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::logger::{IncMetric, error, info};
use crate::rate_limiter::{BucketUpdate, RateLimiter, TokenType};
use crate::utils::{align_up, u64_to_usize};
use crate::vmm_config::RateLimiterConfig;
use crate::vmm_config::pmem::PmemConfig;
use crate::vstate::memory::{ByteValued, Bytes, GuestMemoryMmap, GuestMmapRegion};
use crate::vstate::vm::VmError;
use crate::{Vm, impl_device_type};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PmemError {
    /// Failed to allocate memory region
    AllocationFailed,
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
    /// Head descriptor has invalid length of {0} instead of 4
    Non4byteHeadDescriptor(u32),
    /// Status descriptor has invalid length of {0} instead of 4
    Non4byteStatusDescriptor(u32),
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
    /// Error creating rate limiter: {0}
    RateLimiter(std::io::Error),
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

/// RAII wrapper for a guest address allocation. Frees the allocated region on drop.
#[derive(Debug)]
pub struct GuestPmemRegion {
    vm: Arc<Vm>,
    pub config_space: ConfigSpace,
}

impl GuestPmemRegion {
    /// Allocate a new region in past_mmio64 memory.
    fn new(vm: Arc<Vm>, size: u64) -> Result<Self, PmemError> {
        let start = {
            let mut alloc = vm.resource_allocator();
            alloc
                .past_mmio64_memory
                .allocate(size, Pmem::ALIGNMENT, AllocPolicy::FirstMatch)
                .map_err(|_| PmemError::AllocationFailed)?
                .start()
        };
        Ok(Self {
            vm,
            config_space: ConfigSpace { start, size },
        })
    }

    /// Wrap an existing allocation (e.g. from a snapshot) for RAII cleanup.
    pub fn from_state(vm: Arc<Vm>, config_space: ConfigSpace) -> Self {
        Self { vm, config_space }
    }
}

impl Drop for GuestPmemRegion {
    fn drop(&mut self) {
        let range = RangeInclusive::new(
            self.config_space.start,
            self.config_space.start + self.config_space.size - 1,
        )
        .expect("Invalid config_space range");
        let mut alloc = self.vm.resource_allocator();
        _ = alloc.past_mmio64_memory.free(&range);
    }
}

/// RAII wrapper for the KVM user memory region. Removes the region on drop.
#[derive(Debug)]
pub struct KvmMemSlot {
    vm: Arc<Vm>,
    slot: u32,
}

impl KvmMemSlot {
    fn new(
        vm: Arc<Vm>,
        gpa: u64,
        memory_size: u64,
        hva: u64,
        flags: u32,
    ) -> Result<Self, PmemError> {
        // FIXME: The KVM slot number itself is not returned. This is not an
        // issue currently since there are at least 32K slots available. But we
        // could improve this by implementing a slot allocator that allows us
        // to free slot numbers.
        let slot = vm.next_kvm_slot(1).ok_or(PmemError::NoKvmSlotAvailable)?;
        let region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: gpa,
            memory_size,
            userspace_addr: hva,
            flags,
        };
        vm.set_user_memory_region(region)
            .map_err(PmemError::SetUserMemoryRegion)?;
        Ok(Self { vm, slot })
    }
}

impl Drop for KvmMemSlot {
    fn drop(&mut self) {
        let region = kvm_userspace_memory_region {
            slot: self.slot,
            guest_phys_addr: 0,
            memory_size: 0,
            userspace_addr: 0,
            flags: 0,
        };
        _ = self.vm.set_user_memory_region(region);
    }
}

/// RAII wrapper for the pmem mmap region. Performs mmap on construction and munmap on drop.
#[derive(Debug)]
pub struct PmemMmap {
    pub file_len: u64,
    pub mmap_ptr: u64,
    pub mmap_len: u64,
}

impl PmemMmap {
    const ALIGNMENT: u64 = Pmem::ALIGNMENT;

    pub fn new(path: &str, read_only: bool) -> Result<Self, PmemError> {
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
        Ok(Self {
            file_len,
            mmap_ptr: mmap_ptr as u64,
            mmap_len,
        })
    }
}

impl Drop for PmemMmap {
    fn drop(&mut self) {
        // SAFETY: `mmap_ptr` is a valid pointer since PmemMmap can only be created via `new()`.
        //         `mmap_len` is the same value used for the original mmap call.
        unsafe {
            _ = libc::munmap(
                self.mmap_ptr as *mut libc::c_void,
                u64_to_usize(self.mmap_len),
            );
        }
    }
}

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
    // kvm_mem_slot must be declared before mmap so that its drop function runs
    // first before the HVA gets unmapped
    pub kvm_mem_slot: KvmMemSlot,
    pub guest_region: GuestPmemRegion,
    pub mmap: PmemMmap,
    pub metrics: Arc<PmemMetrics>,
    pub rate_limiter: RateLimiter,

    pub config: PmemConfig,
}

impl Pmem {
    // Pmem devices need to have address and size to be
    // a multiple of 2MB
    pub const ALIGNMENT: u64 = 2 * 1024 * 1024;

    /// Create a new Pmem device with a backing file at `disk_image_path` path.
    pub fn new(vm: Arc<Vm>, config: PmemConfig) -> Result<Self, PmemError> {
        Self::new_with_queues(vm, config, vec![Queue::new(PMEM_QUEUE_SIZE)], 0u64, None)
    }

    /// Create a new Pmem device with a backing file at `disk_image_path` path using a pre-created
    /// set of queues.
    pub fn new_with_queues(
        vm: Arc<Vm>,
        config: PmemConfig,
        queues: Vec<Queue>,
        acked_features: u64,
        config_space: Option<ConfigSpace>,
    ) -> Result<Self, PmemError> {
        let mmap = PmemMmap::new(&config.path_on_host, config.read_only)?;

        let guest_region = match config_space {
            Some(cs) => GuestPmemRegion::from_state(vm.clone(), cs),
            None => GuestPmemRegion::new(vm.clone(), mmap.mmap_len)?,
        };

        let cs = &guest_region.config_space;
        let flags = if config.read_only {
            KVM_MEM_READONLY
        } else {
            0
        };
        let kvm_mem_slot = KvmMemSlot::new(vm, cs.start, cs.size, mmap.mmap_ptr, flags)?;

        let rate_limiter = config
            .rate_limiter
            .map(RateLimiterConfig::try_into)
            .transpose()
            .map_err(PmemError::RateLimiter)?
            .unwrap_or_default();

        Ok(Self {
            avail_features: 1u64 << VIRTIO_F_VERSION_1,
            acked_features,
            activate_event: EventFd::new(libc::EFD_NONBLOCK).map_err(PmemError::EventFd)?,
            device_state: DeviceState::Inactive,
            queues,
            queue_events: vec![EventFd::new(libc::EFD_NONBLOCK).map_err(PmemError::EventFd)?],
            guest_region,
            metrics: PmemMetricsPerDevice::alloc(config.id.clone()),
            rate_limiter,
            config,
            mmap,
            kvm_mem_slot,
        })
    }

    pub fn handle_queue(&mut self) -> Result<(), PmemError> {
        // This is safe since we checked in the event handler that the device is activated.
        let active_state = self.device_state.active_state().unwrap();

        if self.queues[0].is_empty() {
            return Ok(());
        }

        // There is only 1 type of request pmem supports, so we can consume
        // rate-limiter before even looking at the queue. This is still valid
        // even if the queue will not have any valid requests since it indicate
        // broken guest driver and rate-limiting should still apply for such case.
        // Rate limit: consume 1 op and file_len bytes for the coalesced msync.
        // If the rate limiter is blocked, defer notification until the timer fires.
        if !self.rate_limiter.consume(1, TokenType::Ops) {
            self.metrics.rate_limiter_throttled_events.inc();
            return Ok(());
        }
        if !self
            .rate_limiter
            .consume(self.mmap.file_len, TokenType::Bytes)
        {
            self.rate_limiter.manual_replenish(1, TokenType::Ops);
            self.metrics.rate_limiter_throttled_events.inc();
            return Ok(());
        }

        let mut cached_result = None;
        while let Some(head) = self.queues[0].pop()? {
            let add_result = match self.process_chain(head, &mut cached_result) {
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

    fn process_chain(
        &self,
        head: DescriptorChain,
        cached_result: &mut Option<i32>,
    ) -> Result<(), PmemError> {
        // This is safe since we checked in the event handler that the device is activated.
        let active_state = self.device_state.active_state().unwrap();

        // Virtio spec, section 5.19.6 Driver Operations
        // https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-6970006
        if head.is_write_only() {
            return Err(PmemError::WriteOnlyDescriptor);
        }
        if head.len != 4 {
            return Err(PmemError::Non4byteHeadDescriptor(head.len));
        }
        let request: u32 = active_state.mem.read_obj(head.addr)?;
        if request != VIRTIO_PMEM_REQ_TYPE_FLUSH {
            return Err(PmemError::UnknownRequestType(request));
        }

        // Virtio spec, section 5.19.7 Device Operations
        // https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html#x1-6980007
        let Some(status_descriptor) = head.next_descriptor() else {
            return Err(PmemError::DescriptorChainTooShort);
        };
        if !status_descriptor.is_write_only() {
            return Err(PmemError::ReadOnlyDescriptor);
        }
        if status_descriptor.len != 4 {
            return Err(PmemError::Non4byteStatusDescriptor(status_descriptor.len));
        }

        // Since there is only 1 type of request pmem device supports,
        // we treat single notification from the guest as a single request
        // and reuse cached result of `msync` from first valid descriptor
        // for all following descriptors.
        if let Some(result) = cached_result {
            active_state
                .mem
                .write_obj(*result, status_descriptor.addr)?;
        } else {
            let mut status = SUCCESS;
            // SAFETY: We are calling the system call with valid arguments and checking the returned
            // value
            unsafe {
                let ret = libc::msync(
                    self.mmap.mmap_ptr as *mut libc::c_void,
                    u64_to_usize(self.mmap.file_len),
                    libc::MS_SYNC,
                );
                if ret < 0 {
                    error!("pmem: Unable to msync the file. Error: {}", ret);
                    status = FAILURE;
                }
            }
            *cached_result = Some(status);

            active_state.mem.write_obj(status, status_descriptor.addr)?;
        }
        Ok(())
    }

    /// Updates the parameters for the rate limiter.
    pub fn update_rate_limiter(&mut self, bytes: BucketUpdate, ops: BucketUpdate) {
        self.rate_limiter.update_buckets(bytes, ops);
    }

    pub fn process_queue(&mut self) {
        self.metrics.queue_event_count.inc();
        if let Err(err) = self.queue_events[0].read() {
            error!("pmem: Failed to get queue event: {err:?}");
            self.metrics.event_fails.inc();
            return;
        }

        if self.rate_limiter.is_blocked() {
            self.metrics.rate_limiter_throttled_events.inc();
            return;
        }

        self.handle_queue().unwrap_or_else(|err| {
            error!("pmem: {err:?}");
            self.metrics.event_fails.inc();
        });
    }

    pub fn process_rate_limiter_event(&mut self) {
        self.metrics.rate_limiter_event_count.inc();
        if let Err(err) = self.rate_limiter.event_handler() {
            error!("pmem: Failed to get rate-limiter event: {err:?}");
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
    impl_device_type!(VirtioDeviceType::Pmem);

    fn id(&self) -> &str {
        &self.config.id
    }

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
        if let Some(config_space_bytes) = self
            .guest_region
            .config_space
            .as_slice()
            .get(u64_to_usize(offset)..)
        {
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

    fn kick(&mut self) {
        if self.is_activated() {
            info!("kick pmem {}.", self.config.id);
            self.handle_queue();
        }
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::arch::Kvm;
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};

    #[test]
    fn test_from_config() {
        let kvm = Kvm::new(vec![]).unwrap();
        let vm = Arc::new(Vm::new(&kvm).unwrap());

        let config = PmemConfig {
            id: "1".into(),
            path_on_host: "not_a_path".into(),
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        assert!(matches!(
            Pmem::new(vm.clone(), config).unwrap_err(),
            PmemError::BackingFile(_),
        ));

        let dummy_file = TempFile::new().unwrap();
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();
        let config = PmemConfig {
            id: "1".into(),
            path_on_host: dummy_path.clone(),
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        assert!(matches!(
            Pmem::new(vm.clone(), config).unwrap_err(),
            PmemError::BackingFileZeroSize,
        ));

        dummy_file.as_file().set_len(0x20_0000);
        let config = PmemConfig {
            id: "1".into(),
            path_on_host: dummy_path,
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        Pmem::new(vm.clone(), config).unwrap();
    }

    #[test]
    fn test_process_chain() {
        let kvm = Kvm::new(vec![]).unwrap();
        let vm = Arc::new(Vm::new(&kvm).unwrap());

        let dummy_file = TempFile::new().unwrap();
        dummy_file.as_file().set_len(0x20_0000);
        let dummy_path = dummy_file.as_path().to_str().unwrap().to_string();
        let config = PmemConfig {
            id: "1".into(),
            path_on_host: dummy_path,
            root_device: true,
            read_only: false,
            ..Default::default()
        };
        let mut pmem = Pmem::new(vm.clone(), config).unwrap();

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
            let mut result = None;
            pmem.process_chain(head, &mut result).unwrap();
            assert_eq!(mem.read_obj::<u32>(GuestAddress(0x2000)).unwrap(), 0);
            assert!(result.is_some());
        }

        // Valid request cached value reuse
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, VIRTQ_DESC_F_NEXT, 1);
            vq.avail.ring[1].set(1);
            vq.dtable[1].set(0x2000, 4, VIRTQ_DESC_F_WRITE, 0);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();
            mem.write_obj::<u32>(0x69, GuestAddress(0x2000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            let mut result = Some(0x69);
            pmem.process_chain(head, &mut result).unwrap();
            assert_eq!(mem.read_obj::<u32>(GuestAddress(0x2000)).unwrap(), 0x69);
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
                pmem.process_chain(head, &mut None).unwrap_err(),
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
                pmem.process_chain(head, &mut None).unwrap_err(),
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
                pmem.process_chain(head, &mut None).unwrap_err(),
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
                pmem.process_chain(head, &mut None).unwrap_err(),
                PmemError::ReadOnlyDescriptor,
            ));
        }

        // Invalid length head descriptor
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 0x69, VIRTQ_DESC_F_NEXT, 1);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            assert!(matches!(
                pmem.process_chain(head, &mut None).unwrap_err(),
                PmemError::Non4byteHeadDescriptor(0x69),
            ));
        }

        // Invalid length status descriptor
        {
            vq.avail.ring[0].set(0);
            vq.dtable[0].set(0x1000, 4, VIRTQ_DESC_F_NEXT, 1);
            vq.avail.ring[1].set(1);
            vq.dtable[1].set(0x2000, 0x69, VIRTQ_DESC_F_WRITE, 0);
            mem.write_obj::<u32>(0, GuestAddress(0x1000)).unwrap();
            mem.write_obj::<u32>(0x69, GuestAddress(0x2000)).unwrap();

            pmem.queues[0] = vq.create_queue();
            vq.used.idx.set(0);
            vq.avail.idx.set(1);
            let head = pmem.queues[0].pop().unwrap().unwrap();
            assert!(matches!(
                pmem.process_chain(head, &mut None).unwrap_err(),
                PmemError::Non4byteStatusDescriptor(0x69),
            ));
        }
    }
}
