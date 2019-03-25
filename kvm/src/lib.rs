// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

#![deny(missing_docs)]

//! A safe wrapper around the kernel's KVM interface.

extern crate libc;

extern crate kvm_bindings;
#[macro_use]
extern crate sys_util;

mod cap;
mod ioctl_defs;

use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::raw::*;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::ptr::null_mut;
use std::result;

use libc::{open, EINVAL, O_CLOEXEC, O_RDWR};

use kvm_bindings::*;
use sys_util::EventFd;
use sys_util::{
    ioctl, ioctl_with_mut_ptr, ioctl_with_mut_ref, ioctl_with_ptr, ioctl_with_ref, ioctl_with_val,
};

/// Wrapper over possible Kvm method Result.
pub type Result<T> = result::Result<T, io::Error>;

pub use cap::*;
use ioctl_defs::*;
pub use kvm_bindings::KVM_API_VERSION;

/// Taken from Linux Kernel v4.14.13 (arch/x86/include/asm/kvm_host.h)
pub const MAX_KVM_CPUID_ENTRIES: usize = 80;

// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    for _ in 0..rounded_size {
        v.push(T::default())
    }
    v
}

// The kvm API has many structs that resemble the following `Foo` structure:
//
// ```
// #[repr(C)]
// struct Foo {
//    some_data: u32
//    entries: __IncompleteArrayField<__u32>,
// }
// ```
//
// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
// include any space for `entries`. To make the allocation large enough while still being aligned
// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

/// A wrapper around opening and using `/dev/kvm`.
///
/// The handle is used to issue system ioctls.
pub struct Kvm {
    kvm: File,
}

impl Kvm {
    /// Opens `/dev/kvm/` and returns a `Kvm` object on success.
    pub fn new() -> Result<Self> {
        // Open `/dev/kvm` using `O_CLOEXEC` flag.
        let fd = Self::open_with_cloexec(true)?;
        // Safe because we verify that ret is valid and we own the fd.
        Ok(unsafe { Self::new_with_fd_number(fd) })
    }

    /// Creates a new Kvm object assuming `fd` represents an existing open file descriptor
    /// associated with `/dev/kvm`.
    ///
    /// # Arguments
    ///
    /// * `fd` - File descriptor for `/dev/kvm`.
    ///
    pub unsafe fn new_with_fd_number(fd: RawFd) -> Self {
        Kvm {
            kvm: File::from_raw_fd(fd),
        }
    }

    /// Opens `/dev/kvm` and returns the fd number on success.
    ///
    /// # Arguments
    ///
    /// * `close_on_exec`: If true opens `/dev/kvm` using the `O_CLOEXEC` flag.
    ///
    pub fn open_with_cloexec(close_on_exec: bool) -> Result<RawFd> {
        let open_flags = O_RDWR | if close_on_exec { O_CLOEXEC } else { 0 };
        // Safe because we give a constant nul-terminated string and verify the result.
        let ret = unsafe { open("/dev/kvm\0".as_ptr() as *const c_char, open_flags) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }

    /// Returns the KVM API version.
    pub fn get_api_version(&self) -> i32 {
        // Safe because we know that our file is a KVM fd and that the request is one of the ones
        // defined by kernel.
        unsafe { ioctl(self, KVM_GET_API_VERSION()) }
    }

    /// Query the availability of a particular kvm capability.
    /// Returns 0 if the capability is not available and > 0 otherwise.
    ///
    fn check_extension_int(&self, c: Cap) -> i32 {
        // Safe because we know that our file is a KVM fd and that the extension is one of the ones
        // defined by kernel.
        unsafe { ioctl_with_val(self, KVM_CHECK_EXTENSION(), c as c_ulong) }
    }

    /// Checks if a particular `Cap` is available.
    ///
    /// According to the KVM API doc, KVM_CHECK_EXTENSION returns "0 if unsupported; 1 (or some
    /// other positive integer) if supported".
    ///
    /// # Arguments
    ///
    /// * `c` - KVM capability.
    ///
    pub fn check_extension(&self, c: Cap) -> bool {
        self.check_extension_int(c) >= 1
    }

    /// Gets the size of the mmap required to use vcpu's `kvm_run` structure.
    pub fn get_vcpu_mmap_size(&self) -> Result<usize> {
        // Safe because we know that our file is a KVM fd and we verify the return result.
        let res = unsafe { ioctl(self, KVM_GET_VCPU_MMAP_SIZE()) };
        if res > 0 {
            Ok(res as usize)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Gets the recommended number of VCPUs per VM.
    ///
    pub fn get_nr_vcpus(&self) -> usize {
        let x = self.check_extension_int(Cap::NrVcpus);
        if x > 0 {
            x as usize
        } else {
            4
        }
    }

    /// Gets the maximum allowed memory slots per VM.
    ///
    /// KVM reports the number of available memory slots (`KVM_CAP_NR_MEMSLOTS`)
    /// using the extension interface.  Both x86 and s390 implement this, ARM
    /// and powerpc do not yet enable it.
    /// Default to 32 when `KVM_CAP_NR_MEMSLOTS` is not implemented.
    ///
    pub fn get_nr_memslots(&self) -> usize {
        let x = self.check_extension_int(Cap::NrMemslots);
        if x > 0 {
            x as usize
        } else {
            32
        }
    }

    /// Gets the recommended maximum number of VCPUs per VM.
    ///
    pub fn get_max_vcpus(&self) -> usize {
        match self.check_extension_int(Cap::MaxVcpus) {
            0 => self.get_nr_vcpus(),
            x => x as usize,
        }
    }

    /// X86 specific call to get the system supported CPUID values.
    ///
    /// # Arguments
    ///
    /// * `max_entries_count` - Maximum number of CPUID entries. This function can return less than
    ///                         this when the hardware does not support so many CPUID entries.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_supported_cpuid(&self, max_entries_count: usize) -> Result<CpuId> {
        let mut cpuid = CpuId::new(max_entries_count);

        let ret = unsafe {
            // ioctl is unsafe. The kernel is trusted not to write beyond the bounds of the memory
            // allocated for the struct. The limit is read from nent, which is set to the allocated
            // size(max_entries_count) above.
            ioctl_with_mut_ptr(self, KVM_GET_SUPPORTED_CPUID(), cpuid.as_mut_ptr())
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(cpuid)
    }

    /// Creates a VM fd using the KVM fd (`KVM_CREATE_VM`).
    ///
    /// A call to this function will also initialize the supported cpuid (`KVM_GET_SUPPORTED_CPUID`)
    /// and the size of the vcpu mmap area (`KVM_GET_VCPU_MMAP_SIZE`).
    ///
    pub fn create_vm(&self) -> Result<VmFd> {
        // Safe because we know kvm is a real kvm fd as this module is the only one that can make
        // Kvm objects.
        let ret = unsafe { ioctl(&self.kvm, KVM_CREATE_VM()) };
        if ret >= 0 {
            // Safe because we verify the value of ret and we are the owners of the fd.
            let vm_file = unsafe { File::from_raw_fd(ret) };
            let run_mmap_size = self.get_vcpu_mmap_size()?;
            Ok(VmFd {
                vm: vm_file,
                run_size: run_mmap_size,
            })
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl AsRawFd for Kvm {
    fn as_raw_fd(&self) -> RawFd {
        self.kvm.as_raw_fd()
    }
}

/// An address either in programmable I/O space or in memory mapped I/O space.
pub enum IoeventAddress {
    /// Representation of an programmable I/O address.
    Pio(u64),
    /// Representation of an memory mapped I/O address.
    Mmio(u64),
}

/// Used in `VmFd::register_ioevent` to indicate that no datamatch is requested.
pub struct NoDatamatch;
impl Into<u64> for NoDatamatch {
    fn into(self) -> u64 {
        0
    }
}

/// A safe wrapper over the `kvm_run` struct.
///
/// The wrapper is needed for sending the pointer to `kvm_run` between
/// threads as raw pointers do not implement `Send` and `Sync`.
pub struct KvmRunWrapper {
    kvm_run_ptr: *mut u8,
}

// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl Send for KvmRunWrapper {}
unsafe impl Sync for KvmRunWrapper {}

impl KvmRunWrapper {
    /// Maps the first `size` bytes of the given `fd`.
    ///
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    pub fn from_fd(fd: &AsRawFd, size: usize) -> Result<KvmRunWrapper> {
        // This is safe because we are creating a mapping in a place not already used by any other
        // area in this process.
        let addr = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok(KvmRunWrapper {
            kvm_run_ptr: addr as *mut u8,
        })
    }

    /// Returns a mutable reference to `kvm_run`.
    ///
    #[allow(clippy::mut_from_ref)]
    pub fn as_mut_ref(&self) -> &mut kvm_run {
        // Safe because we know we mapped enough memory to hold the `kvm_run` struct because the
        // kernel told us how large it was.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            &mut *(self.kvm_run_ptr as *mut kvm_run)
        }
    }
}

/// A wrapper around creating and using a VM.
pub struct VmFd {
    vm: File,
    run_size: usize,
}

impl VmFd {
    /// Creates/modifies a guest physical memory slot using `KVM_SET_USER_MEMORY_REGION`.
    ///
    /// See the documentation on the `KVM_SET_USER_MEMORY_REGION` ioctl.
    ///
    pub fn set_user_memory_region(
        &self,
        user_memory_region: kvm_userspace_memory_region,
    ) -> Result<()> {
        let ret =
            unsafe { ioctl_with_ref(self, KVM_SET_USER_MEMORY_REGION(), &user_memory_region) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Sets the address of the three-page region in the VM's address space.
    ///
    /// See the documentation on the `KVM_SET_TSS_ADDR` ioctl.
    ///
    /// # Arguments
    ///
    /// * `offset` - Physical address of a three-page region in the guest's physical address space.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_tss_address(&self, offset: usize) -> Result<()> {
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl_with_val(self, KVM_SET_TSS_ADDR(), offset as c_ulong) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Creates an in-kernel interrupt controller.
    ///
    /// See the documentation on the `KVM_CREATE_IRQCHIP` ioctl.
    ///
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn create_irq_chip(&self) -> Result<()> {
        // Safe because we know that our file is a VM fd and we verify the return result.
        let ret = unsafe { ioctl(self, KVM_CREATE_IRQCHIP()) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Creates a PIT as per the `KVM_CREATE_PIT2` ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn create_pit2(&self, pit_config: kvm_pit_config) -> Result<()> {
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_CREATE_PIT2(), &pit_config) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Registers an event to be signaled whenever a certain address is written to.
    ///
    /// # Arguments
    ///
    /// * `evt` - EventFd which will be signaled. When signaling, the usual `vmexit` to userspace
    ///           is prevented.
    /// * `addr` - Address being written to.
    /// * `datamatch` - Limits signaling `evt` to only the cases where the value being written is
    ///                 equal to this parameter. The size of `datamatch` is important and it must
    ///                 match the expected size of the guest's write.
    ///
    pub fn register_ioevent<T: Into<u64>>(
        &self,
        evt: &EventFd,
        addr: &IoeventAddress,
        datamatch: T,
    ) -> Result<()> {
        let mut flags = 0;
        if std::mem::size_of::<T>() > 0 {
            flags |= 1 << kvm_ioeventfd_flag_nr_datamatch
        }
        if let IoeventAddress::Pio(_) = *addr {
            flags |= 1 << kvm_ioeventfd_flag_nr_pio
        }

        let ioeventfd = kvm_ioeventfd {
            datamatch: datamatch.into(),
            len: std::mem::size_of::<T>() as u32,
            addr: match addr {
                IoeventAddress::Pio(ref p) => *p as u64,
                IoeventAddress::Mmio(ref m) => *m,
            },
            fd: evt.as_raw_fd(),
            flags,
            ..Default::default()
        };
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IOEVENTFD(), &ioeventfd) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Gets the bitmap of pages dirtied since the last call of this function.
    ///
    /// Leverages the dirty page logging feature in KVM. As a side-effect, this also resets the
    /// bitmap inside the kernel. Because of this, this function is only usable from one place in
    /// the code. Right now, that's just the dirty page count metrics, but if it's needed in other
    /// places, then some scheme for buffering the results is needed.
    ///
    /// # Arguments
    ///
    /// * `slot` - Guest memory slot identifier.
    /// * `memory_size` - Size of the memory region.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_dirty_log(&self, slot: u32, memory_size: usize) -> Result<Vec<u64>> {
        // Compute the length of the bitmap needed for all dirty pages in one memory slot.
        // One memory page is 4KiB (4096 bits) and KVM_GET_DIRTY_LOG returns one dirty bit for
        // each page.
        let page_size = 4 << 10;

        let div_round_up = |dividend, divisor| (dividend + divisor - 1) / divisor;
        // For ease of access we are saving the bitmap in a u64 vector. If `mem_size` is not a
        // multiple of `page_size * 64`, we use a ceil function to compute the capacity of the
        // bitmap. This way we make sure that all dirty pages are added to the bitmap.
        let bitmap_size = div_round_up(memory_size, page_size * 64);
        let mut bitmap = vec![0; bitmap_size];
        let b_data = bitmap.as_mut_ptr() as *mut c_void;
        let dirtylog = kvm_dirty_log {
            slot,
            padding1: 0,
            __bindgen_anon_1: kvm_dirty_log__bindgen_ty_1 {
                dirty_bitmap: b_data,
            },
        };
        // Safe because we know that our file is a VM fd, and we know that the amount of memory
        // we allocated for the bitmap is at least one bit per page.
        let ret = unsafe { ioctl_with_ref(self, KVM_GET_DIRTY_LOG(), &dirtylog) };
        if ret == 0 {
            Ok(bitmap)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Registers an event that will, when signaled, trigger the `gsi` IRQ.
    ///
    /// # Arguments
    ///
    /// * `evt` - Event to be signaled.
    /// * `gsi` - IRQ to be triggered.
    ///
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn register_irqfd(&self, evt: &EventFd, gsi: u32) -> Result<()> {
        let irqfd = kvm_irqfd {
            fd: evt.as_raw_fd() as u32,
            gsi,
            ..Default::default()
        };
        // Safe because we know that our file is a VM fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_IRQFD(), &irqfd) };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Constructs a new kvm VCPU fd.
    ///
    /// # Arguments
    ///
    /// * `id` - The CPU number between [0, max vcpus).
    ///
    /// # Errors
    /// Returns an error when the VM fd is invalid or the VCPU memory cannot be mapped correctly.
    ///
    pub fn create_vcpu(&self, id: u8) -> Result<VcpuFd> {
        // Safe because we know that vm is a VM fd and we verify the return result.
        #[allow(clippy::cast_lossless)]
        let vcpu_fd = unsafe { ioctl_with_val(&self.vm, KVM_CREATE_VCPU(), id as c_ulong) };
        if vcpu_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Wrap the vcpu now in case the following ? returns early. This is safe because we verified
        // the value of the fd and we own the fd.
        let vcpu = unsafe { File::from_raw_fd(vcpu_fd) };

        let kvm_run_ptr = KvmRunWrapper::from_fd(&vcpu, self.run_size)?;

        Ok(VcpuFd { vcpu, kvm_run_ptr })
    }
}

impl AsRawFd for VmFd {
    fn as_raw_fd(&self) -> RawFd {
        self.vm.as_raw_fd()
    }
}

/// Reasons for vcpu exits. The exit reasons are mapped to the `KVM_EXIT_*` defines
/// from `include/uapi/linux/kvm.h`.
#[derive(Debug)]
pub enum VcpuExit<'a> {
    /// An out port instruction was run on the given port with the given data.
    IoOut(u16 /* port */, &'a [u8] /* data */),
    /// An in port instruction was run on the given port.
    ///
    /// The given slice should be filled in before `Vcpu::run` is called again.
    IoIn(u16 /* port */, &'a mut [u8] /* data */),
    /// A read instruction was run against the given MMIO address.
    ///
    /// The given slice should be filled in before `Vcpu::run` is called again.
    MmioRead(u64 /* address */, &'a mut [u8]),
    /// A write instruction was run against the given MMIO address with the given data.
    MmioWrite(u64 /* address */, &'a [u8]),
    /// Corresponds to KVM_EXIT_UNKNOWN.
    Unknown,
    /// Corresponds to KVM_EXIT_EXCEPTION.
    Exception,
    /// Corresponds to KVM_EXIT_HYPERCALL.
    Hypercall,
    /// Corresponds to KVM_EXIT_DEBUG.
    Debug,
    /// Corresponds to KVM_EXIT_HLT.
    Hlt,
    /// Corresponds to KVM_EXIT_IRQ_WINDOW_OPEN.
    IrqWindowOpen,
    /// Corresponds to KVM_EXIT_SHUTDOWN.
    Shutdown,
    /// Corresponds to KVM_EXIT_FAIL_ENTRY.
    FailEntry,
    /// Corresponds to KVM_EXIT_INTR.
    Intr,
    /// Corresponds to KVM_EXIT_SET_TPR.
    SetTpr,
    /// Corresponds to KVM_EXIT_TPR_ACCESS.
    TprAccess,
    /// Corresponds to KVM_EXIT_S390_SIEIC.
    S390Sieic,
    /// Corresponds to KVM_EXIT_S390_RESET.
    S390Reset,
    /// Corresponds to KVM_EXIT_DCR.
    Dcr,
    /// Corresponds to KVM_EXIT_NMI.
    Nmi,
    /// Corresponds to KVM_EXIT_INTERNAL_ERROR.
    InternalError,
    /// Corresponds to KVM_EXIT_OSI.
    Osi,
    /// Corresponds to KVM_EXIT_PAPR_HCALL.
    PaprHcall,
    /// Corresponds to KVM_EXIT_S390_UCONTROL.
    S390Ucontrol,
    /// Corresponds to KVM_EXIT_WATCHDOG.
    Watchdog,
    /// Corresponds to KVM_EXIT_S390_TSCH.
    S390Tsch,
    /// Corresponds to KVM_EXIT_EPR.
    Epr,
    /// Corresponds to KVM_EXIT_SYSTEM_EVENT.
    SystemEvent,
    /// Corresponds to KVM_EXIT_S390_STSI.
    S390Stsi,
    /// Corresponds to KVM_EXIT_IOAPIC_EOI.
    IoapicEoi,
    /// Corresponds to KVM_EXIT_HYPERV.
    Hyperv,
}

/// A wrapper around creating and using a kvm related VCPU fd
pub struct VcpuFd {
    vcpu: File,
    kvm_run_ptr: KvmRunWrapper,
}

impl VcpuFd {
    /// Gets the VCPU registers using the `KVM_GET_REGS` ioctl.
    ///
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_regs(&self) -> Result<kvm_regs> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let mut regs = unsafe { std::mem::zeroed() };
        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_REGS(), &mut regs) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(regs)
    }

    /// Sets the VCPU registers using `KVM_SET_REGS` ioctl.
    ///
    /// # Arguments
    ///
    /// * `regs` - Registers being set.
    ///
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn set_regs(&self, regs: &kvm_regs) -> Result<()> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_REGS(), regs) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Gets the VCPU special registers using `KVM_GET_SREGS` ioctl.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_sregs(&self) -> Result<kvm_sregs> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only write the
        // correct amount of memory to our pointer, and we verify the return result.
        let mut regs = kvm_sregs::default();

        let ret = unsafe { ioctl_with_mut_ref(self, KVM_GET_SREGS(), &mut regs) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(regs)
    }

    /// Sets the VCPU special registers using `KVM_SET_SREGS` ioctl.
    ///
    /// # Arguments
    ///
    /// * `sregs` - Special registers to be set.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_sregs(&self, sregs: &kvm_sregs) -> Result<()> {
        // Safe because we know that our file is a VCPU fd, we know the kernel will only read the
        // correct amount of memory from our pointer, and we verify the return result.
        let ret = unsafe { ioctl_with_ref(self, KVM_SET_SREGS(), sregs) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// X86 specific call that gets the FPU-related structure.
    ///
    /// See the documentation for `KVM_GET_FPU`.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_fpu(&self) -> Result<kvm_fpu> {
        let mut fpu = kvm_fpu::default();

        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_fpu struct.
            ioctl_with_mut_ref(self, KVM_GET_FPU(), &mut fpu)
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fpu)
    }

    /// X86 specific call to setup the FPU.
    ///
    /// See the documentation for `KVM_SET_FPU`.
    ///
    /// # Arguments
    ///
    /// * `fpu` - FPU configurations struct.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_fpu(&self, fpu: &kvm_fpu) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_fpu struct.
            ioctl_with_ref(self, KVM_SET_FPU(), fpu)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// X86 specific call to setup the CPUID registers.
    ///
    /// See the documentation for `KVM_SET_CPUID2`.
    ///
    /// # Arguments
    ///
    /// * `cpuid` - CPUID registers.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_cpuid2(&self, cpuid: &CpuId) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_msrs struct.
            ioctl_with_ptr(self, KVM_SET_CPUID2(), cpuid.as_ptr())
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// X86 specific call to get the state of the LAPIC (Local Advanced Programmable Interrupt
    /// Controller).
    ///
    /// See the documentation for `KVM_GET_LAPIC`.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_lapic(&self) -> Result<kvm_lapic_state> {
        let mut klapic = kvm_lapic_state::default();

        let ret = unsafe {
            // The ioctl is unsafe unless you trust the kernel not to write past the end of the
            // local_apic struct.
            ioctl_with_mut_ref(self, KVM_GET_LAPIC(), &mut klapic)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(klapic)
    }

    /// X86 specific call to set the state of the LAPIC (Local Advanced Programmable Interrupt
    /// Controller).
    ///
    /// See the documentation for `KVM_SET_LAPIC`.
    ///
    /// # Arguments
    ///
    /// * `klapic` - LAPIC state registers.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_lapic(&self, klapic: &kvm_lapic_state) -> Result<()> {
        let ret = unsafe {
            // The ioctl is safe because the kernel will only read from the klapic struct.
            ioctl_with_ref(self, KVM_SET_LAPIC(), klapic)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// X86 specific call to read model-specific registers for this VCPU.
    ///
    /// It emulates `KVM_GET_MSRS` ioctl's behavior by returning the number of MSRs
    /// successfully read upon success or the last error number in case of failure.
    ///
    /// # Arguments
    ///
    /// * `msrs`  - MSRs to be read.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_msrs(&self, msrs: &mut kvm_msrs) -> Result<(i32)> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_msrs struct.
            ioctl_with_mut_ref(self, KVM_GET_MSRS(), msrs)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ret)
    }

    /// X86 specific call to setup the MSRS.
    ///
    /// See the documentation for `KVM_SET_MSRS`.
    ///
    /// # Arguments
    ///
    /// * `kvm_msrs` - MSRs to be written.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_msrs(&self, msrs: &kvm_msrs) -> Result<()> {
        let ret = unsafe {
            // Here we trust the kernel not to read past the end of the kvm_msrs struct.
            ioctl_with_ref(self, KVM_SET_MSRS(), msrs)
        };
        if ret < 0 {
            // KVM_SET_MSRS actually returns the number of msr entries written.
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Triggers the running of the current virtual CPU returning an exit reason.
    ///
    pub fn run(&self) -> Result<VcpuExit> {
        // Safe because we know that our file is a VCPU fd and we verify the return result.
        let ret = unsafe { ioctl(self, KVM_RUN()) };
        if ret == 0 {
            let run = self.kvm_run_ptr.as_mut_ref();
            match run.exit_reason {
                // make sure you treat all possible exit reasons from include/uapi/linux/kvm.h corresponding
                // when upgrading to a different kernel version
                KVM_EXIT_UNKNOWN => Ok(VcpuExit::Unknown),
                KVM_EXIT_EXCEPTION => Ok(VcpuExit::Exception),
                KVM_EXIT_IO => {
                    let run_start = run as *mut kvm_run as *mut u8;
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let io = unsafe { run.__bindgen_anon_1.io };
                    let port = io.port;
                    let data_size = io.count as usize * io.size as usize;
                    // The data_offset is defined by the kernel to be some number of bytes into the
                    // kvm_run stucture, which we have fully mmap'd.
                    let data_ptr = unsafe { run_start.offset(io.data_offset as isize) };
                    // The slice's lifetime is limited to the lifetime of this Vcpu, which is equal
                    // to the mmap of the kvm_run struct that this is slicing from
                    let data_slice = unsafe {
                        std::slice::from_raw_parts_mut::<u8>(data_ptr as *mut u8, data_size)
                    };
                    match u32::from(io.direction) {
                        KVM_EXIT_IO_IN => Ok(VcpuExit::IoIn(port, data_slice)),
                        KVM_EXIT_IO_OUT => Ok(VcpuExit::IoOut(port, data_slice)),
                        _ => Err(io::Error::from_raw_os_error(EINVAL)),
                    }
                }
                KVM_EXIT_HYPERCALL => Ok(VcpuExit::Hypercall),
                KVM_EXIT_DEBUG => Ok(VcpuExit::Debug),
                KVM_EXIT_HLT => Ok(VcpuExit::Hlt),
                KVM_EXIT_MMIO => {
                    // Safe because the exit_reason (which comes from the kernel) told us which
                    // union field to use.
                    let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
                    let addr = mmio.phys_addr;
                    let len = mmio.len as usize;
                    let data_slice = &mut mmio.data[..len];
                    if mmio.is_write != 0 {
                        Ok(VcpuExit::MmioWrite(addr, data_slice))
                    } else {
                        Ok(VcpuExit::MmioRead(addr, data_slice))
                    }
                }
                KVM_EXIT_IRQ_WINDOW_OPEN => Ok(VcpuExit::IrqWindowOpen),
                KVM_EXIT_SHUTDOWN => Ok(VcpuExit::Shutdown),
                KVM_EXIT_FAIL_ENTRY => Ok(VcpuExit::FailEntry),
                KVM_EXIT_INTR => Ok(VcpuExit::Intr),
                KVM_EXIT_SET_TPR => Ok(VcpuExit::SetTpr),
                KVM_EXIT_TPR_ACCESS => Ok(VcpuExit::TprAccess),
                KVM_EXIT_S390_SIEIC => Ok(VcpuExit::S390Sieic),
                KVM_EXIT_S390_RESET => Ok(VcpuExit::S390Reset),
                KVM_EXIT_DCR => Ok(VcpuExit::Dcr),
                KVM_EXIT_NMI => Ok(VcpuExit::Nmi),
                KVM_EXIT_INTERNAL_ERROR => Ok(VcpuExit::InternalError),
                KVM_EXIT_OSI => Ok(VcpuExit::Osi),
                KVM_EXIT_PAPR_HCALL => Ok(VcpuExit::PaprHcall),
                KVM_EXIT_S390_UCONTROL => Ok(VcpuExit::S390Ucontrol),
                KVM_EXIT_WATCHDOG => Ok(VcpuExit::Watchdog),
                KVM_EXIT_S390_TSCH => Ok(VcpuExit::S390Tsch),
                KVM_EXIT_EPR => Ok(VcpuExit::Epr),
                KVM_EXIT_SYSTEM_EVENT => Ok(VcpuExit::SystemEvent),
                KVM_EXIT_S390_STSI => Ok(VcpuExit::S390Stsi),
                KVM_EXIT_IOAPIC_EOI => Ok(VcpuExit::IoapicEoi),
                KVM_EXIT_HYPERV => Ok(VcpuExit::Hyperv),
                r => panic!("unknown kvm exit reason: {}", r),
            }
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl AsRawFd for VcpuFd {
    fn as_raw_fd(&self) -> RawFd {
        self.vcpu.as_raw_fd()
    }
}

/// Wrapper for `kvm_cpuid2` which has a zero length array at the end.
/// Hides the zero length array behind a bounds check.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub struct CpuId {
    /// Wrapper over `kvm_cpuid2` from which we only use the first element.
    kvm_cpuid: Vec<kvm_cpuid2>,
    // Number of `kvm_cpuid_entry2` structs at the end of kvm_cpuid2.
    allocated_len: usize,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl Clone for CpuId {
    fn clone(&self) -> Self {
        let mut kvm_cpuid = Vec::with_capacity(self.kvm_cpuid.len());
        for _ in 0..self.kvm_cpuid.len() {
            kvm_cpuid.push(kvm_cpuid2::default());
        }

        let num_bytes = self.kvm_cpuid.len() * size_of::<kvm_cpuid2>();

        let src_byte_slice =
            unsafe { std::slice::from_raw_parts(self.kvm_cpuid.as_ptr() as *const u8, num_bytes) };

        let dst_byte_slice =
            unsafe { std::slice::from_raw_parts_mut(kvm_cpuid.as_mut_ptr() as *mut u8, num_bytes) };

        dst_byte_slice.copy_from_slice(src_byte_slice);

        CpuId {
            kvm_cpuid,
            allocated_len: self.allocated_len,
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl CpuId {
    /// Creates a new `CpuId` structure that can contain at most `array_len` KVM CPUID entries.
    ///
    /// # Arguments
    ///
    /// * `array_len` - Maximum number of CPUID entries.
    ///
    pub fn new(array_len: usize) -> CpuId {
        let mut kvm_cpuid = vec_with_array_field::<kvm_cpuid2, kvm_cpuid_entry2>(array_len);
        kvm_cpuid[0].nent = array_len as u32;

        CpuId {
            kvm_cpuid,
            allocated_len: array_len,
        }
    }

    /// Creates a new `CpuId` structure based on a supplied vector of kvm_cpuid_entry2.
    ///
    /// # Arguments
    ///
    /// * `entries` - The vector of kvm_cpuid_entry2 entries.
    ///
    pub fn from_entries(entries: &[kvm_cpuid_entry2]) -> CpuId {
        let mut kvm_cpuid = vec_with_array_field::<kvm_cpuid2, kvm_cpuid_entry2>(entries.len());
        kvm_cpuid[0].nent = entries.len() as u32;

        unsafe {
            kvm_cpuid[0]
                .entries
                .as_mut_slice(entries.len())
                .copy_from_slice(entries);
        }

        CpuId {
            kvm_cpuid,
            allocated_len: entries.len(),
        }
    }

    /// Get the mutable entries slice so they can be modified before passing to the VCPU.
    ///
    pub fn mut_entries_slice(&mut self) -> &mut [kvm_cpuid_entry2] {
        // Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
        // the length we originally allocated with eliminates the possibility of overflow.
        if self.kvm_cpuid[0].nent as usize > self.allocated_len {
            self.kvm_cpuid[0].nent = self.allocated_len as u32;
        }
        let nent = self.kvm_cpuid[0].nent as usize;
        unsafe { self.kvm_cpuid[0].entries.as_mut_slice(nent) }
    }

    /// Get a  pointer so it can be passed to the kernel. Using this pointer is unsafe.
    ///
    pub fn as_ptr(&self) -> *const kvm_cpuid2 {
        &self.kvm_cpuid[0]
    }

    /// Get a mutable pointer so it can be passed to the kernel. Using this pointer is unsafe.
    ///
    pub fn as_mut_ptr(&mut self) -> *mut kvm_cpuid2 {
        &mut self.kvm_cpuid[0]
    }
}

#[cfg(test)]
mod tests {
    extern crate byteorder;

    use super::*;

    use kvm_cpuid_entry2;
    use CpuId;

    // as per https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/fpu/internal.h
    pub const KVM_FPU_CWD: usize = 0x37f;
    pub const KVM_FPU_MXCSR: usize = 0x1f80;

    impl VmFd {
        fn get_run_size(&self) -> usize {
            self.run_size
        }
    }

    // Helper function for mmap an anonymous memory of `size`.
    // Panics if the mmap fails.
    fn mmap_anonymous(size: usize) -> *mut u8 {
        let addr = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            panic!("mmap failed.");
        }

        return addr as *mut u8;
    }

    impl KvmRunWrapper {
        fn new(size: usize) -> Self {
            KvmRunWrapper {
                kvm_run_ptr: mmap_anonymous(size),
            }
        }
    }

    // kvm system related function tests
    #[test]
    fn new() {
        Kvm::new().unwrap();
    }

    #[test]
    fn check_extension() {
        let kvm = Kvm::new().unwrap();
        assert!(kvm.check_extension(Cap::UserMemory));
        // I assume nobody is testing this on s390
        assert!(!kvm.check_extension(Cap::S390UserSigp));
    }

    #[test]
    fn vcpu_mmap_size() {
        let kvm = Kvm::new().unwrap();
        let mmap_size = kvm.get_vcpu_mmap_size().unwrap();
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert!(mmap_size >= page_size);
        assert_eq!(mmap_size % page_size, 0);
    }

    #[test]
    fn get_nr_vcpus() {
        let kvm = Kvm::new().unwrap();
        let nr_vcpus = kvm.get_nr_vcpus();
        assert!(nr_vcpus >= 4);
    }

    #[test]
    fn get_max_memslots() {
        let kvm = Kvm::new().unwrap();
        let max_mem_slots = kvm.get_nr_memslots();
        assert!(max_mem_slots >= 32);
    }

    #[test]
    fn test_faulty_memory_region_slot() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let max_mem_slots = kvm.get_nr_memslots();

        let mem_size = 1 << 20;
        let userspace_addr = mmap_anonymous(mem_size) as u64;
        let region_addr: usize = 0x0;

        // KVM is checking that the memory region slot is less than KVM_CAP_NR_MEMSLOTS.
        // Valid slots are in the interval [0, KVM_CAP_NR_MEMSLOTS).
        let mem_region = kvm_userspace_memory_region {
            slot: max_mem_slots as u32,
            guest_phys_addr: region_addr as u64,
            memory_size: mem_size as u64,
            userspace_addr: userspace_addr as u64,
            flags: 0,
        };

        // KVM returns -EINVAL (22) when the slot > KVM_CAP_NR_MEMSLOTS.
        assert_eq!(
            vm.set_user_memory_region(mem_region)
                .unwrap_err()
                .raw_os_error()
                .unwrap(),
            22
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn cpuid_test() {
        let kvm = Kvm::new().unwrap();
        if kvm.check_extension(Cap::ExtCpuid) {
            let vm = kvm.create_vm().unwrap();
            let mut cpuid = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
            assert!(cpuid.mut_entries_slice().len() <= MAX_KVM_CPUID_ENTRIES);
            let nr_vcpus = kvm.get_nr_vcpus();
            for cpu_id in 0..nr_vcpus {
                let vcpu = vm.create_vcpu(cpu_id as u8).unwrap();
                vcpu.set_cpuid2(&cpuid).unwrap();
            }
        }
    }

    // kvm vm related function tests
    #[test]
    fn create_vm() {
        let kvm = Kvm::new().unwrap();
        kvm.create_vm().unwrap();
    }

    #[test]
    fn get_vm_run_size() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        assert_eq!(kvm.get_vcpu_mmap_size().unwrap(), vm.get_run_size());
    }

    #[test]
    fn set_invalid_memory_test() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let invalid_mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: 0,
            userspace_addr: 0,
            flags: 0,
        };
        assert!(vm.set_user_memory_region(invalid_mem_region).is_err());
    }

    #[test]
    fn set_tss_address() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        assert!(vm.set_tss_address(0xfffb_d000).is_ok());
    }

    #[test]
    fn create_irq_chip() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        assert!(vm.create_irq_chip().is_ok());
    }

    #[test]
    fn create_pit2() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        assert!(vm.create_pit2(kvm_pit_config::default()).is_ok());
    }

    #[test]
    fn register_ioevent() {
        assert_eq!(std::mem::size_of::<NoDatamatch>(), 0);

        let kvm = Kvm::new().unwrap();
        let vm_fd = kvm.create_vm().unwrap();
        let evtfd = EventFd::new().unwrap();
        vm_fd
            .register_ioevent(&evtfd, &IoeventAddress::Pio(0xf4), NoDatamatch)
            .unwrap();
        vm_fd
            .register_ioevent(&evtfd, &IoeventAddress::Mmio(0x1000), NoDatamatch)
            .unwrap();
        vm_fd
            .register_ioevent(&evtfd, &IoeventAddress::Pio(0xc1), 0x7fu8)
            .unwrap();
        vm_fd
            .register_ioevent(&evtfd, &IoeventAddress::Pio(0xc2), 0x1337u16)
            .unwrap();
        vm_fd
            .register_ioevent(&evtfd, &IoeventAddress::Pio(0xc4), 0xdead_beefu32)
            .unwrap();
        vm_fd
            .register_ioevent(&evtfd, &IoeventAddress::Pio(0xc8), 0xdead_beef_dead_beefu64)
            .unwrap();
    }

    #[test]
    fn register_irqfd() {
        let kvm = Kvm::new().unwrap();
        let vm_fd = kvm.create_vm().unwrap();
        let evtfd1 = EventFd::new().unwrap();
        let evtfd2 = EventFd::new().unwrap();
        let evtfd3 = EventFd::new().unwrap();
        vm_fd.register_irqfd(&evtfd1, 4).unwrap();
        vm_fd.register_irqfd(&evtfd2, 8).unwrap();
        vm_fd.register_irqfd(&evtfd3, 4).unwrap();
        vm_fd.register_irqfd(&evtfd3, 4).unwrap_err();
        vm_fd.register_irqfd(&evtfd3, 5).unwrap_err();
    }

    #[test]
    fn create_vcpu() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        vm.create_vcpu(0).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn reg_test() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut regs = vcpu.get_regs().unwrap();
        regs.rax = 0x1;
        vcpu.set_regs(&regs).unwrap();
        assert!(vcpu.get_regs().unwrap().rax == 0x1);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn sreg_test() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut sregs = vcpu.get_sregs().unwrap();
        sregs.cr0 = 0x1;
        sregs.efer = 0x2;

        vcpu.set_sregs(&sregs).unwrap();
        assert_eq!(vcpu.get_sregs().unwrap().cr0, 0x1);
        assert_eq!(vcpu.get_sregs().unwrap().efer, 0x2);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn fpu_test() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut fpu: kvm_fpu = kvm_fpu {
            fcw: KVM_FPU_CWD as u16,
            mxcsr: KVM_FPU_MXCSR as u32,
            ..Default::default()
        };

        fpu.fcw = KVM_FPU_CWD as u16;
        fpu.mxcsr = KVM_FPU_MXCSR as u32;

        vcpu.set_fpu(&fpu).unwrap();
        assert_eq!(vcpu.get_fpu().unwrap().fcw, KVM_FPU_CWD as u16);
        //The following will fail; kvm related bug; uncomment when bug solved
        //assert_eq!(vcpu.get_fpu().unwrap().mxcsr, KVM_FPU_MXCSR as u32);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn lapic_test() {
        use std::io::Cursor;
        //we might get read of byteorder if we replace 5h3 mem::transmute with something safer
        use self::byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
        //as per https://github.com/torvalds/linux/arch/x86/kvm/lapic.c
        //try to write and read the APIC_ICR (0x300) register which is non-read only and
        //one can simply write to it
        let kvm = Kvm::new().unwrap();
        assert!(kvm.check_extension(Cap::Irqchip));
        let vm = kvm.create_vm().unwrap();
        //the get_lapic ioctl will fail if there is no irqchip created beforehand
        assert!(vm.create_irq_chip().is_ok());
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut klapic: kvm_lapic_state = vcpu.get_lapic().unwrap();

        let reg_offset = 0x300;
        let value = 2 as u32;
        //try to write and read the APIC_ICR	0x300
        let write_slice =
            unsafe { &mut *(&mut klapic.regs[reg_offset..] as *mut [i8] as *mut [u8]) };
        let mut writer = Cursor::new(write_slice);
        writer.write_u32::<LittleEndian>(value).unwrap();
        vcpu.set_lapic(&klapic).unwrap();
        klapic = vcpu.get_lapic().unwrap();
        let read_slice = unsafe { &*(&klapic.regs[reg_offset..] as *const [i8] as *const [u8]) };
        let mut reader = Cursor::new(read_slice);
        assert_eq!(reader.read_u32::<LittleEndian>().unwrap(), value);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    #[allow(clippy::cast_ptr_alignment)]
    fn msrs_test() {
        use std::mem;
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut configured_entry_vec = Vec::<kvm_msr_entry>::new();

        configured_entry_vec.push(kvm_msr_entry {
            index: 0x0000_0174,
            data: 0x0,
            ..Default::default()
        });
        configured_entry_vec.push(kvm_msr_entry {
            index: 0x0000_0175,
            data: 0x1,
            ..Default::default()
        });

        let vec_size_bytes = mem::size_of::<kvm_msrs>()
            + (configured_entry_vec.len() * mem::size_of::<kvm_msr_entry>());
        let vec: Vec<u8> = Vec::with_capacity(vec_size_bytes);
        let msrs: &mut kvm_msrs = unsafe { &mut *(vec.as_ptr() as *mut kvm_msrs) };
        unsafe {
            let entries: &mut [kvm_msr_entry] =
                msrs.entries.as_mut_slice(configured_entry_vec.len());
            entries.copy_from_slice(&configured_entry_vec);
        }
        msrs.nmsrs = configured_entry_vec.len() as u32;
        vcpu.set_msrs(msrs).unwrap();

        //now test that GET_MSRS returns the same
        let wanted_kvm_msrs_entries = [
            kvm_msr_entry {
                index: 0x0000_0174,
                ..Default::default()
            },
            kvm_msr_entry {
                index: 0x0000_0175,
                ..Default::default()
            },
        ];
        let vec2: Vec<u8> = Vec::with_capacity(vec_size_bytes);
        let mut msrs2: &mut kvm_msrs = unsafe {
            // Converting the vector's memory to a struct is unsafe.  Carefully using the read-only
            // vector to size and set the members ensures no out-of-bounds errors below.
            &mut *(vec2.as_ptr() as *mut kvm_msrs)
        };

        unsafe {
            let entries: &mut [kvm_msr_entry] =
                msrs2.entries.as_mut_slice(configured_entry_vec.len());
            entries.copy_from_slice(&wanted_kvm_msrs_entries);
        }
        msrs2.nmsrs = configured_entry_vec.len() as u32;

        let read_msrs = vcpu.get_msrs(&mut msrs2).unwrap();
        assert_eq!(read_msrs, configured_entry_vec.len() as i32);

        let returned_kvm_msr_entries: &mut [kvm_msr_entry] =
            unsafe { msrs2.entries.as_mut_slice(msrs2.nmsrs as usize) };

        for (i, entry) in returned_kvm_msr_entries.iter_mut().enumerate() {
            assert_eq!(entry, &mut configured_entry_vec[i]);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_run_code() {
        use std::io::Write;

        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        // This example based on https://lwn.net/Articles/658511/
        #[rustfmt::skip]
        let code = [
            0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
            0x00, 0xd8, /* add %bl, %al */
            0x04, b'0', /* add $'0', %al */
            0xee, /* out %al, %dx */
            0xec, /* in %dx, %al */
            0xc6, 0x06, 0x00, 0x80, 0x00, /* movl $0, (0x8000); This generates a MMIO Write.*/
            0x8a, 0x16, 0x00, 0x80, /* movl (0x8000), %dl; This generates a MMIO Read.*/
            0xc6, 0x06, 0x00, 0x20, 0x00, /* movl $0, (0x2000); Dirty one page in guest mem. */
            0xf4, /* hlt */
        ];

        let mem_size = 0x4000;
        let load_addr = mmap_anonymous(mem_size);
        let guest_addr: u64 = 0x1000;
        let slot: u32 = 0;
        let mem_region = kvm_userspace_memory_region {
            slot,
            guest_phys_addr: guest_addr,
            memory_size: mem_size as u64,
            userspace_addr: load_addr as u64,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };
        vm.set_user_memory_region(mem_region).unwrap();

        unsafe {
            // Get a mutable slice of `mem_size` from `load_addr`.
            // This is safe because we mapped it before.
            let mut slice = std::slice::from_raw_parts_mut(load_addr, mem_size);
            slice.write(&code).unwrap();
        }

        let vcpu_fd = vm.create_vcpu(0).expect("new VcpuFd failed");

        let mut vcpu_sregs = vcpu_fd.get_sregs().expect("get sregs failed");
        assert_ne!(vcpu_sregs.cs.base, 0);
        assert_ne!(vcpu_sregs.cs.selector, 0);
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        vcpu_fd.set_sregs(&vcpu_sregs).expect("set sregs failed");

        let mut vcpu_regs = vcpu_fd.get_regs().expect("get regs failed");
        // Set the Instruction Pointer to the guest address where we loaded the code.
        vcpu_regs.rip = guest_addr;
        vcpu_regs.rax = 2;
        vcpu_regs.rbx = 3;
        vcpu_regs.rflags = 2;
        vcpu_fd.set_regs(&vcpu_regs).expect("set regs failed");

        // Variables used for checking if MMIO Read & Write were performed.
        let mut mmio_read = false;
        let mut mmio_write = false;
        loop {
            match vcpu_fd.run().expect("run failed") {
                VcpuExit::IoIn(addr, data) => {
                    assert_eq!(addr, 0x3f8);
                    assert_eq!(data.len(), 1);
                }
                VcpuExit::IoOut(addr, data) => {
                    assert_eq!(addr, 0x3f8);
                    assert_eq!(data.len(), 1);
                    assert_eq!(data[0], b'5');
                }
                VcpuExit::MmioRead(addr, data) => {
                    assert_eq!(addr, 0x8000);
                    assert_eq!(data.len(), 1);
                    mmio_read = true;
                }
                VcpuExit::MmioWrite(addr, data) => {
                    assert_eq!(addr, 0x8000);
                    assert_eq!(data.len(), 1);
                    assert_eq!(data[0], 0);
                    mmio_write = true;
                }
                VcpuExit::Hlt => {
                    // The code snippet dirties 2 pages:
                    // * one when the code itself is loaded in memory;
                    // * and one more from the `movl` that writes to address 0x2000
                    let dirty_pages_bitmap = vm.get_dirty_log(slot, mem_size).unwrap();
                    let dirty_pages = dirty_pages_bitmap
                        .into_iter()
                        .map(|page| page.count_ones())
                        .fold(0, |dirty_page_count, i| dirty_page_count + i);
                    assert_eq!(dirty_pages, 2);
                    break;
                }
                r => panic!("unexpected exit reason: {:?}", r),
            }
        }
        assert!(mmio_read);
        assert!(mmio_write);
    }

    fn get_raw_errno<T>(result: super::Result<T>) -> i32 {
        result.err().unwrap().raw_os_error().unwrap()
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[test]
    fn faulty_kvm_fds_test() {
        let badf_errno = libc::EBADF;

        let faulty_kvm = Kvm {
            kvm: unsafe { File::from_raw_fd(-1) },
        };
        assert_eq!(get_raw_errno(faulty_kvm.get_vcpu_mmap_size()), badf_errno);
        let max_cpus = faulty_kvm.get_nr_vcpus();
        assert_eq!(max_cpus, 4);
        assert_eq!(
            get_raw_errno(faulty_kvm.get_supported_cpuid(max_cpus)),
            badf_errno
        );

        assert_eq!(get_raw_errno(faulty_kvm.create_vm()), badf_errno);
        let faulty_vm_fd = VmFd {
            vm: unsafe { File::from_raw_fd(-1) },
            run_size: 0,
        };
        let invalid_mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: 0,
            userspace_addr: 0,
            flags: 0,
        };
        assert_eq!(
            get_raw_errno(faulty_vm_fd.set_user_memory_region(invalid_mem_region)),
            badf_errno
        );
        assert_eq!(get_raw_errno(faulty_vm_fd.set_tss_address(0)), badf_errno);
        assert_eq!(get_raw_errno(faulty_vm_fd.create_irq_chip()), badf_errno);
        assert_eq!(
            get_raw_errno(faulty_vm_fd.create_pit2(kvm_pit_config::default())),
            badf_errno
        );
        let event_fd = EventFd::new().unwrap();
        assert_eq!(
            get_raw_errno(faulty_vm_fd.register_ioevent(&event_fd, &IoeventAddress::Pio(0), 0u64)),
            badf_errno
        );
        assert_eq!(
            get_raw_errno(faulty_vm_fd.register_irqfd(&event_fd, 0)),
            badf_errno
        );

        assert_eq!(get_raw_errno(faulty_vm_fd.create_vcpu(0)), badf_errno);
        let faulty_vcpu_fd = VcpuFd {
            vcpu: unsafe { File::from_raw_fd(-1) },
            kvm_run_ptr: KvmRunWrapper::new(10),
        };
        assert_eq!(get_raw_errno(faulty_vcpu_fd.get_regs()), badf_errno);
        assert_eq!(
            get_raw_errno(faulty_vcpu_fd.set_regs(&unsafe { std::mem::zeroed() })),
            badf_errno
        );
        assert_eq!(get_raw_errno(faulty_vcpu_fd.get_sregs()), badf_errno);
        assert_eq!(
            get_raw_errno(faulty_vcpu_fd.set_sregs(&unsafe { std::mem::zeroed() })),
            badf_errno
        );
        assert_eq!(get_raw_errno(faulty_vcpu_fd.get_fpu()), badf_errno);
        assert_eq!(
            get_raw_errno(faulty_vcpu_fd.set_fpu(&unsafe { std::mem::zeroed() })),
            badf_errno
        );
        assert_eq!(
            get_raw_errno(
                faulty_vcpu_fd.set_cpuid2(
                    &Kvm::new()
                        .unwrap()
                        .get_supported_cpuid(MAX_KVM_CPUID_ENTRIES)
                        .unwrap()
                )
            ),
            badf_errno
        );
        // kvm_lapic_state does not implement debug by default so we cannot
        // use unwrap_err here.
        assert!(faulty_vcpu_fd.get_lapic().is_err());
        assert_eq!(
            get_raw_errno(faulty_vcpu_fd.set_lapic(&unsafe { std::mem::zeroed() })),
            badf_errno
        );
        assert_eq!(
            get_raw_errno(faulty_vcpu_fd.get_msrs(&mut kvm_msrs::default())),
            badf_errno
        );
        assert_eq!(
            get_raw_errno(faulty_vcpu_fd.set_msrs(&unsafe { std::mem::zeroed() })),
            badf_errno
        );
        assert_eq!(get_raw_errno(faulty_vcpu_fd.run()), badf_errno);
    }

    #[test]
    fn test_kvm_api_version() {
        let kvm = Kvm::new().unwrap();
        assert_eq!(kvm.get_api_version(), KVM_API_VERSION as i32);
    }

    impl PartialEq for CpuId {
        fn eq(&self, other: &CpuId) -> bool {
            let entries: &[kvm_cpuid_entry2] =
                unsafe { self.kvm_cpuid[0].entries.as_slice(self.allocated_len) };
            let other_entries: &[kvm_cpuid_entry2] =
                unsafe { self.kvm_cpuid[0].entries.as_slice(other.allocated_len) };
            self.allocated_len == other.allocated_len && entries == other_entries
        }
    }

    #[test]
    fn test_cpuid_clone() {
        let kvm = Kvm::new().unwrap();
        let cpuid_1 = kvm.get_supported_cpuid(MAX_KVM_CPUID_ENTRIES).unwrap();
        let mut cpuid_2 = cpuid_1.clone();
        assert!(cpuid_1 == cpuid_2);
        cpuid_2 = unsafe { std::mem::zeroed() };
        assert!(cpuid_1 != cpuid_2);
    }

    #[test]
    fn test_cpu_id_new() {
        let num_entries = 5;
        let mut cpuid = CpuId::new(num_entries);

        // check that the cpuid contains `num_entries` empty entries
        assert!(cpuid.allocated_len == num_entries);
        assert!(cpuid.kvm_cpuid[0].nent == num_entries as u32);
        for entry in cpuid.mut_entries_slice() {
            assert!(
                *entry
                    == kvm_cpuid_entry2 {
                        function: 0,
                        index: 0,
                        flags: 0,
                        eax: 0,
                        ebx: 0,
                        ecx: 0,
                        edx: 0,
                        padding: [0, 0, 0],
                    }
            );
        }
    }

    #[test]
    fn test_cpu_id_from_entries() {
        let num_entries = 4;
        let mut cpuid = CpuId::new(num_entries);

        // add entry
        let mut entries = cpuid.mut_entries_slice().to_vec();
        let new_entry = kvm_cpuid_entry2 {
            function: 0x4,
            index: 0,
            flags: 1,
            eax: 0b1100000,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };
        entries.insert(0, new_entry);
        cpuid = CpuId::from_entries(&entries);

        // check that the cpuid contains the new entry
        assert!(cpuid.allocated_len == num_entries + 1);
        assert!(cpuid.kvm_cpuid[0].nent == (num_entries + 1) as u32);
        assert!(cpuid.mut_entries_slice().len() == num_entries + 1);
        assert!(cpuid.mut_entries_slice()[0] == new_entry);
    }

    #[test]
    fn test_cpu_id_mut_entries_slice() {
        let num_entries = 5;
        let mut cpuid = CpuId::new(num_entries);

        {
            // check that the CpuId has been initialized correctly:
            // there should be `num_entries` empty entries
            assert!(cpuid.allocated_len == num_entries);
            assert!(cpuid.kvm_cpuid[0].nent == num_entries as u32);

            let entries = cpuid.mut_entries_slice();
            assert!(entries.len() == num_entries);
            for entry in entries.iter() {
                assert!(
                    *entry
                        == kvm_cpuid_entry2 {
                            function: 0,
                            index: 0,
                            flags: 0,
                            eax: 0,
                            ebx: 0,
                            ecx: 0,
                            edx: 0,
                            padding: [0, 0, 0],
                        }
                );
            }
        }

        let new_entry = kvm_cpuid_entry2 {
            function: 0x4,
            index: 0,
            flags: 1,
            eax: 0b1100000,
            ebx: 0,
            ecx: 0,
            edx: 0,
            padding: [0, 0, 0],
        };
        // modify the first entry
        cpuid.mut_entries_slice()[0] = new_entry;
        // test that the first entry has been modified in the underlying structure
        assert!(unsafe { cpuid.kvm_cpuid[0].entries.as_slice(num_entries)[0] } == new_entry);
    }
}
