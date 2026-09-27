// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! PCI emulation for a VFIO assigned device.
//!
//! [`VfioPciDevice`] turns a PCI function opened through VFIO into a device on the guest's PCI
//! bus. The model follows the one of QEMU and Cloud Hypervisor, and relies on vfio-pci for
//! everything the host kernel already virtualizes or protects:
//!
//! * **Configuration space** is read from and written to the device through the VFIO
//!   configuration region; vfio-pci filters what the guest may change. On top of that view, the
//!   registers whose guest-visible value must differ from the host one are emulated: the BARs and
//!   the expansion ROM BAR (the guest sees guest physical addresses), the Header Type (the
//!   multi-function bit is cleared: each assigned function is a single-function device in the
//!   guest), the Interrupt Pin and Interrupt Line (a routed INTx is INTA of the device), the MSI
//!   capability and the MSI-X Message Control register ([`super::interrupts`]). Extended capabilities whose guest-visible behaviour
//!   cannot be honoured are removed from the capability list: SR-IOV and ARI (they describe
//!   functions that do not exist in the guest) and Resizable BAR (vfio-pci drops writes to it, so
//!   a guest resize would silently not happen while the guest believes it did).
//! * **BARs** are placed in the guest MMIO windows. The parts the kernel allows to `mmap` are
//!   mapped into the guest as KVM memory slots, so the guest accesses them without VM exits. The
//!   pages holding the MSI-X table and PBA, and any part that cannot be mapped (sub-page BARs,
//!   areas without mmap support), are trapped and forwarded through the VFIO region. A BAR the
//!   guest reprograms moves when memory decoding is next enabled, like virtio-pci BARs do.
//! * **Memory decoding** is tracked: when the guest disables it (Command register) or puts the
//!   device in D3hot, vfio-pci invalidates the BAR mappings and faults on any access. The BAR
//!   memory slots are then removed so that guest accesses trap and read all ones, as they would on
//!   bare metal, instead of making `KVM_RUN` fail.

use std::fmt::Debug;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use vm_allocator::{AddressAllocator, AllocPolicy, RangeInclusive};

use super::OpenedDevice;
use super::generated::pci_regs::{
    PCI_BASE_ADDRESS_0, PCI_BASE_ADDRESS_MEM_PREFETCH, PCI_BASE_ADDRESS_MEM_TYPE_64,
    PCI_BASE_ADDRESS_MEM_TYPE_MASK, PCI_BASE_ADDRESS_SPACE_IO, PCI_CAP_ID_MSI, PCI_CAP_ID_MSIX,
    PCI_CAP_ID_PM, PCI_CAP_LIST_ID, PCI_CAP_LIST_NEXT, PCI_CAPABILITY_LIST, PCI_CFG_SPACE_EXP_SIZE,
    PCI_CFG_SPACE_SIZE, PCI_COMMAND, PCI_COMMAND_MEMORY, PCI_EXT_CAP_ID_ARI, PCI_EXT_CAP_ID_REBAR,
    PCI_EXT_CAP_ID_SRIOV, PCI_HEADER_TYPE, PCI_HEADER_TYPE_MASK, PCI_HEADER_TYPE_MFD,
    PCI_INTERRUPT_LINE, PCI_INTERRUPT_PIN, PCI_MSI_FLAGS, PCI_MSIX_FLAGS, PCI_MSIX_FLAGS_ENABLE,
    PCI_MSIX_PBA, PCI_MSIX_TABLE, PCI_PM_CTRL, PCI_PM_CTRL_STATE_MASK, PCI_ROM_ADDRESS,
    PCI_ROM_ADDRESS_ENABLE, PCI_STATUS, PCI_STATUS_CAP_LIST, PCI_STD_HEADER_SIZEOF,
};
use super::generated::vfio::_bindgen_ty_1::{
    VFIO_PCI_BAR0_REGION_INDEX, VFIO_PCI_CONFIG_REGION_INDEX, VFIO_PCI_ROM_REGION_INDEX,
};
use super::generated::vfio::_bindgen_ty_2::{
    VFIO_PCI_INTX_IRQ_INDEX, VFIO_PCI_MSI_IRQ_INDEX, VFIO_PCI_MSIX_IRQ_INDEX,
};
use super::generated::vfio::{
    VFIO_IRQ_INFO_NORESIZE, VFIO_REGION_INFO_FLAG_MMAP, VFIO_REGION_INFO_FLAG_READ,
    VFIO_REGION_INFO_FLAG_WRITE,
};
use super::interrupts::{Intx, IntxError, Msi, Msix};
use super::sys::{Device, IrqInfo, RegionInfo, SetIrqsError, VfioSysError};
use crate::arch::{self, host_page_size};
use crate::logger::{debug, error, info, warn};
use crate::pci::configuration::{BarPrefetchable, Bars, NUM_BAR_REGS};
use crate::pci::{PciDevice, PciSBDF};
use crate::vstate::bus::{BusDevice, BusError};
use crate::vstate::interrupts::InterruptError;
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vm::{KvmVm, VmError};

/// Virtual Resizable BAR extended capability id (PCIe Base Specification 6.0, 7.8.7), which the
/// kernel headers used to generate the bindings do not define yet.
const PCI_EXT_CAP_ID_VF_REBAR: u16 = 0x24;
/// Extended capabilities removed from the guest's capability list.
const HIDDEN_EXTENDED_CAPABILITIES: [u16; 4] = [
    reg(PCI_EXT_CAP_ID_SRIOV),
    reg(PCI_EXT_CAP_ID_ARI),
    reg(PCI_EXT_CAP_ID_REBAR),
    PCI_EXT_CAP_ID_VF_REBAR,
];
/// Maximum number of capabilities in the standard configuration space, used to bound the walk
/// exactly like Linux does (`PCI_FIND_CAP_TTL` in drivers/pci/pci.c).
const CAPABILITY_TTL: usize = 48;
/// Maximum number of extended capabilities: each is at least 8 bytes long.
const EXTENDED_CAPABILITY_TTL: usize = (PCI_CFG_SPACE_EXP_SIZE - PCI_CFG_SPACE_SIZE) as usize / 8;
/// Upper bound on the host virtual address alignment of BAR mappings: KVM maps guest memory with
/// at most 1 GiB pages.
const MAX_MAPPING_ALIGNMENT: u64 = 1 << 30;
/// PMCSR PowerState value of D3hot.
const PCI_D3HOT: u16 = 3;

/// Narrow a PCI configuration register offset from the generated bindings (which are `u32`).
#[allow(clippy::cast_possible_truncation)]
const fn reg(offset: u32) -> u16 {
    assert!(offset < PCI_CFG_SPACE_EXP_SIZE);
    offset as u16
}

const COMMAND: u16 = reg(PCI_COMMAND);
const STATUS: u16 = reg(PCI_STATUS);
const HEADER_TYPE: u16 = reg(PCI_HEADER_TYPE);
const BAR0: u16 = reg(PCI_BASE_ADDRESS_0);
const ROM_ADDRESS: u16 = reg(PCI_ROM_ADDRESS);
const CAPABILITY_LIST: u16 = reg(PCI_CAPABILITY_LIST);
const INTERRUPT_PIN: u16 = reg(PCI_INTERRUPT_PIN);
const INTERRUPT_LINE: u16 = reg(PCI_INTERRUPT_LINE);
/// Interrupt Pin register value of INTA.
const INTERRUPT_PIN_INTA: u8 = 1;
const STD_HEADER_SIZE: u16 = reg(PCI_STD_HEADER_SIZEOF);
const CFG_SPACE_SIZE: u16 = reg(PCI_CFG_SPACE_SIZE);
const PM_CTRL: u16 = reg(PCI_PM_CTRL);
const MSI_FLAGS: u16 = reg(PCI_MSI_FLAGS);
const MSIX_FLAGS: u16 = reg(PCI_MSIX_FLAGS);
const MSIX_TABLE: u16 = reg(PCI_MSIX_TABLE);
const MSIX_PBA: u16 = reg(PCI_MSIX_PBA);
const CAP_LIST_ID: u16 = reg(PCI_CAP_LIST_ID);
const CAP_LIST_NEXT: u16 = reg(PCI_CAP_LIST_NEXT);
const PM_CTRL_STATE_MASK: u16 = reg(PCI_PM_CTRL_STATE_MASK);
/// Length of the MSI-X capability (PCI Local Bus specification 6.8.2).
const MSIX_CAP_LEN: u16 = 12;

/// Access to an assigned device, implemented by [`Device`] and by a mock in unit tests.
pub trait VfioDeviceIo: Send + Debug {
    /// Information about region `index`, if the device has it.
    fn region(&self, index: u32) -> Option<&RegionInfo>;
    /// Information about interrupt index `index`, if the device has it.
    fn irq(&self, index: u32) -> Option<IrqInfo>;
    /// Read `data.len()` bytes at `offset` of region `index`.
    fn read_region(&self, index: u32, offset: u64, data: &mut [u8]) -> Result<(), VfioSysError>;
    /// Write `data` at `offset` of region `index`.
    fn write_region(&self, index: u32, offset: u64, data: &[u8]) -> Result<(), VfioSysError>;
    /// Route interrupts `start..start + fds.len()` of index `index` to `fds`.
    fn set_irq_eventfds(&self, index: u32, start: u32, fds: &[RawFd]) -> Result<(), SetIrqsError>;
    /// Unmask the interrupt of index `index` whenever `fd` is signalled.
    fn set_irq_unmask_eventfd(&self, index: u32, fd: RawFd) -> Result<(), VfioSysError>;
    /// Disable every interrupt of index `index`.
    fn disable_irqs(&self, index: u32) -> Result<(), VfioSysError>;
    /// The file descriptor whose mappings expose the regions (the VFIO device fd).
    fn mmap_fd(&self) -> RawFd;
}

impl VfioDeviceIo for Device {
    fn region(&self, index: u32) -> Option<&RegionInfo> {
        Device::region(self, index)
    }

    fn irq(&self, index: u32) -> Option<IrqInfo> {
        Device::irq(self, index)
    }

    fn read_region(&self, index: u32, offset: u64, data: &mut [u8]) -> Result<(), VfioSysError> {
        Device::read_region(self, index, offset, data)
    }

    fn write_region(&self, index: u32, offset: u64, data: &[u8]) -> Result<(), VfioSysError> {
        Device::write_region(self, index, offset, data)
    }

    fn set_irq_eventfds(&self, index: u32, start: u32, fds: &[RawFd]) -> Result<(), SetIrqsError> {
        Device::set_irq_eventfds(self, index, start, fds)
    }

    fn set_irq_unmask_eventfd(&self, index: u32, fd: RawFd) -> Result<(), VfioSysError> {
        Device::set_irq_unmask_eventfd(self, index, fd)
    }

    fn disable_irqs(&self, index: u32) -> Result<(), VfioSysError> {
        Device::disable_irqs(self, index)
    }

    fn mmap_fd(&self) -> RawFd {
        self.as_raw_fd()
    }
}

/// Errors that can occur while building a [`VfioPciDevice`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VfioPciError {
    /// Failed to read the configuration space of {0}: {1}
    ConfigRead(String, #[source] VfioSysError),
    /// {0} is not a PCI endpoint (header type {1:#x}); only endpoints can be assigned
    NotAnEndpoint(String, u8),
    /// The host reports an invalid number of MSI messages for {0}: {1}
    MsiVectorCount(String, u32),
    /// BAR {1} of {0} is a 64-bit BAR in the last BAR slot
    InvalidBar(String, u8),
    /// The expansion ROM of {0} ({1:#x} bytes) does not fit in a 32-bit ROM BAR
    InvalidRom(String, u64),
    /// Failed to allocate interrupt vectors: {0}
    Interrupts(#[from] InterruptError),
    /// Failed to route INTx: {0}
    Intx(#[from] IntxError),
    /// Failed to mmap BAR {0}: {1}
    Mmap(u32, #[source] std::io::Error),
    /// Ran out of KVM memory slots while mapping device BARs
    NotEnoughKvmSlots,
    /// Failed to register a BAR as a KVM memory region: {0}
    RegisterMemoryRegion(#[source] VmError),
}

/// The guest MMIO window a BAR must be placed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarWindow {
    /// Below 4 GiB.
    Mmio32,
    /// Above 4 GiB.
    Mmio64,
}

/// A BAR, or the expansion ROM BAR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarSlot {
    /// BAR `n` (for a 64-bit BAR, the index of its lower half).
    Bar(u8),
    /// The expansion ROM BAR.
    Rom,
}

/// Guest address space needed by a BAR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarRequirement {
    /// The BAR.
    pub slot: BarSlot,
    /// Size of the BAR, a power of two. It is also the required alignment.
    pub size: u64,
    /// Window the BAR must be placed in.
    pub window: BarWindow,
}

/// A memory BAR of the device, as found on the host.
#[derive(Debug, Clone, Copy)]
struct ProbedBar {
    index: u8,
    size: u64,
    is_64bit: bool,
    prefetchable: bool,
}

/// A host mapping of part of a BAR, exposed to the guest as a KVM memory slot.
struct BarMapping {
    host_addr: *mut libc::c_void,
    len: usize,
    guest_addr: u64,
    slot: u32,
    /// Whether the memory slot is currently registered with KVM.
    registered: bool,
}

// SAFETY: `BarMapping` owns a raw `mmap` of device memory. The pointer is only handed to the
// kernel (`munmap`, `KVM_SET_USER_MEMORY_REGION`) and never dereferenced from Rust, so the owning
// handle can move across threads.
unsafe impl Send for BarMapping {}

impl Debug for BarMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BarMapping")
            .field("guest_addr", &format_args!("{:#x}", self.guest_addr))
            .field("len", &format_args!("{:#x}", self.len))
            .field("slot", &self.slot)
            .field("registered", &self.registered)
            .finish()
    }
}

/// Alignment of the host mapping of `len` bytes exposed at `guest_addr`: the largest power of two
/// that divides `guest_addr`, is not larger than `len`, and is at most 1 GiB. KVM can only back a
/// guest page with a huge host page when both addresses are equally aligned, and vfio-pci only
/// installs huge page mappings at suitably aligned addresses (`vfio_pci_mmap_huge_fault`).
fn mapping_alignment(guest_addr: u64, len: u64, page_size: u64) -> u64 {
    let by_address = if guest_addr == 0 {
        MAX_MAPPING_ALIGNMENT
    } else {
        1u64 << guest_addr.trailing_zeros()
    };
    let by_len = 1u64 << (63 - len.leading_zeros());
    by_address
        .min(by_len)
        .min(MAX_MAPPING_ALIGNMENT)
        .max(page_size)
}

impl BarMapping {
    /// Map `len` bytes of `fd` at `file_offset`, at a host address aligned like `guest_addr`.
    fn new(
        fd: RawFd,
        file_offset: u64,
        len: u64,
        prot: libc::c_int,
        guest_addr: u64,
        slot: u32,
        bar: u32,
    ) -> Result<Self, VfioPciError> {
        let page_size = host_page_size() as u64;
        let align = mapping_alignment(guest_addr, len, page_size);
        let too_big = || VfioPciError::Mmap(bar, std::io::Error::from_raw_os_error(libc::E2BIG));
        let len_usize = usize::try_from(len).map_err(|_| too_big())?;
        let reserve_len = len
            .checked_add(align)
            .and_then(|reserve| usize::try_from(reserve).ok())
            .ok_or_else(too_big)?;
        let file_offset = libc::off_t::try_from(file_offset).map_err(|_| too_big())?;

        // Reserve enough address space to place the mapping at an aligned address.
        // SAFETY: an anonymous, inaccessible mapping at an address chosen by the kernel.
        let reserve = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                reserve_len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if reserve == libc::MAP_FAILED {
            return Err(VfioPciError::Mmap(bar, std::io::Error::last_os_error()));
        }
        let reserve_start = reserve as usize;
        let align = usize::try_from(align).map_err(|_| too_big())?;
        let start = reserve_start.next_multiple_of(align);

        // SAFETY: `[start, start + len)` lies inside the reservation made above, which this
        // function owns, so `MAP_FIXED` only replaces our own inaccessible pages.
        let host_addr = unsafe {
            libc::mmap(
                start as *mut libc::c_void,
                len_usize,
                prot,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                file_offset,
            )
        };
        if host_addr == libc::MAP_FAILED {
            let err = std::io::Error::last_os_error();
            // SAFETY: unmapping the reservation made above.
            unsafe { libc::munmap(reserve, reserve_len) };
            return Err(VfioPciError::Mmap(bar, err));
        }

        // Release the unused head and tail of the reservation.
        let end = start + len_usize;
        let reserve_end = reserve_start + reserve_len;
        // SAFETY: both ranges are the parts of our reservation outside the device mapping.
        unsafe {
            if start > reserve_start {
                libc::munmap(reserve, start - reserve_start);
            }
            if reserve_end > end {
                libc::munmap(end as *mut libc::c_void, reserve_end - end);
            }
        }

        Ok(BarMapping {
            host_addr,
            len: len_usize,
            guest_addr,
            slot,
            registered: false,
        })
    }

    /// Add (`present`) or remove the memory slot exposing this mapping to the guest.
    fn set_present(&mut self, vm: &KvmVm, present: bool) -> Result<(), VmError> {
        if self.registered == present {
            return Ok(());
        }
        vm.set_user_memory_region(kvm_bindings::kvm_userspace_memory_region {
            slot: self.slot,
            flags: 0,
            guest_phys_addr: self.guest_addr,
            memory_size: if present { self.len as u64 } else { 0 },
            userspace_addr: self.host_addr as u64,
        })?;
        self.registered = present;
        Ok(())
    }
}

impl Drop for BarMapping {
    fn drop(&mut self) {
        // SAFETY: `host_addr` and `len` describe the mapping created in `BarMapping::new`, which
        // this object exclusively owns.
        unsafe {
            libc::munmap(self.host_addr, self.len);
        }
    }
}

/// A memory BAR exposed to the guest.
#[derive(Debug)]
struct BarRegion {
    /// VFIO region index (equal to the BAR index).
    index: u32,
    guest_addr: u64,
    size: u64,
    mappings: Vec<BarMapping>,
}

/// The emulated expansion ROM BAR.
#[derive(Debug)]
struct RomBar {
    /// Size of the ROM BAR (a power of two, at least 2 KiB).
    size: u64,
    /// Guest address the ROM is trapped at on the MMIO bus.
    guest_addr: u64,
    /// The address bits of the register, as written by the guest. They differ from `guest_addr`
    /// until the ROM is relocated, which happens when it starts decoding.
    address: u32,
    enabled: bool,
}

impl RomBar {
    /// The ROM BAR of a ROM of `size` bytes, if a 32-bit expansion ROM BAR can describe it.
    fn new(size: u64) -> Option<Self> {
        // The ROM BAR decodes at least 2 KiB (PCI Local Bus specification 6.2.5.2), and its
        // address bits are bits 11 to 31.
        let size = size.checked_next_power_of_two()?.max(0x800);
        (size <= 1 << 31).then_some(RomBar {
            size,
            guest_addr: 0,
            address: 0,
            enabled: false,
        })
    }

    /// The writable address bits: those above the size (and above the 11 reserved bits, as the
    /// size is at least 2 KiB).
    fn address_mask(&self) -> u32 {
        !u32::try_from(self.size - 1).expect("ROM BAR size fits in 32 bits")
    }

    fn register(&self) -> u32 {
        self.address | u32::from(self.enabled)
    }

    /// Place the ROM at `guest_addr`, which the register then reads back.
    fn place(&mut self, guest_addr: u64) {
        self.guest_addr = guest_addr;
        self.address = u32::try_from(guest_addr).expect("ROM BAR placed below 4 GiB");
    }

    fn write(&mut self, offset: u8, data: &[u8]) {
        let mut value = self.register().to_le_bytes();
        value[usize::from(offset)..][..data.len()].copy_from_slice(data);
        let value = u32::from_le_bytes(value);
        self.enabled = value & PCI_ROM_ADDRESS_ENABLE != 0;
        // Like a BAR, the address bits below the size are read-only zeros: writing all ones reads
        // back the size. The new address takes effect when the ROM starts decoding.
        self.address = value & self.address_mask();
    }
}

/// Why a BAR could not be moved to the address the guest programmed.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
enum RelocationError {
    /// The range is not inside a device MMIO window
    OutsideWindows,
    /// The range is not free: {0}
    Reserve(#[source] vm_allocator::Error),
    /// Failed to move the range on the MMIO bus: {0}
    Bus(#[source] BusError),
    /// A memory slot of the BAR is still registered
    SlotRegistered,
}

/// The device MMIO window that holds the range `[addr, addr + size)`, if any.
fn window_of(addr: u64, size: u64) -> Option<BarWindow> {
    let end = addr.checked_add(size)?;
    let contains = |start: u64, len: u64| start <= addr && end <= start + len;
    if contains(arch::MEM_32BIT_DEVICES_START, arch::MEM_32BIT_DEVICES_SIZE) {
        Some(BarWindow::Mmio32)
    } else if contains(arch::MEM_64BIT_DEVICES_START, arch::MEM_64BIT_DEVICES_SIZE) {
        Some(BarWindow::Mmio64)
    } else {
        None
    }
}

/// The allocator of the guest address space of `window`.
fn window_allocator(allocator: &mut ResourceAllocator, window: BarWindow) -> &mut AddressAllocator {
    match window {
        BarWindow::Mmio32 => &mut allocator.mmio32_memory,
        BarWindow::Mmio64 => &mut allocator.mmio64_memory,
    }
}

/// Who handles a byte of configuration space on a guest write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigOwner {
    /// Forwarded to the device.
    Device,
    /// Read-only in the guest's view.
    ReadOnly,
    /// The emulated MSI capability.
    Msi,
    /// The high byte of the emulated MSI-X Message Control register.
    MsixControl,
    /// The emulated Interrupt Line register.
    InterruptLine,
}

/// A physical PCI function assigned to the guest through VFIO.
pub struct VfioPciDevice {
    /// Firecracker id of the device.
    id: String,
    /// Address of the device on the guest PCI bus.
    sbdf: PciSBDF,
    /// Address of the function on the host, e.g. `0000:01:00.0`.
    host_name: String,
    /// Host sysfs path the function was assigned with.
    sysfs_path: PathBuf,
    vm: Arc<KvmVm>,
    device: Box<dyn VfioDeviceIo>,
    /// Size of the VFIO configuration region (256 bytes for conventional PCI functions).
    config_size: u64,
    /// Offset of the power management capability.
    pm_cap: Option<u16>,
    msi: Option<Msi>,
    msix: Option<Msix>,
    /// Whether the host can route the INTx of the device (vfio-pci reports one INTx interrupt).
    intx_supported: bool,
    /// The routing of INTx to the guest, once a GSI is assigned to it.
    intx: Option<Intx>,
    /// The Interrupt Line register, a scratch register for the guest.
    interrupt_line: u8,
    /// Extended capability headers rewritten to remove hidden capabilities from the list, as
    /// `(offset, value)`.
    ecap_overrides: Vec<(u16, u32)>,
    /// Memory BARs found on the host.
    probed_bars: Vec<ProbedBar>,
    /// The emulated BAR registers.
    bars: Bars,
    /// The BARs placed in the guest address space.
    regions: Vec<BarRegion>,
    rom: Option<RomBar>,
    /// Whether the device currently decodes memory accesses (Memory Space enabled and not in
    /// D3hot), i.e. whether the BAR memory slots are present.
    memory_enabled: bool,
}

impl Debug for VfioPciDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VfioPciDevice")
            .field("id", &self.id)
            .field("sbdf", &self.sbdf)
            .field("host_name", &self.host_name)
            .field("regions", &self.regions)
            .field("rom", &self.rom)
            .field("memory_enabled", &self.memory_enabled)
            .finish_non_exhaustive()
    }
}

impl VfioPciDevice {
    /// Build the emulation of `opened`, placed at `sbdf` on the guest PCI bus.
    ///
    /// The device's BARs are not placed yet: see [`VfioPciDevice::bar_requirements`],
    /// [`VfioPciDevice::place_bar`] and [`VfioPciDevice::map_bars`].
    pub fn new(
        id: String,
        sbdf: PciSBDF,
        opened: OpenedDevice,
        vm: Arc<KvmVm>,
    ) -> Result<Self, VfioPciError> {
        Self::with_io(
            id,
            sbdf,
            opened.name,
            opened.sysfs_path,
            Box::new(opened.device),
            vm,
        )
    }

    fn with_io(
        id: String,
        sbdf: PciSBDF,
        host_name: String,
        sysfs_path: PathBuf,
        device: Box<dyn VfioDeviceIo>,
        vm: Arc<KvmVm>,
    ) -> Result<Self, VfioPciError> {
        let config_size = device
            .region(VFIO_PCI_CONFIG_REGION_INDEX)
            .map_or(0, |region| region.size);
        let read = |offset: u16, data: &mut [u8]| {
            device
                .read_region(VFIO_PCI_CONFIG_REGION_INDEX, u64::from(offset), data)
                .map_err(|err| VfioPciError::ConfigRead(host_name.clone(), err))
        };
        let read_u8 = |offset: u16| -> Result<u8, VfioPciError> {
            let mut data = [0u8; 1];
            read(offset, &mut data)?;
            Ok(data[0])
        };
        let read_u16 = |offset: u16| -> Result<u16, VfioPciError> {
            let mut data = [0u8; 2];
            read(offset, &mut data)?;
            Ok(u16::from_le_bytes(data))
        };
        let read_u32 = |offset: u16| -> Result<u32, VfioPciError> {
            let mut data = [0u8; 4];
            read(offset, &mut data)?;
            Ok(u32::from_le_bytes(data))
        };

        let header_type = read_u8(HEADER_TYPE)? & u8::try_from(PCI_HEADER_TYPE_MASK).unwrap();
        if header_type != 0 {
            return Err(VfioPciError::NotAnEndpoint(host_name, header_type));
        }

        // Walk the standard capability list, bounded like Linux's __pci_find_next_cap_ttl.
        let mut pm_cap = None;
        let mut msi_cap = None;
        let mut msix_cap = None;
        if u32::from(read_u16(STATUS)?) & PCI_STATUS_CAP_LIST != 0 {
            let mut pos = read_u8(CAPABILITY_LIST)?;
            for _ in 0..CAPABILITY_TTL {
                if u16::from(pos) < STD_HEADER_SIZE {
                    break;
                }
                let cap = u16::from(pos & !3);
                let id = read_u8(cap + CAP_LIST_ID)?;
                if id == 0xff {
                    break;
                }
                match u32::from(id) {
                    PCI_CAP_ID_PM => pm_cap = pm_cap.or(Some(cap)),
                    PCI_CAP_ID_MSI => msi_cap = msi_cap.or(Some(cap)),
                    PCI_CAP_ID_MSIX => msix_cap = msix_cap.or(Some(cap)),
                    _ => {}
                }
                pos = read_u8(cap + CAP_LIST_NEXT)?;
            }
        }

        // Walk the extended capability list, bounded like Linux's pci_find_next_ext_capability.
        let mut ecaps: Vec<(u16, u32)> = Vec::new();
        if config_size > u64::from(CFG_SPACE_SIZE) {
            let mut pos = CFG_SPACE_SIZE;
            for _ in 0..EXTENDED_CAPABILITY_TTL {
                let header = read_u32(pos)?;
                if header == 0 || header == u32::MAX {
                    break;
                }
                ecaps.push((pos, header));
                let next = u16::try_from((header >> 20) & 0xffc).unwrap();
                if next < CFG_SPACE_SIZE {
                    break;
                }
                pos = next;
            }
        }
        let ecap_overrides = hide_extended_capabilities(&ecaps, &HIDDEN_EXTENDED_CAPABILITIES);

        // vfio-pci reports no INTx when the device has no interrupt pin, or when it cannot route it
        // (`nointx`, virtual functions, kernels without CONFIG_VFIO_PCI_INTX).
        let intx_supported = device
            .irq(VFIO_PCI_INTX_IRQ_INDEX)
            .is_some_and(|irq| irq.count == 1);

        let msi = match msi_cap {
            Some(cap) => {
                let flags = read_u16(cap + MSI_FLAGS)?;
                // The number of messages comes from the MSI interrupt index, which is the limit
                // VFIO_DEVICE_SET_IRQS enforces, and is read from the device by the kernel. The
                // Message Control register is read through vfio-pci, which virtualizes its low
                // byte.
                let count = device
                    .irq(VFIO_PCI_MSI_IRQ_INDEX)
                    .map_or(0, |irq| irq.count);
                if !count.is_power_of_two() || count > Msi::MAX_VECTORS {
                    return Err(VfioPciError::MsiVectorCount(host_name, count));
                }
                let vectors = KvmVm::create_msix_group(vm.clone(), u16::try_from(count).unwrap())?;
                Some(Msi::new(cap, flags, Arc::new(vectors), sbdf))
            }
            None => None,
        };
        let msix = match msix_cap {
            Some(cap) => {
                let flags = read_u16(cap + MSIX_FLAGS)?;
                let table = read_u32(cap + MSIX_TABLE)?;
                let pba = read_u32(cap + MSIX_PBA)?;
                let vectors = KvmVm::create_msix_group(vm.clone(), Msix::table_size(flags))?;
                let dynamic = device
                    .irq(VFIO_PCI_MSIX_IRQ_INDEX)
                    .is_some_and(|irq| irq.flags & VFIO_IRQ_INFO_NORESIZE == 0);
                Some(Msix::new(cap, table, pba, Arc::new(vectors), sbdf, dynamic))
            }
            None => None,
        };

        let mut probed_bars = Vec::new();
        let mut index = 0u8;
        while index < NUM_BAR_REGS {
            let size = device
                .region(VFIO_PCI_BAR0_REGION_INDEX + u32::from(index))
                .map_or(0, |region| region.size);
            if size == 0 {
                index += 1;
                continue;
            }
            let bar = read_u32(BAR0 + 4 * u16::from(index))?;
            if bar & PCI_BASE_ADDRESS_SPACE_IO != 0 {
                // I/O BARs are not exposed: PCI Express endpoints must not depend on I/O space
                // (PCIe Base Specification 6.0, 7.5.1.2.1).
                info!(
                    "vfio: {host_name}: I/O BAR {index} ({size:#x} bytes) is not exposed to the \
                     guest"
                );
                index += 1;
                continue;
            }
            let is_64bit = bar & PCI_BASE_ADDRESS_MEM_TYPE_MASK == PCI_BASE_ADDRESS_MEM_TYPE_64;
            if is_64bit && index + 1 >= NUM_BAR_REGS {
                return Err(VfioPciError::InvalidBar(host_name, index));
            }
            probed_bars.push(ProbedBar {
                index,
                size: size.next_power_of_two(),
                is_64bit,
                prefetchable: bar & PCI_BASE_ADDRESS_MEM_PREFETCH != 0,
            });
            index += if is_64bit { 2 } else { 1 };
        }

        let rom = match device
            .region(VFIO_PCI_ROM_REGION_INDEX)
            .filter(|region| region.size > 0)
        {
            Some(region) => Some(
                RomBar::new(region.size)
                    .ok_or_else(|| VfioPciError::InvalidRom(host_name.clone(), region.size))?,
            ),
            None => None,
        };

        Ok(VfioPciDevice {
            id,
            sbdf,
            host_name,
            sysfs_path,
            vm,
            device,
            config_size,
            pm_cap,
            msi,
            msix,
            intx_supported,
            intx: None,
            // The value of an unknown or unconnected interrupt line (PCI Local Bus 6.2.4).
            interrupt_line: 0xff,
            ecap_overrides,
            probed_bars,
            bars: Bars::default(),
            regions: Vec::new(),
            rom,
            memory_enabled: false,
        })
    }

    /// Whether the INTx of the device can be routed to the guest.
    pub fn supports_intx(&self) -> bool {
        self.intx_supported
    }

    /// Route the INTx of the device to guest GSI `gsi`: the guest sees it as INTA of the device.
    /// Must be called before the guest runs, while it has neither MSI nor MSI-X enabled.
    pub fn route_intx(&mut self, gsi: u32) -> Result<(), VfioPciError> {
        assert!(self.intx_supported && self.intx.is_none());
        let mut intx = Intx::new(self.vm.clone(), gsi)?;
        intx.enable_host(self.device.as_ref())?;
        self.intx = Some(intx);
        // Like firmware does, tell the guest which interrupt line INTA is routed to: on x86 the
        // IOAPIC input, which Linux uses as the IRQ number of GSIs.
        #[cfg(target_arch = "x86_64")]
        {
            self.interrupt_line = u8::try_from(gsi).unwrap_or(0xff);
        }
        Ok(())
    }

    /// The guest GSI the INTx of the device is routed to.
    pub fn intx_gsi(&self) -> Option<u32> {
        self.intx.as_ref().map(Intx::gsi)
    }

    /// Route INTx to the guest exactly while the guest has neither MSI nor MSI-X enabled.
    fn update_intx(&mut self) {
        let messages = self.msi.as_ref().is_some_and(Msi::guest_enabled)
            || self.msix.as_ref().is_some_and(Msix::guest_enabled);
        let Some(intx) = &mut self.intx else {
            return;
        };
        if messages {
            intx.disable_host(self.device.as_ref());
        } else if let Err(err) = intx.enable_host(self.device.as_ref()) {
            error!("vfio: {}: failed to route INTx: {err}", self.host_name);
        }
    }

    /// The Firecracker id of this device.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The address of the device on the guest PCI bus.
    pub fn sbdf(&self) -> PciSBDF {
        self.sbdf
    }

    /// The host sysfs path of the assigned function.
    pub fn sysfs_path(&self) -> &Path {
        &self.sysfs_path
    }

    /// The guest address space the device BARs need.
    pub fn bar_requirements(&self) -> Vec<BarRequirement> {
        let mut requirements: Vec<BarRequirement> = self
            .probed_bars
            .iter()
            .map(|bar| BarRequirement {
                slot: BarSlot::Bar(bar.index),
                size: bar.size,
                window: if bar.is_64bit {
                    BarWindow::Mmio64
                } else {
                    BarWindow::Mmio32
                },
            })
            .collect();
        if let Some(rom) = &self.rom {
            requirements.push(BarRequirement {
                slot: BarSlot::Rom,
                size: rom.size,
                // The expansion ROM BAR is a 32-bit register.
                window: BarWindow::Mmio32,
            });
        }
        requirements
    }

    /// Place BAR `slot` at guest physical address `guest_addr`.
    pub fn place_bar(&mut self, slot: BarSlot, guest_addr: u64) {
        match slot {
            BarSlot::Rom => {
                if let Some(rom) = &mut self.rom {
                    rom.place(guest_addr);
                }
            }
            BarSlot::Bar(index) => {
                let bar = *self
                    .probed_bars
                    .iter()
                    .find(|bar| bar.index == index)
                    .expect("only probed BARs are placed");
                let prefetchable = if bar.prefetchable {
                    BarPrefetchable::Yes
                } else {
                    BarPrefetchable::No
                };
                if bar.is_64bit {
                    self.bars
                        .set_bar_64(index, guest_addr, bar.size, prefetchable);
                } else {
                    // 32-bit BARs are placed in the 32-bit MMIO window, below 4 GiB, and a 32-bit
                    // BAR register cannot describe a size of 4 GiB or more.
                    self.bars.set_bar_32(
                        index,
                        u32::try_from(guest_addr).expect("32-bit BAR placed below 4 GiB"),
                        u32::try_from(bar.size).expect("32-bit BAR smaller than 4 GiB"),
                        prefetchable,
                    );
                }
                self.regions.push(BarRegion {
                    index: VFIO_PCI_BAR0_REGION_INDEX + u32::from(index),
                    guest_addr,
                    size: bar.size,
                    mappings: Vec::new(),
                });
            }
        }
    }

    /// The page-aligned ranges of BAR `index` that must stay trapped: those holding the MSI-X
    /// table and PBA.
    fn msix_holes(&self, index: u32, page_size: u64) -> Vec<(u64, u64)> {
        let Some(msix) = &self.msix else {
            return Vec::new();
        };
        [msix.table_location(), msix.pba_location()]
            .into_iter()
            .filter(|&(bar, _, _)| bar == index)
            .map(|(_, offset, size)| {
                let start = offset / page_size * page_size;
                let end = (offset + size).next_multiple_of(page_size);
                (start, end - start)
            })
            .collect()
    }

    /// Map the directly accessible parts of every placed BAR into the host address space, and
    /// expose them to the guest if the device decodes memory.
    pub fn map_bars(&mut self) -> Result<(), VfioPciError> {
        let page_size = host_page_size() as u64;
        let fd = self.device.mmap_fd();
        for region_index in 0..self.regions.len() {
            let index = self.regions[region_index].index;
            let Some(info) = self.device.region(index).cloned() else {
                continue;
            };
            let areas = mappable_areas(
                &info,
                self.regions[region_index].size,
                &self.msix_holes(index, page_size),
                page_size,
            );
            let mut prot = 0;
            if info.flags & VFIO_REGION_INFO_FLAG_READ != 0 {
                prot |= libc::PROT_READ;
            }
            if info.flags & VFIO_REGION_INFO_FLAG_WRITE != 0 {
                prot |= libc::PROT_WRITE;
            }
            for (offset, len) in areas {
                // Reserve the memory slot first so a failure cannot leak a mapping.
                let slot = self
                    .vm
                    .next_kvm_slot(1)
                    .ok_or(VfioPciError::NotEnoughKvmSlots)?;
                let guest_addr = self.regions[region_index].guest_addr + offset;
                let mapping =
                    BarMapping::new(fd, info.offset + offset, len, prot, guest_addr, slot, index)?;
                debug!(
                    "vfio: {} BAR {index}: mapped {len:#x} bytes at guest address {guest_addr:#x}",
                    self.host_name
                );
                self.regions[region_index].mappings.push(mapping);
            }
        }
        let enabled = self.memory_decoding_enabled();
        self.set_memory_enabled(enabled)
            .map_err(VfioPciError::RegisterMemoryRegion)
    }

    /// The guest physical ranges `(start, len)` to register on the MMIO bus: every BAR and the
    /// expansion ROM. Accesses only trap where no memory slot is present.
    pub fn mmio_ranges(&self) -> Vec<(u64, u64)> {
        let mut ranges: Vec<(u64, u64)> = self
            .regions
            .iter()
            .map(|region| (region.guest_addr, region.size))
            .collect();
        if let Some(rom) = &self.rom {
            ranges.push((rom.guest_addr, rom.size));
        }
        ranges
    }

    fn read_config(&self, offset: u16, data: &mut [u8]) -> bool {
        match self
            .device
            .read_region(VFIO_PCI_CONFIG_REGION_INDEX, u64::from(offset), data)
        {
            Ok(()) => true,
            Err(err) => {
                warn!(
                    "vfio: {}: configuration read at {offset:#x} failed: {err}",
                    self.host_name
                );
                false
            }
        }
    }

    /// Whether the device decodes memory accesses: Memory Space is enabled in the Command
    /// register and the device is not in D3hot. This is the condition under which vfio-pci
    /// allows BAR accesses (`__vfio_pci_memory_enabled`).
    fn memory_decoding_enabled(&self) -> bool {
        let mut command = [0u8; 2];
        if !self.read_config(COMMAND, &mut command) {
            return false;
        }
        if u32::from(u16::from_le_bytes(command)) & PCI_COMMAND_MEMORY == 0 {
            return false;
        }
        match self.pm_cap {
            Some(pm) => {
                let mut control = [0u8; 2];
                self.read_config(pm + PM_CTRL, &mut control)
                    && u16::from_le_bytes(control) & PM_CTRL_STATE_MASK < PCI_D3HOT
            }
            None => true,
        }
    }

    /// Add or remove the BAR memory slots.
    fn set_memory_enabled(&mut self, enabled: bool) -> Result<(), VmError> {
        for region in &mut self.regions {
            for mapping in &mut region.mappings {
                mapping.set_present(&self.vm, enabled)?;
            }
        }
        self.memory_enabled = enabled;
        Ok(())
    }

    fn update_memory_enabled(&mut self, enabled: bool) {
        if enabled == self.memory_enabled {
            return;
        }
        if enabled {
            // The BAR registers are only applied when the device starts decoding, as upstream
            // virtio-pci does: moving a 64-bit BAR takes two writes, and guests program BARs with
            // decoding disabled. The memory slots are absent at this point.
            self.relocate_bars();
            if self.rom.as_ref().is_some_and(|rom| rom.enabled) {
                self.relocate_rom();
            }
        }
        if let Err(err) = self.set_memory_enabled(enabled) {
            error!(
                "vfio: {}: failed to {} the BAR memory slots: {err}",
                self.host_name,
                if enabled { "add" } else { "remove" }
            );
        }
    }

    /// Move the guest range `[old, old + size)` of a BAR on the MMIO bus to `new`, and update the
    /// reservations of the device MMIO windows. Nothing changes on failure.
    ///
    /// The allocator lock is only held while reserving or freeing a range, never together with
    /// the bus locks.
    fn move_guest_range(&self, old: u64, new: u64, size: u64) -> Result<(), RelocationError> {
        let new_window = window_of(new, size).ok_or(RelocationError::OutsideWindows)?;
        let old_window = window_of(old, size).expect("BARs are placed in a device MMIO window");
        let new_range = window_allocator(&mut self.vm.resource_allocator(), new_window)
            .allocate(size, size, AllocPolicy::ExactMatch(new))
            .map_err(RelocationError::Reserve)?;
        if let Err(err) = self.vm.common.mmio_bus.move_range(old, new, size) {
            window_allocator(&mut self.vm.resource_allocator(), new_window)
                .free(&new_range)
                .expect("the range was just reserved");
            return Err(RelocationError::Bus(err));
        }
        // The old range was reserved when the BAR was placed, or by its previous relocation.
        let old_range = RangeInclusive::new(old, old + size - 1).expect("BAR range is valid");
        window_allocator(&mut self.vm.resource_allocator(), old_window)
            .free(&old_range)
            .expect("the BAR range is reserved");
        Ok(())
    }

    /// Move BAR region `region` to guest address `new`.
    fn relocate_region(&mut self, region: usize, new: u64) -> Result<(), RelocationError> {
        let BarRegion {
            guest_addr: old,
            size,
            ref mappings,
            ..
        } = self.regions[region];
        // A registered slot would keep exposing the BAR at its old address.
        if mappings.iter().any(|mapping| mapping.registered) {
            return Err(RelocationError::SlotRegistered);
        }
        self.move_guest_range(old, new, size)?;
        let region = &mut self.regions[region];
        region.guest_addr = new;
        // Both addresses are aligned to the BAR size, so each mapping keeps the host alignment
        // `mapping_alignment` chose for it: the alignment of an offset inside the BAR does not
        // depend on the base.
        for mapping in &mut region.mappings {
            mapping.guest_addr = new + (mapping.guest_addr - old);
        }
        Ok(())
    }

    /// Apply the addresses the guest wrote to the BAR registers. A BAR that cannot move keeps its
    /// address, and its register is reset to it, so the guest reads the address the BAR decodes.
    fn relocate_bars(&mut self) {
        for region in 0..self.regions.len() {
            let index = u8::try_from(self.regions[region].index - VFIO_PCI_BAR0_REGION_INDEX)
                .expect("BAR regions have a BAR index");
            let old = self.regions[region].guest_addr;
            let new = self.bars.get_bar_addr(index);
            if new == old {
                continue;
            }
            match self.relocate_region(region, new) {
                Ok(()) => debug!(
                    "vfio: {}: relocated BAR {index} {old:#x} -> {new:#x}",
                    self.host_name
                ),
                Err(err) => {
                    error!(
                        "vfio: {}: cannot relocate BAR {index} {old:#x} -> {new:#x}: {err}",
                        self.host_name
                    );
                    self.set_bar_address(index, old);
                }
            }
        }
    }

    /// Set the address bits of BAR register `index` (both halves of a 64-bit BAR).
    fn set_bar_address(&mut self, index: u8, addr: u64) {
        let [low, high] = [addr & 0xffff_ffff, addr >> 32].map(|half| {
            u32::try_from(half)
                .expect("each half fits in 32 bits")
                .to_le_bytes()
        });
        // The flag bits are read-only: writing the address leaves them unchanged.
        self.bars.write(index, 0, &low);
        if self.bars.bars[usize::from(index)].is_64bit() {
            self.bars.write(index + 1, 0, &high);
        }
    }

    /// Apply the address the guest wrote to the ROM BAR register, like [`Self::relocate_bars`].
    fn relocate_rom(&mut self) {
        let rom = self.rom.as_ref().expect("ROM exists");
        let (old, new, size) = (rom.guest_addr, u64::from(rom.address), rom.size);
        if new == old {
            return;
        }
        let result = self.move_guest_range(old, new, size);
        let rom = self.rom.as_mut().expect("ROM exists");
        match result {
            Ok(()) => {
                rom.guest_addr = new;
                debug!(
                    "vfio: {}: relocated the ROM BAR {old:#x} -> {new:#x}",
                    self.host_name
                );
            }
            Err(err) => {
                rom.place(old);
                error!(
                    "vfio: {}: cannot relocate the ROM BAR {old:#x} -> {new:#x}: {err}",
                    self.host_name
                );
            }
        }
    }

    /// Whether writing `data` at configuration offset `start` stops memory decoding.
    fn write_disables_memory(&self, start: u16, data: &[u8]) -> bool {
        let byte_at = |offset: u16| {
            offset
                .checked_sub(start)
                .and_then(|i| data.get(usize::from(i)))
                .copied()
        };
        let memory_off =
            byte_at(COMMAND).is_some_and(|command| u32::from(command) & PCI_COMMAND_MEMORY == 0);
        let to_d3hot = self.pm_cap.is_some_and(|pm| {
            byte_at(pm + PM_CTRL)
                .is_some_and(|control| u16::from(control) & PM_CTRL_STATE_MASK >= PCI_D3HOT)
        });
        memory_off || to_d3hot
    }

    /// Whether the range `[start, start + len)` may change memory decoding.
    fn write_affects_memory(&self, start: u16, len: u16) -> bool {
        let touches = |offset: u16, size: u16| start < offset + size && offset < start + len;
        touches(COMMAND, 2) || self.pm_cap.is_some_and(|pm| touches(pm + PM_CTRL, 2))
    }

    /// The emulated value of configuration byte `offset`, if it is emulated. `device` is the
    /// value read from the device.
    fn virtual_config_byte(&self, offset: u16, device: u8) -> Option<u8> {
        if offset == HEADER_TYPE {
            // Each assigned function is a single-function device in the guest.
            return Some(device & !u8::try_from(PCI_HEADER_TYPE_MFD).unwrap());
        }
        if offset == INTERRUPT_PIN {
            // A routed INTx is INTA of the device, which is function 0 of its guest slot.
            return Some(if self.intx.is_some() {
                INTERRUPT_PIN_INTA
            } else {
                0
            });
        }
        if offset == INTERRUPT_LINE {
            return Some(self.interrupt_line);
        }
        if let Some(msi) = &self.msi {
            let cap = msi.cap();
            if offset >= cap + 2 && offset < cap + msi.len() {
                return Some(msi.read_byte(usize::from(offset - cap)));
            }
        }
        if let Some(msix) = &self.msix {
            let cap = msix.cap();
            if offset == cap + 2 || offset == cap + 3 {
                return Some(msix.control().to_le_bytes()[usize::from(offset - cap - 2)]);
            }
        }
        self.ecap_overrides
            .iter()
            .find(|&&(pos, _)| offset >= pos && offset < pos + 4)
            .map(|&(pos, header)| header.to_le_bytes()[usize::from(offset - pos)])
    }

    fn config_owner(&self, offset: u16) -> ConfigOwner {
        if offset == INTERRUPT_PIN {
            return ConfigOwner::ReadOnly;
        }
        if offset == INTERRUPT_LINE {
            return ConfigOwner::InterruptLine;
        }
        if let Some(msi) = &self.msi {
            let cap = msi.cap();
            if offset >= cap + 2 && offset < cap + msi.len() {
                return ConfigOwner::Msi;
            }
            if offset >= cap && offset < cap + 2 {
                // Capability ID and next pointer.
                return ConfigOwner::ReadOnly;
            }
        }
        if let Some(msix) = &self.msix {
            let cap = msix.cap();
            if offset == cap + 3 {
                return ConfigOwner::MsixControl;
            }
            if offset >= cap && offset < cap + MSIX_CAP_LEN {
                // Capability ID, next pointer, table size, and the Table and PBA registers.
                return ConfigOwner::ReadOnly;
            }
        }
        if self
            .ecap_overrides
            .iter()
            .any(|&(pos, _)| offset >= pos && offset < pos + 4)
        {
            return ConfigOwner::ReadOnly;
        }
        ConfigOwner::Device
    }

    fn write_config_run(&mut self, owner: ConfigOwner, offset: u16, data: &[u8]) {
        match owner {
            ConfigOwner::ReadOnly => {}
            ConfigOwner::InterruptLine => self.interrupt_line = data[0],
            ConfigOwner::Msi => {
                let msi = self.msi.as_mut().expect("MSI capability exists");
                msi.write_bytes(usize::from(offset - msi.cap()), data);
                // vfio-pci enables at most one of INTx, MSI and MSI-X at a time.
                if msi.guest_enabled() {
                    if let Some(msix) = &mut self.msix
                        && msix.host_enabled()
                    {
                        warn!(
                            "vfio: {}: guest enabled MSI while MSI-X is enabled",
                            self.host_name
                        );
                        msix.disable_host(self.device.as_ref());
                    }
                    if let Some(intx) = &mut self.intx {
                        intx.disable_host(self.device.as_ref());
                    }
                }
                self.msi
                    .as_mut()
                    .expect("MSI capability exists")
                    .sync(self.device.as_ref());
                self.update_intx();
            }
            ConfigOwner::MsixControl => {
                let enable = (u32::from(data[0]) << 8) & PCI_MSIX_FLAGS_ENABLE != 0;
                if enable {
                    if let Some(msi) = &mut self.msi
                        && msi.host_enabled()
                    {
                        warn!(
                            "vfio: {}: guest enabled MSI-X while MSI is enabled",
                            self.host_name
                        );
                        msi.disable_host(self.device.as_ref());
                    }
                    if let Some(intx) = &mut self.intx {
                        intx.disable_host(self.device.as_ref());
                    }
                }
                self.msix
                    .as_mut()
                    .expect("MSI-X capability exists")
                    .write_control_high(self.device.as_ref(), data[0]);
                self.update_intx();
            }
            ConfigOwner::Device => {
                let len = u16::try_from(data.len()).unwrap();
                let affects_memory = self.write_affects_memory(offset, len);
                // vfio-pci invalidates the BAR mappings as soon as the write reaches it: take
                // the memory slots out of the guest first, so that concurrent guest accesses
                // trap instead of faulting.
                if affects_memory && self.write_disables_memory(offset, data) {
                    self.update_memory_enabled(false);
                }
                if let Err(err) =
                    self.device
                        .write_region(VFIO_PCI_CONFIG_REGION_INDEX, u64::from(offset), data)
                {
                    warn!(
                        "vfio: {}: configuration write at {offset:#x} failed: {err}",
                        self.host_name
                    );
                }
                if affects_memory {
                    let enabled = self.memory_decoding_enabled();
                    self.update_memory_enabled(enabled);
                }
            }
        }
    }

    fn bar_region(&self, base: u64) -> Option<&BarRegion> {
        self.regions.iter().find(|region| region.guest_addr == base)
    }

    fn is_rom(&self, base: u64) -> bool {
        self.rom.as_ref().is_some_and(|rom| rom.guest_addr == base)
    }
}

/// Rewrite the extended capability headers so that the capabilities with an id in `hidden` are
/// skipped. `ecaps` lists `(offset, header)` in list order. Returns the `(offset, header)` values
/// the guest must see instead of the device ones.
///
/// A hidden capability at the head of the list (offset 0x100) cannot be skipped by a pointer: its
/// header is replaced by one with capability id 0, which Linux and vfio-pci treat as a
/// placeholder whose next pointer is still followed.
fn hide_extended_capabilities(ecaps: &[(u16, u32)], hidden: &[u16]) -> Vec<(u16, u32)> {
    let is_hidden = |header: u32| hidden.contains(&u16::try_from(header & 0xffff).unwrap());
    let next_visible = |from: usize| {
        ecaps[from..]
            .iter()
            .find(|&&(_, header)| !is_hidden(header))
            .map_or(0, |&(pos, _)| u32::from(pos))
    };
    let mut overrides = Vec::new();
    for (i, &(pos, header)) in ecaps.iter().enumerate() {
        let next = next_visible(i + 1);
        if is_hidden(header) {
            if i == 0 {
                overrides.push((pos, next << 20));
            }
        } else if (header >> 20) & 0xffc != next {
            overrides.push((pos, (header & 0x000f_ffff) | (next << 20)));
        }
    }
    overrides
}

/// The `(offset, len)` parts of a BAR that can be mapped into the guest: the areas the kernel
/// allows to `mmap`, minus the `holes`, shrunk to whole pages. Everything else is trapped.
fn mappable_areas(
    region: &RegionInfo,
    bar_size: u64,
    holes: &[(u64, u64)],
    page_size: u64,
) -> Vec<(u64, u64)> {
    if region.flags & VFIO_REGION_INFO_FLAG_MMAP == 0 {
        return Vec::new();
    }
    let size = region.size.min(bar_size);
    let areas = region
        .sparse_mmap_areas
        .clone()
        .unwrap_or_else(|| vec![(0, size)]);
    let mut pieces = Vec::new();
    for (offset, len) in areas {
        let mut remaining = vec![(offset, offset.saturating_add(len).min(size))];
        for &(hole, hole_len) in holes {
            let hole_end = hole + hole_len;
            remaining = remaining
                .into_iter()
                .flat_map(|(start, end)| {
                    if hole_end <= start || hole >= end {
                        vec![(start, end)]
                    } else {
                        vec![(start, hole.max(start)), (hole_end.min(end), end)]
                    }
                })
                .collect();
        }
        for (start, end) in remaining {
            let start = start.next_multiple_of(page_size);
            let end = end / page_size * page_size;
            if end > start {
                pieces.push((start, end - start));
            }
        }
    }
    pieces.sort_unstable();
    pieces
}

impl PciDevice for VfioPciDevice {
    fn write_config_register(
        &mut self,
        reg_idx: u16,
        offset: u8,
        data: &[u8],
    ) -> Option<Arc<Barrier>> {
        let register = reg_idx.checked_mul(4)?;
        if usize::from(offset) + data.len() > 4 || u64::from(register) + 4 > self.config_size {
            return None;
        }
        if (BAR0..BAR0 + 4 * u16::from(NUM_BAR_REGS)).contains(&register) {
            // BAR writes go to the emulated registers only: the device keeps its host addresses.
            // A new guest address takes effect when memory decoding is next enabled.
            let index = u8::try_from((register - BAR0) / 4).unwrap();
            self.bars.write(index, offset, data);
            return None;
        }
        if register == ROM_ADDRESS {
            let memory_enabled = self.memory_enabled;
            if let Some(rom) = &mut self.rom {
                let was_decoding = memory_enabled && rom.enabled;
                rom.write(offset, data);
                // The ROM decodes when both Memory Space and the ROM enable bit are set: its new
                // address takes effect when it starts decoding, like the BARs.
                if !was_decoding && memory_enabled && rom.enabled {
                    self.relocate_rom();
                }
            }
            return None;
        }

        let start = register + u16::from(offset);
        let mut i = 0;
        while i < data.len() {
            let owner = self.config_owner(start + u16::try_from(i).unwrap());
            let mut end = i + 1;
            while end < data.len()
                && self.config_owner(start + u16::try_from(end).unwrap()) == owner
            {
                end += 1;
            }
            self.write_config_run(owner, start + u16::try_from(i).unwrap(), &data[i..end]);
            i = end;
        }
        None
    }

    fn read_config_register(&mut self, reg_idx: u16) -> u32 {
        let Some(register) = reg_idx.checked_mul(4) else {
            return u32::MAX;
        };
        if u64::from(register) + 4 > self.config_size {
            return u32::MAX;
        }
        if (BAR0..BAR0 + 4 * u16::from(NUM_BAR_REGS)).contains(&register) {
            let index = u8::try_from((register - BAR0) / 4).unwrap();
            let mut value = [0u8; 4];
            self.bars.read(index, 0, &mut value);
            return u32::from_le_bytes(value);
        }
        if register == ROM_ADDRESS {
            return self.rom.as_ref().map_or(0, RomBar::register);
        }
        let mut bytes = [0xffu8; 4];
        if !self.read_config(register, &mut bytes) {
            return u32::MAX;
        }
        for (i, byte) in bytes.iter_mut().enumerate() {
            if let Some(value) =
                self.virtual_config_byte(register + u16::try_from(i).unwrap(), *byte)
            {
                *byte = value;
            }
        }
        u32::from_le_bytes(bytes)
    }

    fn read_bar(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        // Without memory decoding the device does not respond: reads return all ones.
        if !self.memory_enabled {
            data.fill(0xff);
            return;
        }
        if self.is_rom(base) {
            let rom = self.rom.as_ref().expect("ROM exists");
            if !rom.enabled
                || self
                    .device
                    .read_region(VFIO_PCI_ROM_REGION_INDEX, offset, data)
                    .is_err()
            {
                data.fill(0xff);
            }
            return;
        }
        let Some(region) = self.bar_region(base) else {
            data.fill(0xff);
            return;
        };
        let index = region.index;
        if let Some(msix) = &self.msix {
            let (table_bar, table, table_size) = msix.table_location();
            if index == table_bar && offset >= table && offset < table + table_size {
                msix.read_table(offset - table, data);
                return;
            }
            let (pba_bar, pba, pba_size) = msix.pba_location();
            if index == pba_bar && offset >= pba && offset < pba + pba_size {
                msix.read_pba(self.device.as_ref(), offset - pba, data);
                return;
            }
        }
        if let Err(err) = self.device.read_region(index, offset, data) {
            debug!(
                "vfio: {}: BAR {index} read at {offset:#x} failed: {err}",
                self.host_name
            );
            data.fill(0xff);
        }
    }

    fn write_bar(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        if !self.memory_enabled || self.is_rom(base) {
            return None;
        }
        let index = self.bar_region(base)?.index;
        if let Some(msix) = &mut self.msix {
            let (table_bar, table, table_size) = msix.table_location();
            if index == table_bar && offset >= table && offset < table + table_size {
                msix.write_table(self.device.as_ref(), offset - table, data);
                return None;
            }
            let (pba_bar, pba, pba_size) = msix.pba_location();
            if index == pba_bar && offset >= pba && offset < pba + pba_size {
                // The pending bit array is read-only.
                return None;
            }
        }
        if let Err(err) = self.device.write_region(index, offset, data) {
            debug!(
                "vfio: {}: BAR {index} write at {offset:#x} failed: {err}",
                self.host_name
            );
        }
        None
    }
}

impl BusDevice for VfioPciDevice {
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {
        self.read_bar(base, offset, data)
    }

    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        self.write_bar(base, offset, data)
    }
}

impl Drop for VfioPciDevice {
    fn drop(&mut self) {
        // Take the BARs out of the guest address space before their host mappings go away. The
        // host interrupts need no teardown: closing the device file disables them
        // (`vfio_pci_core_close_device`), and dropping the vector groups deassigns the MSI and
        // MSI-X irqfds. The INTx irqfd belongs to no vector group and is deassigned here.
        if let Err(err) = self.set_memory_enabled(false) {
            error!(
                "vfio: {}: failed to remove the BAR memory slots: {err}",
                self.host_name
            );
        }
        if let Some(intx) = &mut self.intx {
            intx.release();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::File;
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::FileExt;
    use std::sync::Mutex;

    use super::*;
    use crate::devices::vfio::generated::pci_regs::{PCI_CAP_ID_EXP, PCI_COMMAND_MEMORY};
    use crate::devices::vfio::generated::vfio::{VFIO_IRQ_INFO_EVENTFD, VFIO_IRQ_INFO_NORESIZE};
    use crate::vstate::vm::tests::setup_vm_with_memory;

    const RW: u32 = VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE;
    const RW_MMAP: u32 = RW | VFIO_REGION_INFO_FLAG_MMAP;

    // Layout of the mock device file: every region at its own offset.
    const BAR0_OFFSET: u64 = 0x10_0000;
    const BAR0_SIZE: u64 = 0x4000;
    const BAR2_OFFSET: u64 = 0x20_0000;
    const BAR2_SIZE: u64 = 0x20_0000;
    const BAR4_OFFSET: u64 = 0x50_0000;
    const BAR5_OFFSET: u64 = 0x60_0000;
    const BAR5_SIZE: u64 = 0x100;
    const ROM_OFFSET: u64 = 0x70_0000;
    const ROM_SIZE: u64 = 0x1_0000;
    const FILE_SIZE: u64 = 0x80_0000;

    // Capabilities of the mock device configuration space.
    const PM_CAP: u16 = 0x40;
    const MSI_CAP: u16 = 0x50;
    const EXP_CAP: u16 = 0x70;
    const MSIX_CAP: u16 = 0xb0;
    const MSIX_TABLE_OFFSET: u64 = 0x2000;
    const MSIX_PBA_OFFSET: u64 = 0x3000;
    const MSIX_ENTRIES: usize = 8;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum IrqCall {
        Enable {
            index: u32,
            start: u32,
            count: usize,
        },
        Unmask(u32),
        Disable(u32),
    }

    /// State shared between a test and its [`MockDevice`].
    #[derive(Debug, Default)]
    struct MockState {
        irq_calls: Vec<IrqCall>,
        /// When set, the next MSI/MSI-X enable only allocates this many vectors.
        partial: Option<u32>,
        /// When set, setting the INTx unmask eventfd fails.
        fail_unmask: bool,
        config_writes: Vec<(u64, Vec<u8>)>,
    }

    #[derive(Debug)]
    struct MockDevice {
        regions: Vec<RegionInfo>,
        irqs: Vec<IrqInfo>,
        file: File,
        state: Arc<Mutex<MockState>>,
    }

    impl VfioDeviceIo for MockDevice {
        fn region(&self, index: u32) -> Option<&RegionInfo> {
            self.regions.get(index as usize)
        }

        fn irq(&self, index: u32) -> Option<IrqInfo> {
            self.irqs.get(index as usize).copied()
        }

        fn read_region(
            &self,
            index: u32,
            offset: u64,
            data: &mut [u8],
        ) -> Result<(), VfioSysError> {
            let region = &self.regions[index as usize];
            if offset + data.len() as u64 > region.size {
                return Err(VfioSysError::OutOfRange {
                    index,
                    offset,
                    len: data.len(),
                });
            }
            self.file
                .read_exact_at(data, region.offset + offset)
                .map_err(|err| VfioSysError::RegionAccess(index, err))
        }

        fn write_region(&self, index: u32, offset: u64, data: &[u8]) -> Result<(), VfioSysError> {
            let region = &self.regions[index as usize];
            if offset + data.len() as u64 > region.size || region.flags & RW != RW {
                return Err(VfioSysError::AccessDenied(index));
            }
            if index == VFIO_PCI_CONFIG_REGION_INDEX {
                self.state
                    .lock()
                    .unwrap()
                    .config_writes
                    .push((offset, data.to_vec()));
            }
            self.file
                .write_all_at(data, region.offset + offset)
                .map_err(|err| VfioSysError::RegionAccess(index, err))
        }

        fn set_irq_eventfds(
            &self,
            index: u32,
            start: u32,
            fds: &[RawFd],
        ) -> Result<(), SetIrqsError> {
            let mut state = self.state.lock().unwrap();
            state.irq_calls.push(IrqCall::Enable {
                index,
                start,
                count: fds.len(),
            });
            match state.partial.take() {
                Some(available) => Err(SetIrqsError::Partial(available)),
                None => Ok(()),
            }
        }

        fn set_irq_unmask_eventfd(&self, index: u32, _fd: RawFd) -> Result<(), VfioSysError> {
            let mut state = self.state.lock().unwrap();
            state.irq_calls.push(IrqCall::Unmask(index));
            if state.fail_unmask {
                return Err(VfioSysError::Ioctl(
                    "VFIO_DEVICE_SET_IRQS",
                    vmm_sys_util::errno::Error::new(libc::EINVAL),
                ));
            }
            Ok(())
        }

        fn disable_irqs(&self, index: u32) -> Result<(), VfioSysError> {
            self.state
                .lock()
                .unwrap()
                .irq_calls
                .push(IrqCall::Disable(index));
            Ok(())
        }

        fn mmap_fd(&self) -> RawFd {
            self.file.as_raw_fd()
        }
    }

    fn put(file: &File, offset: u64, data: &[u8]) {
        file.write_all_at(data, offset).unwrap();
    }

    fn put_u16(file: &File, offset: u16, value: u16) {
        put(file, u64::from(offset), &value.to_le_bytes());
    }

    fn put_u32(file: &File, offset: u16, value: u32) {
        put(file, u64::from(offset), &value.to_le_bytes());
    }

    /// A memory file holding the regions of a mock device: an NVIDIA-like function with PM, MSI,
    /// PCIe and MSI-X capabilities and a list of extended capabilities.
    fn mock_file() -> File {
        // SAFETY: memfd_create with a valid name returns a new file descriptor we own.
        let fd = unsafe { libc::memfd_create(c"vfio-mock".as_ptr(), 0) };
        assert!(fd >= 0);
        // SAFETY: `fd` is a new file descriptor that nothing else owns.
        let file = unsafe { File::from_raw_fd(fd) };
        file.set_len(FILE_SIZE).unwrap();

        put_u32(&file, 0x00, 0x2684_10de);
        put_u16(&file, COMMAND, u16::try_from(PCI_COMMAND_MEMORY).unwrap());
        put_u16(&file, STATUS, u16::try_from(PCI_STATUS_CAP_LIST).unwrap());
        // Multi-function device.
        put(&file, u64::from(HEADER_TYPE), &[0x80]);
        // BAR0: 32-bit memory; BAR2: 64-bit prefetchable memory; BAR4: I/O; BAR5: 32-bit memory.
        put_u32(&file, BAR0, 0);
        put_u32(&file, BAR0 + 8, 0xc);
        put_u32(&file, BAR0 + 16, 1);
        put_u32(&file, BAR0 + 20, 0);
        put(&file, u64::from(CAPABILITY_LIST), &[0x40]);
        put(&file, u64::from(INTERRUPT_PIN), &[1]);

        // PM capability, in D0.
        put(&file, u64::from(PM_CAP), &[1, 0x50]);
        // MSI capability: 64-bit, per-vector masking, 4 messages.
        put(&file, u64::from(MSI_CAP), &[5, 0x70]);
        put_u16(&file, MSI_CAP + 2, 0x0184);
        // PCI Express capability.
        put(
            &file,
            u64::from(EXP_CAP),
            &[u8::try_from(PCI_CAP_ID_EXP).unwrap(), 0xb0],
        );
        // MSI-X capability: 8 entries, table and PBA in BAR0.
        put(&file, u64::from(MSIX_CAP), &[0x11, 0]);
        put_u16(
            &file,
            MSIX_CAP + 2,
            u16::try_from(MSIX_ENTRIES - 1).unwrap(),
        );
        put_u32(
            &file,
            MSIX_CAP + 4,
            u32::try_from(MSIX_TABLE_OFFSET).unwrap(),
        );
        put_u32(&file, MSIX_CAP + 8, u32::try_from(MSIX_PBA_OFFSET).unwrap());

        // Extended capabilities: Resizable BAR (hidden, list head), AER, SR-IOV (hidden), ARI
        // (hidden), vendor specific.
        let ecap = |id: u32, next: u32| id | (1 << 16) | (next << 20);
        put_u32(&file, 0x100, ecap(0x15, 0x140));
        put_u32(&file, 0x140, ecap(0x01, 0x180));
        put_u32(&file, 0x180, ecap(0x10, 0x1c0));
        put_u32(&file, 0x1c0, ecap(0x0e, 0x200));
        put_u32(&file, 0x200, ecap(0x0b, 0));

        // Physical PBA of the MSI-X table: vector 5 pending in hardware.
        put(&file, BAR0_OFFSET + MSIX_PBA_OFFSET, &[1 << 5]);
        // Recognizable contents for BAR5 and the ROM.
        put(&file, BAR5_OFFSET, &[0xa5; 0x100]);
        put(&file, ROM_OFFSET, &[0x55, 0xaa]);
        file
    }

    fn mock_regions(bar2_sparse: Option<Vec<(u64, u64)>>) -> Vec<RegionInfo> {
        let region = |flags, size, offset| RegionInfo {
            flags,
            size,
            offset,
            sparse_mmap_areas: None,
        };
        let mut regions = vec![
            region(RW_MMAP, BAR0_SIZE, BAR0_OFFSET),
            region(0, 0, 0),
            region(RW_MMAP, BAR2_SIZE, BAR2_OFFSET),
            region(0, 0, 0),
            region(RW, 0x80, BAR4_OFFSET),
            region(RW_MMAP, BAR5_SIZE, BAR5_OFFSET),
            region(VFIO_REGION_INFO_FLAG_READ, ROM_SIZE, ROM_OFFSET),
            region(RW, 0x1000, 0),
        ];
        regions[2].sparse_mmap_areas = bar2_sparse;
        regions
    }

    fn mock_irqs(dynamic_msix: bool) -> Vec<IrqInfo> {
        let msix_flags = if dynamic_msix {
            VFIO_IRQ_INFO_EVENTFD
        } else {
            VFIO_IRQ_INFO_EVENTFD | VFIO_IRQ_INFO_NORESIZE
        };
        vec![
            IrqInfo {
                flags: VFIO_IRQ_INFO_EVENTFD,
                count: 1,
            },
            IrqInfo {
                flags: VFIO_IRQ_INFO_EVENTFD | VFIO_IRQ_INFO_NORESIZE,
                count: 4,
            },
            IrqInfo {
                flags: msix_flags,
                count: u32::try_from(MSIX_ENTRIES).unwrap(),
            },
        ]
    }

    struct TestDevice {
        device: VfioPciDevice,
        state: Arc<Mutex<MockState>>,
        file: File,
    }

    fn build(file: File, regions: Vec<RegionInfo>, dynamic_msix: bool) -> TestDevice {
        build_in(
            Arc::new(setup_vm_with_memory(0x1000_0000)),
            file,
            regions,
            dynamic_msix,
        )
    }

    fn build_in(
        vm: Arc<KvmVm>,
        file: File,
        regions: Vec<RegionInfo>,
        dynamic_msix: bool,
    ) -> TestDevice {
        let state = Arc::new(Mutex::new(MockState::default()));
        let mock = MockDevice {
            regions,
            irqs: mock_irqs(dynamic_msix),
            file: file.try_clone().unwrap(),
            state: state.clone(),
        };
        let device = VfioPciDevice::with_io(
            "gpu0".to_string(),
            PciSBDF::new(0, 0, 3, 0),
            "0000:01:00.0".to_string(),
            PathBuf::from("/sys/bus/pci/devices/0000:01:00.0"),
            Box::new(mock),
            vm,
        )
        .unwrap();
        TestDevice {
            device,
            state,
            file,
        }
    }

    fn default_device(dynamic_msix: bool) -> TestDevice {
        build(mock_file(), mock_regions(None), dynamic_msix)
    }

    /// Place BARs as the PCI manager does: reserved at the top of the MMIO windows of the VM.
    fn place_and_map(device: &mut VfioPciDevice) -> HashMap<String, u64> {
        let mut placed = HashMap::new();
        let vm = device.vm.clone();
        for requirement in device.bar_requirements() {
            let addr = window_allocator(&mut vm.resource_allocator(), requirement.window)
                .allocate(requirement.size, requirement.size, AllocPolicy::LastMatch)
                .unwrap()
                .start();
            device.place_bar(requirement.slot, addr);
            placed.insert(format!("{:?}", requirement.slot), addr);
        }
        device.map_bars().unwrap();
        placed
    }

    fn read_config(device: &mut VfioPciDevice, offset: u16) -> u32 {
        device.read_config_register(offset / 4)
    }

    fn write_config(device: &mut VfioPciDevice, offset: u16, data: &[u8]) {
        device.write_config_register(offset / 4, u8::try_from(offset % 4).unwrap(), data);
    }

    #[test]
    fn test_hide_extended_capabilities() {
        let ecap = |id: u32, next: u32| id | (1 << 16) | (next << 20);
        let hidden = HIDDEN_EXTENDED_CAPABILITIES;

        // Nothing to hide.
        let ecaps = [(0x100, ecap(1, 0x140)), (0x140, ecap(0xb, 0))];
        assert!(hide_extended_capabilities(&ecaps, &hidden).is_empty());

        // Hidden head, hidden entries in the middle and at the tail.
        let ecaps = [
            (0x100, ecap(0x15, 0x140)),
            (0x140, ecap(0x01, 0x180)),
            (0x180, ecap(0x10, 0x1c0)),
            (0x1c0, ecap(0x0b, 0x200)),
            (0x200, ecap(0x0e, 0)),
        ];
        assert_eq!(
            hide_extended_capabilities(&ecaps, &hidden),
            vec![
                (0x100, 0x140 << 20),
                (0x140, ecap(0x01, 0x1c0)),
                (0x1c0, ecap(0x0b, 0)),
            ]
        );

        // Only hidden capabilities: the list becomes empty.
        let ecaps = [(0x100, ecap(0x10, 0x140)), (0x140, ecap(0x15, 0))];
        assert_eq!(
            hide_extended_capabilities(&ecaps, &hidden),
            vec![(0x100, 0)]
        );
    }

    #[test]
    fn test_mappable_areas() {
        let page = 0x1000;
        let region = |flags, size, sparse| RegionInfo {
            flags,
            size,
            offset: 0,
            sparse_mmap_areas: sparse,
        };

        // Not mappable at all.
        assert!(mappable_areas(&region(RW, 0x4000, None), 0x4000, &[], page).is_empty());
        // Whole BAR.
        assert_eq!(
            mappable_areas(&region(RW_MMAP, 0x4000, None), 0x4000, &[], page),
            vec![(0, 0x4000)]
        );
        // MSI-X table and PBA holes.
        assert_eq!(
            mappable_areas(
                &region(RW_MMAP, 0x8000, None),
                0x8000,
                &[(0x2000, 0x1000), (0x5000, 0x1000)],
                page
            ),
            vec![(0, 0x2000), (0x3000, 0x2000), (0x6000, 0x2000)]
        );
        // Sub-page BAR: trapped.
        assert!(mappable_areas(&region(RW_MMAP, 0x100, None), 0x100, &[], page).is_empty());
        // Sparse areas, one of them not page aligned: shrunk to whole pages.
        assert_eq!(
            mappable_areas(
                &region(
                    RW_MMAP,
                    0x10000,
                    Some(vec![(0x800, 0x2000), (0x8000, 0x8000)])
                ),
                0x10000,
                &[],
                page
            ),
            vec![(0x1000, 0x1000), (0x8000, 0x8000)]
        );
        // Areas beyond the BAR are clipped.
        assert_eq!(
            mappable_areas(&region(RW_MMAP, 0x10000, None), 0x4000, &[], page),
            vec![(0, 0x4000)]
        );
    }

    #[test]
    fn test_mapping_alignment() {
        let page = 0x1000;
        // Limited by the guest address alignment.
        assert_eq!(mapping_alignment(0x40_0020_0000, 1 << 30, page), 0x20_0000);
        // Limited by the length.
        assert_eq!(
            mapping_alignment(0x40_0000_0000, 0x10_0000, page),
            0x10_0000
        );
        assert_eq!(
            mapping_alignment(0x40_0000_0000, 0x18_0000, page),
            0x10_0000
        );
        // Capped at 1 GiB.
        assert_eq!(mapping_alignment(0x40_0000_0000, 1 << 34, page), 1 << 30);
        assert_eq!(mapping_alignment(0, 1 << 34, page), 1 << 30);
        // Never below the page size.
        assert_eq!(mapping_alignment(0x1800, 0x1000, page), page);
    }

    #[test]
    fn test_rom_bar_register() {
        // The size is rounded up to a power of two of at least 2 KiB, and must fit in the 32-bit
        // register.
        assert_eq!(RomBar::new(0x100).unwrap().size, 0x800);
        assert_eq!(RomBar::new(1 << 31).unwrap().size, 1 << 31);
        assert!(RomBar::new((1 << 31) + 1).is_none());
        assert!(RomBar::new(u64::MAX).is_none());

        let mut rom = RomBar::new(0xc000).unwrap();
        assert_eq!(rom.size, 0x1_0000);
        rom.place(0xc001_0000);
        assert_eq!(rom.register(), 0xc001_0000);
        // Sizing: all ones in the address bits, enable bit clear.
        rom.write(0, &0xffff_fffeu32.to_le_bytes());
        assert_eq!(rom.register(), 0xffff_0000);
        // Restoring the address and enabling decoding.
        rom.write(0, &0xc001_0001u32.to_le_bytes());
        assert_eq!(rom.register(), 0xc001_0001);
        // A byte write to the enable bit only.
        rom.write(0, &[0]);
        assert_eq!(rom.register(), 0xc001_0000);
        // A new address: the bits below the size are read-only zeros. The ROM stays where it is
        // trapped until it is relocated.
        rom.write(0, &0xd000_8001u32.to_le_bytes());
        assert_eq!(rom.register(), 0xd000_0001);
        assert_eq!(rom.guest_addr, 0xc001_0000);
    }

    #[test]
    fn test_config_space_virtualization() {
        let mut test = default_device(true);
        let device = &mut test.device;

        // The multi-function bit is cleared, the rest of the header type is kept.
        assert_eq!(read_config(device, 0x0c) >> 16 & 0xff, 0);
        // The interrupt pin reads 0.
        assert_eq!(read_config(device, 0x3c) >> 8 & 0xff, 0);
        // Unplaced BARs read 0.
        for bar in 0..6 {
            assert_eq!(read_config(device, BAR0 + 4 * bar), 0);
        }

        // MSI: flags taken from the device, disabled with one message.
        assert_eq!(read_config(device, MSI_CAP), 0x0184_7005);
        // MSI-X: table size from the device, disabled and unmasked.
        assert_eq!(read_config(device, MSIX_CAP), 0x0007_0011);

        // Extended capabilities: the Resizable BAR head becomes a placeholder, SR-IOV and ARI
        // are skipped.
        assert_eq!(read_config(device, 0x100), 0x140 << 20);
        assert_eq!(read_config(device, 0x140), 0x01 | (1 << 16) | (0x200 << 20));
        // Beyond the configuration region.
        assert_eq!(device.read_config_register(0x400), u32::MAX);

        // Writes to emulated bytes do not reach the device: the interrupt line keeps the value
        // the guest wrote, the interrupt pin and the other read-only bytes are unchanged.
        write_config(device, 0x3c, &[0x0b, 0x02]);
        write_config(device, 0x100, &[0, 0, 0, 0]);
        write_config(device, MSIX_CAP, &[0, 0]);
        assert!(test.state.lock().unwrap().config_writes.is_empty());
        assert_eq!(read_config(&mut test.device, 0x3c) & 0xffff, 0x000b);
        assert_eq!(read_config(&mut test.device, 0x100), 0x140 << 20);
        assert_eq!(read_config(&mut test.device, MSIX_CAP), 0x0007_0011);
    }

    #[test]
    fn test_device_rejections() {
        // A bridge cannot be assigned.
        let file = mock_file();
        put(&file, u64::from(HEADER_TYPE), &[0x01]);
        let vm = Arc::new(setup_vm_with_memory(0x1000_0000));
        let mock = MockDevice {
            regions: mock_regions(None),
            irqs: mock_irqs(true),
            file,
            state: Arc::default(),
        };
        let result = VfioPciDevice::with_io(
            "bridge".to_string(),
            PciSBDF::new(0, 0, 3, 0),
            "0000:00:01.0".to_string(),
            PathBuf::from("/sys/bus/pci/devices/0000:00:01.0"),
            Box::new(mock),
            vm.clone(),
        );
        assert!(matches!(result, Err(VfioPciError::NotAnEndpoint(_, 1))));

        // A device that only has INTx can be assigned.
        let file = mock_file();
        put_u16(&file, STATUS, 0);
        let mock = MockDevice {
            regions: mock_regions(None),
            irqs: mock_irqs(true),
            file,
            state: Arc::default(),
        };
        let device = VfioPciDevice::with_io(
            "intx".to_string(),
            PciSBDF::new(0, 0, 3, 0),
            "0000:02:00.0".to_string(),
            PathBuf::from("/sys/bus/pci/devices/0000:02:00.0"),
            Box::new(mock),
            vm.clone(),
        )
        .unwrap();
        assert!(device.msi.is_none() && device.msix.is_none() && device.supports_intx());

        // The number of MSI messages reported by the host must be a power of two up to 32.
        for count in [0, 3, 64] {
            let mut irqs = mock_irqs(true);
            irqs[VFIO_PCI_MSI_IRQ_INDEX as usize].count = count;
            let mock = MockDevice {
                regions: mock_regions(None),
                irqs,
                file: mock_file(),
                state: Arc::default(),
            };
            let result = VfioPciDevice::with_io(
                "msi".to_string(),
                PciSBDF::new(0, 0, 3, 0),
                "0000:03:00.0".to_string(),
                PathBuf::from("/sys/bus/pci/devices/0000:03:00.0"),
                Box::new(mock),
                vm.clone(),
            );
            assert!(
                matches!(result, Err(VfioPciError::MsiVectorCount(_, c)) if c == count),
                "{count}"
            );
        }
    }

    #[test]
    fn test_bars() {
        let file = mock_file();
        // The second BAR2 area is not page aligned and is shrunk away.
        let sparse = Some(vec![(0, 0x10_0000), (0x10_0800, 0x800)]);
        let mut test = build(file, mock_regions(sparse), true);
        let device = &mut test.device;

        assert_eq!(
            device.bar_requirements(),
            vec![
                BarRequirement {
                    slot: BarSlot::Bar(0),
                    size: BAR0_SIZE,
                    window: BarWindow::Mmio32
                },
                BarRequirement {
                    slot: BarSlot::Bar(2),
                    size: BAR2_SIZE,
                    window: BarWindow::Mmio64
                },
                // BAR4 is an I/O BAR and is not exposed.
                BarRequirement {
                    slot: BarSlot::Bar(5),
                    size: BAR5_SIZE,
                    window: BarWindow::Mmio32
                },
                BarRequirement {
                    slot: BarSlot::Rom,
                    size: ROM_SIZE,
                    window: BarWindow::Mmio32
                },
            ]
        );
        let placed = place_and_map(device);
        let bar0 = placed["Bar(0)"];
        let bar2 = placed["Bar(2)"];
        let bar5 = placed["Bar(5)"];
        let rom = placed["Rom"];

        // The emulated registers hold the guest addresses and keep the type bits.
        assert_eq!(u64::from(read_config(device, BAR0)), bar0);
        assert_eq!(
            u64::from(read_config(device, BAR0 + 8)),
            (bar2 & 0xffff_ffff) | 0xc
        );
        assert_eq!(u64::from(read_config(device, BAR0 + 12)), bar2 >> 32);
        assert_eq!(read_config(device, BAR0 + 16), 0);
        assert_eq!(u64::from(read_config(device, BAR0 + 20)), bar5);
        assert_eq!(u64::from(read_config(device, ROM_ADDRESS)), rom);

        // BAR sizing, then restoring the address.
        write_config(device, BAR0, &u32::MAX.to_le_bytes());
        assert_eq!(
            read_config(device, BAR0),
            !(u32::try_from(BAR0_SIZE).unwrap() - 1)
        );
        write_config(device, BAR0, &u32::try_from(bar0).unwrap().to_le_bytes());
        assert_eq!(u64::from(read_config(device, BAR0)), bar0);
        // The high half of a 64-bit BAR sizes to all ones.
        write_config(device, BAR0 + 12, &u32::MAX.to_le_bytes());
        assert_eq!(read_config(device, BAR0 + 12), u32::MAX);
        write_config(
            device,
            BAR0 + 12,
            &u32::try_from(bar2 >> 32).unwrap().to_le_bytes(),
        );
        assert_eq!(u64::from(read_config(device, BAR0 + 12)), bar2 >> 32);

        // Mappings: BAR0 without the MSI-X table and PBA pages, the first BAR2 area, nothing
        // for the sub-page BAR5. All are exposed since the device decodes memory.
        let mappings: Vec<(u64, usize, bool)> = device
            .regions
            .iter()
            .flat_map(|region| region.mappings.iter())
            .map(|mapping| (mapping.guest_addr, mapping.len, mapping.registered))
            .collect();
        assert_eq!(
            mappings,
            vec![(bar0, 0x2000, true), (bar2, 0x10_0000, true)]
        );
        // The host mapping of BAR2 is aligned like its guest address.
        let bar2_mapping = &device.regions[1].mappings[0];
        assert_eq!(bar2_mapping.host_addr as u64 % 0x10_0000, 0);

        assert_eq!(
            device.mmio_ranges(),
            vec![
                (bar0, BAR0_SIZE),
                (bar2, BAR2_SIZE),
                (bar5, BAR5_SIZE),
                (rom, ROM_SIZE)
            ]
        );

        // Trapped accesses go through the VFIO region.
        let mut data = [0u8; 4];
        device.read_bar(bar5, 0x10, &mut data);
        assert_eq!(data, [0xa5; 4]);
        device.write_bar(bar5, 0x10, &[1, 2, 3, 4]);
        device.read_bar(bar5, 0x10, &mut data);
        assert_eq!(data, [1, 2, 3, 4]);
        // Unknown base.
        device.read_bar(0x1234_0000, 0, &mut data);
        assert_eq!(data, [0xff; 4]);

        // The ROM only decodes when enabled.
        let mut rom_data = [0u8; 2];
        device.read_bar(rom, 0, &mut rom_data);
        assert_eq!(rom_data, [0xff, 0xff]);
        write_config(
            device,
            ROM_ADDRESS,
            &(u32::try_from(rom).unwrap() | 1).to_le_bytes(),
        );
        device.read_bar(rom, 0, &mut rom_data);
        assert_eq!(rom_data, [0x55, 0xaa]);
        // The ROM is read-only.
        device.write_bar(rom, 0, &[0, 0]);
        device.read_bar(rom, 0, &mut rom_data);
        assert_eq!(rom_data, [0x55, 0xaa]);
    }

    #[test]
    fn test_memory_decoding() {
        let mut test = default_device(true);
        let device = &mut test.device;
        let placed = place_and_map(device);
        let bar5 = placed["Bar(5)"];
        let registered = |device: &VfioPciDevice| {
            device
                .regions
                .iter()
                .flat_map(|region| region.mappings.iter())
                .all(|mapping| mapping.registered)
        };
        assert!(device.memory_enabled && registered(device));

        // Memory Space disabled: the memory slots go away and accesses read all ones.
        write_config(device, COMMAND, &[0]);
        assert!(!device.memory_enabled);
        assert!(
            device
                .regions
                .iter()
                .flat_map(|region| region.mappings.iter())
                .all(|mapping| !mapping.registered)
        );
        let mut data = [0u8; 4];
        device.read_bar(bar5, 0, &mut data);
        assert_eq!(data, [0xff; 4]);
        // Writes are dropped.
        device.write_bar(bar5, 0, &[0, 0, 0, 0]);

        // Memory Space enabled again.
        write_config(
            device,
            COMMAND,
            &[u8::try_from(PCI_COMMAND_MEMORY).unwrap()],
        );
        assert!(device.memory_enabled && registered(device));
        device.read_bar(bar5, 0, &mut data);
        assert_eq!(data, [0xa5; 4]);

        // D3hot also stops memory decoding, D0 restores it.
        write_config(device, PM_CAP + PM_CTRL, &[3, 0]);
        assert!(!device.memory_enabled);
        write_config(device, PM_CAP + PM_CTRL, &[0, 0]);
        assert!(device.memory_enabled && registered(device));

        // Writes to other registers do not change the state.
        write_config(device, 0x3c, &[5]);
        assert!(device.memory_enabled);

        // Dropping the device removes the memory slots before unmapping.
        drop(test);
    }

    /// A placed and mapped device, trapped on the MMIO bus of its VM like the PCI manager does.
    fn attached_device() -> (Arc<KvmVm>, Arc<Mutex<VfioPciDevice>>, HashMap<String, u64>) {
        let vm = Arc::new(setup_vm_with_memory(0x1000_0000));
        let mut device = build_in(vm.clone(), mock_file(), mock_regions(None), true).device;
        let placed = place_and_map(&mut device);
        let ranges = device.mmio_ranges();
        let device = Arc::new(Mutex::new(device));
        for (base, len) in ranges {
            vm.common
                .mmio_bus
                .insert(device.clone(), base, len)
                .unwrap();
        }
        (vm, device, placed)
    }

    fn set_memory_space(device: &Mutex<VfioPciDevice>, enabled: bool) {
        let command = if enabled { PCI_COMMAND_MEMORY } else { 0 };
        write_config(
            &mut device.lock().unwrap(),
            COMMAND,
            &[u8::try_from(command).unwrap()],
        );
    }

    fn write_config_u32(device: &Mutex<VfioPciDevice>, offset: u16, value: u64) {
        write_config(
            &mut device.lock().unwrap(),
            offset,
            &u32::try_from(value).unwrap().to_le_bytes(),
        );
    }

    fn read_config_u64(device: &Mutex<VfioPciDevice>, offset: u16) -> u64 {
        u64::from(read_config(&mut device.lock().unwrap(), offset))
    }

    /// Whether `[addr, addr + size)` is reserved in the MMIO window holding it.
    fn is_reserved(vm: &KvmVm, addr: u64, size: u64) -> bool {
        let mut allocator = vm.resource_allocator();
        let window = window_allocator(&mut allocator, window_of(addr, size).unwrap());
        match window.allocate(size, size, AllocPolicy::ExactMatch(addr)) {
            Ok(range) => {
                window.free(&range).unwrap();
                false
            }
            Err(_) => true,
        }
    }

    /// Whether a device is trapped at `addr` on the MMIO bus.
    fn on_bus(vm: &KvmVm, addr: u64) -> bool {
        vm.common.mmio_bus.read(addr, &mut [0u8; 4]).is_ok()
    }

    /// The guest addresses and registration of the BAR memory slots.
    fn slots(device: &Mutex<VfioPciDevice>) -> Vec<(u64, bool)> {
        device
            .lock()
            .unwrap()
            .regions
            .iter()
            .flat_map(|region| region.mappings.iter())
            .map(|mapping| (mapping.guest_addr, mapping.registered))
            .collect()
    }

    #[test]
    fn test_bar_relocation() {
        let (vm, device, placed) = attached_device();
        let (bar0, bar2, bar5) = (placed["Bar(0)"], placed["Bar(2)"], placed["Bar(5)"]);
        // New addresses at the bottom of the 32-bit window, away from the placed BARs at the top.
        // The 64-bit BAR2 moves into the 32-bit window, which a 64-bit BAR may decode.
        let new2 = arch::MEM_32BIT_DEVICES_START.next_multiple_of(BAR2_SIZE);
        let new0 = new2 + BAR2_SIZE;
        assert_eq!(slots(&device), vec![(bar0, true), (bar2, true)]);

        // The guest programs the BARs with decoding disabled: nothing moves yet, the registers
        // read the new addresses.
        set_memory_space(&device, false);
        write_config_u32(&device, BAR0, new0);
        write_config_u32(&device, BAR0 + 8, new2);
        write_config_u32(&device, BAR0 + 12, 0);
        assert_eq!(read_config_u64(&device, BAR0), new0);
        assert_eq!(read_config_u64(&device, BAR0 + 8), new2 | 0xc);
        assert_eq!(read_config_u64(&device, BAR0 + 12), 0);
        assert!(on_bus(&vm, bar0) && on_bus(&vm, bar2) && !on_bus(&vm, new0));

        // Enabling decoding applies them: the bus ranges, the reservations and the memory slots
        // follow, and the BAR is accessed at its new address.
        set_memory_space(&device, true);
        assert!(!on_bus(&vm, bar0) && !on_bus(&vm, bar2));
        assert!(on_bus(&vm, new0) && on_bus(&vm, new2) && on_bus(&vm, bar5));
        assert!(!is_reserved(&vm, bar0, BAR0_SIZE) && !is_reserved(&vm, bar2, BAR2_SIZE));
        assert!(is_reserved(&vm, new0, BAR0_SIZE) && is_reserved(&vm, new2, BAR2_SIZE));
        assert_eq!(slots(&device), vec![(new0, true), (new2, true)]);
        // The MSI-X table is still trapped, at its offset in the relocated BAR0.
        vm.common
            .mmio_bus
            .write(new0 + MSIX_TABLE_OFFSET + 8, &0xabcdu32.to_le_bytes())
            .unwrap();
        let mut data = [0u8; 4];
        vm.common
            .mmio_bus
            .read(new0 + MSIX_TABLE_OFFSET + 8, &mut data)
            .unwrap();
        assert_eq!(u32::from_le_bytes(data), 0xabcd);

        // Moving back works the same way.
        set_memory_space(&device, false);
        write_config_u32(&device, BAR0, bar0);
        set_memory_space(&device, true);
        assert!(on_bus(&vm, bar0) && !on_bus(&vm, new0));
        assert!(is_reserved(&vm, bar0, BAR0_SIZE) && !is_reserved(&vm, new0, BAR0_SIZE));
        assert_eq!(slots(&device), vec![(bar0, true), (new2, true)]);
    }

    #[test]
    fn test_bar_relocation_on_decode_enable_only() {
        let (vm, device, placed) = attached_device();
        let bar0 = placed["Bar(0)"];
        let new0 = arch::MEM_32BIT_DEVICES_START.next_multiple_of(BAR0_SIZE);

        // A write while decoding is only recorded in the register.
        write_config_u32(&device, BAR0, new0);
        assert_eq!(read_config_u64(&device, BAR0), new0);
        assert!(on_bus(&vm, bar0) && !on_bus(&vm, new0));
        // Writes to other registers, or re-enabling while decoding, do not apply it either.
        write_config(&mut device.lock().unwrap(), INTERRUPT_LINE, &[5]);
        set_memory_space(&device, true);
        assert!(on_bus(&vm, bar0) && !on_bus(&vm, new0));

        // Leaving D3hot is a transition to decoding too.
        let pm_ctrl = PM_CAP + PM_CTRL;
        write_config(&mut device.lock().unwrap(), pm_ctrl, &[3, 0]);
        write_config(&mut device.lock().unwrap(), pm_ctrl, &[0, 0]);
        assert!(!on_bus(&vm, bar0) && on_bus(&vm, new0));
        assert_eq!(slots(&device)[0], (new0, true));
    }

    #[test]
    fn test_bar_relocation_refused() {
        let (vm, device, placed) = attached_device();
        let (bar0, bar5) = (placed["Bar(0)"], placed["Bar(5)"]);

        // Into a range used by another BAR, and outside the device MMIO windows (guest memory):
        // the BAR stays, and its register is reset to the address it decodes at.
        for target in [bar5 & !(BAR0_SIZE - 1), 0x10_0000] {
            set_memory_space(&device, false);
            write_config_u32(&device, BAR0, target);
            set_memory_space(&device, true);
            assert_eq!(read_config_u64(&device, BAR0), bar0, "{target:#x}");
            assert!(on_bus(&vm, bar0) && on_bus(&vm, bar5));
            assert!(is_reserved(&vm, bar0, BAR0_SIZE));
            assert_eq!(slots(&device)[0], (bar0, true));
        }

        // A 64-bit BAR just past the 64-bit window: both halves of the register are reset.
        let bar2 = placed["Bar(2)"];
        let beyond = arch::MEM_64BIT_DEVICES_START + arch::MEM_64BIT_DEVICES_SIZE;
        assert!(window_of(beyond, BAR2_SIZE).is_none());
        set_memory_space(&device, false);
        write_config_u32(&device, BAR0 + 8, beyond & 0xffff_ffff);
        write_config_u32(&device, BAR0 + 12, beyond >> 32);
        set_memory_space(&device, true);
        assert_eq!(
            read_config_u64(&device, BAR0 + 8) & !0xf | read_config_u64(&device, BAR0 + 12) << 32,
            bar2
        );
        assert!(on_bus(&vm, bar2));

        // A BAR whose memory slot is still present is not moved: the slot would keep exposing
        // it at the old address.
        let new0 = arch::MEM_32BIT_DEVICES_START.next_multiple_of(BAR0_SIZE);
        let mut locked = device.lock().unwrap();
        assert!(matches!(
            locked.relocate_region(0, new0),
            Err(RelocationError::SlotRegistered)
        ));
        drop(locked);
        assert!(on_bus(&vm, bar0) && !is_reserved(&vm, new0, BAR0_SIZE));
    }

    #[test]
    fn test_rom_relocation() {
        let (vm, device, placed) = attached_device();
        let rom = placed["Rom"];
        let new_rom = arch::MEM_32BIT_DEVICES_START.next_multiple_of(ROM_SIZE);
        let read_rom = |addr: u64| {
            let mut data = [0u8; 2];
            vm.common.mmio_bus.read(addr, &mut data).unwrap();
            data
        };

        // A new address with the ROM disabled is only recorded.
        write_config_u32(&device, ROM_ADDRESS, new_rom);
        assert_eq!(read_config_u64(&device, ROM_ADDRESS), new_rom);
        assert!(on_bus(&vm, rom) && !on_bus(&vm, new_rom));
        // Enabling the ROM while Memory Space is enabled applies it.
        write_config_u32(&device, ROM_ADDRESS, new_rom | 1);
        assert!(!on_bus(&vm, rom) && on_bus(&vm, new_rom));
        assert!(!is_reserved(&vm, rom, ROM_SIZE) && is_reserved(&vm, new_rom, ROM_SIZE));
        assert_eq!(read_rom(new_rom), [0x55, 0xaa]);

        // While the ROM decodes, a new address waits for the next transition to decoding, here
        // Memory Space being enabled again.
        write_config_u32(&device, ROM_ADDRESS, rom | 1);
        assert!(on_bus(&vm, new_rom) && !on_bus(&vm, rom));
        set_memory_space(&device, false);
        set_memory_space(&device, true);
        assert!(on_bus(&vm, rom) && !on_bus(&vm, new_rom));
        assert_eq!(read_rom(rom), [0x55, 0xaa]);

        // A refused relocation resets the register, keeping the enable bit.
        write_config_u32(&device, ROM_ADDRESS, 0);
        write_config_u32(&device, ROM_ADDRESS, 1);
        assert_eq!(read_config_u64(&device, ROM_ADDRESS), rom | 1);
        assert!(on_bus(&vm, rom));
    }

    /// A VM with guest memory and its interrupt controller, which INTx routing needs.
    fn setup_vm_with_irqchip() -> KvmVm {
        #[cfg(target_arch = "x86_64")]
        {
            let vm = setup_vm_with_memory(0x1000_0000);
            vm.setup_irqchip().unwrap();
            vm
        }
        #[cfg(target_arch = "aarch64")]
        {
            let mut vm = setup_vm_with_memory(0x1000_0000);
            vm.setup_irqchip(1).unwrap();
            vm
        }
    }

    #[test]
    fn test_intx() {
        let vm = setup_vm_with_irqchip();
        let gsi = crate::arch::GSI_LEGACY_START;
        let vm = Arc::new(vm);
        let mut test = build_in(vm.clone(), mock_file(), mock_regions(None), true);
        let device = &mut test.device;
        let calls = |test: &TestDevice| test.state.lock().unwrap().irq_calls.clone();

        // Until INTx is routed, the guest sees no interrupt pin, and the host keeps INTx disabled.
        assert!(device.supports_intx());
        assert_eq!(read_config(device, INTERRUPT_LINE) >> 8 & 0xff, 0);
        assert_eq!(read_config(device, INTERRUPT_LINE) & 0xff, 0xff);
        assert!(calls(&test).is_empty());

        // Routing INTx enables it on the host, with the unmask eventfd set after the trigger.
        let device = &mut test.device;
        device.route_intx(gsi).unwrap();
        assert_eq!(device.intx_gsi(), Some(gsi));
        assert_eq!(read_config(device, INTERRUPT_LINE) >> 8 & 0xff, 1);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(read_config(device, INTERRUPT_LINE) & 0xff, gsi);
        // Interrupt Line is a scratch register for the guest.
        write_config(device, INTERRUPT_LINE, &[0x42]);
        assert_eq!(read_config(device, INTERRUPT_LINE) & 0xff, 0x42);
        assert_eq!(
            calls(&test),
            [
                IrqCall::Enable {
                    index: VFIO_PCI_INTX_IRQ_INDEX,
                    start: 0,
                    count: 1
                },
                IrqCall::Unmask(VFIO_PCI_INTX_IRQ_INDEX),
            ]
        );
        test.state.lock().unwrap().irq_calls.clear();

        // INTx is disabled while MSI is enabled, and enabled again afterwards.
        let device = &mut test.device;
        msi_setup(device, 0);
        write_config(device, MSI_CAP + 2, &[0]);
        let intx_enable = [
            IrqCall::Enable {
                index: VFIO_PCI_INTX_IRQ_INDEX,
                start: 0,
                count: 1,
            },
            IrqCall::Unmask(VFIO_PCI_INTX_IRQ_INDEX),
        ];
        let mut expected = vec![
            IrqCall::Disable(VFIO_PCI_INTX_IRQ_INDEX),
            IrqCall::Enable {
                index: VFIO_PCI_MSI_IRQ_INDEX,
                start: 0,
                count: 1,
            },
            IrqCall::Disable(VFIO_PCI_MSI_IRQ_INDEX),
        ];
        expected.extend(intx_enable);
        assert_eq!(calls(&test), expected);
        test.state.lock().unwrap().irq_calls.clear();

        // The same holds for MSI-X.
        let device = &mut test.device;
        write_config(device, MSIX_CAP + 3, &[0x80]);
        assert!(!device.intx.as_ref().unwrap().host_enabled());
        write_config(device, MSIX_CAP + 3, &[0]);
        assert!(device.intx.as_ref().unwrap().host_enabled());
        let calls_now = calls(&test);
        assert_eq!(calls_now[0], IrqCall::Disable(VFIO_PCI_INTX_IRQ_INDEX));
        assert!(matches!(
            calls_now[1],
            IrqCall::Enable {
                index: VFIO_PCI_MSIX_IRQ_INDEX,
                ..
            }
        ));
        assert_eq!(calls_now[calls_now.len() - 2..], intx_enable);
        test.state.lock().unwrap().irq_calls.clear();

        // Dropping the device deassigns the INTx irqfd and makes no VFIO call, which the seccomp
        // filter of the thread that drops it does not allow: closing the device file disables
        // INTx on the host. KVM refuses to assign an eventfd that already is an irqfd, so a
        // duplicate of the trigger eventfd can be assigned only once the irqfd is gone.
        let trigger = test
            .device
            .intx
            .as_ref()
            .unwrap()
            .trigger()
            .try_clone()
            .unwrap();
        assert_eq!(
            vm.fd().register_irqfd(&trigger, gsi).unwrap_err().errno(),
            libc::EBUSY
        );
        let state = test.state.clone();
        drop(test);
        assert!(state.lock().unwrap().irq_calls.is_empty());
        vm.fd().register_irqfd(&trigger, gsi).unwrap();
    }

    #[test]
    fn test_intx_route_failure() {
        let vm = setup_vm_with_irqchip();
        let mut test = build_in(Arc::new(vm), mock_file(), mock_regions(None), true);
        test.state.lock().unwrap().fail_unmask = true;

        // A failure to route INTx is reported, and leaves INTx disabled on the host.
        let err = test
            .device
            .route_intx(crate::arch::GSI_LEGACY_START)
            .unwrap_err();
        assert!(
            matches!(err, VfioPciError::Intx(IntxError::Unmask(_))),
            "{err}"
        );
        assert_eq!(test.device.intx_gsi(), None);
        assert_eq!(read_config(&mut test.device, INTERRUPT_LINE) >> 8 & 0xff, 0);
        assert_eq!(
            test.state.lock().unwrap().irq_calls,
            [
                IrqCall::Enable {
                    index: VFIO_PCI_INTX_IRQ_INDEX,
                    start: 0,
                    count: 1
                },
                IrqCall::Unmask(VFIO_PCI_INTX_IRQ_INDEX),
                IrqCall::Disable(VFIO_PCI_INTX_IRQ_INDEX),
            ]
        );
    }

    fn msi_setup(device: &mut VfioPciDevice, messages_log2: u8) {
        // Address 0xfee00000, data 0x40, masking vector 1.
        write_config(device, MSI_CAP + 4, &0xfee0_0000u32.to_le_bytes());
        write_config(device, MSI_CAP + 8, &0u32.to_le_bytes());
        write_config(device, MSI_CAP + 12, &0x40u16.to_le_bytes());
        write_config(device, MSI_CAP + 16, &2u32.to_le_bytes());
        write_config(device, MSI_CAP + 2, &[1 | (messages_log2 << 4)]);
    }

    #[test]
    fn test_msi() {
        let mut test = default_device(true);
        let device = &mut test.device;

        msi_setup(device, 2);
        assert_eq!(
            test.state.lock().unwrap().irq_calls,
            vec![IrqCall::Enable {
                index: VFIO_PCI_MSI_IRQ_INDEX,
                start: 0,
                count: 4
            }]
        );
        let device = &mut test.device;
        // Read-only bits are preserved, writable ones reflect the guest configuration.
        assert_eq!(read_config(device, MSI_CAP) >> 16, 0x01a5);
        assert_eq!(read_config(device, MSI_CAP + 4), 0xfee0_0000);
        assert_eq!(read_config(device, MSI_CAP + 12), 0x40);
        assert_eq!(read_config(device, MSI_CAP + 16), 2);
        // Mask bits of unimplemented vectors are read-only.
        write_config(device, MSI_CAP + 16, &0xffff_ffffu32.to_le_bytes());
        assert_eq!(read_config(device, MSI_CAP + 16), 0xf);
        write_config(device, MSI_CAP + 16, &2u32.to_le_bytes());

        // A message sent while vector 1 is masked is pending; unmasked vectors never are.
        let msi = device.msi.as_ref().unwrap();
        msi.vector_event(1).write(1).unwrap();
        msi.vector_event(0).write(1).unwrap();
        assert_eq!(read_config(device, MSI_CAP + 20), 2);

        // Changing the address does not reprogram the host.
        write_config(device, MSI_CAP + 4, &0xfee0_1000u32.to_le_bytes());
        assert_eq!(test.state.lock().unwrap().irq_calls.len(), 1);

        // Changing the number of messages re-enables the index.
        let device = &mut test.device;
        write_config(device, MSI_CAP + 2, &[1 | (1 << 4)]);
        // Disabling MSI disables the index.
        write_config(device, MSI_CAP + 2, &[0]);
        assert_eq!(
            test.state.lock().unwrap().irq_calls[1..],
            [
                IrqCall::Disable(VFIO_PCI_MSI_IRQ_INDEX),
                IrqCall::Enable {
                    index: VFIO_PCI_MSI_IRQ_INDEX,
                    start: 0,
                    count: 2
                },
                IrqCall::Disable(VFIO_PCI_MSI_IRQ_INDEX),
            ]
        );
    }

    #[test]
    fn test_msi_partial_allocation() {
        let mut test = default_device(true);
        test.state.lock().unwrap().partial = Some(2);
        msi_setup(&mut test.device, 2);
        assert_eq!(
            test.state.lock().unwrap().irq_calls,
            vec![
                IrqCall::Enable {
                    index: VFIO_PCI_MSI_IRQ_INDEX,
                    start: 0,
                    count: 4
                },
                IrqCall::Enable {
                    index: VFIO_PCI_MSI_IRQ_INDEX,
                    start: 0,
                    count: 2
                },
            ]
        );
        assert_eq!(test.device.msi.as_ref().unwrap().host_vectors(), 2);
    }

    fn msix_write_entry(device: &mut VfioPciDevice, bar0: u64, index: u64, masked: bool) {
        let entry = MSIX_TABLE_OFFSET + index * 16;
        device.write_bar(bar0, entry, &0xfee0_0000u32.to_le_bytes());
        device.write_bar(bar0, entry + 4, &0u32.to_le_bytes());
        device.write_bar(
            bar0,
            entry + 8,
            &(0x30 + u32::try_from(index).unwrap()).to_le_bytes(),
        );
        device.write_bar(bar0, entry + 12, &u32::from(masked).to_le_bytes());
    }

    fn check_msix(dynamic: bool) {
        let mut test = default_device(dynamic);
        let placed = place_and_map(&mut test.device);
        let bar0 = placed["Bar(0)"];
        let device = &mut test.device;

        // Enabling MSI-X enables one host vector even with every entry masked.
        write_config(device, MSIX_CAP + 3, &[0x80]);
        assert_eq!(read_config(device, MSIX_CAP) >> 16, 0x8007);
        // Entry 0 unmasked: already covered. Entry 3 unmasked: the host vectors grow.
        msix_write_entry(device, bar0, 0, false);
        msix_write_entry(device, bar0, 3, false);
        let mut entry = [0u8; 8];
        device.read_bar(bar0, MSIX_TABLE_OFFSET + 3 * 16, &mut entry);
        assert_eq!(entry, [0, 0, 0xe0, 0xfe, 0, 0, 0, 0]);
        device.read_bar(bar0, MSIX_TABLE_OFFSET + 3 * 16 + 8, &mut entry);
        assert_eq!(entry, [0x33, 0, 0, 0, 0, 0, 0, 0]);

        let grow = if dynamic {
            vec![IrqCall::Enable {
                index: VFIO_PCI_MSIX_IRQ_INDEX,
                start: 1,
                count: 3,
            }]
        } else {
            vec![
                IrqCall::Disable(VFIO_PCI_MSIX_IRQ_INDEX),
                IrqCall::Enable {
                    index: VFIO_PCI_MSIX_IRQ_INDEX,
                    start: 0,
                    count: 4,
                },
            ]
        };
        let mut expected = vec![IrqCall::Enable {
            index: VFIO_PCI_MSIX_IRQ_INDEX,
            start: 0,
            count: 1,
        }];
        expected.extend(grow);
        assert_eq!(test.state.lock().unwrap().irq_calls, expected);

        let device = &mut test.device;
        // Function mask.
        write_config(device, MSIX_CAP + 3, &[0xc0]);
        assert_eq!(read_config(device, MSIX_CAP) >> 16, 0xc007);

        // PBA: vector 5 is pending in the physical PBA, vector 0 in its eventfd while masked
        // by the function mask, vector 3 is masked but has nothing pending.
        let msix = device.msix.as_ref().unwrap();
        msix.vector_event(0).write(1).unwrap();
        let mut pba = [0u8; 8];
        device.read_bar(bar0, MSIX_PBA_OFFSET, &mut pba);
        assert_eq!(u64::from_le_bytes(pba), (1 << 5) | 1);
        // Invalid accesses read all ones; the PBA is read-only.
        let mut short = [0u8; 2];
        device.read_bar(bar0, MSIX_PBA_OFFSET, &mut short);
        assert_eq!(short, [0xff, 0xff]);
        device.write_bar(bar0, MSIX_PBA_OFFSET, &[0; 8]);
        device.read_bar(bar0, MSIX_PBA_OFFSET, &mut pba);
        assert_eq!(u64::from_le_bytes(pba), (1 << 5) | 1);

        // Invalid table accesses.
        let mut misaligned = [0u8; 4];
        device.read_bar(bar0, MSIX_TABLE_OFFSET + 2, &mut misaligned);
        assert_eq!(misaligned, [0xff; 4]);
        // Past the table, the trapped page is an ordinary part of the BAR.
        let past_table = MSIX_TABLE_OFFSET + 16 * MSIX_ENTRIES as u64;
        put(&test.file, BAR0_OFFSET + past_table, &[0x77; 4]);
        device.read_bar(bar0, past_table, &mut misaligned);
        assert_eq!(misaligned, [0x77; 4]);

        // Enabling MSI disables MSI-X on the host first.
        msi_setup(device, 0);
        let calls = test.state.lock().unwrap().irq_calls.clone();
        assert_eq!(
            calls[calls.len() - 2..],
            [
                IrqCall::Disable(VFIO_PCI_MSIX_IRQ_INDEX),
                IrqCall::Enable {
                    index: VFIO_PCI_MSI_IRQ_INDEX,
                    start: 0,
                    count: 1
                }
            ]
        );
        // And enabling MSI-X again disables MSI.
        let device = &mut test.device;
        write_config(device, MSIX_CAP + 3, &[0]);
        write_config(device, MSIX_CAP + 3, &[0x80]);
        let calls = test.state.lock().unwrap().irq_calls.clone();
        assert_eq!(
            calls[calls.len() - 2..],
            [
                IrqCall::Disable(VFIO_PCI_MSI_IRQ_INDEX),
                IrqCall::Enable {
                    index: VFIO_PCI_MSIX_IRQ_INDEX,
                    start: 0,
                    count: 4
                }
            ]
        );
        // Disabling MSI-X disables the host index.
        let device = &mut test.device;
        write_config(device, MSIX_CAP + 3, &[0]);
        assert_eq!(
            test.state.lock().unwrap().irq_calls.last(),
            Some(&IrqCall::Disable(VFIO_PCI_MSIX_IRQ_INDEX))
        );
    }

    #[test]
    fn test_msix_dynamic() {
        check_msix(true);
    }

    #[test]
    fn test_msix_noresize() {
        check_msix(false);
    }

    #[test]
    fn test_msix_partial_allocation() {
        let mut test = default_device(true);
        let placed = place_and_map(&mut test.device);
        let bar0 = placed["Bar(0)"];
        for index in 0..4 {
            msix_write_entry(&mut test.device, bar0, index, false);
        }
        test.state.lock().unwrap().partial = Some(3);
        write_config(&mut test.device, MSIX_CAP + 3, &[0x80]);
        assert_eq!(
            test.state.lock().unwrap().irq_calls,
            vec![
                IrqCall::Enable {
                    index: VFIO_PCI_MSIX_IRQ_INDEX,
                    start: 0,
                    count: 4
                },
                IrqCall::Enable {
                    index: VFIO_PCI_MSIX_IRQ_INDEX,
                    start: 0,
                    count: 3
                },
            ]
        );
        assert_eq!(test.device.msix.as_ref().unwrap().host_vectors(), 3);
    }
}
