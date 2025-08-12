// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::LazyLock;

use log::warn;
use serde::{Deserialize, Serialize};
use vm_memory::GuestAddress;

/// Module for aarch64 related functionality.
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::kvm::{Kvm, KvmArchError, OptionalCapabilities};
#[cfg(target_arch = "aarch64")]
pub use aarch64::vcpu::*;
#[cfg(target_arch = "aarch64")]
pub use aarch64::vm::{ArchVm, ArchVmError, VmState};
#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    ConfigurationError, arch_memory_regions, configure_system_for_boot, get_kernel_start,
    initrd_load_addr, layout::BOOT_DEVICE_MEM_START, layout::CMDLINE_MAX_SIZE,
    layout::GSI_LEGACY_END, layout::GSI_LEGACY_NUM, layout::GSI_LEGACY_START, layout::GSI_MSI_END,
    layout::GSI_MSI_NUM, layout::GSI_MSI_START, layout::MEM_32BIT_DEVICES_SIZE,
    layout::MEM_32BIT_DEVICES_START, layout::MEM_64BIT_DEVICES_SIZE,
    layout::MEM_64BIT_DEVICES_START, layout::MMIO32_MEM_SIZE, layout::MMIO32_MEM_START,
    layout::PCI_MMCONFIG_SIZE, layout::PCI_MMCONFIG_START,
    layout::PCI_MMIO_CONFIG_SIZE_PER_SEGMENT, layout::RTC_MEM_START, layout::SERIAL_MEM_START,
    layout::SPI_START, layout::SYSTEM_MEM_SIZE, layout::SYSTEM_MEM_START, load_kernel,
};

/// Module for x86_64 related functionality.
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::kvm::{Kvm, KvmArchError};
#[cfg(target_arch = "x86_64")]
pub use x86_64::vcpu::*;
#[cfg(target_arch = "x86_64")]
pub use x86_64::vm::{ArchVm, ArchVmError, VmState};

#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::{
    ConfigurationError, arch_memory_regions, configure_system_for_boot, get_kernel_start,
    initrd_load_addr, layout::APIC_ADDR, layout::BOOT_DEVICE_MEM_START, layout::CMDLINE_MAX_SIZE,
    layout::GSI_LEGACY_END, layout::GSI_LEGACY_NUM, layout::GSI_LEGACY_START, layout::GSI_MSI_END,
    layout::GSI_MSI_NUM, layout::GSI_MSI_START, layout::IOAPIC_ADDR,
    layout::MEM_32BIT_DEVICES_SIZE, layout::MEM_32BIT_DEVICES_START,
    layout::MEM_64BIT_DEVICES_SIZE, layout::MEM_64BIT_DEVICES_START, layout::MMIO32_MEM_SIZE,
    layout::MMIO32_MEM_START, layout::PCI_MMCONFIG_SIZE, layout::PCI_MMCONFIG_START,
    layout::PCI_MMIO_CONFIG_SIZE_PER_SEGMENT, layout::SYSTEM_MEM_SIZE, layout::SYSTEM_MEM_START,
    load_kernel,
};

/// Types of devices that can get attached to this platform.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Copy, Serialize, Deserialize)]
pub enum DeviceType {
    /// Device Type: Virtio.
    Virtio(u32),
    /// Device Type: Serial.
    #[cfg(target_arch = "aarch64")]
    Serial,
    /// Device Type: RTC.
    #[cfg(target_arch = "aarch64")]
    Rtc,
    /// Device Type: BootTimer.
    BootTimer,
}

/// Default page size for the guest OS.
pub const GUEST_PAGE_SIZE: usize = 4096;

/// Get the size of the host page size.
pub fn host_page_size() -> usize {
    /// Default page size for the host OS.
    static PAGE_SIZE: LazyLock<usize> = LazyLock::new(|| {
        // # Safety: Value always valid
        let r = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(r).unwrap_or_else(|_| {
            warn!("Could not get host page size with sysconf, assuming default 4K host pages");
            4096
        })
    });

    *PAGE_SIZE
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Supported boot protocols for
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum BootProtocol {
    /// Linux 64-bit boot protocol
    LinuxBoot,
    #[cfg(target_arch = "x86_64")]
    /// PVH boot protocol (x86/HVM direct boot ABI)
    PvhBoot,
}

impl fmt::Display for BootProtocol {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match self {
            BootProtocol::LinuxBoot => write!(f, "Linux 64-bit boot protocol"),
            #[cfg(target_arch = "x86_64")]
            BootProtocol::PvhBoot => write!(f, "PVH boot protocol"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
/// Specifies the entry point address where the guest must start
/// executing code, as well as which boot protocol is to be used
/// to configure the guest initial state.
pub struct EntryPoint {
    /// Address in guest memory where the guest must start execution
    pub entry_addr: GuestAddress,
    /// Specifies which boot protocol to use
    pub protocol: BootProtocol,
}

/// Adds in [`regions`] the valid memory regions suitable for RAM taking into account a gap in the
/// available address space and returns the remaining region (if any) past this gap
fn arch_memory_regions_with_gap(
    regions: &mut Vec<(GuestAddress, usize)>,
    region_start: usize,
    region_size: usize,
    gap_start: usize,
    gap_size: usize,
) -> Option<(usize, usize)> {
    // 0-sized gaps don't really make sense. We should never receive such a gap.
    assert!(gap_size > 0);

    let first_addr_past_gap = gap_start + gap_size;
    match (region_start + region_size).checked_sub(gap_start) {
        // case0: region fits all before gap
        None | Some(0) => {
            regions.push((GuestAddress(region_start as u64), region_size));
            None
        }
        // case1: region starts before the gap and goes past it
        Some(remaining) if region_start < gap_start => {
            regions.push((GuestAddress(region_start as u64), gap_start - region_start));
            Some((first_addr_past_gap, remaining))
        }
        // case2: region starts past the gap
        Some(_) => Some((first_addr_past_gap.max(region_start), region_size)),
    }
}
