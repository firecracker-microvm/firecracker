// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use serde::{Deserialize, Serialize};
use vm_memory::GuestAddress;

/// Module for aarch64 related functionality.
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "aarch64")]
pub use aarch64::{
    arch_memory_regions, configure_system, get_kernel_start, initrd_load_addr,
    layout::CMDLINE_MAX_SIZE, layout::IRQ_BASE, layout::IRQ_MAX, layout::SYSTEM_MEM_SIZE,
    layout::SYSTEM_MEM_START, ConfigurationError, MMIO_MEM_SIZE, MMIO_MEM_START,
};

/// Module for x86_64 related functionality.
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::{
    arch_memory_regions, configure_system, get_kernel_start, initrd_load_addr, layout::APIC_ADDR,
    layout::CMDLINE_MAX_SIZE, layout::IOAPIC_ADDR, layout::IRQ_BASE, layout::IRQ_MAX,
    layout::SYSTEM_MEM_SIZE, layout::SYSTEM_MEM_START, ConfigurationError, MMIO_MEM_SIZE,
    MMIO_MEM_START,
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

/// Type for passing information about the initrd in the guest memory.
#[derive(Debug)]
pub struct InitrdConfig {
    /// Load address of initrd in guest memory
    pub address: crate::vstate::memory::GuestAddress,
    /// Size of initrd in guest memory
    pub size: usize,
}

/// Default (smallest) memory page size for the supported architectures.
pub const PAGE_SIZE: usize = 4096;

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Suported boot protocols for
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
