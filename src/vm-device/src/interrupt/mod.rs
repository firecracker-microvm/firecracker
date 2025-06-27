// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright (C) 2019 Alibaba Cloud. All rights reserved.
// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

//! Traits and Structs to manage interrupt sources for devices.
//!
//! In system programming, an interrupt is a signal to the processor emitted by hardware or
//! software indicating an event that needs immediate attention. An interrupt alerts the processor
//! to a high-priority condition requiring the interruption of the current code the processor is
//! executing. The processor responds by suspending its current activities, saving its state, and
//! executing a function called an interrupt handler (or an interrupt service routine, ISR) to deal
//! with the event. This interruption is temporary, and, after the interrupt handler finishes,
//! unless handling the interrupt has emitted a fatal error, the processor resumes normal
//! activities.
//!
//! Hardware interrupts are used by devices to communicate that they require attention from the
//! operating system, or a bare-metal program running on the CPU if there are no OSes. The act of
//! initiating a hardware interrupt is referred to as an interrupt request (IRQ). Different devices
//! are usually associated with different interrupts using a unique value associated with each
//! interrupt. This makes it possible to know which hardware device caused which interrupts.
//! These interrupt values are often called IRQ lines, or just interrupt lines.
//!
//! Nowadays, IRQ lines is not the only mechanism to deliver device interrupts to processors.
//! MSI [(Message Signaled Interrupt)](https://en.wikipedia.org/wiki/Message_Signaled_Interrupts)
//! is another commonly used alternative in-band method of signaling an interrupt, using special
//! in-band messages to replace traditional out-of-band assertion of dedicated interrupt lines.
//! While more complex to implement in a device, message signaled interrupts have some significant
//! advantages over pin-based out-of-band interrupt signaling. Message signaled interrupts are
//! supported in PCI bus since its version 2.2, and in later available PCI Express bus. Some
//! non-PCI architectures also use message signaled interrupts.
//!
//! While IRQ is a term commonly used by Operating Systems when dealing with hardware
//! interrupts, the IRQ numbers managed by OSes are independent of the ones managed by VMM.
//! For simplicity sake, the term `Interrupt Source` is used instead of IRQ to represent both
//! pin-based interrupts and MSI interrupts.
//!
//! A device may support multiple types of interrupts, and each type of interrupt may support one
//! or multiple interrupt sources. For example, a PCI device may support:
//! * Legacy Irq: exactly one interrupt source.
//! * PCI MSI Irq: 1,2,4,8,16,32 interrupt sources.
//! * PCI MSIx Irq: 2^n(n=0-11) interrupt sources.
//!
//! A distinct Interrupt Source Identifier (ISID) will be assigned to each interrupt source.
//! An ID allocator will be used to allocate and free Interrupt Source Identifiers for devices.
//! To decouple the vm-device crate from the ID allocator, the vm-device crate doesn't take the
//! responsibility to allocate/free Interrupt Source IDs but only makes use of assigned IDs.
//!
//! The overall flow to deal with interrupts is:
//! * The VMM creates an interrupt manager
//! * The VMM creates a device manager, passing on an reference to the interrupt manager
//! * The device manager passes on an reference to the interrupt manager to all registered devices
//! * The guest kernel loads drivers for virtual devices
//! * The guest device driver determines the type and number of interrupts needed, and update the
//!   device configuration
//! * The virtual device backend requests the interrupt manager to create an interrupt group
//!   according to guest configuration information

use std::sync::Arc;

use vmm_sys_util::eventfd::EventFd;

/// Reuse std::io::Result to simplify interoperability among crates.
pub type Result<T> = std::io::Result<T>;

/// Data type to store an interrupt source identifier.
pub type InterruptIndex = u32;

/// Configuration data for legacy interrupts.
///
/// On x86 platforms, legacy interrupts means those interrupts routed through PICs or IOAPICs.
#[derive(Copy, Clone, Debug)]
pub struct LegacyIrqSourceConfig {
    pub irqchip: u32,
    pub pin: u32,
}

/// Configuration data for MSI/MSI-X interrupts.
///
/// On x86 platforms, these interrupts are vectors delivered directly to the LAPIC.
#[derive(Copy, Clone, Debug, Default)]
pub struct MsiIrqSourceConfig {
    /// High address to delivery message signaled interrupt.
    pub high_addr: u32,
    /// Low address to delivery message signaled interrupt.
    pub low_addr: u32,
    /// Data to write to delivery message signaled interrupt.
    pub data: u32,
    /// Unique ID of the device to delivery message signaled interrupt.
    pub devid: u32,
}

/// Configuration data for an interrupt source.
#[derive(Copy, Clone, Debug)]
pub enum InterruptSourceConfig {
    /// Configuration data for Legacy interrupts.
    LegacyIrq(LegacyIrqSourceConfig),
    /// Configuration data for PciMsi, PciMsix and generic MSI interrupts.
    MsiIrq(MsiIrqSourceConfig),
}

/// Configuration data for legacy, pin based interrupt groups.
///
/// A legacy interrupt group only takes one irq number as its configuration.
#[derive(Copy, Clone, Debug)]
pub struct LegacyIrqGroupConfig {
    /// Legacy irq number.
    pub irq: InterruptIndex,
}

/// Configuration data for MSI/MSI-X interrupt groups
///
/// MSI/MSI-X interrupt groups are basically a set of vectors.
#[derive(Copy, Clone, Debug)]
pub struct MsiIrqGroupConfig {
    /// First index of the MSI/MSI-X interrupt vectors
    pub base: InterruptIndex,
    /// Number of vectors in the MSI/MSI-X group.
    pub count: InterruptIndex,
}

/// Trait to manage interrupt sources for virtual device backends.
///
/// The InterruptManager implementations should protect itself from concurrent accesses internally,
/// so it could be invoked from multi-threaded context.
pub trait InterruptManager: Send + Sync {
    type GroupConfig;

    /// Create an [InterruptSourceGroup](trait.InterruptSourceGroup.html) object to manage
    /// interrupt sources for a virtual device
    ///
    /// An [InterruptSourceGroup](trait.InterruptSourceGroup.html) object manages all interrupt
    /// sources of the same type for a virtual device.
    ///
    /// # Arguments
    /// * interrupt_type: type of interrupt source.
    /// * base: base Interrupt Source ID to be managed by the group object.
    /// * count: number of Interrupt Sources to be managed by the group object.
    fn create_group(&self, config: Self::GroupConfig) -> Result<Arc<dyn InterruptSourceGroup>>;

    /// Destroy an [InterruptSourceGroup](trait.InterruptSourceGroup.html) object created by
    /// [create_group()](trait.InterruptManager.html#tymethod.create_group).
    ///
    /// Assume the caller takes the responsibility to disable all interrupt sources of the group
    /// before calling destroy_group(). This assumption helps to simplify InterruptSourceGroup
    /// implementations.
    fn destroy_group(&self, group: Arc<dyn InterruptSourceGroup>) -> Result<()>;
}

pub trait InterruptSourceGroup: Send + Sync {
    /// Enable the interrupt sources in the group to generate interrupts.
    fn enable(&self) -> Result<()> {
        // Not all interrupt sources can be enabled.
        // To accommodate this, we can have a no-op here.
        Ok(())
    }

    /// Disable the interrupt sources in the group to generate interrupts.
    fn disable(&self) -> Result<()> {
        // Not all interrupt sources can be disabled.
        // To accommodate this, we can have a no-op here.
        Ok(())
    }

    /// Inject an interrupt from this interrupt source into the guest.
    fn trigger(&self, index: InterruptIndex) -> Result<()>;

    /// Returns an interrupt notifier from this interrupt.
    ///
    /// An interrupt notifier allows for external components and processes
    /// to inject interrupts into a guest, by writing to the file returned
    /// by this method.
    #[allow(unused_variables)]
    fn notifier(&self, index: InterruptIndex) -> Option<&EventFd>;

    /// Update the interrupt source group configuration.
    ///
    /// # Arguments
    /// * index: sub-index into the group.
    /// * config: configuration data for the interrupt source.
    /// * masked: if the interrupt is masked
    /// * set_gsi: whether update the GSI routing table.
    fn update(
        &self,
        index: InterruptIndex,
        config: InterruptSourceConfig,
        masked: bool,
        set_gsi: bool,
    ) -> Result<()>;

    /// Set the interrupt group GSI routing table.
    fn set_gsi(&self) -> Result<()>;
}
