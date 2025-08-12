// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use vmm_sys_util::eventfd::EventFd;

/// MMIO transport for VirtIO devices
pub mod mmio;
/// PCI transport for VirtIO devices
pub mod pci;

/// Represents the types of interrupts used by VirtIO devices
#[derive(Debug, Clone)]
pub enum VirtioInterruptType {
    /// Interrupt for VirtIO configuration changes
    Config,
    /// Interrupts for new events in a queue.
    Queue(u16),
}

/// API of interrupt types used by VirtIO devices
pub trait VirtioInterrupt: std::fmt::Debug + Send + Sync {
    /// Trigger a VirtIO interrupt.
    fn trigger(&self, interrupt_type: VirtioInterruptType) -> Result<(), std::io::Error>;

    /// Trigger multiple Virtio interrupts for selected queues.
    /// The caller needs to ensure that [`queues`] does not include duplicate entries to
    /// avoid sending multiple interrupts for the same queue.
    /// This is to allow sending a single interrupt for implementations that don't
    /// distinguish different queues, like IrqTrigger, instead of sending multiple same
    /// interrupts.
    fn trigger_queues(&self, queues: &[u16]) -> Result<(), std::io::Error> {
        queues
            .iter()
            .try_for_each(|&qidx| self.trigger(VirtioInterruptType::Queue(qidx)))
    }

    /// Get the `EventFd` (if any) that backs the underlying interrupt.
    fn notifier(&self, _interrupt_type: VirtioInterruptType) -> Option<&EventFd> {
        None
    }

    /// Get the current device interrupt status.
    fn status(&self) -> Arc<AtomicU32>;

    /// Returns true if there is any pending interrupt
    #[cfg(test)]
    fn has_pending_interrupt(&self, interrupt_type: VirtioInterruptType) -> bool;
}
