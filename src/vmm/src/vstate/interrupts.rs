// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kvm_ioctls::VmFd;
use vmm_sys_util::eventfd::EventFd;

use crate::Vm;
use crate::logger::{IncMetric, METRICS};
use crate::snapshot::Persist;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Errors related with Firecracker interrupts
pub enum InterruptError {
    /// Error allocating resources: {0}
    Allocator(#[from] vm_allocator::Error),
    /// IO error: {0}
    Io(#[from] std::io::Error),
    /// FamStruct error: {0}
    FamStruct(#[from] vmm_sys_util::fam::Error),
    /// KVM error: {0}
    Kvm(#[from] kvm_ioctls::Error),
    /// Invalid vector index: {0}
    InvalidVectorIndex(usize),
}

/// Configuration data for an MSI-X interrupt.
#[derive(Copy, Clone, Debug, Default)]
pub struct MsixVectorConfig {
    /// High address to delivery message signaled interrupt.
    pub high_addr: u32,
    /// Low address to delivery message signaled interrupt.
    pub low_addr: u32,
    /// Data to write to delivery message signaled interrupt.
    pub data: u32,
    /// Unique ID of the device to delivery message signaled interrupt.
    pub devid: u32,
}

/// Type that describes an allocated interrupt
#[derive(Debug)]
pub struct MsixVector {
    /// GSI used for this vector
    pub gsi: u32,
    /// EventFd used for this vector
    pub event_fd: EventFd,
    /// Flag determining whether the vector is enabled
    pub enabled: AtomicBool,
}

impl MsixVector {
    /// Create a new [`MsixVector`] of a particular type
    pub fn new(gsi: u32, enabled: bool) -> Result<MsixVector, InterruptError> {
        Ok(MsixVector {
            gsi,
            event_fd: EventFd::new(libc::EFD_NONBLOCK)?,
            enabled: AtomicBool::new(enabled),
        })
    }
}

impl MsixVector {
    /// Enable vector
    pub fn enable(&self, vmfd: &VmFd) -> Result<(), InterruptError> {
        if !self.enabled.load(Ordering::Acquire) {
            vmfd.register_irqfd(&self.event_fd, self.gsi)?;
            self.enabled.store(true, Ordering::Release);
        }

        Ok(())
    }

    /// Disable vector
    pub fn disable(&self, vmfd: &VmFd) -> Result<(), InterruptError> {
        if self.enabled.load(Ordering::Acquire) {
            vmfd.unregister_irqfd(&self.event_fd, self.gsi)?;
            self.enabled.store(false, Ordering::Release);
        }

        Ok(())
    }
}

#[derive(Debug)]
/// MSI interrupts created for a VirtIO device
pub struct MsixVectorGroup {
    /// Reference to the Vm object, which we'll need for interacting with the underlying KVM Vm
    /// file descriptor
    pub vm: Arc<Vm>,
    /// A list of all the MSI-X vectors
    pub vectors: Vec<MsixVector>,
}

impl MsixVectorGroup {
    /// Returns the number of vectors in this group
    pub fn num_vectors(&self) -> u16 {
        // It is safe to unwrap here. We are creating `MsixVectorGroup` objects through the
        // `Vm::create_msix_group` where the argument for the number of `vectors` is a `u16`.
        u16::try_from(self.vectors.len()).unwrap()
    }

    /// Enable the MSI-X vector group
    pub fn enable(&self) -> Result<(), InterruptError> {
        for route in &self.vectors {
            route.enable(&self.vm.common.fd)?;
        }

        Ok(())
    }

    /// Disable the MSI-X vector group
    pub fn disable(&self) -> Result<(), InterruptError> {
        for route in &self.vectors {
            route.disable(&self.vm.common.fd)?;
        }

        Ok(())
    }

    /// Trigger an interrupt for a vector in the group
    pub fn trigger(&self, index: usize) -> Result<(), InterruptError> {
        self.notifier(index)
            .ok_or(InterruptError::InvalidVectorIndex(index))?
            .write(1)?;
        METRICS.interrupts.triggers.inc();
        Ok(())
    }

    /// Get a referece to the underlying `EventFd` used to trigger interrupts for a vector in the
    /// group
    pub fn notifier(&self, index: usize) -> Option<&EventFd> {
        self.vectors.get(index).map(|route| &route.event_fd)
    }

    /// Update the MSI-X configuration for a vector in the group
    pub fn update(
        &self,
        index: usize,
        msi_config: MsixVectorConfig,
        masked: bool,
        set_gsi: bool,
    ) -> Result<(), InterruptError> {
        if let Some(vector) = self.vectors.get(index) {
            METRICS.interrupts.config_updates.inc();
            // When an interrupt is masked the GSI will not be passed to KVM through
            // KVM_SET_GSI_ROUTING. So, call [`disable()`] to unregister the interrupt file
            // descriptor before passing the interrupt routes to KVM
            if masked {
                vector.disable(&self.vm.common.fd)?;
            }

            self.vm.register_msi(vector, masked, msi_config)?;
            if set_gsi {
                self.vm
                    .set_gsi_routes()
                    .map_err(|err| std::io::Error::other(format!("MSI-X update: {err}")))?
            }

            // Assign KVM_IRQFD after KVM_SET_GSI_ROUTING to avoid
            // panic on kernel which does not have commit a80ced6ea514
            // (KVM: SVM: fix panic on out-of-bounds guest IRQ).
            if !masked {
                vector.enable(&self.vm.common.fd)?;
            }

            return Ok(());
        }

        Err(InterruptError::InvalidVectorIndex(index))
    }
}

impl<'a> Persist<'a> for MsixVectorGroup {
    type State = Vec<u32>;
    type ConstructorArgs = Arc<Vm>;
    type Error = InterruptError;

    fn save(&self) -> Self::State {
        // We don't save the "enabled" state of the MSI interrupt. PCI devices store the MSI-X
        // configuration and make sure that the vector is enabled during the restore path if it was
        // initially enabled
        self.vectors.iter().map(|route| route.gsi).collect()
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let mut vectors = Vec::with_capacity(state.len());

        for gsi in state {
            vectors.push(MsixVector::new(*gsi, false)?);
        }

        Ok(MsixVectorGroup {
            vm: constructor_args,
            vectors,
        })
    }
}
