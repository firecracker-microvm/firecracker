// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kvm_ioctls::VmFd;
use vmm_sys_util::eventfd::EventFd;

use crate::logger::{IncMetric, METRICS, error};
use crate::pci::PciSBDF;
use crate::pci::msix::MsixTableEntry;
use crate::snapshot::Persist;
use crate::vstate::vm::KvmVm;

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
    /// MSI-X state size mismatch: {0}
    MsixStateSizeMismatch(String),
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
    /// Reference to the KvmVm object, which we'll need for interacting with the underlying KVM
    /// KvmVm file descriptor
    pub vm: Arc<KvmVm>,
    /// A list of all the MSI-X vectors
    pub vectors: Vec<MsixVector>,
}

impl MsixVectorGroup {
    /// Returns the number of vectors in this group
    pub fn num_vectors(&self) -> u16 {
        // It is safe to unwrap here. We are creating `MsixVectorGroup` objects through the
        // `KvmVm::create_msix_group` where the argument for the number of `vectors` is a `u16`.
        u16::try_from(self.vectors.len()).unwrap()
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

    /// Registers the configuration of a vector in the group in the VM.
    /// Note: this function doesn't set the GSI routes. Please do that separately, or use [update]/[update_batched].
    pub fn register(
        &self,
        index: usize,
        table_entry: &MsixTableEntry,
        pci_sbdf: PciSBDF,
    ) -> Result<(), InterruptError> {
        if let Some(vector) = self.vectors.get(index) {
            self.vm.register_msi(vector, table_entry, pci_sbdf)?;
            return Ok(());
        }

        Err(InterruptError::InvalidVectorIndex(index))
    }

    /// Update the MSI-X configuration for all vectors in the group
    pub fn update_batched(
        &self,
        msi_config: &[MsixTableEntry],
        pci_sbdf: PciSBDF,
    ) -> Result<(), InterruptError> {
        self.update_vectors(msi_config, &self.vectors, pci_sbdf)
    }

    /// Update the MSI-X configuration for a vector in the group
    pub fn update(
        &self,
        index: usize,
        table_entry: &MsixTableEntry,
        pci_sbdf: PciSBDF,
    ) -> Result<(), InterruptError> {
        if let Some(vector) = self.vectors.get(index) {
            self.update_vectors(
                std::slice::from_ref(table_entry),
                std::slice::from_ref(vector),
                pci_sbdf,
            )
        } else {
            Err(InterruptError::InvalidVectorIndex(index))
        }
    }

    /// Update the MSI-X configuration for the given vectors
    fn update_vectors(
        &self,
        table_entries: &[MsixTableEntry],
        vectors: &[MsixVector],
        pci_sbdf: PciSBDF,
    ) -> Result<(), InterruptError> {
        assert_eq!(table_entries.len(), vectors.len());

        METRICS.interrupts.config_updates.inc();

        // Disables masked vectors and update the config
        for (idx, vector) in vectors.iter().enumerate() {
            let table_entry = &table_entries[idx];
            if table_entry.masked() {
                vector.disable(&self.vm.common.fd)?;
            }
            self.vm.register_msi(vector, table_entry, pci_sbdf)?;
        }

        self.vm
            .set_gsi_routes()
            .map_err(|err| std::io::Error::other(format!("MSI-X update: {err}")))?;

        // Enables unmasked. Must be done after set_gsi_routes to avoid panic on kernel
        // which does not have commit a80ced6ea514 (KVM: SVM: fix panic on out-of-bounds guest IRQ).
        for (idx, vector) in vectors.iter().enumerate() {
            if !table_entries[idx].masked() {
                vector.enable(&self.vm.common.fd)?;
            }
        }

        Ok(())
    }
}

impl Drop for MsixVectorGroup {
    fn drop(&mut self) {
        let vmfd = &self.vm.common.fd;

        {
            let mut interrupts = self.vm.common.interrupts.lock().expect("Poisoned lock");
            for vector in &self.vectors {
                if let Err(e) = vector.disable(vmfd) {
                    error!("Failed to unregister irqfd for GSI {}: {e}", vector.gsi);
                }
                interrupts.remove(&vector.gsi);
            }
        }

        let mut allocator = self
            .vm
            .common
            .resource_allocator
            .lock()
            .expect("Poisoned lock");
        for vector in &self.vectors {
            // SAFETY: we allocated gsi from this allocator.
            allocator.gsi_msi_allocator.free_id(vector.gsi).unwrap();
        }
    }
}

impl<'a> Persist<'a> for MsixVectorGroup {
    type State = Vec<u32>;
    type ConstructorArgs = Arc<KvmVm>;
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

        {
            // Replay the GSI allocations rather than trusting the serialized allocator state.
            // This validates the snapshot is not malformed, containing doubly allocated GSI IDs
            let mut resource_allocator = constructor_args.resource_allocator();
            for gsi in state {
                resource_allocator.gsi_msi_allocator.allocate_id_at(*gsi)?;
                vectors.push(MsixVector::new(*gsi, false)?);
            }
        }

        Ok(MsixVectorGroup {
            vm: constructor_args,
            vectors,
        })
    }
}
