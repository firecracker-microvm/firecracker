// Copyright © 2025 Computing Systems Laboratory (CSLab), ECE, NTUA. All rights reserved.
//
// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::Kvm;
use crate::arch::riscv64::aia::AiaState;
use crate::vstate::memory::GuestMemoryState;
use crate::vstate::vm::{VmCommon, VmError};

/// Structure representing the current architecture's understand of what a "virtual machine" is.
#[derive(Debug)]
pub struct ArchVm {
    /// Architecture independent parts of a vm.
    pub common: VmCommon,
    /// On riscv64 we need to keep around the fd obtained by creating the AIA device.
    irqchip_handle: Option<crate::arch::riscv64::aia::AIADevice>,
}

/// Error type for [`Vm::restore_state`]
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum ArchVmError {
    /// Error creating the global interrupt controller: {0}
    VmCreateAIA(crate::arch::riscv64::aia::AiaError),
    /// Failed to save the VM's AIA state: {0}
    SaveAia(crate::arch::riscv64::aia::AiaError),
    /// Failed to restore the VM's AIA state: {0}
    RestoreAia(crate::arch::riscv64::aia::AiaError),
}

impl ArchVm {
    /// Create a new `Vm` struct.
    pub fn new(kvm: &Kvm) -> Result<ArchVm, VmError> {
        let common = Self::create_common(kvm)?;
        Ok(ArchVm {
            common,
            irqchip_handle: None,
        })
    }

    /// Pre-vCPU creation setup.
    pub fn arch_pre_create_vcpus(&mut self, _: u8) -> Result<(), ArchVmError> {
        Ok(())
    }

    /// Post-vCPU creation setup.
    pub fn arch_post_create_vcpus(&mut self, nr_vcpus: u8) -> Result<(), ArchVmError> {
        self.setup_irqchip(nr_vcpus)
    }

    /// Creates the AIA (Advanced Interrupt Architecture) IRQchip.
    pub fn setup_irqchip(&mut self, vcpu_count: u8) -> Result<(), ArchVmError> {
        self.irqchip_handle = Some(
            crate::arch::riscv64::aia::AIADevice::create_aia(&self.fd(), vcpu_count.into())
                .map_err(ArchVmError::VmCreateAIA)?,
        );
        Ok(())
    }

    /// Gets a reference to the irqchip of the VM.
    pub fn get_irqchip(&self) -> &crate::arch::riscv64::aia::AIADevice {
        self.irqchip_handle.as_ref().expect("IRQ chip not set")
    }

    /// Saves and returns the Kvm Vm state.
    pub fn save_state(&self) -> Result<VmState, ArchVmError> {
        unimplemented!()
    }

    /// Restore the KVM VM state
    pub fn restore_state(&mut self) -> Result<(), ArchVmError> {
        unimplemented!()
    }
}

/// Structure holding an general specific VM state.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VmState {
    /// Guest memory state.
    pub memory: GuestMemoryState,
    /// AIA state.
    pub aia: AiaState,
}
