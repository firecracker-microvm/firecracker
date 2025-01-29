// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use crate::arch::aarch64::gic::GicState;
use crate::vstate::vm::VmError;
use crate::Vm;

/// Error type for [`Vm::restore_state`]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum RestoreStateError {
    /// {0}
    GicError(crate::arch::aarch64::gic::GicError),
    /// {0}
    VmError(VmError),
}

impl Vm {
    /// Creates the GIC (Global Interrupt Controller).
    pub fn setup_irqchip(&mut self, vcpu_count: u8) -> Result<(), VmError> {
        self.irqchip_handle = Some(
            crate::arch::aarch64::gic::create_gic(&self.fd, vcpu_count.into(), None)
                .map_err(VmError::VmCreateGIC)?,
        );
        Ok(())
    }

    /// Gets a reference to the irqchip of the VM.
    pub fn get_irqchip(&self) -> &crate::arch::aarch64::gic::GICDevice {
        self.irqchip_handle.as_ref().expect("IRQ chip not set")
    }

    /// Saves and returns the Kvm Vm state.
    pub fn save_state(&self, mpidrs: &[u64]) -> Result<crate::vstate::vm::VmState, VmError> {
        Ok(crate::vstate::vm::VmState {
            gic: self
                .get_irqchip()
                .save_device(mpidrs)
                .map_err(VmError::SaveGic)?,
        })
    }

    /// Restore the KVM VM state
    ///
    /// # Errors
    ///
    /// When [`crate::arch::aarch64::gic::GICDevice::restore_device`] errors.
    pub fn restore_state(
        &mut self,
        mpidrs: &[u64],
        state: &crate::vstate::vm::VmState,
    ) -> Result<(), RestoreStateError> {
        self.get_irqchip()
            .restore_device(mpidrs, &state.gic)
            .map_err(RestoreStateError::GicError)?;
        Ok(())
    }
}

/// Structure holding an general specific VM state.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VmState {
    /// GIC state.
    pub gic: GicState,
}
