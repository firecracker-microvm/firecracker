// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vm_device::BusError;

use super::resources::ResourceAllocator;
use crate::devices::pci::PciSegment;

#[derive(Debug, Default)]
pub struct PciDevices {
    /// PCIe segment of the VMM, if PCI is enabled. We currently support a single PCIe segment.
    pub pci_segment: Option<PciSegment>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PciManagerError {
    /// Resource allocation error: {0}
    ResourceAllocation(#[from] vm_allocator::Error),
    /// Bus error: {0}
    Bus(#[from] BusError),
}

impl PciDevices {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn attach_pci_segment(
        &mut self,
        resource_allocator: &Arc<ResourceAllocator>,
    ) -> Result<(), PciManagerError> {
        // We only support a single PCIe segment. Calling this function twice is a Firecracker
        // internal error.
        assert!(self.pci_segment.is_none());

        // Currently we don't assign any IRQs to PCI devices. We will be using MSI-X interrupts
        // only.
        let pci_segment = PciSegment::new(0, resource_allocator, &[0u8; 32])?;
        self.pci_segment = Some(pci_segment);

        Ok(())
    }

    pub fn save(&self) -> PciDevicesState {
        PciDevicesState {
            pci_enabled: self.pci_segment.is_some(),
        }
    }

    pub fn restore(
        &mut self,
        state: &PciDevicesState,
        resource_allocator: &Arc<ResourceAllocator>,
    ) -> Result<(), PciManagerError> {
        if state.pci_enabled {
            self.attach_pci_segment(resource_allocator)?;
        }

        Ok(())
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PciDevicesState {
    pci_enabled: bool,
}
