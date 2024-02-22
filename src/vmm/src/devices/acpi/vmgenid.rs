// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use acpi_tables::{aml, Aml};
use aws_lc_rs::error::Unspecified as RandError;
use aws_lc_rs::rand;
use log::{debug, error};
use utils::eventfd::EventFd;
use vm_memory::{GuestAddress, GuestMemoryError};
use vm_superio::Trigger;

use super::super::legacy::EventFdTrigger;
use crate::vstate::memory::{Bytes, GuestMemoryMmap};

/// Virtual Machine Generation ID device
///
/// VMGenID is an emulated device which exposes to the guest a 128-bit cryptographically random
/// integer value which will be different every time the virtual machine executes from a different
/// configuration file. In Firecracker terms this translates to a different value every time a new
/// microVM is created, either from scratch or restored from a snapshot.
///
/// The device specification can be found here: https://go.microsoft.com/fwlink/?LinkId=260709
#[derive(Debug)]
pub struct VmGenId {
    /// Current generation ID of guest VM
    pub gen_id: u128,
    /// Interrupt line for notifying the device about generation ID changes
    pub interrupt_evt: EventFdTrigger,
    /// Guest physical address where VMGenID data lives.
    pub guest_address: GuestAddress,
    /// GSI number for the device
    pub gsi: u32,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmGenIdError {
    /// Error with VMGenID interrupt: {0}
    Interrupt(#[from] std::io::Error),
    /// Error accessing VMGenID memory: {0}
    GuestMemory(#[from] GuestMemoryError),
    /// Create generation ID error: {0}
    GenerationId(#[from] RandError),
}

impl VmGenId {
    /// Create a new VmGenerationId device at the given guest address with a given generation ID
    pub fn new(
        guest_address: GuestAddress,
        gsi: u32,
        mem: &GuestMemoryMmap,
    ) -> Result<Self, VmGenIdError> {
        debug!(
            "vmgenid: building VMGenID device. Address: {:#010x}. IRQ: {}",
            guest_address.0, gsi
        );
        let interrupt_evt = EventFdTrigger::new(EventFd::new(libc::EFD_NONBLOCK)?);
        let gen_id = Self::make_genid()?;

        // Write generation ID in guest memory
        debug!(
            "vmgenid: writing new generation ID to guest: {:#034x}",
            gen_id
        );
        mem.write_slice(&gen_id.to_le_bytes(), guest_address)
            .inspect_err(|err| error!("vmgenid: could not write generation ID to guest: {err}"))?;

        Ok(Self {
            gen_id,
            interrupt_evt,
            guest_address,
            gsi,
        })
    }

    // Create a 16-bytes random number
    fn make_genid() -> Result<u128, RandError> {
        let mut gen_id_bytes = [0u8; 16];
        rand::fill(&mut gen_id_bytes)
            .inspect_err(|err| error!("vmgenid: could not create new generation ID: {err}"))?;
        Ok(u128::from_le_bytes(gen_id_bytes))
    }

    /// Send an ACPI notification to guest device.
    ///
    /// This will only have effect if we have updated the generation ID in guest memory, i.e. when
    /// re-creating the device after snapshot resumption.
    pub fn notify_guest(&mut self) -> Result<(), VmGenIdError> {
        self.interrupt_evt
            .trigger()
            .inspect_err(|err| error!("vmgenid: could not send guest notification: {err}"))?;
        debug!("vmgenid: notifying guest about new generation ID");
        Ok(())
    }
}

impl Aml for VmGenId {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) {
        #[allow(clippy::cast_possible_truncation)]
        let addr_low = self.guest_address.0 as u32;
        let addr_high = (self.guest_address.0 >> 32) as u32;
        aml::Device::new(
            "_SB_.VGEN".into(),
            vec![
                &aml::Name::new("_HID".into(), &"FCVMGID"),
                &aml::Name::new("_CID".into(), &"VM_Gen_Counter"),
                &aml::Name::new("_DDN".into(), &"VM_Gen_Counter"),
                &aml::Name::new(
                    "ADDR".into(),
                    &aml::Package::new(vec![&addr_low, &addr_high]),
                ),
            ],
        )
        .append_aml_bytes(v)
    }
}
