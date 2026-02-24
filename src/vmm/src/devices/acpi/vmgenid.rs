// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;

use acpi_tables::{Aml, aml};
use aws_lc_rs::error::Unspecified as RandError;
use aws_lc_rs::rand;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use vm_memory::{GuestAddress, GuestMemoryError};
use vm_superio::Trigger;
use vmm_sys_util::eventfd::EventFd;

use super::super::legacy::EventFdTrigger;
use crate::snapshot::Persist;
use crate::vstate::memory::{Bytes, GuestMemoryMmap};
use crate::vstate::resources::ResourceAllocator;

/// Bytes of memory we allocate for VMGenID device
pub const VMGENID_MEM_SIZE: u64 = 16;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmGenIdError {
    /// Could not create EventFd: {0}
    CreateEventFd(std::io::Error),
    /// Could not allocate GSI: {0}
    AllocateGsi(vm_allocator::Error),
    /// Could not allocate guest memory: {0}
    AllocateMemory(vm_allocator::Error),
    /// Could not write generation ID to guest memory: {0}
    WriteGuestMemory(#[from] GuestMemoryError),
    /// Could not notify guest: {0}
    NotifyGuest(std::io::Error),
}

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

impl VmGenId {
    /// Create a new Vm Generation Id device using an address in the guest for writing the
    /// generation ID and a GSI for sending device notifications.
    pub fn from_parts(guest_address: GuestAddress, gsi: u32) -> Result<Self, VmGenIdError> {
        debug!(
            "vmgenid: building VMGenID device. Address: {:#010x}. IRQ: {}",
            guest_address.0, gsi
        );
        let interrupt_evt = EventFdTrigger::new(
            EventFd::new(libc::EFD_NONBLOCK).map_err(VmGenIdError::CreateEventFd)?,
        );
        let gen_id = Self::make_genid();

        Ok(Self {
            gen_id,
            interrupt_evt,
            guest_address,
            gsi,
        })
    }

    /// Create a new VMGenID device
    ///
    /// Allocate memory and a GSI for sending notifications and build the device
    pub fn new(resource_allocator: &mut ResourceAllocator) -> Result<Self, VmGenIdError> {
        let gsi = resource_allocator
            .allocate_gsi_legacy(1)
            .map_err(VmGenIdError::AllocateGsi)?[0];
        // The generation ID needs to live in an 8-byte aligned buffer
        let addr = resource_allocator
            .allocate_system_memory(VMGENID_MEM_SIZE, 8, vm_allocator::AllocPolicy::LastMatch)
            .map_err(VmGenIdError::AllocateMemory)?;

        Self::from_parts(GuestAddress(addr), gsi)
    }

    // Create a 16-bytes random number
    fn make_genid() -> u128 {
        let mut gen_id_bytes = [0u8; 16];
        rand::fill(&mut gen_id_bytes).expect("vmgenid: could not create new generation ID");
        u128::from_le_bytes(gen_id_bytes)
    }

    /// Notify guest after snapshot restore
    ///
    /// This will only have effect if we have updated the generation ID in guest memory, i.e. when
    /// re-creating the device after snapshot resumption.
    pub fn do_post_restore(&self) -> Result<(), VmGenIdError> {
        self.interrupt_evt
            .trigger()
            .map_err(VmGenIdError::NotifyGuest)?;
        debug!("vmgenid: notifying guest about new generation ID");
        Ok(())
    }

    /// Attach the [`VmGenId`] device
    pub fn activate(&self, mem: &GuestMemoryMmap) -> Result<(), VmGenIdError> {
        debug!(
            "vmgenid: writing new generation ID to guest: {:#034x}",
            self.gen_id
        );
        mem.write_slice(&self.gen_id.to_le_bytes(), self.guest_address)
            .map_err(VmGenIdError::WriteGuestMemory)?;

        Ok(())
    }
}

/// Logic to save/restore the state of a VMGenID device

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct VMGenIDState {
    /// GSI used for VMGenID device
    pub gsi: u32,
    /// memory address of generation ID
    pub addr: u64,
}

impl<'a> Persist<'a> for VmGenId {
    type State = VMGenIDState;
    type ConstructorArgs = ();
    type Error = VmGenIdError;

    fn save(&self) -> Self::State {
        VMGenIDState {
            gsi: self.gsi,
            addr: self.guest_address.0,
        }
    }

    fn restore(_: Self::ConstructorArgs, state: &Self::State) -> Result<Self, Self::Error> {
        Self::from_parts(GuestAddress(state.addr), state.gsi)
    }
}

impl Aml for VmGenId {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) -> Result<(), aml::AmlError> {
        #[allow(clippy::cast_possible_truncation)]
        let addr_low = self.guest_address.0 as u32;
        let addr_high = (self.guest_address.0 >> 32) as u32;
        aml::Device::new(
            "_SB_.VGEN".try_into()?,
            vec![
                &aml::Name::new("_HID".try_into()?, &"FCVMGID")?,
                &aml::Name::new("_CID".try_into()?, &"VM_Gen_Counter")?,
                &aml::Name::new("_DDN".try_into()?, &"VM_Gen_Counter")?,
                &aml::Name::new(
                    "ADDR".try_into()?,
                    &aml::Package::new(vec![&addr_low, &addr_high]),
                )?,
            ],
        )
        .append_aml_bytes(v)
    }
}
