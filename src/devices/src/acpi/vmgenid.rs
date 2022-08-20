// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use acpi::aml::{Aml, Device, Name, Package, Scope};
use logger::debug;
use std::fmt::{Display, Formatter};
use vm_memory::{Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};
use vm_superio::Trigger;

use crate::{legacy::EventFdTrigger, BusDevice};

/// Virtual Machine Generation ID device (VMGenID)
///
/// VMGenID is an emulated device which exposes to the guest a 128-bit cryptographically random
/// integer value identifier that will be different every time the virtual machine executes from a
/// different configuration file. In terms of Firecracker, this translates to different values,
/// every time a new microVM is created either from scratch or restored from a snapshot.
///
/// The specification can be found here: https://go.microsoft.com/fwlink/?LinkId=260709
pub struct VMGenID {
    /// Current generation ID of guest VM
    gen_id: u128,
    /// Guest physical address where VMGenID data live.
    /// The address will be provided by the MMIO device manager
    guest_addr: GuestAddress,
    ///  to let the guest know there's a new generation ID
    interrupt_evt: EventFdTrigger,
}

#[derive(Debug)]
pub enum Error {
    /// Could not create EventFd handler
    EventFd(std::io::Error),
    /// Error while writing to guest memory
    GuestMemory(GuestMemoryError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Error::EventFd(err) => write!(
                f,
                "Error while creating Event File Descriptor. Error {}",
                err
            ),
            Error::GuestMemory(err) => write!(f, "Error while writing to guest. Error {}", err),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::EventFd(err)
    }
}

impl From<GuestMemoryError> for Error {
    fn from(err: GuestMemoryError) -> Self {
        Error::GuestMemory(err)
    }
}

type Result<T> = std::result::Result<T, Error>;

impl VMGenID {
    pub fn new(
        gen_id: u128,
        interrupt_evt: EventFdTrigger,
        guest_addr: GuestAddress,
    ) -> Result<Self> {
        Ok(VMGenID {
            gen_id,
            guest_addr,
            interrupt_evt,
        })
    }

    /// Set generation id
    pub fn update_generation_id(&mut self, new_gen_id: u128) {
        self.gen_id = new_gen_id;
    }

    /// Write generation ID to guest
    pub fn write_to_guest(&self, mem: &GuestMemoryMmap) -> Result<()> {
        debug!(
            "Writing VM Generation ID {}({:?}) to guest at address {:#04x}",
            self.gen_id,
            self.gen_id.to_le_bytes(),
            self.guest_addr.0
        );
        mem.write_slice(&self.gen_id.to_le_bytes(), self.guest_addr)?;
        Ok(())
    }

    /// Notify guest about a change in the Generation ID
    pub fn notify(&self) -> Result<()> {
        self.interrupt_evt.trigger()?;
        Ok(())
    }
}

impl Aml for VMGenID {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) {
        let addr_low = self.guest_addr.0 as u32;
        let addr_high = (self.guest_addr.0 >> 32) as u32;
        Scope::new(
            "_SB_".into(),
            vec![&Device::new(
                "VGEN".into(),
                vec![
                    &Name::new("_HID".into(), &"FCVMVGID"),
                    &Name::new("_CID".into(), &"VM_Gen_Counter"),
                    &Name::new("_DDN".into(), &"VM_Gen_Counter"),
                    &Name::new("ADDR".into(), &Package::new(vec![&addr_low, &addr_high])),
                ],
            )],
        )
        .append_aml_bytes(v);
    }
}

impl BusDevice for VMGenID {}
