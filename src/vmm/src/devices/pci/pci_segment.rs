// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// Copyright © 2019 - 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//

use std::sync::{Arc, Mutex};

#[cfg(target_arch = "x86_64")]
use acpi_tables::{Aml, aml};
use log::info;
#[cfg(target_arch = "x86_64")]
use pci::{PCI_CONFIG_IO_PORT, PCI_CONFIG_IO_PORT_SIZE, PciConfigIo};
use pci::{PciBdf, PciBus, PciConfigMmio, PciRoot, PciRootError};
use uuid::Uuid;
use vm_allocator::AddressAllocator;
use vm_device::{BusDeviceSync, BusError};

use crate::arch::{ArchVm as Vm, PCI_MMCONFIG_START, PCI_MMIO_CONFIG_SIZE_PER_SEGMENT};
use crate::vstate::resources::ResourceAllocator;

pub struct PciSegment {
    pub(crate) id: u16,
    pub(crate) pci_bus: Arc<Mutex<PciBus>>,
    pub(crate) pci_config_mmio: Arc<Mutex<PciConfigMmio>>,
    pub(crate) mmio_config_address: u64,
    pub(crate) proximity_domain: u32,

    #[cfg(target_arch = "x86_64")]
    pub(crate) pci_config_io: Option<Arc<Mutex<PciConfigIo>>>,

    // Bitmap of PCI devices to hotplug.
    pub(crate) pci_devices_up: u32,
    // Bitmap of PCI devices to hotunplug.
    pub(crate) pci_devices_down: u32,
    // List of allocated IRQs for each PCI slot.
    pub(crate) pci_irq_slots: [u8; 32],

    // Device memory covered by this segment
    pub(crate) start_of_mem32_area: u64,
    pub(crate) end_of_mem32_area: u64,

    pub(crate) start_of_mem64_area: u64,
    pub(crate) end_of_mem64_area: u64,
}

impl std::fmt::Debug for PciSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PciSegment")
            .field("id", &self.id)
            .field("mmio_config_address", &self.mmio_config_address)
            .field("proximity_domain", &self.proximity_domain)
            .field("pci_devices_up", &self.pci_devices_up)
            .field("pci_devices_down", &self.pci_devices_down)
            .field("pci_irq_slots", &self.pci_irq_slots)
            .field("start_of_mem32_area", &self.start_of_mem32_area)
            .field("end_of_mem32_area", &self.end_of_mem32_area)
            .field("start_of_mem64_area", &self.start_of_mem64_area)
            .field("end_of_mem64_area", &self.end_of_mem64_area)
            .finish()
    }
}

impl PciSegment {
    fn build(id: u16, vm: &Arc<Vm>, pci_irq_slots: &[u8; 32]) -> Result<PciSegment, BusError> {
        let pci_root = PciRoot::new(None);
        let pci_bus = Arc::new(Mutex::new(PciBus::new(pci_root, vm.clone())));

        let pci_config_mmio = Arc::new(Mutex::new(PciConfigMmio::new(Arc::clone(&pci_bus))));
        let mmio_config_address = PCI_MMCONFIG_START + PCI_MMIO_CONFIG_SIZE_PER_SEGMENT * id as u64;

        vm.common.mmio_bus.insert(
            Arc::clone(&pci_config_mmio) as Arc<dyn BusDeviceSync>,
            mmio_config_address,
            PCI_MMIO_CONFIG_SIZE_PER_SEGMENT,
        )?;

        let resource_allocator = vm.resource_allocator();

        let start_of_mem32_area = resource_allocator.mmio32_memory.base();
        let end_of_mem32_area = resource_allocator.mmio32_memory.end();

        let start_of_mem64_area = resource_allocator.mmio64_memory.base();
        let end_of_mem64_area = resource_allocator.mmio64_memory.end();

        let segment = PciSegment {
            id,
            pci_bus,
            pci_config_mmio,
            mmio_config_address,
            proximity_domain: 0,
            pci_devices_up: 0,
            pci_devices_down: 0,
            #[cfg(target_arch = "x86_64")]
            pci_config_io: None,
            start_of_mem32_area,
            end_of_mem32_area,
            start_of_mem64_area,
            end_of_mem64_area,
            pci_irq_slots: *pci_irq_slots,
        };

        Ok(segment)
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn new(
        id: u16,
        vm: &Arc<Vm>,
        pci_irq_slots: &[u8; 32],
    ) -> Result<PciSegment, BusError> {
        use crate::Vm;

        let mut segment = Self::build(id, vm, pci_irq_slots)?;
        let pci_config_io = Arc::new(Mutex::new(PciConfigIo::new(Arc::clone(&segment.pci_bus))));

        vm.pio_bus.insert(
            pci_config_io.clone(),
            PCI_CONFIG_IO_PORT,
            PCI_CONFIG_IO_PORT_SIZE,
        )?;

        segment.pci_config_io = Some(pci_config_io);

        info!(
            "pci: adding PCI segment: id={:#x}, PCI MMIO config address: {:#x}, mem32 area: \
             [{:#x}-{:#x}], mem64 area: [{:#x}-{:#x}] IO area: [{PCI_CONFIG_IO_PORT:#x}-{:#x}]",
            segment.id,
            segment.mmio_config_address,
            segment.start_of_mem32_area,
            segment.end_of_mem32_area,
            segment.start_of_mem64_area,
            segment.end_of_mem64_area,
            PCI_CONFIG_IO_PORT + PCI_CONFIG_IO_PORT_SIZE - 1
        );

        Ok(segment)
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn new(
        id: u16,
        vm: &Arc<Vm>,
        pci_irq_slots: &[u8; 32],
    ) -> Result<PciSegment, BusError> {
        let segment = Self::build(id, vm, pci_irq_slots)?;
        info!(
            "pci: adding PCI segment: id={:#x}, PCI MMIO config address: {:#x}, mem32 area: \
             [{:#x}-{:#x}], mem64 area: [{:#x}-{:#x}]",
            segment.id,
            segment.mmio_config_address,
            segment.start_of_mem32_area,
            segment.end_of_mem32_area,
            segment.start_of_mem64_area,
            segment.end_of_mem64_area,
        );

        Ok(segment)
    }

    pub(crate) fn next_device_bdf(&self) -> Result<PciBdf, PciRootError> {
        Ok(PciBdf::new(
            self.id,
            0,
            self.pci_bus
                .lock()
                .unwrap()
                .next_device_id()?
                .try_into()
                .unwrap(),
            0,
        ))
    }
}

#[cfg(target_arch = "x86_64")]
struct PciDevSlot {
    device_id: u8,
}

#[cfg(target_arch = "x86_64")]
impl Aml for PciDevSlot {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) -> Result<(), aml::AmlError> {
        let sun = self.device_id;
        let adr: u32 = (self.device_id as u32) << 16;
        aml::Device::new(
            format!("S{:03}", self.device_id).as_str().try_into()?,
            vec![
                &aml::Name::new("_SUN".try_into()?, &sun)?,
                &aml::Name::new("_ADR".try_into()?, &adr)?,
                &aml::Method::new(
                    "_EJ0".try_into()?,
                    1,
                    true,
                    vec![&aml::MethodCall::new(
                        "\\_SB_.PHPR.PCEJ".try_into()?,
                        vec![&aml::Path::new("_SUN")?, &aml::Path::new("_SEG")?],
                    )],
                ),
            ],
        )
        .append_aml_bytes(v)
    }
}

#[cfg(target_arch = "x86_64")]
struct PciDevSlotNotify {
    device_id: u8,
}

#[cfg(target_arch = "x86_64")]
impl Aml for PciDevSlotNotify {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) -> Result<(), aml::AmlError> {
        let device_id_mask: u32 = 1 << self.device_id;
        let object = aml::Path::new(&format!("S{:03}", self.device_id))?;
        aml::And::new(&aml::Local(0), &aml::Arg(0), &device_id_mask).append_aml_bytes(v)?;
        aml::If::new(
            &aml::Equal::new(&aml::Local(0), &device_id_mask),
            vec![&aml::Notify::new(&object, &aml::Arg(1))],
        )
        .append_aml_bytes(v)
    }
}

#[cfg(target_arch = "x86_64")]
struct PciDevSlotMethods {}

#[cfg(target_arch = "x86_64")]
impl Aml for PciDevSlotMethods {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) -> Result<(), aml::AmlError> {
        let mut device_notifies = Vec::new();
        for device_id in 0..32 {
            device_notifies.push(PciDevSlotNotify { device_id });
        }

        let mut device_notifies_refs: Vec<&dyn Aml> = Vec::new();
        for device_notify in device_notifies.iter() {
            device_notifies_refs.push(device_notify);
        }

        aml::Method::new("DVNT".try_into()?, 2, true, device_notifies_refs).append_aml_bytes(v)?;
        aml::Method::new(
            "PCNT".try_into()?,
            0,
            true,
            vec![
                &aml::Acquire::new("\\_SB_.PHPR.BLCK".try_into()?, 0xffff),
                &aml::Store::new(
                    &aml::Path::new("\\_SB_.PHPR.PSEG")?,
                    &aml::Path::new("_SEG")?,
                ),
                &aml::MethodCall::new(
                    "DVNT".try_into()?,
                    vec![&aml::Path::new("\\_SB_.PHPR.PCIU")?, &aml::ONE],
                ),
                &aml::MethodCall::new(
                    "DVNT".try_into()?,
                    vec![&aml::Path::new("\\_SB_.PHPR.PCID")?, &3usize],
                ),
                &aml::Release::new("\\_SB_.PHPR.BLCK".try_into()?),
            ],
        )
        .append_aml_bytes(v)
    }
}

#[cfg(target_arch = "x86_64")]
struct PciDsmMethod {}

#[cfg(target_arch = "x86_64")]
impl Aml for PciDsmMethod {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) -> Result<(), aml::AmlError> {
        // Refer to ACPI spec v6.3 Ch 9.1.1 and PCI Firmware spec v3.3 Ch 4.6.1
        // _DSM (Device Specific Method), the following is the implementation in ASL.

        // Method (_DSM, 4, NotSerialized)  // _DSM: Device-Specific Method
        // {
        //      If ((Arg0 == ToUUID ("e5c937d0-3553-4d7a-9117-ea4d19c3434d") /* Device Labeling
        // Interface */))      {
        //          If ((Arg2 == Zero))
        //          {
        //              Return (Buffer (One) { 0x21 })
        //          }
        //          If ((Arg2 == 0x05))
        //          {
        //              Return (Zero)
        //          }
        //      }
        //
        //      Return (Buffer (One) { 0x00 })
        // }
        //
        // As per ACPI v6.3 Ch 19.6.142, the UUID is required to be in mixed endian:
        // Among the fields of a UUID:
        //   {d1 (8 digits)} - {d2 (4 digits)} - {d3 (4 digits)} - {d4 (16 digits)}
        // d1 ~ d3 need to be little endian, d4 be big endian.
        // See https://en.wikipedia.org/wiki/Universally_unique_identifier#Encoding .
        let uuid = Uuid::parse_str("E5C937D0-3553-4D7A-9117-EA4D19C3434D").unwrap();
        let (uuid_d1, uuid_d2, uuid_d3, uuid_d4) = uuid.as_fields();
        let mut uuid_buf = vec![];
        uuid_buf.extend(uuid_d1.to_le_bytes());
        uuid_buf.extend(uuid_d2.to_le_bytes());
        uuid_buf.extend(uuid_d3.to_le_bytes());
        uuid_buf.extend(uuid_d4);
        aml::Method::new(
            "_DSM".try_into()?,
            4,
            false,
            vec![
                &aml::If::new(
                    &aml::Equal::new(&aml::Arg(0), &aml::Buffer::new(uuid_buf)),
                    vec![
                        &aml::If::new(
                            &aml::Equal::new(&aml::Arg(2), &aml::ZERO),
                            vec![&aml::Return::new(&aml::Buffer::new(vec![0x21]))],
                        ),
                        &aml::If::new(
                            &aml::Equal::new(&aml::Arg(2), &0x05u8),
                            vec![&aml::Return::new(&aml::ZERO)],
                        ),
                    ],
                ),
                &aml::Return::new(&aml::Buffer::new(vec![0])),
            ],
        )
        .append_aml_bytes(v)
    }
}

#[cfg(target_arch = "x86_64")]
impl Aml for PciSegment {
    fn append_aml_bytes(&self, v: &mut Vec<u8>) -> Result<(), aml::AmlError> {
        let mut pci_dsdt_inner_data: Vec<&dyn Aml> = Vec::new();
        let hid = aml::Name::new("_HID".try_into()?, &aml::EisaName::new("PNP0A08")?)?;
        pci_dsdt_inner_data.push(&hid);
        let cid = aml::Name::new("_CID".try_into()?, &aml::EisaName::new("PNP0A03")?)?;
        pci_dsdt_inner_data.push(&cid);
        let adr = aml::Name::new("_ADR".try_into()?, &aml::ZERO)?;
        pci_dsdt_inner_data.push(&adr);
        let seg = aml::Name::new("_SEG".try_into()?, &self.id)?;
        pci_dsdt_inner_data.push(&seg);
        let uid = aml::Name::new("_UID".try_into()?, &aml::ZERO)?;
        pci_dsdt_inner_data.push(&uid);
        let cca = aml::Name::new("_CCA".try_into()?, &aml::ONE)?;
        pci_dsdt_inner_data.push(&cca);
        let supp = aml::Name::new("SUPP".try_into()?, &aml::ZERO)?;
        pci_dsdt_inner_data.push(&supp);

        let proximity_domain = self.proximity_domain;
        let pxm_return = aml::Return::new(&proximity_domain);
        let pxm = aml::Method::new("_PXM".try_into()?, 0, false, vec![&pxm_return]);
        pci_dsdt_inner_data.push(&pxm);

        let pci_dsm = PciDsmMethod {};
        pci_dsdt_inner_data.push(&pci_dsm);

        #[allow(clippy::if_same_then_else)]
        let crs = if self.id == 0 {
            aml::Name::new(
                "_CRS".try_into()?,
                &aml::ResourceTemplate::new(vec![
                    &aml::AddressSpace::new_bus_number(0x0u16, 0x0u16)?,
                    &aml::Io::new(0xcf8, 0xcf8, 1, 0x8),
                    &aml::Memory32Fixed::new(
                        true,
                        self.mmio_config_address.try_into().unwrap(),
                        PCI_MMIO_CONFIG_SIZE_PER_SEGMENT.try_into().unwrap(),
                    ),
                    &aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::NotCacheable,
                        true,
                        self.start_of_mem32_area,
                        self.end_of_mem32_area,
                    )?,
                    &aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::NotCacheable,
                        true,
                        self.start_of_mem64_area,
                        self.end_of_mem64_area,
                    )?,
                    &aml::AddressSpace::new_io(0u16, 0x0cf7u16)?,
                    &aml::AddressSpace::new_io(0x0d00u16, 0xffffu16)?,
                ]),
            )?
        } else {
            aml::Name::new(
                "_CRS".try_into()?,
                &aml::ResourceTemplate::new(vec![
                    &aml::AddressSpace::new_bus_number(0x0u16, 0x0u16)?,
                    &aml::Memory32Fixed::new(
                        true,
                        self.mmio_config_address.try_into().unwrap(),
                        PCI_MMIO_CONFIG_SIZE_PER_SEGMENT.try_into().unwrap(),
                    ),
                    &aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::NotCacheable,
                        true,
                        self.start_of_mem32_area,
                        self.end_of_mem32_area,
                    )?,
                    &aml::AddressSpace::new_memory(
                        aml::AddressSpaceCacheable::NotCacheable,
                        true,
                        self.start_of_mem64_area,
                        self.end_of_mem64_area,
                    )?,
                ]),
            )?
        };
        pci_dsdt_inner_data.push(&crs);

        let mut pci_devices = Vec::new();
        for device_id in 0..32 {
            let pci_device = PciDevSlot { device_id };
            pci_devices.push(pci_device);
        }
        for pci_device in pci_devices.iter() {
            pci_dsdt_inner_data.push(pci_device);
        }

        let pci_device_methods = PciDevSlotMethods {};
        pci_dsdt_inner_data.push(&pci_device_methods);

        // Build PCI routing table, listing IRQs assigned to PCI devices.
        let prt_package_list: Vec<(u32, u32)> = self
            .pci_irq_slots
            .iter()
            .enumerate()
            .map(|(i, irq)| {
                (
                    ((((u32::try_from(i).unwrap()) & 0x1fu32) << 16) | 0xffffu32),
                    *irq as u32,
                )
            })
            .collect();
        let prt_package_list: Vec<aml::Package> = prt_package_list
            .iter()
            .map(|(bdf, irq)| aml::Package::new(vec![bdf, &0u8, &0u8, irq]))
            .collect();
        let prt_package_list: Vec<&dyn Aml> = prt_package_list
            .iter()
            .map(|item| item as &dyn Aml)
            .collect();
        let prt = aml::Name::new("_PRT".try_into()?, &aml::Package::new(prt_package_list))?;
        pci_dsdt_inner_data.push(&prt);

        aml::Device::new(
            format!("_SB_.PC{:02X}", self.id).as_str().try_into()?,
            pci_dsdt_inner_data,
        )
        .append_aml_bytes(v)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::arch;
    use crate::builder::tests::default_vmm;
    use crate::utils::u64_to_usize;

    #[test]
    fn test_pci_segment_build() {
        let vmm = default_vmm();
        let pci_irq_slots = &[0u8; 32];
        let pci_segment = PciSegment::new(0, &vmm.vm, pci_irq_slots).unwrap();

        assert_eq!(pci_segment.id, 0);
        assert_eq!(
            pci_segment.start_of_mem32_area,
            arch::MEM_32BIT_DEVICES_START
        );
        assert_eq!(
            pci_segment.end_of_mem32_area,
            arch::MEM_32BIT_DEVICES_START + arch::MEM_32BIT_DEVICES_SIZE - 1
        );
        assert_eq!(
            pci_segment.start_of_mem64_area,
            arch::MEM_64BIT_DEVICES_START
        );
        assert_eq!(
            pci_segment.end_of_mem64_area,
            arch::MEM_64BIT_DEVICES_START + arch::MEM_64BIT_DEVICES_SIZE - 1
        );
        assert_eq!(pci_segment.mmio_config_address, arch::PCI_MMCONFIG_START);
        assert_eq!(pci_segment.proximity_domain, 0);
        assert_eq!(pci_segment.pci_devices_up, 0);
        assert_eq!(pci_segment.pci_devices_down, 0);
        assert_eq!(pci_segment.pci_irq_slots, [0u8; 32]);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_io_bus() {
        let vmm = default_vmm();
        let pci_irq_slots = &[0u8; 32];
        let pci_segment = PciSegment::new(0, &vmm.vm, pci_irq_slots).unwrap();

        let mut data = [0u8; u64_to_usize(PCI_CONFIG_IO_PORT_SIZE)];
        vmm.vm.pio_bus.read(PCI_CONFIG_IO_PORT, &mut data).unwrap();

        vmm.vm
            .pio_bus
            .read(PCI_CONFIG_IO_PORT + PCI_CONFIG_IO_PORT_SIZE, &mut data)
            .unwrap_err();
    }

    #[test]
    fn test_mmio_bus() {
        let vmm = default_vmm();
        let pci_irq_slots = &[0u8; 32];
        let pci_segment = PciSegment::new(0, &vmm.vm, pci_irq_slots).unwrap();

        let mut data = [0u8; u64_to_usize(PCI_MMIO_CONFIG_SIZE_PER_SEGMENT)];

        vmm.vm
            .common
            .mmio_bus
            .read(pci_segment.mmio_config_address, &mut data)
            .unwrap();
        vmm.vm
            .common
            .mmio_bus
            .read(
                pci_segment.mmio_config_address + PCI_MMIO_CONFIG_SIZE_PER_SEGMENT,
                &mut data,
            )
            .unwrap_err();
    }

    #[test]
    fn test_next_device_bdf() {
        let vmm = default_vmm();
        let pci_irq_slots = &[0u8; 32];
        let pci_segment = PciSegment::new(0, &vmm.vm, pci_irq_slots).unwrap();

        // Start checking from device id 1, since 0 is allocated to the Root port.
        for dev_id in 1..32 {
            let bdf = pci_segment.next_device_bdf().unwrap();
            // In our case we have a single Segment with id 0, which has
            // a single bus with id 0. Also, each device of ours has a
            // single function.
            assert_eq!(bdf, PciBdf::new(0, 0, dev_id, 0));
        }

        // We can only have 32 devices on a segment
        pci_segment.next_device_bdf().unwrap_err();
    }
}
