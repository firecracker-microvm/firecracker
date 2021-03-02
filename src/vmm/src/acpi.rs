// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use acpi_tables::{rsdp::RSDP, sdt::SDT};
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

#[repr(packed)]
struct LocalAPIC {
    pub r#type: u8,
    pub length: u8,
    pub processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

#[repr(packed)]
#[derive(Default)]
struct IOAPIC {
    pub r#type: u8,
    pub length: u8,
    pub ioapic_id: u8,
    _reserved: u8,
    pub apic_address: u32,
    pub gsi_base: u32,
}

const MADT_CPU_ENABLE_FLAG: usize = 0;

// TODO: move this to arch defines
// ACPI RSDP table
// Needs to be in upper memory range 0xE0000-0xFFFFF, see
// https://elixir.bootlin.com/linux/v4.14.209/source/drivers/acpi/acpica/tbxfroot.c#L211
pub const RSDP_ADDR: u64 = 0xe0000;

pub fn create_acpi_tables(guest_mem: &GuestMemoryMmap, num_cpus: u8) -> GuestAddress {
    let rsdp_offset = GuestAddress(RSDP_ADDR);
    let mut tables: Vec<u64> = Vec::new();

    // DSDT
    let mut dsdt = SDT::new(*b"DSDT", 36, 6, *b"FIRECK", *b"FCDSDT  ", 1);
    dsdt.update_checksum();
    let dsdt_offset = rsdp_offset.checked_add(RSDP::len() as u64).unwrap();
    guest_mem
        .write_slice(dsdt.as_slice(), dsdt_offset)
        .expect("Error writing DSDT table");

    // FACP aka FADT
    // Revision 6 of the ACPI FADT table is 276 bytes long
    let mut facp = SDT::new(*b"FACP", 276, 6, *b"FIRECK", *b"FCFACP  ", 1);

    let fadt_flags: u32 = 1 << 20; // HW_REDUCED_ACPI
    facp.write(112, fadt_flags);

    facp.write(131, 3u8); // FADT minor version
    facp.write(140, dsdt_offset.0); // X_DSDT

    facp.write(268, b"FIRECRCK"); // Hypervisor Vendor Identity

    facp.update_checksum();
    let facp_offset = dsdt_offset.checked_add(dsdt.len() as u64).unwrap();
    guest_mem
        .write_slice(facp.as_slice(), facp_offset)
        .expect("Error writing FACP table");
    tables.push(facp_offset.0);

    // MADT
    let mut madt = SDT::new(*b"APIC", 44, 5, *b"FIRECK", *b"FCMADT  ", 1);
    madt.write(36, arch::x86_64::APIC_DEFAULT_PHYS_BASE);

    for cpu in 0..num_cpus {
        let lapic = LocalAPIC {
            r#type: 0,
            length: 8,
            processor_id: cpu,
            apic_id: cpu,
            flags: 1 << MADT_CPU_ENABLE_FLAG,
        };
        madt.append(lapic);
    }

    madt.append(IOAPIC {
        r#type: 1,
        length: 12,
        ioapic_id: 0,
        apic_address: arch::x86_64::IO_APIC_DEFAULT_PHYS_BASE,
        gsi_base: 0,
        ..Default::default()
    });

    let madt_offset = facp_offset.checked_add(facp.len() as u64).unwrap();
    guest_mem
        .write_slice(madt.as_slice(), madt_offset)
        .expect("Error writing MADT table");
    tables.push(madt_offset.0);

    // XSDT
    let mut xsdt = SDT::new(*b"XSDT", 36, 1, *b"FIRECK", *b"FCXSDT  ", 1);
    for table in tables {
        xsdt.append(table);
    }
    xsdt.update_checksum();

    let xsdt_offset = madt_offset.checked_add(madt.len() as u64).unwrap();
    guest_mem
        .write_slice(xsdt.as_slice(), xsdt_offset)
        .expect("Error writing XSDT table");

    // RSDP
    let rsdp = RSDP::new(*b"FIRECK", xsdt_offset.0);
    guest_mem
        .write_slice(rsdp.as_slice(), rsdp_offset)
        .expect("Error writing RSDP");

    rsdp_offset
}
