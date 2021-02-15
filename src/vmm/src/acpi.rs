// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
use acpi_tables::{rsdp::RSDP, sdt::GenericAddress, sdt::SDT};
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

#[repr(packed)]
#[derive(Default)]
struct InterruptSourceOverride {
    pub r#type: u8,
    pub length: u8,
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

const MADT_CPU_ENABLE_FLAG: usize = 0;

fn create_dsdt_table(_cpu_count: u8) -> SDT {
    // DSDT
    let dsdt = SDT::new(*b"DSDT", 36, 6, *b"FIRECR", *b"FCDSDT  ", 1);

    // TODO: add CPU devices

    dsdt
}

fn create_madt(_cpu_count: u8) -> SDT {
    let mut madt = SDT::new(*b"APIC", 44, 5, *b"FIRECR", *b"FCMADT  ", 1);

    madt.write(
        36,
        GuestAddress(arch::x86_64::APIC_DEFAULT_PHYS_BASE as u64),
    );

    for cpu in 0.._cpu_count {
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

    madt.append(InterruptSourceOverride {
        r#type: 2,
        length: 10,
        bus: 0,
        source: 4,
        gsi: 4,
        flags: 0,
    });

    madt
}

// TODO: move this to arch defines
// ACPI RSDP table
pub const RSDP_POINTER: u64 = 0xa0000;

pub fn create_acpi_tables(guest_mem: &GuestMemoryMmap, cpu_count: u8) -> GuestAddress {
    let rsdp_offset = GuestAddress(RSDP_POINTER);

    let mut tables: Vec<u64> = Vec::new();

    // DSDT
    let dsdt = create_dsdt_table(cpu_count);
    let dsdt_offset = rsdp_offset.checked_add(RSDP::len() as u64).unwrap();
    guest_mem
        .write_slice(dsdt.as_slice(), dsdt_offset)
        .expect("Error writing DSDT table");

    // FACP aka FADT
    // Revision 6 of the ACPI FADT table is 276 bytes long
    let mut facp = SDT::new(*b"FACP", 276, 6, *b"FIRECR", *b"FCFACP  ", 1);

    // PM_TMR_BLK I/O port
    facp.write(76, 0xb008u32);

    // HW_REDUCED_ACPI, RESET_REG_SUP, TMR_VAL_EXT
    let fadt_flags: u32 = 1 << 20 | 1 << 10 | 1 << 8;
    facp.write(112, fadt_flags);

    // RESET_REG
    facp.write(116, GenericAddress::io_port_address::<u8>(0x3c0));
    // RESET_VALUE
    facp.write(128, 1u8);

    facp.write(131, 3u8); // FADT minor version
    facp.write(140, dsdt_offset.0); // X_DSDT

    // X_PM_TMR_BLK
    facp.write(208, GenericAddress::io_port_address::<u32>(0xb008));

    // SLEEP_CONTROL_REG
    facp.write(244, GenericAddress::io_port_address::<u8>(0x3c0));
    // SLEEP_STATUS_REG
    facp.write(256, GenericAddress::io_port_address::<u8>(0x3c0));

    facp.write(268, b"FIRECRKR"); // Firecracker Vendor Identity

    facp.update_checksum();
    let facp_offset = dsdt_offset.checked_add(dsdt.len() as u64).unwrap();
    guest_mem
        .write_slice(facp.as_slice(), facp_offset)
        .expect("Error writing FACP table");
    tables.push(facp_offset.0);

    // MADT
    let madt = create_madt(cpu_count);
    let madt_offset = facp_offset.checked_add(facp.len() as u64).unwrap();
    guest_mem
        .write_slice(madt.as_slice(), madt_offset)
        .expect("Error writing MADT table");
    tables.push(madt_offset.0);

    // XSDT
    let mut xsdt = SDT::new(*b"XSDT", 36, 1, *b"FIRECR", *b"FCXSDT  ", 1);
    for table in tables {
        xsdt.append(table);
    }
    xsdt.update_checksum();

    let xsdt_offset = madt_offset.checked_add(madt.len() as u64).unwrap();
    guest_mem
        .write_slice(xsdt.as_slice(), xsdt_offset)
        .expect("Error writing XSDT table");

    // RSDP
    let rsdp = RSDP::new(*b"FIRECR", xsdt_offset.0);
    guest_mem
        .write_slice(rsdp.as_slice(), rsdp_offset)
        .expect("Error writing RSDP");

    rsdp_offset
}
