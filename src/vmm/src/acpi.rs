// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
#[cfg(target_arch = "x86_64")]
use acpi_tables::aml::Aml;
#[cfg(target_arch = "x86_64")]
use acpi_tables::{aml, rsdp::Rsdp, sdt::GenericAddress, sdt::Sdt};
#[cfg(target_arch = "x86_64")]
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

#[cfg(target_arch = "x86_64")]
#[repr(packed)]
struct LocalAPIC {
    pub r#type: u8,
    pub length: u8,
    pub processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

#[cfg(target_arch = "x86_64")]
#[repr(packed)]
#[derive(Default)]
struct Ioapic {
    pub r#type: u8,
    pub length: u8,
    pub ioapic_id: u8,
    _reserved: u8,
    pub apic_address: u32,
    pub gsi_base: u32,
}

#[cfg(target_arch = "x86_64")]
const MADT_CPU_ENABLE_FLAG: usize = 0;

// TODO: move this to arch defines
// Needs to be in upper memory range 0xE0000-0xFFFFF, see
// https://elixir.bootlin.com/linux/v4.14.209/source/drivers/acpi/acpica/tbxfroot.c#L211
#[cfg(target_arch = "x86_64")]
pub const RSDP_ADDR: u64 = 0xe0000;
#[cfg(target_arch = "x86_64")]
pub const ACPI_SCI_INT: u8 = 9;

#[cfg(target_arch = "x86_64")]
pub const ACPI_REGISTERS_BASE_ADDRESS: u16 = 0x500;
#[cfg(target_arch = "x86_64")]
pub const ACPI_PM1_EVT_LEN: u16 = 4;
#[cfg(target_arch = "x86_64")]
pub const ACPI_PM1_CNT_LEN: u16 = 2;
#[cfg(target_arch = "x86_64")]
pub const ACPI_REGISTERS_TOTAL_LENGTH: u16 = ACPI_PM1_EVT_LEN + ACPI_PM1_CNT_LEN;

#[cfg(target_arch = "x86_64")]
pub fn create_acpi_tables(guest_mem: &GuestMemoryMmap, num_cpus: u8) -> GuestAddress {
    let mut tables: Vec<u64> = Vec::new();

    let (dsdt_offset, dsdt) = create_dsdt_table(guest_mem, GuestAddress(RSDP_ADDR));

    let (fadt_offset, fadt) = create_fadt_table(guest_mem, dsdt_offset, dsdt.len() as u64);
    tables.push(fadt_offset.0);

    let (madt_offset, madt) =
        create_madt_table(num_cpus, guest_mem, fadt_offset, fadt.len() as u64);
    tables.push(madt_offset.0);

    let xsdt_offset = create_xsdt_table(tables, guest_mem, madt_offset, madt.len() as u64);

    create_rsdp_table(guest_mem, xsdt_offset)
}

#[cfg(target_arch = "x86_64")]
fn create_dsdt_table(
    guest_mem: &GuestMemoryMmap,
    rsdp_offset: GuestAddress,
) -> (GuestAddress, Sdt) {
    let mut dsdt = Sdt::new(*b"DSDT", 36, 6, *b"FIRECK", *b"FCDSDT  ", 1);

    let s5 = aml::Name::new("_S5_".into(), &aml::Package::new(vec![&5u8]));
    dsdt.append_slice(&s5.to_aml_bytes());

    let dsdt_offset = rsdp_offset.checked_add(Rsdp::len() as u64).unwrap();
    guest_mem
        .write_slice(dsdt.as_slice(), dsdt_offset)
        .expect("Error writing DSDT table");

    (dsdt_offset, dsdt)
}

#[cfg(target_arch = "x86_64")]
fn create_fadt_table(
    guest_mem: &GuestMemoryMmap,
    dsdt_offset: GuestAddress,
    dsdt_len: u64,
) -> (GuestAddress, Sdt) {
    // FADT aka FACP
    // Revision 6 of the ACPI FADT table is 276 bytes long
    let mut fadt = Sdt::new(*b"FACP", 276, 6, *b"FIRECK", *b"FCFACP  ", 1);

    fadt.write(46, ACPI_SCI_INT); // SCI_INT
    fadt.write(88, ACPI_PM1_EVT_LEN); // PM1_EVT_LEN
    fadt.write(89, ACPI_PM1_CNT_LEN); // PM1_CNT_LEN
    fadt.write(131, 3u8); // FADT minor version
    fadt.write(140, dsdt_offset.0); // X_DSDT

    let mut acpi_register_offset = ACPI_REGISTERS_BASE_ADDRESS;
    fadt.write(
        148,
        GenericAddress::io_port_address::<u32>(acpi_register_offset),
    ); // X_PM1a_EVT_BLK

    acpi_register_offset += ACPI_PM1_EVT_LEN;
    fadt.write(
        172,
        GenericAddress::io_port_address::<u16>(acpi_register_offset),
    ); // X_PM1a_CNT_BLK
    fadt.write(268, b"FIRECRCK"); // Hypervisor Vendor Identity
    fadt.update_checksum();

    let fadt_offset = dsdt_offset.checked_add(dsdt_len).unwrap();
    guest_mem
        .write_slice(fadt.as_slice(), fadt_offset)
        .expect("Error writing FADT table");

    (fadt_offset, fadt)
}

#[cfg(target_arch = "x86_64")]
fn create_madt_table(
    num_cpus: u8,
    guest_mem: &GuestMemoryMmap,
    fadt_offset: GuestAddress,
    fadt_len: u64,
) -> (GuestAddress, Sdt) {
    let mut madt = Sdt::new(*b"APIC", 44, 5, *b"FIRECK", *b"FCMADT  ", 1);
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

    madt.append(Ioapic {
        r#type: 1,
        length: 12,
        ioapic_id: 0,
        apic_address: arch::x86_64::IO_APIC_DEFAULT_PHYS_BASE,
        gsi_base: 0,
        ..Default::default()
    });

    let madt_offset = fadt_offset.checked_add(fadt_len).unwrap();
    guest_mem
        .write_slice(madt.as_slice(), madt_offset)
        .expect("Error writing MADT table");

    (madt_offset, madt)
}

#[cfg(target_arch = "x86_64")]
fn create_xsdt_table(
    tables: Vec<u64>,
    guest_mem: &GuestMemoryMmap,
    madt_offset: GuestAddress,
    madt_len: u64,
) -> GuestAddress {
    let mut xsdt = Sdt::new(*b"XSDT", 36, 1, *b"FIRECK", *b"FCXSDT  ", 1);
    for table in tables {
        xsdt.append(table);
    }
    xsdt.update_checksum();

    let xsdt_offset = madt_offset.checked_add(madt_len).unwrap();
    guest_mem
        .write_slice(xsdt.as_slice(), xsdt_offset)
        .expect("Error writing XSDT table");

    xsdt_offset
}

#[cfg(target_arch = "x86_64")]
fn create_rsdp_table(guest_mem: &GuestMemoryMmap, xsdt_offset: GuestAddress) -> GuestAddress {
    let rsdp_offset = GuestAddress(RSDP_ADDR);
    let rsdp = Rsdp::new(*b"FIRECK", xsdt_offset.0);

    guest_mem
        .write_slice(rsdp.as_slice(), rsdp_offset)
        .expect("Error writing RSDP");

    rsdp_offset
}
