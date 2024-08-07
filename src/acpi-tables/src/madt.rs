// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2023 Rivos, Inc.
//
// SPDX-License-Identifier: Apache-2.0

use std::mem::size_of;

use vm_memory::{Address, Bytes, GuestAddress, GuestMemory};
use zerocopy::little_endian::U32;
use zerocopy::AsBytes;

use crate::{checksum, AcpiError, Result, Sdt, SdtHeader};

const MADT_CPU_ENABLE_FLAG: u32 = 0;

const MADT_CPU_ONLINE_CAPABLE_FLAG: u32 = 1;
// clippy doesn't understand that we actually "use" the fields of this struct when we serialize
// them as bytes in guest memory, so here we just ignore dead code to avoid having to name
// everything with an underscore prefix
#[allow(dead_code)]
#[repr(packed)]
#[derive(Copy, Clone, Debug, Default, AsBytes)]
pub struct LocalAPIC {
    r#type: u8,
    length: u8,
    processor_uid: u8,
    apic_id: u8,
    flags: U32,
}

impl LocalAPIC {
    pub fn new(cpu_id: u8, online_capable: bool) -> Self {
        if online_capable {
            Self {
                r#type: 0,
                length: 8,
                processor_uid: cpu_id,
                apic_id: cpu_id,
                flags: U32::new(1u32 << MADT_CPU_ONLINE_CAPABLE_FLAG),
            }
        } else {
            Self {
                r#type: 0,
                length: 8,
                processor_uid: cpu_id,
                apic_id: cpu_id,
                flags: U32::new(1u32 << MADT_CPU_ENABLE_FLAG),
            }
        }
    }
}

// clippy doesn't understand that we actually "use" the fields of this struct when we serialize
// them as bytes in guest memory, so here we just ignore dead code to avoid having to name
// everything with an underscore prefix
#[allow(dead_code)]
#[repr(packed)]
#[derive(Copy, Clone, Debug, Default, AsBytes)]
pub struct IoAPIC {
    r#type: u8,
    length: u8,
    ioapic_id: u8,
    reserved: u8,
    apic_address: U32,
    gsi_base: U32,
}

impl IoAPIC {
    pub fn new(ioapic_id: u8, apic_address: u32) -> Self {
        IoAPIC {
            r#type: 1,
            length: 12,
            ioapic_id,
            reserved: 0,
            apic_address: U32::new(apic_address),
            gsi_base: U32::ZERO,
        }
    }
}

// clippy doesn't understand that we actually "use" the fields of this struct when we serialize
// them as bytes in guest memory, so here we just ignore dead code to avoid having to name
// everything with an underscore prefix
#[allow(dead_code)]
#[repr(packed)]
#[derive(Debug, AsBytes)]
struct MadtHeader {
    sdt: SdtHeader,
    base_address: U32,
    flags: U32,
}

/// Multiple APIC Description Table (MADT)
///
/// This table includes information about the interrupt controllers of the device.
/// More information about this table can be found in the ACPI specification:
/// https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#multiple-apic-description-table-madt
#[derive(Debug)]
pub struct Madt {
    header: MadtHeader,
    interrupt_controllers: Vec<u8>,
}

impl Madt {
    pub fn new(
        oem_id: [u8; 6],
        oem_table_id: [u8; 8],
        oem_revision: u32,
        base_address: u32,
        interrupt_controllers: Vec<u8>,
    ) -> Self {
        let length = size_of::<MadtHeader>() + interrupt_controllers.len();
        let sdt_header = SdtHeader::new(
            *b"APIC",
            // It is ok to unwrap the conversion of `length` to u32. `SdtHeader` is 36 bytes long,
            // so `length` here has a value of 44.
            length.try_into().unwrap(),
            6,
            oem_id,
            oem_table_id,
            oem_revision,
        );

        let mut header = MadtHeader {
            sdt: sdt_header,
            base_address: U32::new(base_address),
            flags: U32::ZERO,
        };

        header.sdt.checksum = checksum(&[header.as_bytes(), interrupt_controllers.as_bytes()]);

        Madt {
            header,
            interrupt_controllers,
        }
    }
}

impl Sdt for Madt {
    fn len(&self) -> usize {
        self.header.sdt.length.get().try_into().unwrap()
    }

    fn write_to_guest<M: GuestMemory>(&mut self, mem: &M, address: GuestAddress) -> Result<()> {
        mem.write_slice(self.header.as_bytes(), address)?;
        let address = address
            .checked_add(size_of::<MadtHeader>() as u64)
            .ok_or(AcpiError::InvalidGuestAddress)?;
        mem.write_slice(self.interrupt_controllers.as_bytes(), address)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::little_endian::U32;

    use crate::madt::LocalAPIC;

    #[test]
    fn test_online_local_apic() {
        let online_apic = super::LocalAPIC::new(0, false);
        assert_eq!(online_apic.r#type, 0);
        assert_eq!(online_apic.length, 8);
        assert_eq!(online_apic.processor_uid, 0);
        assert_eq!(online_apic.apic_id, 0);
        assert_eq!(online_apic.flags, U32::new(1));
    }

    #[test]
    fn test_online_capable_local_apic() {
        let online_capable_apic = LocalAPIC::new(1, true);
        assert_eq!(online_capable_apic.r#type, 0);
        assert_eq!(online_capable_apic.length, 8);
        assert_eq!(online_capable_apic.processor_uid, 1);
        assert_eq!(online_capable_apic.apic_id, 1);
        assert_eq!(online_capable_apic.flags, U32::new(2));
    }
}
