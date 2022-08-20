use logger::debug;
use std::mem::size_of;
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use crate::sdt::{Sdt, SdtHeader};
use crate::{checksum, AcpiError, Result};

pub struct Xsdt {
    header: SdtHeader,
    tables: Vec<u8>,
}

impl Xsdt {
    pub fn new(tables: Vec<u64>) -> Self {
        let mut tables_bytes = Vec::with_capacity(8 * tables.len());
        for addr in tables {
            debug!("Address in bytes: {:?}", addr.to_be_bytes());
            tables_bytes.extend(&addr.to_le_bytes());
        }

        let header = SdtHeader::new(
            *b"XSDT",
            (std::mem::size_of::<SdtHeader>() + tables_bytes.len()) as u32,
            1,
            *b"FCVMXSDT",
        );

        let mut xsdt = Xsdt {
            header,
            tables: tables_bytes,
        };

        xsdt.header
            .set_checksum(checksum(&[xsdt.header.as_slice(), &xsdt.tables.as_slice()]));
        debug!("XSDT checksum: {}", xsdt.header.checksum);

        xsdt
    }
}

impl Sdt for Xsdt {
    fn len(&self) -> usize {
        std::mem::size_of::<SdtHeader>() + self.tables.len()
    }

    fn write_to_guest(&self, mem: &GuestMemoryMmap, address: GuestAddress) -> Result<()> {
        mem.write_slice(self.header.as_slice(), address)?;
        let address = address
            .checked_add(size_of::<SdtHeader>() as u64)
            .ok_or_else(|| AcpiError::InvalidGuestAddress)?;
        mem.write_slice(self.tables.as_slice(), address)?;
        Ok(())
    }
}
