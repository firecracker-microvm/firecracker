use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use crate::sdt::Sdt;
use crate::{checksum, Result, FC_OEM_ID};

/// Root System Description Pointer
///
/// This is the root pointer to the ACPI hierarchy. This is what OSs
/// are looking for in the memory when initializing ACPI. It includes
/// a pointer to XSDT
#[repr(packed)]
#[derive(Clone, Copy, Default)]
pub struct Rsdp {
    _signature: [u8; 8],
    checksum: u8,
    _oem_id: [u8; 6],
    _revision: u8,
    _rsdt_addr: u32,
    _length: u32,
    _xsdt_addr: u64,
    extended_checksum: u8,
    _reserved: [u8; 3],
}

// Rsdp only contains plain data
unsafe impl ByteValued for Rsdp {}

impl Rsdp {
    pub fn new(_xsdt_addr: u64) -> Self {
        let mut rsdp = Rsdp {
            // Space in the end of string is needed!
            _signature: *b"RSD PTR ",
            checksum: 0,
            _oem_id: FC_OEM_ID,
            _revision: 2,
            _rsdt_addr: 0,
            _length: std::mem::size_of::<Rsdp>() as u32,
            _xsdt_addr,
            extended_checksum: 0,
            _reserved: [0u8; 3],
        };

        rsdp.checksum = checksum(&[&rsdp.as_slice()[..20]]);
        rsdp.extended_checksum = checksum(&[rsdp.as_slice()]);

        rsdp
    }
}

impl Sdt for Rsdp {
    fn len(&self) -> usize {
        self.as_slice().len()
    }

    fn write_to_guest(&self, mem: &GuestMemoryMmap, address: GuestAddress) -> Result<()> {
        mem.write_slice(self.as_slice(), address)?;
        Ok(())
    }
}
