use std::mem::size_of;
use vm_memory::{Address, ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use crate::sdt::{Sdt, SdtHeader};
use crate::{checksum, AcpiError, Result};

const MADT_CPU_ENABLE_FLAG: usize = 0;

#[repr(packed)]
#[derive(Copy, Clone, Default)]
pub struct LocalAPIC {
    _type: u8,
    _length: u8,
    _processor_uid: u8,
    _apic_id: u8,
    _flags: u32,
}

unsafe impl ByteValued for LocalAPIC {}

impl LocalAPIC {
    pub fn new(cpu_id: u8) -> Self {
        Self {
            _type: 0,
            _length: 8,
            _processor_uid: cpu_id,
            _apic_id: cpu_id,
            _flags: 1 << MADT_CPU_ENABLE_FLAG,
        }
    }
}

impl Into<Vec<u8>> for LocalAPIC {
    fn into(self) -> Vec<u8> {
        self.as_slice().into()
    }
}

#[repr(packed)]
#[derive(Copy, Clone, Default)]
struct IoAPIC {
    _type: u8,
    _length: u8,
    _ioapic_id: u8,
    _reserved: u8,
    _apic_address: u32,
    _gsi_base: u32,
}

unsafe impl ByteValued for IoAPIC {}

impl IoAPIC {
    pub fn new(_ioapic_id: u8) -> Self {
        IoAPIC {
            _type: 1,
            _length: 12,
            _ioapic_id,
            _reserved: 0,
            _apic_address: arch::x86_64::IO_APIC_DEFAULT_PHYS_BASE,
            _gsi_base: 0,
        }
    }
}

pub struct Madt {
    header: SdtHeader,
    base_address: u32,
    flags: u32,
    interrupt_controllers: Vec<u8>,
}

impl Madt {
    pub fn new(num_cpus: usize) -> Self {
        let lapic: Vec<LocalAPIC> = (0..num_cpus).map(|i| LocalAPIC::new(i as u8)).collect();
        let ioapic = vec![IoAPIC::new(0)];

        let mut interrupt_controllers = Vec::with_capacity(
            lapic.len() * size_of::<LocalAPIC>() + ioapic.len() * size_of::<IoAPIC>(),
        );

        interrupt_controllers.extend(lapic.iter().map(|ic| ic.as_slice()).flatten());
        interrupt_controllers.extend(ioapic.iter().map(|ic| ic.as_slice()).flatten());

        let header = SdtHeader::new(
            *b"APIC",
            (size_of::<SdtHeader>() + interrupt_controllers.len() + 8) as u32,
            6,
            *b"FCVMMADT",
        );

        let mut madt = Madt {
            header,
            base_address: arch::x86_64::APIC_DEFAULT_PHYS_BASE,
            flags: 0,
            interrupt_controllers,
        };

        madt.header.set_checksum(checksum(&[
            madt.header.as_slice(),
            &madt.base_address.to_le_bytes(),
            &madt.flags.to_le_bytes(),
            madt.interrupt_controllers.as_slice(),
        ]));

        madt
    }
}

impl Sdt for Madt {
    fn len(&self) -> usize {
        self.header.length as usize
    }

    fn write_to_guest(&self, mem: &GuestMemoryMmap, address: GuestAddress) -> Result<()> {
        mem.write_slice(self.header.as_slice(), address)?;
        let address = address
            .checked_add(size_of::<SdtHeader>() as u64)
            .ok_or_else(|| AcpiError::InvalidGuestAddress)?;
        mem.write_obj(self.base_address, address)?;
        let address = address
            .checked_add(size_of::<u32>() as u64)
            .ok_or_else(|| AcpiError::InvalidGuestAddress)?;
        mem.write_obj(self.flags, address)?;
        let address = address
            .checked_add(size_of::<u32>() as u64)
            .ok_or_else(|| AcpiError::InvalidGuestAddress)?;
        mem.write_slice(self.interrupt_controllers.as_slice(), address)?;

        Ok(())
    }
}
