use std::mem::size_of;
use vm_memory::GuestMemoryError;

pub mod aml;
pub mod dsdt;
pub mod fadt;
pub mod madt;
pub mod rsdp;
mod sdt;
pub mod xsdt;

pub use aml::Aml;
pub use dsdt::Dsdt;
pub use fadt::Fadt;
pub use madt::Madt;
pub use rsdp::Rsdp;
pub use sdt::Sdt;
pub use xsdt::Xsdt;

const FC_OEM_ID: [u8; 6] = *b"FIRECK";

// Fixed HW parameters
pub const ACPI_SCI_INT: u16 = 9;
const ACPI_PM1_EVT_LEN: u8 = 4;
const ACPI_PM1_CNT_LEN: u8 = 2;
pub const ACPI_REGISTERS_BASE_ADDRESS: u16 = 0x500;
pub const ACPI_REGISTERS_LEN: u8 = ACPI_PM1_CNT_LEN + ACPI_PM1_EVT_LEN;

fn checksum(buf: &[&[u8]]) -> u8 {
    (255 - buf
        .iter()
        .flat_map(|b| b.iter())
        .fold(0u8, |acc, x| acc.wrapping_add(*x)))
    .wrapping_add(1)
}

#[derive(Debug)]
pub enum AcpiError {
    /// Error writing table to guest memory
    GuestMemory(GuestMemoryError),
    /// Invalid guest address
    InvalidGuestAddress,
}

impl From<GuestMemoryError> for AcpiError {
    fn from(err: GuestMemoryError) -> Self {
        AcpiError::GuestMemory(err)
    }
}

pub type Result<T> = std::result::Result<T, AcpiError>;

#[repr(packed)]
#[derive(Clone, Copy, Default)]
pub(crate) struct GenericAddress {
    _address_space_id: u8,
    _register_bit_width: u8,
    _register_bit_offset: u8,
    _access_size: u8,
    _address: u64,
}

impl GenericAddress {
    pub fn io_port_address<T>(address: u16) -> Self {
        GenericAddress {
            _address_space_id: 0x1, /* System I/O space */
            _register_bit_width: 8 * size_of::<T>() as u8,
            _register_bit_offset: 0,
            _access_size: size_of::<T>() as u8,
            _address: u64::from(address),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::checksum;

    #[test]
    fn test_checksum() {
        assert_eq!(checksum(&[&[]]), 0u8);
        assert_eq!(checksum(&[]), 0u8);
        assert_eq!(checksum(&[&[1, 2, 3]]), 250u8);
        assert_eq!(checksum(&[&[1, 2, 3], &[]]), 250u8);
        assert_eq!(checksum(&[&[1, 2], &[3]]), 250u8);
        assert_eq!(checksum(&[&[1, 2], &[3], &[250]]), 0u8);
        assert_eq!(checksum(&[&[255]]), 1u8);
        assert_eq!(checksum(&[&[1, 2], &[3], &[250], &[255]]), 1u8);
    }
}
