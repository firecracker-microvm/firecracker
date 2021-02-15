// Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use vm_memory::ByteValued;

#[repr(packed)]
#[derive(Clone, Copy, Default)]
pub struct RSDP {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    _rsdt_addr: u32,
    pub length: u32,
    pub xsdt_addr: u64,
    pub extended_checksum: u8,
    _reserved: [u8; 3],
}

unsafe impl ByteValued for RSDP {}

impl RSDP {
    pub fn new(oem_id: [u8; 6], xsdt_addr: u64) -> Self {
        let mut rsdp = RSDP {
            signature: *b"RSD PTR ",
            checksum: 0,
            oem_id,
            revision: 2,
            _rsdt_addr: 0,
            length: std::mem::size_of::<RSDP>() as u32,
            xsdt_addr,
            extended_checksum: 0,
            _reserved: [0; 3],
        };

        rsdp.checksum = super::generate_checksum(&rsdp.as_slice()[0..19]);
        rsdp.extended_checksum = super::generate_checksum(&rsdp.as_slice());
        rsdp
    }

    pub fn len() -> usize {
        std::mem::size_of::<RSDP>()
    }
}

#[cfg(test)]
mod tests {
    use super::RSDP;
    use vm_memory::bytes::ByteValued;

    #[test]
    fn test_rsdp() {
        let rsdp = RSDP::new(*b"CHYPER", 0xdead_beef);
        let sum = rsdp
            .as_slice()
            .iter()
            .fold(0u8, |acc, x| acc.wrapping_add(*x));
        assert_eq!(sum, 0);
        let sum: u8 = rsdp
            .as_slice()
            .iter()
            .fold(0u8, |acc, x| acc.wrapping_add(*x));
        assert_eq!(sum, 0);
    }
}
