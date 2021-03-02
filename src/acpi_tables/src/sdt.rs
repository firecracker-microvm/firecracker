// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright © 2019 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

#[repr(packed)]
pub struct GenericAddress {
    pub address_space_id: u8,
    pub register_bit_width: u8,
    pub register_bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
}

#[allow(unused)]
// FADT revision 5
#[repr(packed)]
pub struct AcpiFadtData {
    pm1a_cnt: GenericAddress,  /* PM1a_CNT_BLK */
    pm1a_evt: GenericAddress,  /* PM1a_EVT_BLK */
    pm_tmr: GenericAddress,    /* PM_TMR_BLK */
    gpe0_blk: GenericAddress,  /* GPE0_BLK */
    reset_reg: GenericAddress, /* RESET_REG */
    sleep_ctl: GenericAddress, /* SLEEP_CONTROL_REG */
    sleep_sts: GenericAddress, /* SLEEP_STATUS_REG */
    reset_val: u8,             /* RESET_VALUE */
    rev: u8,                   /* Revision */
    flags: u32,                /* Flags */
    smi_cmd: u32,              /* SMI_CMD */
    sci_int: u16,              /* SCI_INT */
    int_model: u8,             /* INT_MODEL */
    acpi_enable_cmd: u8,       /* ACPI_ENABLE */
    acpi_disable_cmd: u8,      /* ACPI_DISABLE */
    rtc_century: u8,           /* CENTURY */
    plvl2_lat: u16,            /* P_LVL2_LAT */
    plvl3_lat: u16,            /* P_LVL3_LAT */
    arm_boot_arch: u16,        /* ARM_BOOT_ARCH */
    minor_ver: u8,             /* FADT Minor Version */

    /*
     * respective tables offsets within ACPI_BUILD_TABLE_FILE,
     * NULL if table doesn't exist (in that case field's value
     * won't be patched by linker and will be kept set to 0)
     */
    pub facs_tbl_offset: u64, /* FACS offset in */
    pub dsdt_tbl_offset: u64,
    pub xdsdt_tbl_offset: u64,
}

impl GenericAddress {
    pub fn io_port_address<T>(address: u16) -> Self {
        GenericAddress {
            address_space_id: 1,
            register_bit_width: 8 * std::mem::size_of::<T>() as u8,
            register_bit_offset: 0,
            access_size: std::mem::size_of::<T>() as u8,
            address: u64::from(address),
        }
    }
}

pub struct SDT {
    data: Vec<u8>,
}

#[allow(clippy::len_without_is_empty)]
impl SDT {
    pub fn new(
        signature: [u8; 4],
        length: u32,
        revision: u8,
        oem_id: [u8; 6],
        oem_table: [u8; 8],
        oem_revision: u32,
    ) -> Self {
        assert!(length >= 36);

        let mut data = Vec::with_capacity(length as usize);
        data.extend_from_slice(&signature);
        data.extend_from_slice(&length.to_le_bytes());
        data.push(revision);
        data.push(0); // checksum
        data.extend_from_slice(&oem_id);
        data.extend_from_slice(&oem_table);
        data.extend_from_slice(&oem_revision.to_le_bytes());
        data.extend_from_slice(b"FCVM");
        data.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(data.len(), 36);

        data.resize(length as usize, 0);
        let mut sdt = SDT { data };

        sdt.update_checksum();
        sdt
    }

    pub fn update_checksum(&mut self) {
        self.data[9] = 0;
        let checksum = super::generate_checksum(self.data.as_slice());
        self.data[9] = checksum
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data.as_slice()
    }

    pub fn append<T>(&mut self, value: T) {
        let orig_length = self.data.len();
        let new_length = orig_length + std::mem::size_of::<T>();
        self.data.resize(new_length, 0);
        self.write_u32(4, new_length as u32);
        self.write(orig_length, value);
    }

    pub fn append_slice(&mut self, data: &[u8]) {
        let orig_length = self.data.len();
        let new_length = orig_length + data.len();
        self.write_u32(4, new_length as u32);
        self.data.extend_from_slice(data);
        self.update_checksum();
    }

    /// Write a value at the given offset
    pub fn write<T>(&mut self, offset: usize, value: T) {
        assert!((offset + (std::mem::size_of::<T>() - 1)) < self.data.len());
        unsafe {
            *(((self.data.as_mut_ptr() as usize) + offset) as *mut T) = value;
        }
        self.update_checksum();
    }

    pub fn write_u8(&mut self, offset: usize, val: u8) {
        self.write(offset, val);
    }

    pub fn write_u16(&mut self, offset: usize, val: u16) {
        self.write(offset, val);
    }

    pub fn write_u32(&mut self, offset: usize, val: u32) {
        self.write(offset, val);
    }

    pub fn write_u64(&mut self, offset: usize, val: u64) {
        self.write(offset, val);
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::SDT;

    #[test]
    fn test_sdt() {
        let mut sdt = SDT::new(*b"TEST", 40, 1, *b"FIRECR", *b"TESTTEST", 1);
        let sum: u8 = sdt
            .as_slice()
            .iter()
            .fold(0u8, |acc, x| acc.wrapping_add(*x));
        assert_eq!(sum, 0);
        sdt.write_u32(36, 0x12345678);
        let sum: u8 = sdt
            .as_slice()
            .iter()
            .fold(0u8, |acc, x| acc.wrapping_add(*x));
        assert_eq!(sum, 0);
    }
}
