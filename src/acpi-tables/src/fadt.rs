// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2023 Rivos, Inc.
//
// SPDX-License-Identifier: Apache-2.0

use vm_memory::{Bytes, GuestAddress, GuestMemory};
use zerocopy::little_endian::{U16, U32, U64};
use zerocopy::{Immutable, IntoBytes};

use crate::{GenericAddressStructure, Result, Sdt, SdtHeader, checksum};

#[cfg(target_arch = "x86_64")]
pub const IAPC_BOOT_ARG_FLAGS_VGA_NOT_PRESENT: u16 = 2;
#[cfg(target_arch = "x86_64")]
pub const IAPC_BOOT_ARG_FLAGS_MSI_NOT_PRESENT: u16 = 3;
#[cfg(target_arch = "x86_64")]
pub const IAPC_BOOT_ARG_FLAGS_PCI_ASPM: u16 = 4;

// ACPI Flags. Reading from the specification here:
// https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#fixed-acpi-description-table-fixed-feature-flags

/// Flag for the Power Button functionality.
/// If the system does not have a power button, this value would be “1” and no power button device
/// would be present
pub const FADT_F_PWR_BUTTON: u8 = 4;
/// Flag for the Sleep Button Functionality.
/// If the system does not have a sleep button, this value would be “1” and no power button device
/// would be present
pub const FADT_F_SLP_BUTTON: u8 = 5;
/// Flag for Hardware Reduced API. If enabled, software-only alternatives are used for supported
/// fixed features.
pub const FADT_F_HW_REDUCED_ACPI: u8 = 20;

// clippy doesn't understand that we actually "use" the fields of this struct when we serialize
// them as bytes in guest memory, so here we just ignore dead code to avoid having to name
// everything with an underscore prefix
#[allow(dead_code)]
/// Fixed ACPI Description Table (FADT)
///
/// This table includes fixed hardware ACPI information such as addresses of register blocks and
/// the pointer to the DSDT table.
/// More information about this table can be found in the ACPI specification:
/// https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#fixed-acpi-description-table-fadt
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default, IntoBytes, Immutable)]
pub struct Fadt {
    header: SdtHeader,
    firmware_control: U32,
    dsdt: U32,
    reserved_1: u8,
    preferred_pm_profile: u8,
    // In HW-reduced mode, fields starting from SCI_INT until CENTURY are ignored
    sci_int: U16,
    smi_cmd: U32,
    acpi_enable: u8,
    acpi_disable: u8,
    s4bios_req: u8,
    pstate_cnt: u8,
    pm1a_evt_blk: U32,
    pm1b_evt_blk: U32,
    pm1a_cnt_blk: U32,
    pm1b_cnt_blk: U32,
    pm2_cnt_blk: U32,
    pm_tmr_blk: U32,
    gpe0_blk: U32,
    gpe1_blk: U32,
    pm1_evt_len: u8,
    pm1_cnt_len: u8,
    pm2_cnt_len: u8,
    pm_tmr_len: u8,
    gpe0_blk_len: u8,
    gpe1_blk_len: u8,
    gpe1_base: u8,
    cst_cnt: u8,
    p_lvl2_lat: U16,
    p_lvl3_lat: U16,
    flush_size: U16,
    flush_stride: U16,
    duty_offset: u8,
    duty_width: u8,
    day_alrm: u8,
    mon_alrm: u8,
    century: u8,
    iapc_boot_arch: U16,
    reserved_2: u8,
    flags: U32,
    reset_reg: GenericAddressStructure,
    reset_value: u8,
    arm_boot_arch: U16,
    fadt_minor_version: u8,
    x_firmware_ctrl: U64,
    x_dsdt: U64,
    // In HW-reduced mode, fields starting from X_PM1a_EVT_BLK through X_GPE1_BLK
    // are ignored
    x_pm1a_evt_blk: GenericAddressStructure,
    x_pm1b_evt_blk: GenericAddressStructure,
    x_pm1a_cnt_blk: GenericAddressStructure,
    x_pm1b_cnt_blk: GenericAddressStructure,
    x_pm2_cnt_blk: GenericAddressStructure,
    x_pm_tmr_blk: GenericAddressStructure,
    x_gpe0_blk: GenericAddressStructure,
    x_gpe1_blk: GenericAddressStructure,
    sleep_control_reg: GenericAddressStructure,
    sleep_status_reg: GenericAddressStructure,
    hypervisor_vendor_id: [u8; 8],
}

impl Fadt {
    pub fn new(oem_id: [u8; 6], oem_table_id: [u8; 8], oem_revision: u32) -> Self {
        let header = SdtHeader::new(
            *b"FACP",
            // It's fine to unwrap here, we know that the size of the Fadt structure fits in 32
            // bits.
            std::mem::size_of::<Self>().try_into().unwrap(),
            6, // revision 6
            oem_id,
            oem_table_id,
            oem_revision,
        );

        Fadt {
            header,
            fadt_minor_version: 5,
            ..Default::default()
        }
    }

    /// Set the address of the DSDT table
    ///
    /// This sets the 64bit variant, X_DSDT field of the FADT table
    pub fn set_x_dsdt(&mut self, addr: u64) {
        self.x_dsdt = U64::new(addr);
    }

    /// Set the FADT flags
    pub fn set_flags(&mut self, flags: u32) {
        self.flags = U32::new(flags);
    }

    /// Set the IA-PC specific flags
    pub fn setup_iapc_flags(&mut self, flags: u16) {
        self.iapc_boot_arch = U16::new(flags);
    }

    /// Set the hypervisor vendor ID
    pub fn set_hypervisor_vendor_id(&mut self, hypervisor_vendor_id: [u8; 8]) {
        self.hypervisor_vendor_id = hypervisor_vendor_id;
    }
}

impl Sdt for Fadt {
    fn len(&self) -> usize {
        self.header.length.get().try_into().unwrap()
    }

    fn write_to_guest<M: GuestMemory>(&mut self, mem: &M, address: GuestAddress) -> Result<()> {
        self.header.checksum = checksum(&[self.as_bytes()]);
        mem.write_slice(self.as_bytes(), address)?;
        Ok(())
    }
}
