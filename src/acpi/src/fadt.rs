use std::mem::size_of;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

use crate::sdt::{Sdt, SdtHeader};
use crate::{checksum, GenericAddress, Result};
use crate::{ACPI_PM1_CNT_LEN, ACPI_PM1_EVT_LEN, ACPI_REGISTERS_BASE_ADDRESS, ACPI_SCI_INT};

const HYPERVISOR_VENDOR_ID: [u8; 8] = *b"FIRECRCK";
const FADT_MINOR_VERSION: u8 = 4;

const IAPC_BOOT_ARG_FLAGS_VGA_NOT_PRESENT: u8 = 2;
const IAPC_BOOT_ARG_FLAGS_MSI_NOT_PRESENT: u8 = 3;
const IAPC_BOOT_ARG_FLAGS_PCI_ASPM: u8 = 4;

/// ACPI Flags
const F_HARDWARE_REDUCED_ACPI: u8 = 20;

#[repr(packed)]
#[derive(Copy, Clone, Default)]
pub struct Fadt {
    header: SdtHeader,
    _firmware_control: u32,
    _dsdt: u32,
    _reserved_1: u8,
    _preferred_pm_profile: u8,
    sci_int: u16,
    _smi_cmd: u32,
    _acpi_enable: u8,
    _acpi_disable: u8,
    _s4bios_req: u8,
    _pstate_cnt: u8,
    _pm1a_evt_blk: u32,
    _pm1b_evt_blk: u32,
    _pm1a_cnt_blk: u32,
    _pm1b_cnt_blk: u32,
    _pm2_cnt_blk: u32,
    _pm_tmr_blk: u32,
    _gpe0_blk: u32,
    _gpe1_blk: u32,
    pm1_evt_len: u8,
    pm1_cnt_len: u8,
    _pm2_cnt_len: u8,
    _pm_tmr_len: u8,
    _gpe0_blk_len: u8,
    _gpe1_blk_len: u8,
    _gpe1_base: u8,
    _cst_cnt: u8,
    _p_lvl2_lat: u16,
    _p_lvl3_lat: u16,
    _flush_size: u16,
    _flush_stride: u16,
    _duty_offset: u8,
    _duty_width: u8,
    _day_alrm: u8,
    _mon_alrm: u8,
    _century: u8,
    iapc_boot_arch: u16,
    _reserved_2: u8,
    flags: u32,
    _reset_reg: GenericAddress,
    _reset_value: u8,
    _arm_boot_arch: u16,
    fadt_minor_version: u8,
    _x_firmware_ctrl: u64,
    x_dsdt: u64,
    x_pm1a_evt_blk: GenericAddress,
    _x_pm1b_evt_blk: GenericAddress,
    x_pm1a_cnt_blk: GenericAddress,
    _x_pm1b_cnt_blk: GenericAddress,
    _x_pm2_cnt_blk: GenericAddress,
    _x_pm_tmr_blk: GenericAddress,
    _x_gpe0_blk: GenericAddress,
    _x_gpe1_blk: GenericAddress,
    _sleep_control_reg: GenericAddress,
    _sleep_status_reg: GenericAddress,
    hypervisor_vendor_id: [u8; 8],
}

// Fadt only contains plain data
unsafe impl ByteValued for Fadt {}

impl Fadt {
    pub fn new(x_dsdt_addr: u64) -> Self {
        assert_eq!(size_of::<Self>(), 276);
        let header = SdtHeader::new(
            *b"FACP",
            size_of::<Self>() as u32,
            6, /* revision 6 */
            *b"FCVMFADT",
        );

        let mut fadt = Fadt {
            header,
            ..Default::default()
        };

        fadt.sci_int = ACPI_SCI_INT;
        fadt.pm1_evt_len = ACPI_PM1_EVT_LEN;
        fadt.pm1_cnt_len = ACPI_PM1_CNT_LEN;
        fadt.fadt_minor_version = FADT_MINOR_VERSION;
        // Disable FACP table
        fadt.flags = 1 << F_HARDWARE_REDUCED_ACPI;
        fadt.x_dsdt = x_dsdt_addr;
        fadt.hypervisor_vendor_id = HYPERVISOR_VENDOR_ID;
        /* Disable probing for VGA, enabling MSI and PCI ASPM Controls,
         * maybe we can speed-up a bit booting */
        fadt.iapc_boot_arch = 1 << IAPC_BOOT_ARG_FLAGS_VGA_NOT_PRESENT
            | 1 << IAPC_BOOT_ARG_FLAGS_MSI_NOT_PRESENT
            | 1 << IAPC_BOOT_ARG_FLAGS_PCI_ASPM;

        let mut acpi_register_offset = ACPI_REGISTERS_BASE_ADDRESS;
        fadt.x_pm1a_evt_blk = GenericAddress::io_port_address::<u32>(acpi_register_offset);

        acpi_register_offset += ACPI_PM1_EVT_LEN as u16;
        fadt.x_pm1a_cnt_blk = GenericAddress::io_port_address::<u16>(acpi_register_offset);

        fadt.header.set_checksum(checksum(&[fadt.as_slice()]));

        fadt
    }
}

impl Sdt for Fadt {
    fn len(&self) -> usize {
        self.header.length as usize
    }

    fn write_to_guest(&self, mem: &GuestMemoryMmap, address: GuestAddress) -> Result<()> {
        mem.write_slice(self.as_slice(), address)?;
        Ok(())
    }
}
