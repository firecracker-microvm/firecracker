use std::fmt::{Display, Formatter};

use acpi::{aml, AcpiError, Aml, Dsdt, Fadt, Madt, Rsdp, Sdt, Xsdt};
use vm_allocator::{AddressAllocator, AllocPolicy, Error as VmAllocatorError, IdAllocator};
use vm_memory::{GuestAddress, GuestMemoryMmap};

use crate::device_manager::mmio::MMIODeviceManager;
use crate::vstate::vcpu::Vcpu;

/// A device manager for ACPI devices. It handles a range of IRQs and an address
/// space for allocating to ACPI devices.
pub(crate) struct AcpiDeviceManager {
    _irq_allocator: IdAllocator,
    mem_allocator: AddressAllocator,
}

#[derive(Debug)]
pub enum AcpiDeviceManagerError {
    /// An error occurred while interacting with vm-allocator
    VmAllocator(VmAllocatorError),
    /// Failed to register and IRQ file descriptor.
    RegisterIrqFd(kvm_ioctls::Error),
    /// Error handling ACPI tables
    AcpiTable(AcpiError),
}

impl Display for AcpiDeviceManagerError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use AcpiDeviceManagerError::*;
        match self {
            VmAllocator(err) => write!(f, "vm-allocator error ({})", err),
            RegisterIrqFd(err) => write!(f, "Could not register IRQ fd: {}", err),
            AcpiTable(err) => write!(f, "ACPI tables error: {:#?}", err),
        }
    }
}

impl From<VmAllocatorError> for AcpiDeviceManagerError {
    fn from(err: VmAllocatorError) -> Self {
        AcpiDeviceManagerError::VmAllocator(err)
    }
}

impl From<kvm_ioctls::Error> for AcpiDeviceManagerError {
    fn from(err: kvm_ioctls::Error) -> Self {
        AcpiDeviceManagerError::RegisterIrqFd(err)
    }
}

impl From<AcpiError> for AcpiDeviceManagerError {
    fn from(err: AcpiError) -> Self {
        AcpiDeviceManagerError::AcpiTable(err)
    }
}

type Result<T> = std::result::Result<T, AcpiDeviceManagerError>;

impl AcpiDeviceManager {
    /// Create a new BIOS Manager
    pub(crate) fn new(irq_start: u32, irq_end: u32) -> Result<Self> {
        let (mem_start, mem_size) = arch::boot_data_region();
        Ok(Self {
            _irq_allocator: IdAllocator::new(irq_start, irq_end)?,
            mem_allocator: AddressAllocator::new(mem_start, mem_size)?,
        })
    }

    fn write_acpi_table(&mut self, mem: &GuestMemoryMmap, table: &dyn Sdt) -> Result<u64> {
        let addr = self
            .mem_allocator
            .allocate(table.len() as u64, 64, AllocPolicy::FirstMatch)?
            .start() as u64;

        table.write_to_guest(mem, GuestAddress(addr))?;

        Ok(addr)
    }

    pub(crate) fn create_acpi_tables(
        &mut self,
        _mmio: &MMIODeviceManager,
        guest_mem: &GuestMemoryMmap,
        vcpus: &[Vcpu],
    ) -> Result<()> {
        // Make sure we allocate space for the RSDP pointer at the address the OS
        // expects to find it
        let rsdp_addr = self
            .mem_allocator
            .allocate(
                std::mem::size_of::<Rsdp>() as u64,
                arch::PAGE_SIZE as u64,
                AllocPolicy::ExactMatch(arch::get_rsdp_addr()),
            )?
            .start();

        let mut dsdt_data =
            aml::Name::new("_S5_".into(), &aml::Package::new(vec![&5u8])).to_aml_bytes();

        let hid = aml::Name::new("_HID".into(), &"ACPI0010");
        let uid = aml::Name::new("_CID".into(), &aml::EisaName::new("PNP0A05"));
        let cpu_methods = aml::Method::new("CSCN".into(), 0, true, vec![]);

        let mut cpu_inner_data: Vec<&dyn Aml> = vec![&hid, &uid, &cpu_methods];

        for vcpu in vcpus {
            cpu_inner_data.push(vcpu);
        }

        aml::Device::new("_SB_.CPUS".into(), cpu_inner_data).append_aml_bytes(&mut dsdt_data);

        let dsdt = Dsdt::new(dsdt_data);
        let dsdt_addr = self.write_acpi_table(guest_mem, &dsdt)?;

        let fadt = Fadt::new(dsdt_addr);
        let fadt_addr = self.write_acpi_table(guest_mem, &fadt)?;

        let madt = Madt::new(vcpus.len());
        let madt_addr = self.write_acpi_table(guest_mem, &madt)?;

        let xsdt = Xsdt::new(vec![fadt_addr, madt_addr]);
        let xsdt_addr = self.write_acpi_table(guest_mem, &xsdt)?;

        let rsdp = Rsdp::new(xsdt_addr);
        rsdp.write_to_guest(guest_mem, GuestAddress(rsdp_addr))?;

        Ok(())
    }
}
