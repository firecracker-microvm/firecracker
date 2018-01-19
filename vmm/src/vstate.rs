extern crate devices;
extern crate sys_util;
extern crate x86_64;

use std::result;
use std::collections::{BinaryHeap, HashMap};
use std::collections::hash_map::Entry;
use sys_util::{EventFd, GuestAddress, GuestMemory, MemoryMapping};
use std::sync::{Arc, Mutex};
use kvm::*;
use x86_64::{interrupts, regs};

pub const KVM_TSS_ADDRESS: usize = 0xfffbd000;
//x86_64 specific values
const KERNEL_64BIT_ENTRY_OFFSET: usize = 0x200;
const BOOT_STACK_POINTER: usize = 0x8000;

#[derive(Debug)]
pub enum Error {
    GuestMemory(sys_util::GuestMemoryError),
    Kvm(sys_util::Error),
    VmFd(sys_util::Error),
    VcpuFd(sys_util::Error),
    VmSetup(sys_util::Error),
    VcpuRun(sys_util::Error),
    GetSupportedCpusFailed(sys_util::Error),
    SetSupportedCpusFailed(sys_util::Error),
    NotEnoughMemory,
    NoMemoryEntry,
    LocalIntConfiguration(interrupts::Error),
    SetUserMemoryRegion(sys_util::Error),
    /// The kernel extends past the end of RAM
    KernelOffsetPastEnd,
    /// Error configuring the MSR registers
    MSRSConfiguration(regs::Error),
    /// Error configuring the general purpose registers
    REGSConfiguration(regs::Error),
    /// Error configuring the special registers
    SREGSConfiguration(regs::Error),
    /// Error configuring the floating point related registers
    FPUConfiguration(regs::Error),
    EventFd(sys_util::Error),
    Irq(sys_util::Error),
}
pub type Result<T> = result::Result<T, Error>;

impl ::std::convert::From<sys_util::Error> for Error {
    fn from(e: sys_util::Error) -> Error {
        Error::SetUserMemoryRegion(e)
    }
}

/// A wrapper around creating and using a VM.
pub struct Vm {
    fd: VmFd,
    guest_mem: GuestMemory,
    device_memory: HashMap<u32, MemoryMapping>,
    mem_slot_gaps: BinaryHeap<i32>,
}

impl Vm {
    /// Constructs a new `Vm` using the given `Kvm` instance.
    pub fn new(kvm: &Kvm, guest_mem: GuestMemory) -> Result<Self> {
        //create fd for interacting with kvm-vm specific functions
        let vm_fd = VmFd::new(&kvm).map_err(Error::VmFd)?;
        guest_mem.with_regions(|index, guest_addr, size, host_addr| {
            // Safe because the guest regions are guaranteed not to overlap.
            vm_fd.set_user_memory_region(
                index as u32,
                guest_addr.offset() as u64,
                size as u64,
                host_addr as u64,
                0,
            )
        })?;

        Ok(Vm {
            fd: vm_fd,
            guest_mem,
            device_memory: HashMap::new(),
            mem_slot_gaps: BinaryHeap::new(),
        })
    }

    /// All setup required before starting a vm goes here
    /// Currently this is x86 specific
    pub fn setup(&self) -> Result<()> {
        let tss_addr = GuestAddress(KVM_TSS_ADDRESS);
        self.fd
            .set_tss_address(tss_addr.offset())
            .map_err(Error::VmSetup)?;
        self.fd.create_irq_chip().map_err(Error::VmSetup)?;
        self.fd.create_pit2().map_err(Error::VmSetup)?;
        Ok(())
    }

    /// Attaching the serial with its related EventFd(s) and the exit event
    pub fn set_io_bus(
        &self,
        io_bus: &mut devices::Bus,
        stdio_serial: &Arc<Mutex<devices::Serial>>,
        com_evt_1_3: &EventFd,
        com_evt_2_4: &EventFd,
        exit_evt: &EventFd,
    ) -> Result<()> {
        io_bus.insert(stdio_serial.clone(), 0x3f8, 0x8).unwrap();
        io_bus
            .insert(
                Arc::new(Mutex::new(devices::Serial::new_sink(com_evt_2_4
                    .try_clone()
                    .map_err(Error::EventFd)?))),
                0x2f8,
                0x8,
            )
            .unwrap();
        io_bus
            .insert(
                Arc::new(Mutex::new(devices::Serial::new_sink(com_evt_1_3
                    .try_clone()
                    .map_err(Error::EventFd)?))),
                0x3e8,
                0x8,
            )
            .unwrap();
        io_bus
            .insert(
                Arc::new(Mutex::new(devices::Serial::new_sink(com_evt_2_4
                    .try_clone()
                    .map_err(Error::EventFd)?))),
                0x2e8,
                0x8,
            )
            .unwrap();

        self.fd.register_irqfd(&com_evt_1_3, 4).map_err(Error::Irq)?;
        self.fd.register_irqfd(&com_evt_2_4, 3).map_err(Error::Irq)?;

        io_bus
            .insert(
                Arc::new(Mutex::new(devices::I8042Device::new(exit_evt
                    .try_clone()
                    .map_err(Error::EventFd)?))),
                0x064,
                0x1,
            )
            .unwrap();
        Ok(())
    }

    /// Inserts the given `MemoryMapping` into the VM's address space at `guest_addr`.
    ///
    /// The slot that was assigned the device memory mapping is returned on success. The slot can be
    /// given to `Vm::remove_device_memory` to remove the memory from the VM's address space and
    /// take back ownership of `mem`.
    ///
    /// Note that memory inserted into the VM's address space must not overlap with any other memory
    /// slot's region.
    pub fn add_device_memory(
        &mut self,
        guest_addr: GuestAddress,
        mem: MemoryMapping,
    ) -> Result<u32> {
        if guest_addr < self.guest_mem.end_addr() {
            return Err(Error::NotEnoughMemory);
        }

        // The slot gaps are stored negated because `mem_slot_gaps` is a max-heap, so we negate the
        // popped value from the heap to get the lowest slot. If there are no gaps, the lowest slot
        // number is equal to the number of slots we are currently using between guest memory and
        // device memory. For example, if 2 slots are used by guest memory, 3 slots are used for
        // device memory, and there are no gaps, it follows that the lowest unused slot is 2+3=5.
        let slot = match self.mem_slot_gaps.pop() {
            Some(gap) => (-gap) as u32,
            None => (self.device_memory.len() + self.guest_mem.num_regions()) as u32,
        };

        // TODO we also need to check that the number of slots does not
        // exceed the maximum allowed slots

        // Safe because we check that the given guest address is valid and has no overlaps. We also
        // know that the pointer and size are correct because the MemoryMapping interface ensures
        // this. We take ownership of the memory mapping so that it won't be unmapped until the slot
        // is removed.
        self.fd.set_user_memory_region(
            slot,
            guest_addr.offset() as u64,
            mem.size() as u64,
            mem.as_ptr() as u64,
            0,
        )?;
        self.device_memory.insert(slot, mem);

        Ok(slot)
    }

    /// Removes device memory that was previously added at the given slot.
    ///
    /// Ownership of the host memory mapping associated with the given slot is returned on success.
    pub fn remove_device_memory(&mut self, slot: u32) -> Result<MemoryMapping> {
        match self.device_memory.entry(slot) {
            Entry::Occupied(entry) => {
                // Safe because the slot is checked against the list of device memory slots.
                self.fd.set_user_memory_region(slot, 0, 0, 0, 0)?;
                // Because `mem_slot_gaps` is a max-heap, but we want to pop the min slots, we
                // negate the slot value before insertion.
                self.mem_slot_gaps.push(-(slot as i32));
                Ok(entry.remove())
            }
            _ => Err(Error::NoMemoryEntry),
        }
    }

    /// Gets a reference to the guest memory owned by this VM.
    ///
    /// Note that `GuestMemory` does not include any device memory that may have been added after
    /// this VM was constructed.
    pub fn get_memory(&self) -> &GuestMemory {
        &self.guest_mem
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    ///
    pub fn get_fd(&self) -> &VmFd {
        &self.fd
    }
}

// constants for setting the fields of kvm_cpuid2 structures
// CPUID bits in ebx, ecx, and edx.
const EBX_CLFLUSH_CACHELINE: u32 = 8; // Flush a cache line size.
const EBX_CLFLUSH_SIZE_SHIFT: u32 = 8; // Bytes flushed when executing CLFLUSH.
const EBX_CPU_COUNT_SHIFT: u32 = 16; // Index of this CPU.
const EBX_CPUID_SHIFT: u32 = 24; // Index of this CPU.
const ECX_EPB_SHIFT: u32 = 3; // "Energy Performance Bias" bit.
const ECX_HYPERVISOR_SHIFT: u32 = 31; // Flag to be set when the cpu is running on a hypervisor.
const EDX_HTT_SHIFT: u32 = 28; // Hyper Threading Enabled.

/// A wrapper around creating and using a kvm-based VCPU
pub struct Vcpu {
    fd: VcpuFd,
    id: u8,
}

impl Vcpu {
    /// Constructs a new VCPU for `vm`.
    ///
    /// The `id` argument is the CPU number between [0, max vcpus).
    pub fn new(id: u8, vm: &Vm) -> Result<Self> {
        let kvm_vcpu = VcpuFd::new(id, &vm.fd).map_err(Error::VcpuFd)?;

        Ok(Vcpu { fd: kvm_vcpu, id })
    }

    /// Sets up the cpuid entries for the given vcpu
    fn filter_cpuid(&self, cpu_count: u8, kvm_cpuid: &mut CpuId) -> Result<()> {
        let entries = kvm_cpuid.mut_entries_slice();

        for entry in entries.iter_mut() {
            match entry.function {
                1 => {
                    // X86 hypervisor feature
                    if entry.index == 0 {
                        entry.ecx |= 1 << ECX_HYPERVISOR_SHIFT;
                    }
                    entry.ebx = ((self.id as u32) << EBX_CPUID_SHIFT) as u32
                        | (EBX_CLFLUSH_CACHELINE << EBX_CLFLUSH_SIZE_SHIFT);
                    if cpu_count > 1 {
                        entry.ebx |= (cpu_count as u32) << EBX_CPU_COUNT_SHIFT;
                        entry.edx |= 1 << EDX_HTT_SHIFT;
                    }
                }
                6 => {
                    // Clear X86 EPB feature.  No frequency selection in the hypervisor.
                    entry.ecx &= !(1 << ECX_EPB_SHIFT);
                }
                _ => (),
            }
        }

        Ok(())
    }

    /// /// Configures the vcpu and should be called once per vcpu from the vcpu's thread.
    ///
    /// # Arguments
    ///
    /// * `kernel_load_offset` - Offset from `guest_mem` at which the kernel starts.
    /// nr cpus is required for checking populating the kvm_cpuid2 entry for ebx and edx registers
    pub fn configure(
        &mut self,
        nrcpus: u8,
        kernel_start_addr: GuestAddress,
        vm: &Vm,
    ) -> Result<()> {
        let mut kvm_cpuid = vm.get_fd().get_cpuid();
        self.filter_cpuid(nrcpus, &mut kvm_cpuid)?;

        self.fd
            .set_cpuid2(&kvm_cpuid)
            .map_err(Error::SetSupportedCpusFailed)?;

        regs::setup_msrs(&self.fd).map_err(Error::MSRSConfiguration)?;
        let kernel_end = vm.get_memory()
            .checked_offset(kernel_start_addr, KERNEL_64BIT_ENTRY_OFFSET)
            .ok_or(Error::KernelOffsetPastEnd)?;
        regs::setup_regs(
            &self.fd,
            (kernel_end).offset() as u64,
            BOOT_STACK_POINTER as u64,
            x86_64::ZERO_PAGE_OFFSET as u64,
        ).map_err(Error::REGSConfiguration)?;
        regs::setup_fpu(&self.fd).map_err(Error::FPUConfiguration)?;
        regs::setup_sregs(vm.get_memory(), &self.fd).map_err(Error::SREGSConfiguration)?;
        interrupts::set_lint(&self.fd).map_err(Error::LocalIntConfiguration)?;
        Ok(())
    }

    /// Runs the VCPU until it exits, returning the reason.
    ///
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    pub fn run(&self) -> Result<VcpuExit> {
        match self.fd.run() {
            Ok(v) => Ok(v),
            Err(e) => return Err(Error::VcpuRun(<sys_util::Error>::new(e.errno()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_vm() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        Vm::new(&kvm, gm).unwrap();
    }

    #[test]
    fn add_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        let mem_size = 0x1000;
        let mem = MemoryMapping::new(mem_size).unwrap();
        vm.add_device_memory(GuestAddress(0x2000), mem).unwrap();
    }

    #[test]
    fn remove_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        let mem_size = 0x1000;
        let mem = MemoryMapping::new(mem_size).unwrap();
        let mem_ptr = mem.as_ptr();
        let slot = vm.add_device_memory(GuestAddress(0x1000), mem).unwrap();
        let mem = vm.remove_device_memory(slot).unwrap();
        assert_eq!(mem.size(), mem_size);
        assert_eq!(mem.as_ptr(), mem_ptr);
    }

    #[test]
    fn remove_invalid_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        assert!(vm.remove_device_memory(0).is_err());
    }

    #[test]
    fn overlap_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        let mem_size = 0x2000;
        let mem = MemoryMapping::new(mem_size).unwrap();
        assert!(vm.add_device_memory(GuestAddress(0x2000), mem).is_err());
    }

    #[test]
    fn get_memory() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x1000)]).unwrap();
        let vm = Vm::new(&kvm, gm).unwrap();
        let obj_addr = GuestAddress(0xf0);
        vm.get_memory().write_obj_at_addr(67u8, obj_addr).unwrap();
        let read_val: u8 = vm.get_memory().read_obj_from_addr(obj_addr).unwrap();
        assert_eq!(read_val, 67u8);
    }

    #[test]
    fn create_vcpu() {
        let kvm = Kvm::new().unwrap();
        let gm = GuestMemory::new(&vec![(GuestAddress(0), 0x10000)]).unwrap();
        let mut vm = Vm::new(&kvm, gm).unwrap();
        Vcpu::new(0, &mut vm).unwrap();
    }

    #[test]
    fn run_code() {
        use std::io::{self, Write};
        // This example based on https://lwn.net/Articles/658511/
        let code = [
            0xba, 0xf8, 0x03 /* mov $0x3f8, %dx */, 0x00, 0xd8 /* add %bl, %al */, 0x04,
            '0' as u8 /* add $'0', %al */, 0xee /* out %al, (%dx) */, 0xb0,
            '\n' as u8 /* mov $'\n', %al */, 0xee /* out %al, (%dx) */,
            0xf4 /* hlt */,
        ];

        let mem_size = 0x1000;
        let load_addr = GuestAddress(0x1000);
        let mem = GuestMemory::new(&vec![(load_addr, mem_size)]).unwrap();

        let kvm = Kvm::new().expect("new kvm failed");
        let mut vm = Vm::new(&kvm, mem).expect("new vm failed");
        vm.get_memory()
            .write_slice_at_addr(&code, load_addr)
            .expect("Writing code to memory failed.");

        let vcpu = Vcpu::new(0, &mut vm).expect("new vcpu failed");

        let mut vcpu_sregs = vcpu.fd.get_sregs().expect("get sregs failed");
        assert_ne!(vcpu_sregs.cs.base, 0);
        assert_ne!(vcpu_sregs.cs.selector, 0);
        vcpu_sregs.cs.base = 0;
        vcpu_sregs.cs.selector = 0;
        vcpu.fd.set_sregs(&vcpu_sregs).expect("set sregs failed");

        let mut vcpu_regs = vcpu.fd.get_regs().expect("get regs failed");
        vcpu_regs.rip = 0x1000;
        vcpu_regs.rax = 2;
        vcpu_regs.rbx = 3;
        vcpu_regs.rflags = 2;
        vcpu.fd.set_regs(&vcpu_regs).expect("set regs failed");

        loop {
            match vcpu.run().expect("run failed") {
                VcpuExit::IoOut(0x3f8, data) => {
                    assert_eq!(data.len(), 1);
                    io::stdout().write(data).unwrap();
                }
                VcpuExit::Hlt => {
                    io::stdout().write(b"KVM_EXIT_HLT\n").unwrap();
                    break;
                }
                r => panic!("unexpected exit reason: {:?}", r),
            }
        }
    }
}
