use std::fmt::{Display, Formatter};
use vm_memory::Bytes;
use vmm_sys_util::errno::Error;

#[cfg(target_arch = "x86_64")]
pub use arch::x86_64::regs::setup_sregs;
pub use kernel::loader::elf::{Elf64_Phdr, PT_LOAD};

use super::kvm_bindings::*;
use super::{GuestAddress, GuestMemoryMmap, VcpuFd};

// See Chapter 2.5 (Control Registers), Volume 3A in Intel Arch SW Developer's Manual.
// Bit 0 of CR0 register on x86 architecture
const CR0_PG: u64 = 0x8000_0000;
// Bit 5 of CR4 register on x86 architecture
const CR4_PAE: u64 = 0x0000_0020;
// Bit 12 of CR4 register on x86 architecture
const CR4_LA57: u64 = 0x0000_1000;

// See Chapter 2.2.1 (Extended Feature Enable Register),
// Volume 3A in Intel Arch SW Developer's Manual.
// Bit 8 of IA32_EFER register on x86 architecture
const EFER_LME: u64 = 0x0000_0100;

// See Tables 4.16 - 4.18, Volume 3A in Intel Arch SW Developer's Manual.
// Bit 7 of a PDPT entry
const PDPTE_PS: u64 = 0x0000_0080;
// Bit 7 of a PD entry
const PDE_PS: u64 = 0x0000_0080;

// See Chapter 4.7, Volume 3A in Intel Arch SW Developer's Manual.
// Bit 0 in any level's page table entry. Marks whether a valid translation
// is available
const BIT_P: u64 = 0x1;

// [PML4E, PDPTE_PS0, PDPTE_PS1, PDE_PS0, PDE_PS1, PTE]
const TABLE_ENTRY_RSVD_BITS: [u64; 6] = [0x80, 0x0, 0x3fff_e000, 0x0, 0x1f_e000, 0x0];

// Bits 51:12 of register CR3 and mostly any page table entry that follows.
// These bits become part of the next level's entry address
const TABLE_ENTRY_MASK: u64 = 0x000f_ffff_ffff_f000u64;
// Bits 51:30 of a PDPT entry when PS flag is 1.
// These bits become part of a 1GB memory region start address
const PDPTE_PS_ENTRY_MASK: u64 = 0x000f_ffff_c000_0000u64;
// Bits 51:21 of PD entry when PS flag is 1.
// These bits become part of a 2MB page table start address
const PDE_PS_ENTRY_MASK: u64 = 0x000f_ffff_ffe0_0000u64;

// In 4-Level paging mode we only need first 52 bits
const LINEAR_ADDR_FULL_MASK: u64 = 0x0000_ffff_ffff_ffffu64;
// Mask of bits in the linear address that are to be part of PML4 entry address
const LINEAR_ADDR_PML4_MASK: u64 = 0x0000_ff80_0000_0000u64;
// Mask of bits in the linear address that are to be part of the final physical
// address together with bits from a PDPT entry when PS flag is 1
const LINEAR_ADDR_PDPTE_PS_MASK: u64 = 0x3fff_ffffu64;
// Mask of bits in the linear address that are to be part of the final physical
// address together with bits from a PD entry when PS flag is 1
const LINEAR_ADDR_PDE_PS_MASK: u64 = 0x1f_ffff;
// Mask of bits in the linear address that are to be part of the final physical
// address together with bits from a PT entry
const LINEAR_ADDR_PTE_MASK: u64 = 0xfff;

// Possible paging modes on x86 architecture
#[derive(PartialEq, Eq, Debug)]
enum PagingType {
    NONE,
    _32BIT,
    PAE,
    _4LVL,
    _5LVL,
}

pub enum DebugEvent {
    Notify(Box<FullVcpuState>),
    SetRegs(Box<FullVcpuState>),
    GetRegs,
    PeekRegs(Box<FullVcpuState>),
    Continue(bool),
    StepInto(bool),
}

#[derive(Default, Clone)]
pub struct FullVcpuState {
    pub regular_regs: kvm_regs,
    pub special_regs: kvm_sregs,
}

#[derive(Debug)]
pub enum DebuggerError {
    InvalidState,
    ChannelError,
    MemoryError,
    IoctlError(Error),
    InvalidLinearAddress,
    UnsupportedPagingStrategy,
}

impl Display for DebuggerError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            DebuggerError::InvalidState => write!(f, "[GDB Server] An invalid state was reached"),
            DebuggerError::ChannelError => write!(
                f,
                "[GDB Server] An error interrupted the GDB server - main thread communication"
            ),
            DebuggerError::MemoryError => write!(f, "[GDB Server] Failed access to guest memory"),
            DebuggerError::IoctlError(errno) => {
                write!(f, "[GDB Server] Failed ioctl call: {}", errno)
            }
            DebuggerError::InvalidLinearAddress => write!(
                f,
                "[GDB Server] An invalid linear address was passed from client"
            ),
            DebuggerError::UnsupportedPagingStrategy => write!(
                f,
                "A paging strategy that is not currently supported has been detected"
            ),
        }
    }
}

pub struct Debugger;

#[cfg(target_arch = "x86_64")]
impl Debugger {
    /// Enables KVM support for debugging. We make use of the capability
    /// of KVM to generate a KVM_EXIT either when encountering a breakpoint
    /// or after executing an instruction in single-step mode
    ///
    /// # Arguments
    ///
    /// * `vcpu` - reference of a vCPU object
    /// * `step` - tells whether we want to generate a KVM_EXIT when encountering
    ///             a breakpoint or after executing the next instruction (single-step)
    pub fn enable_kvm_debug(vcpu: &VcpuFd, step: bool) -> Result<(), DebuggerError> {
        let mut control: __u32 = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
        if step {
            control |= KVM_GUESTDBG_SINGLESTEP;
        }
        let debug_struct = kvm_guest_debug {
            control,
            pad: 0,
            arch: kvm_guest_debug_arch {
                debugreg: [0, 0, 0, 0, 0, 0, 0, 0],
            },
        };

        if let Err(errno) = vcpu.set_guest_debug(&debug_struct) {
            return Err(DebuggerError::IoctlError(errno));
        }

        Ok(())
    }

    /// Performs guest page-walking, on top of the 4-Level paging mechanism,
    /// obtaining the physical address corresponding to the one received from a GDB client.
    /// In case no valid entry is discovered in the page tables, the physical address
    /// will be obtained by directly subtracting an offset - computed by using information
    /// from the ELF executable only.
    ///
    /// See Chapter 4.5, Volume 3A in  Intel® 64 and IA-32 Architectures Software Developer’s Manual
    /// for a detailed description of how this paging strategy works.
    /// # Arguments
    ///
    /// * `addr`            - linear guest address to be translated.
    /// * `guest_memory`    - guest memory mapping, from which we read page table entries
    /// * `guest_state`     - current state of all guest registers, used in determining the paging
    ///                     strategy and the start address of the paging hierarchy
    /// * `e_phdrs`         - program headers of the kernel image, used in determining the physical
    ///                     address when paging is not available
    pub fn virt_to_phys(
        addr: u64,
        guest_memory: &GuestMemoryMmap,
        guest_state: &FullVcpuState,
        e_phdrs: &[Elf64_Phdr],
    ) -> Result<u64, DebuggerError> {
        let mut linear_addr = addr;
        let pt_level = Debugger::get_paging_strategy(&guest_state.special_regs);

        let mut paddr: u64;
        let mut mask: u64;
        let mut movem;
        if pt_level == PagingType::_4LVL {
            // Translation from 48 bits linear address
            // to 52 bits physical address
            linear_addr &= LINEAR_ADDR_FULL_MASK;
            mask = LINEAR_ADDR_PML4_MASK;

            paddr = guest_state.special_regs.cr3 & TABLE_ENTRY_MASK;
            // Shift value for the linear address bits in the PML4 entry address
            movem = 36;
        } else {
            return Err(DebuggerError::UnsupportedPagingStrategy);
        }

        // Computing address of PML4 entry address
        paddr += (linear_addr & mask) >> movem;

        let mut table_entry;
        // Retrieving PML4 entry
        if let Ok(e) = guest_memory.read_obj(GuestAddress(paddr)) {
            table_entry = e;
        } else {
            return Err(DebuggerError::MemoryError);
        }

        if Debugger::check_entry(table_entry, TABLE_ENTRY_RSVD_BITS[0]).is_err() {
            return Debugger::fixup_pointer(addr, e_phdrs);
        }

        // There is one loop iteration for each page-table level (PDPT, PDT, PT);
        // However, the way we check for the validity of the entry
        // changes for the first two, depending on the PS flag. Therefore,
        // we have to either keep track of the index in the TABLE_ENTRY_RSVD_BITS
        // array or create individual const symbols for each possible value or
        // const symbols for each index. We chose the first.
        let mut rsvd_idx = 0;
        for i in 0..3 {
            rsvd_idx = 2 * i + 1;

            // Number of bits (9) and the shift value (9) for the part of the linear address
            // that is used in the computation of next level's entry address are both
            // constant with the exception of PDPT and PD entries when PS flag is 1.
            // In that case, instead of ((addr & mask) >> movem) we simply use (addr & mask)
            mask >>= 9;
            movem -= 9;
            paddr = table_entry & TABLE_ENTRY_MASK;
            paddr += (linear_addr & mask) >> movem;
            if let Ok(e) = guest_memory.read_obj(GuestAddress(paddr)) {
                table_entry = e;
            } else {
                return Err(DebuggerError::MemoryError);
            }

            match i {
                // translation to 1GB page
                0 => {
                    if (table_entry & PDPTE_PS) != 0 {
                        // Final address
                        paddr = table_entry & PDPTE_PS_ENTRY_MASK;
                        paddr += linear_addr & LINEAR_ADDR_PDPTE_PS_MASK;
                        rsvd_idx = 2 * i + 2;
                        break;
                    }
                }
                1 => {
                    if (table_entry & PDE_PS) != 0 {
                        // Final address
                        paddr = table_entry & PDE_PS_ENTRY_MASK;
                        paddr += linear_addr & LINEAR_ADDR_PDE_PS_MASK;
                        rsvd_idx = 2 * i + 2;
                        break;
                    }
                }
                2 => {
                    // Final address
                    paddr = table_entry & TABLE_ENTRY_MASK;
                    paddr += linear_addr & LINEAR_ADDR_PTE_MASK;
                    break;
                }
                _ => {
                    return Err(DebuggerError::InvalidState);
                }
            }
            // After each page table iteration we check whether the current entry is valid.
            // If that is not the case, we try saving the translation process by skipping
            // the page tables altogether and using direct translation through offset subtraction.
            if Debugger::check_entry(table_entry, TABLE_ENTRY_RSVD_BITS[rsvd_idx]).is_err() {
                return Debugger::fixup_pointer(addr, e_phdrs);
            }
        }
        if Debugger::check_entry(table_entry, TABLE_ENTRY_RSVD_BITS[rsvd_idx]).is_err() {
            return Debugger::fixup_pointer(addr, e_phdrs);
        }

        Ok(paddr)
    }

    /// Determines the type of paging that is currently used by the guest.
    /// Bits from registers CR0, CR4 and IA32_EFER are used for determining
    /// the exact paging mode.
    ///
    /// See Table 4.1, Volume 3A in Intel Arch SW Developer's Manual.
    /// # Arguments
    ///
    /// * `context` - special registers corresponding to the current state of the vCPU   
    fn get_paging_strategy(context: &kvm_sregs) -> PagingType {
        let mut pt_level: PagingType = PagingType::NONE;
        // Paging enabled
        if context.cr0 & CR0_PG != 0 {
            pt_level = if context.cr4 & CR4_LA57 != 0 {
                PagingType::_5LVL
            } else if context.efer & EFER_LME != 0 {
                PagingType::_4LVL
            } else if context.cr4 & CR4_PAE != 0 {
                PagingType::PAE
            } else {
                PagingType::_32BIT
            }
        }
        pt_level
    }

    /// Checks whether the current table entry is valid (there is a valid translation
    /// for the linear address)
    ///
    /// See Chapter 4.7, Volume 3A in Intel Arch SW Developer's Manual.
    ///
    /// # Arguments
    ///
    /// * `entry`           - contents of a page table entry
    /// * `reserved_bits`   - depending on the actual page table the entry belongs to,
    ///                     values of bits that that should not be set.
    fn check_entry(entry: u64, reserved_bits: u64) -> Result<(), DebuggerError> {
        if entry & BIT_P == 0 {
            return Err(DebuggerError::InvalidLinearAddress);
        }
        if entry & reserved_bits != 0 {
            return Err(DebuggerError::InvalidLinearAddress);
        }

        Ok(())
    }

    /// Following the kernel strategy, during the early boot phase, before the notion
    /// of virtual addresses has been put in place, we obtain the corresponding
    /// physical address by subtracting the section offset.
    ///
    /// # Arguments
    ///
    /// * `addr`    - linear address for which a valid translation through the page table
    ///             mechanism was not found
    /// * `e_phdrs` - ELF program headers   
    fn fixup_pointer(addr: u64, e_phdrs: &[Elf64_Phdr]) -> Result<u64, DebuggerError> {
        for phdr in e_phdrs {
            if (phdr.p_type & PT_LOAD) == 0 {
                continue;
            }
            if (phdr.p_vaddr <= addr) && (phdr.p_vaddr + phdr.p_memsz > addr) {
                return Ok(addr - phdr.p_vaddr + phdr.p_paddr);
            }
        }

        Err(DebuggerError::InvalidLinearAddress)
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::setup_sregs;
    use kvm_ioctls::Kvm;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    #[test]
    fn test_virt_to_phys() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu_fd = vm.create_vcpu(0).unwrap();
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();

        setup_sregs(&gm, &vcpu_fd).unwrap();
        let state = super::FullVcpuState {
            regular_regs: vcpu_fd.get_regs().unwrap(),
            special_regs: vcpu_fd.get_sregs().unwrap(),
        };
        let e_phdrs = vec![
            super::Elf64_Phdr {
                p_type: super::PT_LOAD,
                p_flags: 0,
                p_offset: 0,
                p_vaddr: 0xffff_ffff_8100_0000,
                p_paddr: 0x100_0000,
                p_filesz: 11_984_896,
                p_memsz: 11_984_896,
                p_align: 0,
            },
            super::Elf64_Phdr {
                p_type: super::PT_LOAD,
                p_flags: 0,
                p_offset: 0,
                p_vaddr: 0xffff_ffff_81cc_a000,
                p_paddr: 0x1cc_a000,
                p_filesz: 4_243_456,
                p_memsz: 4_243_456,
                p_align: 0,
            },
        ];
        // Testing translation through identity-mapped page tables set by Firecracker.
        // These page tables cover the first 1GB of memory, therefore we can only go
        // as far as 0x3ffffff
        assert_eq!(
            super::Debugger::virt_to_phys(0x100_0000, &gm, &state, &e_phdrs).unwrap(),
            0x100_0000
        );
        assert_eq!(
            super::Debugger::virt_to_phys(0xf00_0000, &gm, &state, &e_phdrs).unwrap(),
            0xf00_0000
        );
        assert_eq!(
            super::Debugger::virt_to_phys(0x3f00_0000, &gm, &state, &e_phdrs).unwrap(),
            0x3f00_0000
        );
        assert_eq!(
            super::Debugger::virt_to_phys(0x3fff_ffff, &gm, &state, &e_phdrs).unwrap(),
            0x3fff_ffff
        );
        // Testing translation thorugh elf binary information
        assert_eq!(
            super::Debugger::virt_to_phys(0xffff_ffff_81cc_ab6b, &gm, &state, &e_phdrs).unwrap(),
            0x1cc_ab6b
        );
        assert_eq!(
            super::Debugger::virt_to_phys(0xffff_ffff_81cd_e9b1, &gm, &state, &e_phdrs).unwrap(),
            0x1cd_e9b1
        );
        assert_eq!(
            super::Debugger::virt_to_phys(0xffff_ffff_8136_5070, &gm, &state, &e_phdrs).unwrap(),
            0x136_5070
        );
    }
}
