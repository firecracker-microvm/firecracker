#[cfg(target_arch = "x86_64")]
pub use arch::x86_64::regs::setup_sregs;

use crate::vm_memory::Bytes;

use super::{GuestAddress, GuestMemoryMmap};
use super::kvm_bindings::*;

// If 1, enable paging and use the § CR3 register, else disable paging.
const CR0_PG_MASK: u64 = 1 << 31;

// 4 level paging - Enabling PAE (by setting bit 5, PAE, of the system register CR4)
// If set, changes page table layout to translate 32-bit virtual addresses into extended 36-bit
// physical addresses.
const CR4_PAE_MASK: u64 = 1 << 5;

// 5 level paging - Likewise, the new extension is enabled by setting bit 12 of the CR4 register
// (known as LA57). If the bit is not set, the processor operates with four paging levels.
const CR4_LA57_MASK: u64 = 1 << 12;

// Long mode Active
// when BIT 10 of Extended Feature Enable Register (EFER) register is set,
// it indicates long mode is active
const MSR_EFER_LMA: u64 = 1 << 10;

// bits 12 through 51 are the address in a PTE.
// fffff & !0x0fff
// Bit mask for Page Number
const PTE_ADDR_MASK: u64 = ((1 << 52) - 1) & !0x0fff;

// If more than 12 bits remain in the linear address, bit 7 (PS — page size) of the current
// paging-structure entry is consulted. If the bit is 0, the entry references
// another paging structure;
const PAGE_PSE_MASK: u64 = 0x1 << 7;

// See Chapter 4.7, Volume 3A in Intel Arch SW Developer's Manual.
// Bit 0 in any level's page table entry. Marks whether a valid translation
// is available
const PAGE_PRESENT: u64 = 0x1;

//Paging types
const PAGE_SIZE_4K: u64 = 4 * 1024;
const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    UnsupportedPagingStrategy,
    VirtAddrTranslationError,
}

#[derive(Default, Clone)]
pub struct FullVcpuState {
    pub regular_regs: kvm_regs,
    pub special_regs: kvm_sregs,
}

pub type Result<T> = std::result::Result<T, Error>;

//https://github.com/crash-utility/crash/blob/master/qemu.c#L72
fn virt_to_phys(
    vaddr: u64,
    guest_memory: &GuestMemoryMmap,
    guest_state: &FullVcpuState,
) -> Result<(u64, u64)> {
    // Moves from one page table entry to next page table entry.
    fn walk(
        guest_memory: &GuestMemoryMmap,
        table_entry: u64,
        vaddr: u64,
        page_level: usize,
    ) -> Result<u64> {
        let page_number = table_entry & PTE_ADDR_MASK;
        let paddr = page_number + page_table_offset(vaddr, page_level);
        let next_entry: u64 = guest_memory.read_obj(GuestAddress(paddr))
            .map_err(|_| Error::VirtAddrTranslationError)?;

        Ok(next_entry)
    }

    fn page_offset(vaddr: u64, page_size: u64) -> u64 {
        // Offset = (address reference % page size)
        // vaddr % page_size
        vaddr & (page_size - 1)
    }

    fn page_table_offset(addr: u64, level: usize) -> u64 {
        // 12 bits offset with 9 bits of for each level.
        let offset = (level - 1) * 9 + 12;
        // Shifting right to 12 bits in binary is equivalent to shifting
        // a hexadecimal number 3 places to the right
        // eg - (((addr >> 39) & 0x1ff) << 3))
        ((addr >> offset) & 0x1ff) << 3
    }

    if guest_state.special_regs.cr0 & CR0_PG_MASK == 0 {
        return Ok((vaddr, PAGE_SIZE_4K));
    }

    if guest_state.special_regs.cr4 & CR4_PAE_MASK == 0 {
        return Err(Error::VirtAddrTranslationError);
    }

    if guest_state.special_regs.efer & MSR_EFER_LMA != 0 {
        let mut pg_lvl_5_ent: Option<u64> = None;
        let pg_lvl_4_ent;

        if guest_state.special_regs.cr4 & CR4_LA57_MASK != 0 {
            // 5 level paging enabled
            // The first paging structure used for any translation is located at the physical address in CR3
            pg_lvl_5_ent = Some(walk(guest_memory, guest_state.special_regs.cr3, vaddr, 5)?);
        }

        if let Some(ent) = pg_lvl_5_ent {
            pg_lvl_4_ent = walk(guest_memory, ent, vaddr, 4)?;
        } else {
            pg_lvl_4_ent = walk(guest_memory, guest_state.special_regs.cr3, vaddr, 4)?;
        }

        //Level 3
        let pg_lvl_3_ent = walk(guest_memory, pg_lvl_4_ent, vaddr, 3)?;
        // Till now, we have traversed 18 bits or 27 bits (for 5 level paging) and if we see
        // PAGE_PSE_MASK set, we clearly have space for a 1G page .
        if pg_lvl_3_ent & PAGE_PSE_MASK != 0 {
            // Find the page address through the page table entry
            let page_addr = pg_lvl_3_ent & PTE_ADDR_MASK;
            //Find the offset within the page through the linear address
            let offset = page_offset(vaddr, PAGE_SIZE_1G);
            //Physical address = page address + page offset
            let paddr = page_addr | offset;
            return Ok((paddr, PAGE_SIZE_1G));
        }

        //Level 2
        let pg_lvl_2_ent = walk(guest_memory, pg_lvl_3_ent, vaddr, 2)?;
        if pg_lvl_2_ent & PAGE_PSE_MASK != 0 {
            let page_addr = pg_lvl_2_ent & PTE_ADDR_MASK;
            let offset = page_offset(vaddr, PAGE_SIZE_2M);
            let paddr = page_addr | offset;
            return Ok((paddr, PAGE_SIZE_2M));
        }

        //Level 1
        let pg_lvl_1_ent = walk(guest_memory, pg_lvl_2_ent, vaddr, 1)?;
        let page_addr = pg_lvl_1_ent & PTE_ADDR_MASK;
        let offset = page_offset(vaddr, PAGE_SIZE_2M);
        let paddr = page_addr | offset;
        return Ok((paddr, PAGE_SIZE_4K));
    }

    Err(Error::VirtAddrTranslationError)
}
