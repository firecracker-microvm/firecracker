use gdbstub::{
    arch, BreakOp, OptResult, ResumeAction, StopReason, Target, Tid, TidSelector, WatchKind, SINGLE_THREAD_TID,
};

use super::{kvm_translation, kvm_sregs};
use super::{Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion, ByteValued};
use super::VcpuFd;
use crate::DynResult;

const CR0_PG : u64 = 0x80000000;
const CR4_PAE : u64 = 0x00000020;
const CR4_LA57 : u64 = 0x00001000;
const CR4_PSE : u64 = 0x00000010;
const EFER_LME : u64 = 0x00000100;
const EFER_LMA : u64 = 0x00000400;
const PDPTE_PS : u64 = 0x00000080;
const PDE_PS : u64 = 0x00000080;
#[derive(PartialEq, Eq, Debug)]
enum PAGING_TYPE {
    NONE,
    _32BIT,
    PAE,
    _4LVL,
    _5LVL,
}

pub struct FirecrackerGDBServer<'a> {
    guest_memory : &'a GuestMemoryMmap,
    vcpu : &'a VcpuFd,
}

impl<'a> FirecrackerGDBServer<'a> {
    pub fn new<'b>(guest_memory: &'b GuestMemoryMmap, vcpu: &'b VcpuFd) -> DynResult <FirecrackerGDBServer<'b>> {
        Ok(FirecrackerGDBServer{guest_memory, vcpu})
    }
}

impl<'a> Target for FirecrackerGDBServer<'a> {
    type Arch = arch::x86::X86_64;
    type Error = &'static str;
    
    fn resume(
        &mut self,
        actions: gdbstub::target::Actions,
        check_gdb_interrupt: &mut dyn FnMut() -> bool,
    ) -> Result<(Tid, StopReason<u64>), Self::Error> {
        Ok((SINGLE_THREAD_TID, StopReason::DoneStep))
    }

    fn read_registers(
        &mut self,
        regs: &mut arch::x86::reg::X86_64CoreRegs,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &arch::x86::reg::X86_64CoreRegs,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn read_addrs(
        &mut self,
        addrs: u64,
        val: &mut [u8],
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    fn write_addrs(
        &mut self,
        start_addr: u64,
        data: &[u8],
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    fn update_sw_breakpoint(
        &mut self,
        addr: u64,
        op: BreakOp,
    ) -> Result<bool, Self::Error> {
        let int3: u8 = 0xCC;
        let mut linear_addr : u64 = addr;

        /*
        match self.vcpu.translate(new_addr) {
            Ok(t) => println!("...Linear address {:x?} -> Physical address {:x?}", new_addr, t.physical_address),
            Err(_) => println!("Translation failed"),
        }
        */

        let context : kvm_sregs;
        let mut pt_level = PAGING_TYPE::NONE;
        match self.vcpu.get_sregs() {
            Ok(sregs) => context = sregs,
            Err(_) => return Err("Error retrieving registers"),
        }
        // Paging enabled
        if context.cr0 & CR0_PG == 0 {

        // Determine the type of paging
        } else {
            // See Table 4.1, Volume 3A in Intel Arch SW Developer's Manual
            pt_level = 
            if context.cr4 & CR4_LA57 != 0 {
                PAGING_TYPE::_5LVL
            } else {
                if context.efer & EFER_LME != 0 {
                    PAGING_TYPE::_4LVL
                } else {
                    if context.cr4 & CR4_PAE != 0 {
                        PAGING_TYPE::PAE
                    } else {
                        PAGING_TYPE::_32BIT
                    }
                }
            }
        }
        println!("cr4 = {:x?}; cr3 = {:x?} efer={:x?}", context.cr4, context.cr3, context.efer);
        println!("Paging type: {:?}", pt_level);

        let mut paddr: u64 = 0;
        let mut mask : u64 = 0;
        let mut movem = 0;
        if pt_level == PAGING_TYPE::PAE {
            linear_addr &= 0x00000000ffffffffu64;
            mask =  0x0000007fc0000000u64;

            paddr = context.cr3 & 0x00000000ffffffe0u64;
        } else {
            if pt_level == PAGING_TYPE::_4LVL {
                // Translation from 48 bits linear address
                // to 52 bits physical address
                linear_addr &= 0x0000ffffffffffffu64;
                mask =  0x0000ff8000000000u64;

                paddr = context.cr3 & 0x000ffffffffff000u64;
                movem = 36;
            } else {
                // Performs a translation from 32 bits linear address
                // to a 40 bits physical address
                if pt_level == PAGING_TYPE::_32BIT {
                    // The PDE physical address contains
                    // on 31:12 -> bits 31:12 from cr3
                    // on 11:2 -> bits 31:22 from the linear address
                    // on 1:0 -> 0
                    linear_addr &= 0x00000000ffffffffu64;
                    mask =  0x00000000ffc00000u64;

                    paddr = context.cr3 & 0x00000000fffff000u64;
                    movem = 20;
                }
            }
        }
        println!("Linear address: {:x?}", linear_addr);
        let mut d : u64; 
        let mut add : u64 = 0x9000;
        for i in 1..512 {
            d = self.guest_memory.read_obj(GuestAddress(add)).unwrap();
            println!("{:x?} : {:x?}", add, d);
            add += 8;
        }
        paddr += (linear_addr & mask) >> movem;
        let mut table_entry: u64 = self.guest_memory.read_obj(GuestAddress(paddr)).unwrap();
        println!("PML4={:x?} and PML4E content={:x?}", paddr, table_entry);

        mask >>= 9;
        movem -= 9;
        paddr = table_entry & 0x000ffffffffff000u64;
        paddr += (linear_addr & mask) >> movem;
        table_entry = self.guest_memory.read_obj(GuestAddress(paddr)).unwrap();
        println!("PDPT={:x?} and PDPTE content={:x?}", paddr, table_entry);

        if table_entry & PDPTE_PS != 0 {
            // translation to 1GB page
            println!("Translation to 1GB page");
            paddr = table_entry & 0x000fffffc0000000u64;
            // Final address
            paddr += linear_addr & 0x3fffffffu64;
        } else {
            // translation to 2MB page
            println!("Translation to 2MB page");
            mask >>= 9;
            movem -= 9;
            paddr = table_entry & 0x000ffffffffff000u64;
            paddr += (linear_addr & mask) >> movem;

            table_entry = self.guest_memory.read_obj(GuestAddress(paddr)).unwrap();
            println!("Page directory addr: {:x?} and PDE: {:x?}", paddr, table_entry);
            if table_entry & PDE_PS != 0 {
                // Final address
                paddr = table_entry & 0x000ffffffff00000u64;
                paddr += linear_addr & 0xfffff;
            } else {
                mask >>= 9;
                movem -= 9;
                paddr = table_entry & 0x000ffffffffff000u64;
                paddr += (linear_addr & mask) >> movem;

                table_entry = self.guest_memory.read_obj(GuestAddress(paddr)).unwrap();
                println!("2MB page addr: {:x?} and the entry: {:x?}", paddr, table_entry);
                // Final address
                paddr = table_entry & 0x000ffffffffff000u64;
                paddr += linear_addr & 0xfff;
            }
        }
        let data: u64 = self.guest_memory.read_obj(GuestAddress(paddr)).unwrap();
        println!("Final address: {:x?} and data: {:x?}", paddr, data);
        //if context.cr4 & CR4_PSE == 0 {
            
            // The PTE physical address contains
            // on 31:12 -> 31:12 from pde
            // on 11:2 -> 21:12 from the linear address
            // on 1:0 -> 0
        
        /*    mask >>= 10;
            paddr = pde & (!0xfffu64);
            paddr += (linear_addr & mask) >> 10;
            let raw_pte: u32 = self.guest_memory.read_obj(GuestAddress(paddr)).unwrap();
            let pte: u64 = raw_pte.into();
            println!("PTE address: {:x?} and content: {}", paddr, pte);
        */    
            // The final physical address contains
            // on 31:12 -> 31:12 from pte
            // on 11:0 -> 11:0 from the linear address
        /*    mask = 0xfff;
            paddr = pte & (!0xfffu64);
            paddr += linear_addr & mask;
            let data: u32 = self.guest_memory.read_obj(GuestAddress(0x1000000 + paddr)).unwrap();
            println!("At address {:x?} it's {}", paddr, data);
        */
        //}

        //self.guest_memory.write_obj(int3, GuestAddress(new_addr));
        Ok(true)
    }

    fn update_hw_breakpoint(
        &mut self,
        addr: u64,
        op: BreakOp,
    ) -> OptResult<bool, Self::Error> {
        Ok(false)
    }

    fn update_hw_watchpoint(
        &mut self,
        addr: u64,
        op: BreakOp,
        kind: WatchKind,
    ) -> OptResult<bool, Self::Error> {
        Ok(false)
    }
}