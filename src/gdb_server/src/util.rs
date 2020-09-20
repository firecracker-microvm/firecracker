use super::target::FirecrackerGDBServer;

use super::kvm_bindings::*;
use super::{Bytes, GuestAddress, VcpuFd};

const CR0_PG : u64 = 0x80000000;
const CR4_PAE : u64 = 0x00000020;
const CR4_LA57 : u64 = 0x00001000;
const CR4_PSE : u64 = 0x00000010;
const EFER_LME : u64 = 0x00000100;
const EFER_LMA : u64 = 0x00000400;
const PDPTE_PS : u64 = 0x00000080;
const PDE_PS : u64 = 0x00000080;
#[derive(PartialEq, Eq, Debug)]
enum PagingType {
    NONE,
    _32BIT,
    PAE,
    _4LVL,
    _5LVL,
}

pub enum DebugEvent {
    START,
    PRINT_PTs(u64),
    GET_REGS,
    PEEK_REGS(FullVcpuState),
    CONTINUE(bool),
    STEP_INTO(bool),
    BREAKPOINT,
}

pub struct FullVcpuState {
    pub regular_regs : kvm_regs,
    pub special_regs : kvm_sregs,
}
pub struct Debugger;

impl Debugger {
    pub fn enable_kvm_debug(vcpu: &VcpuFd, step: bool) {
        let mut control : __u32 = 0;
        control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
        if (step) {
            control |= KVM_GUESTDBG_SINGLESTEP;
        }
        let debug_struct = kvm_guest_debug {
            control : control,
            pad : 0,
            arch : kvm_guest_debug_arch { debugreg : [0,0,0,0,0,0,0,0]},
        };
 
        match vcpu.set_guest_debug(&debug_struct) {
            Ok(_) => println!("Done setting the kvm guest debug flags"),
            Err(_) => println!("Setting of KVM_SET_GUEST_DEBUG failed"),
        }
    }

    pub fn virt_to_phys(addr: u64, srv: &FirecrackerGDBServer, regs: FullVcpuState) -> Result<u64, &'static str> {
        /*
        match self.vcpu.translate(new_addr) {
            Ok(t) => println!("...Linear address {:x?} -> Physical address {:x?}", new_addr, t.physical_address),
            Err(_) => println!("Translation failed"),
        }
        */
        let mut linear_addr = addr;
        let context : kvm_sregs;
        let mut pt_level = PagingType::NONE;
        
        context = regs.special_regs;
        // Paging enabled
        if context.cr0 & CR0_PG == 0 {

        // Determine the type of paging
        } else {
            // See Table 4.1, Volume 3A in Intel Arch SW Developer's Manual
            pt_level = 
            if context.cr4 & CR4_LA57 != 0 {
                PagingType::_5LVL
            } else {
                if context.efer & EFER_LME != 0 {
                    PagingType::_4LVL
                } else {
                    if context.cr4 & CR4_PAE != 0 {
                        PagingType::PAE
                    } else {
                        PagingType::_32BIT
                    }
                }
            }
        }
        println!("cr4 = {:x?}; cr3 = {:x?} efer={:x?}", context.cr4, context.cr3, context.efer);
        println!("Paging type: {:?}", pt_level);

        let mut paddr: u64 = 0;
        let mut mask : u64 = 0;
        let mut movem = 0;
        if pt_level == PagingType::PAE {
            linear_addr &= 0x00000000ffffffffu64;
            mask =  0x0000007fc0000000u64;

            paddr = context.cr3 & 0x00000000ffffffe0u64;
        } else {
            if pt_level == PagingType::_4LVL {
                // Translation from 48 bits linear address
                // to 52 bits physical address
                linear_addr &= 0x0000ffffffffffffu64;
                mask =  0x0000ff8000000000u64;

                paddr = context.cr3 & 0x000ffffffffff000u64;
                movem = 36;
            } else {
                // Performs a translation from 32 bits linear address
                // to a 40 bits physical address
                if pt_level == PagingType::_32BIT {
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
        // PML4 address after the kernel booting should be:
        // 1c0a000, to this u add, as below, the offset from the 

        println!("Linear address: {:x?}", linear_addr);
        paddr += (linear_addr & mask) >> movem;
        let mut table_entry: u64 = srv.guest_memory.read_obj(GuestAddress(paddr)).unwrap();
        println!("PML4={:x?} and PML4E content={:x?}", paddr, table_entry);

        mask >>= 9;
        movem -= 9;
        paddr = table_entry & 0x000ffffffffff000u64;
        paddr += (linear_addr & mask) >> movem;
        table_entry = srv.guest_memory.read_obj(GuestAddress(paddr)).unwrap();
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

            table_entry = srv.guest_memory.read_obj(GuestAddress(paddr)).unwrap();
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

                table_entry = srv.guest_memory.read_obj(GuestAddress(paddr)).unwrap();
                println!("2MB page addr: {:x?} and the entry: {:x?}", paddr, table_entry);
                // Final address
                paddr = table_entry & 0x000ffffffffff000u64;
                paddr += linear_addr & 0xfff;
            }
        }
        let data: u64 = srv.guest_memory.read_obj(GuestAddress(paddr)).unwrap();
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

        // Regs state after boot: cr0:80050033 cr3:1c0a005 cr4:7606b0 efer:d01
        Ok(paddr)
    }
}