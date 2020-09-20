use gdbstub::{
    arch, BreakOp, OptResult, StopReason, Target, Tid, WatchKind, SINGLE_THREAD_TID,
};

use super::{Debugger, DebugEvent, Receiver, Sender, ResumeAction};
use super::{Bytes, GuestAddress, GuestMemoryMmap};
use crate::DynResult;

pub struct FirecrackerGDBServer {
    pub guest_memory: GuestMemoryMmap,

    pub vcpu_event_receiver: Receiver<DebugEvent>,
    pub vcpu_event_sender: Sender<DebugEvent>,

    pub breakpoints: Vec<(u8, u64)>,

    pub single_step_en: bool,
}

impl FirecrackerGDBServer {
    pub fn new(guest_memory: GuestMemoryMmap,
        vcpu_event_receiver: Receiver<DebugEvent>,
        vcpu_event_sender: Sender<DebugEvent>) -> DynResult <FirecrackerGDBServer > {
        Ok(FirecrackerGDBServer{guest_memory, vcpu_event_receiver,
            vcpu_event_sender, breakpoints: Vec::new(), single_step_en: false})
    }

    pub fn remove_bp(&mut self, addr : u64) {
        for (idx, it) in self.breakpoints.iter().enumerate() {
            if it.1 == addr {
                self.guest_memory.write_obj(it.0, GuestAddress(addr))
                        .expect("Failed removing interrupt");

                self.breakpoints.remove(idx);
                break;
            }
        }
    }
    pub fn insert_bp(&mut self, phys_addr: u64) {
        let int3: u8 = 0xCC;
        let entry_addr: u64 = 0x1000000;

        if phys_addr != entry_addr {
            self.vcpu_event_sender.send(DebugEvent::BREAKPOINT).unwrap();
        }

        let opcode: u8 = self.guest_memory.read_obj(GuestAddress(phys_addr)).unwrap();
        self.breakpoints.push((opcode, phys_addr));
        self.guest_memory.write_obj(int3, GuestAddress(phys_addr))
                        .expect("Failed inserting interrupt");
    }
}

impl Target for FirecrackerGDBServer {
    type Arch = arch::x86::X86_64;
    type Error = &'static str;
    
    fn resume(
        &mut self,
        actions: gdbstub::Actions,
        check_gdb_interrupt: &mut dyn FnMut() -> bool,
    ) -> Result<(Tid, StopReason<u64>), Self::Error> {
        for item in actions {
            match item.1 {
                ResumeAction::Continue => {
                    self.vcpu_event_sender.send(DebugEvent::CONTINUE(self.single_step_en)).unwrap();
                    self.single_step_en = false;
                    while !check_gdb_interrupt() {
                        match self.vcpu_event_receiver.try_recv() {
                            Ok(DebugEvent::PRINT_PTs(cr3)) => {
                                println!("Printing PTs...");
                                for i in 0..512 {
                                    let addr: u64 = cr3 & 0x000ffffffffff000u64;
                                    let data: u64 = self.guest_memory.read_obj(GuestAddress(addr + i * 8)).unwrap();
                                    println!("{:x?} : {:x?}", addr + i * 8, data);
                                }
                                // A better return value would probably be SwBreak, but
                                // there are some problems regarding the thread id that
                                // gdbstub chooses to return for that case
                                return Ok((SINGLE_THREAD_TID, StopReason::GdbInterrupt));
                            }
                            Ok(_) => { println!("Wrong message type"); break; }
                            Err(_) => {}
                        }
                    }
                    // This can be reached either by a 0x03 signal from the client or by a
                    // connection error occurring. It is not clear for now what the return
                    // value should be
                    return Ok((SINGLE_THREAD_TID, StopReason::Halted));
                }
                ResumeAction::Step => {
                    self.vcpu_event_sender.send(DebugEvent::STEP_INTO(self.single_step_en)).unwrap();
                    // Main thread will take care of what it means enabling/disabling single-stepping
                    self.single_step_en = true;
                    loop {
                        match self.vcpu_event_receiver.try_recv() {
                            Ok(DebugEvent::PRINT_PTs(cr3)) =>
                                return Ok((SINGLE_THREAD_TID, StopReason::DoneStep)),
                            Ok(_) => { println!("Wrong message type"); break;}
                            Err(_) => {}
                        }
                    }
                    return Ok((SINGLE_THREAD_TID, StopReason::Halted));
                }
            }
        }
        Err("Continue/Step op failed")
    }

    fn read_registers(
        &mut self,
        regs: &mut arch::x86::reg::X86_64CoreRegs,
    ) -> Result<(), Self::Error> {
        self.vcpu_event_sender.send(DebugEvent::GET_REGS).unwrap();
        match self.vcpu_event_receiver.recv() {
            Ok(DebugEvent::PEEK_REGS(state)) => {
                regs.regs[0] = state.regular_regs.rax;
                regs.regs[1] = state.regular_regs.rbx;
                regs.regs[2] = state.regular_regs.rcx;
                regs.regs[3] = state.regular_regs.rdx;
                regs.regs[4] = state.regular_regs.rsi;
                regs.regs[5] = state.regular_regs.rdi;
                regs.regs[6] = state.regular_regs.rbp;
                regs.regs[7] = state.regular_regs.rsp;

                regs.regs[8] = state.regular_regs.r8;
                regs.regs[9] = state.regular_regs.r9;
                regs.regs[10] = state.regular_regs.r10;
                regs.regs[11] = state.regular_regs.r11;
                regs.regs[12] = state.regular_regs.r12;
                regs.regs[13] = state.regular_regs.r13;
                regs.regs[14] = state.regular_regs.r14;
                regs.regs[15] = state.regular_regs.r15;

                regs.rip = state.regular_regs.rip;
                regs.eflags = state.regular_regs.rflags as u32;
            }
            Ok(_) => println!("Error! Expecting PEEK_REGS packet"),
            Err(_) => println!("Error receiving regs"),
        }
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
        // The address passed to the "m" packet can be of the form 0x1000000
        // or 0xffffff.... so u have to be prepared
        for i in 0..val.len() {
            val[i] = self.guest_memory.read_obj(GuestAddress((addrs & 0xfffffff) + (i as u64))).unwrap();
        }
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
        //let phys_addr = Debugger::virt_to_phys(linear_addr, &self).unwrap();
        let phys_addr = addr & 0xfffffff;

        match op {
            BreakOp::Add => self.insert_bp(phys_addr),
            BreakOp::Remove => self.remove_bp(phys_addr),
        }
        
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