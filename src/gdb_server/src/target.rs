use gdbstub::{
    arch, BreakOp, OptResult, StopReason, Target, Tid, TidSelector, WatchKind, SINGLE_THREAD_TID, Actions,
};

use super::{DebuggerError, Debugger, DebugEvent, Receiver, Sender, ResumeAction, FullVcpuState};
use super::{Bytes, GuestAddress, GuestMemoryMmap, Elf64_Phdr};
use crate::DynResult;

pub struct FirecrackerGDBServer {
    pub guest_memory: GuestMemoryMmap,

    pub vcpu_event_receiver: Receiver<DebugEvent>,
    pub vcpu_event_sender: Sender<DebugEvent>,
    // Stores (real opcode, linear address)
    pub breakpoints: Vec<(u8, u64)>,
    pub guest_state: FullVcpuState,
    pub single_step_en: bool,

    pub e_phdrs: Vec<Elf64_Phdr>,
}

impl FirecrackerGDBServer {
    pub fn new(guest_memory: GuestMemoryMmap,
        vcpu_event_receiver: Receiver<DebugEvent>,
        vcpu_event_sender: Sender<DebugEvent>,
        e_phdrs: Vec<Elf64_Phdr>) -> DynResult <FirecrackerGDBServer > {
        Ok(FirecrackerGDBServer{guest_memory, vcpu_event_receiver, vcpu_event_sender,
            breakpoints: Vec::new(), guest_state: Default::default(), single_step_en: false, e_phdrs})
    }

    pub fn remove_bp(&mut self, phys_addr: u64) -> Result<(), DebuggerError> {
        for (idx, it) in self.breakpoints.iter().enumerate() {
            if it.1 == phys_addr {
                if self.guest_memory.write_obj(it.0, GuestAddress(phys_addr)).is_err() {
                    return Err(DebuggerError::MemoryError);
                }

                self.breakpoints.remove(idx);
                break;
            }
        }

        Ok(())
    }
    pub fn insert_bp(&mut self, phys_addr: u64) -> Result<(), DebuggerError>{
        // Opcode specific to x86 architecture that triggers a trap when
        // encountered during cpu execution
        let int3: u8 = 0xCC;

        let opcode: u8;
        if let Ok(byte) = self.guest_memory.read_obj(GuestAddress(phys_addr)) {
            opcode = byte;
        } else {
            return Err(DebuggerError::MemoryError);
        }

        self.breakpoints.push((opcode, phys_addr));

        if self.guest_memory.write_obj(int3, GuestAddress(phys_addr)).is_err() {
            return Err(DebuggerError::MemoryError);
        }

        Ok(())
    }

    /// Normally, when a continue/single-step packet is received from the client,
    /// no breakpoint should exist at the current address, as it would cause an
    /// unwanted trap. The client takes care of this by removing the breakpoint
    /// each time right after using it and re-inserting it after the current
    /// instruction was executed.
    /// A problem occurs when the client is not aware of a breakpoint existing
    /// (during early boot, the breakpoint may be set at linear address 0xffffffff81000007,
    /// but the eip would show 0x1000007 - the physical address). In this case,
    ///  we solve the problem on the server side.
    fn invalid_state(&self, rip: u64) -> bool {
        for it in self.breakpoints.iter() {
            if it.1 == rip {
                return true;
            }
        }
        return false;
    }
}

impl Target for FirecrackerGDBServer {
    type Arch = arch::x86::X86_64;
    type Error = DebuggerError;
    
    /// Function that is called when a continue/single-step packet is received from client
    fn resume(
        &mut self,
        actions: Actions,
        check_gdb_interrupt: &mut dyn FnMut() -> bool,
    ) -> Result<(Tid, StopReason<u64>), Self::Error> {
        let mut ret: Option<StopReason<u64>> = None;

        for item in actions {
            let invalid_state = self.invalid_state(self.guest_state.regular_regs.rip);
            let prev_bp_addr = Debugger::virt_to_phys(self.guest_state.regular_regs.rip, 
                &self, &self.guest_state).unwrap();
            match item.1 {
                ResumeAction::Continue => {
                    // Client has failed in removing the bp before continuing
                    if invalid_state {
                        if let Err(e) = self.remove_bp(prev_bp_addr) {
                            return Err(e);
                        }
                        if self.vcpu_event_sender.send(DebugEvent::STEP_INTO(self.single_step_en)).is_err() {
                            return Err(Self::Error::ChannelError);
                        }
                        self.single_step_en = true;

                        if let Ok(DebugEvent::NOTIFY) = self.vcpu_event_receiver.recv() {
                            if let Err(e) = self.insert_bp(prev_bp_addr) {
                                return Err(e);
                            }
                        } else {
                            return Err(Self::Error::ChannelError);
                        }
                    }
                    if self.vcpu_event_sender.send(DebugEvent::CONTINUE(self.single_step_en)).is_err() {
                        return Err(Self::Error::ChannelError);
                    }
                    self.single_step_en = false;
                    while !check_gdb_interrupt() {
                        if let Ok(DebugEvent::NOTIFY) = self.vcpu_event_receiver.try_recv() {
                            // A better return value would probably be SwBreak, but
                            // there are some problems regarding the thread id that
                            // gdbstub chooses to return for that case
                            ret = Some(StopReason::GdbInterrupt);
                            break;
                        }
                    }
                    if ret.is_some() {
                        continue;
                    }
                    // This can be reached only as a result of a Ctrl-C signal
                    return Ok((SINGLE_THREAD_TID, StopReason::Halted));
                }
                ResumeAction::Step => {
                    if invalid_state {
                        if let Err(e) = self.remove_bp(prev_bp_addr) {
                            return Err(e);
                        }
                    }
                    if self.vcpu_event_sender.send(DebugEvent::STEP_INTO(self.single_step_en)).is_err() {
                        return Err(Self::Error::ChannelError);
                    }
                    // Main thread will take care of what it means enabling/disabling single-stepping
                    self.single_step_en = true;
                    while !check_gdb_interrupt() {
                        if let Ok(DebugEvent::NOTIFY) = self.vcpu_event_receiver.try_recv() {
                            if invalid_state {
                                if let Err(e) = self.insert_bp(prev_bp_addr) {
                                    return Err(e);
                                }
                            }
                            ret = Some(StopReason::DoneStep);
                            break;
                        }
                    }
                    if ret.is_some() {
                        continue;
                    }
                    return Ok((SINGLE_THREAD_TID, StopReason::Halted));
                }
            }
        }
        if ret.is_some() {
            // Guest registers' values are needed throughout the entire execution and
            // the state can be requested by the client at any point in time.
            // In order to reduce the number of ioctl calls and channel messages,
            // we only perform this operation once after each continue/single-step.
            // Since the guest is not the only one that alters its state (the GDB client
            // can do it too), when this happens, we must also ensure that our local
            // "cache" is also properly updated
            if self.vcpu_event_sender.send(DebugEvent::GET_REGS).is_err() {
                return Err(Self::Error::ChannelError);
            }
            if let Ok(DebugEvent::PEEK_REGS(state)) = self.vcpu_event_receiver.recv() {
                self.guest_state = state;
                return Ok((SINGLE_THREAD_TID, ret.unwrap()));
            } else {
                return Err(Self::Error::ChannelError);
            }
        }

        Err(Self::Error::InvalidState)
    }

    /// Function that is called when the user or the GDB client requests the guest state
    fn read_registers(
        &mut self,
        regs: &mut arch::x86::reg::X86_64CoreRegs,
    ) -> Result<(), Self::Error> {
        regs.regs[0] = self.guest_state.regular_regs.rax;
        regs.regs[1] = self.guest_state.regular_regs.rbx;
        regs.regs[2] = self.guest_state.regular_regs.rcx;
        regs.regs[3] = self.guest_state.regular_regs.rdx;
        regs.regs[4] = self.guest_state.regular_regs.rsi;
        regs.regs[5] = self.guest_state.regular_regs.rdi;
        regs.regs[6] = self.guest_state.regular_regs.rbp;
        regs.regs[7] = self.guest_state.regular_regs.rsp;

        regs.regs[8] = self.guest_state.regular_regs.r8;
        regs.regs[9] = self.guest_state.regular_regs.r9;
        regs.regs[10] = self.guest_state.regular_regs.r10;
        regs.regs[11] = self.guest_state.regular_regs.r11;
        regs.regs[12] = self.guest_state.regular_regs.r12;
        regs.regs[13] = self.guest_state.regular_regs.r13;
        regs.regs[14] = self.guest_state.regular_regs.r14;
        regs.regs[15] = self.guest_state.regular_regs.r15;

        regs.rip = self.guest_state.regular_regs.rip;
        regs.eflags = self.guest_state.regular_regs.rflags as u32;

        return Ok(());
    }

    fn write_registers(
        &mut self,
        regs: &arch::x86::reg::X86_64CoreRegs,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Function that is called when the user or the GDB client requests a number of val.len
    /// bytes from the guest memory at address 'addrs'
    fn read_addrs(
        &mut self,
        addrs: u64,
        val: &mut [u8],
    ) -> Result<bool, Self::Error> {
        return Debugger::virt_to_phys(addrs, &self, &self.guest_state)
            .and_then(|phys_addr: u64| -> Result<bool, Self::Error> {
                for i in 0..val.len() {
                    if let Ok(byte) = self.guest_memory.read_obj(GuestAddress(phys_addr + (i as u64))) {
                        val[i] = byte;
                    } else {
                        return Err(Self::Error::MemoryError);
                    }
                }
                Ok(true)
            } );
    }

    fn write_addrs(
        &mut self,
        start_addr: u64,
        data: &[u8],
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    /// Function called when the user or the GDB client request the insertion/removal of a
    /// software breakpoint
    fn update_sw_breakpoint(
        &mut self,
        addr: u64,
        op: BreakOp,
    ) -> Result<bool, Self::Error> {
        return Debugger::virt_to_phys(addr, &self, &self.guest_state)
            .and_then(|phys_addr: u64| -> Result<bool, Self::Error>{
                match op {
                    BreakOp::Add => self.insert_bp(phys_addr),
                    BreakOp::Remove => self.remove_bp(phys_addr),
                }.map(|_| true)
            });
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