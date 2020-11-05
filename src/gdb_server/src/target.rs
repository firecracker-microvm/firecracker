use std::collections::HashMap;

use gdbstub::{
    arch, Actions, BreakOp, OptResult, StopReason, Target, Tid, WatchKind, SINGLE_THREAD_TID,
};

use super::{Bytes, Elf64_Phdr, GuestAddress, GuestMemoryMmap};
use super::{DebugEvent, Debugger, DebuggerError, FullVcpuState, Receiver, ResumeAction, Sender};
use crate::DynResult;

pub struct FirecrackerGDBServer {
    pub guest_memory: GuestMemoryMmap,

    pub vcpu_event_receiver: Receiver<DebugEvent>,
    pub vcpu_event_sender: Sender<DebugEvent>,
    // Stores (real opcode, physical address, set)
    pub breakpoints_linear: HashMap<u64, (u8, u64, bool)>,
    // Stores (real opcode, set)
    pub breakpoints_phys: HashMap<u64, (u8, bool)>,
    // The guest state is retrieved only when NOTIFY is received (after continue
    // or single-step), although the client can request it at any time.
    // However, since the guest is not the only one that alters its state (the GDB client
    // can do it too), when this happens, we must also ensure that our local
    // "cache" is also properly updated
    pub guest_state: FullVcpuState,
    pub single_step_en: bool,

    pub e_phdrs: Vec<Elf64_Phdr>,
    pub entry_addr: GuestAddress,
}

impl FirecrackerGDBServer {
    pub fn new(
        guest_memory: GuestMemoryMmap,
        vcpu_event_receiver: Receiver<DebugEvent>,
        vcpu_event_sender: Sender<DebugEvent>,
        e_phdrs: Vec<Elf64_Phdr>,
        entry_addr: GuestAddress,
    ) -> DynResult<FirecrackerGDBServer> {
        Ok(FirecrackerGDBServer {
            guest_memory,
            vcpu_event_receiver,
            vcpu_event_sender,
            breakpoints_linear: HashMap::new(),
            breakpoints_phys: HashMap::new(),
            guest_state: Default::default(),
            single_step_en: false,
            e_phdrs,
            entry_addr,
        })
    }

    pub fn remove_bp(
        &mut self,
        linear_addr: u64,
        phys_addr: Option<u64>,
    ) -> Result<(), DebuggerError> {
        if phys_addr.is_some() && self.breakpoints_phys.contains_key(&phys_addr.unwrap()) {
            let val = self.breakpoints_phys.get_mut(&phys_addr.unwrap()).unwrap();
            if self
                .guest_memory
                .write_obj(val.0, GuestAddress(phys_addr.unwrap()))
                .is_err()
            {
                return Err(DebuggerError::MemoryError);
            }
            val.1 = false;

            return Ok(());
        }
        if phys_addr.is_none() && self.breakpoints_linear.contains_key(&linear_addr) {
            let val = self.breakpoints_linear.get_mut(&linear_addr).unwrap();
            if val.2 {
                if self
                    .guest_memory
                    .write_obj(val.0, GuestAddress(val.1))
                    .is_err()
                {
                    return Err(DebuggerError::MemoryError);
                }
                val.2 = false;
            }
        }

        Ok(())
    }
    pub fn insert_bp(&mut self, linear_addr: u64, translate: bool) -> Result<(), DebuggerError> {
        // Opcode specific to x86 architecture that triggers a trap when
        // encountered during cpu execution
        let int3: u8 = 0xCC;
        let mut opcode: Option<u8> = None;
        if self.breakpoints_linear.contains_key(&linear_addr) {
            let val = self.breakpoints_linear.get_mut(&linear_addr).unwrap();
            if !val.2 {
                if self
                    .guest_memory
                    .write_obj(int3, GuestAddress(val.1))
                    .is_err()
                {
                    return Err(DebuggerError::MemoryError);
                }
                val.2 = true;
            }
            return Ok(());
        }
        let mut phys_addr = linear_addr;
        // Breakpoint has never been set until now
        if translate {
            match Debugger::virt_to_phys(
                linear_addr,
                &self.guest_memory,
                &self.guest_state,
                &self.e_phdrs,
            ) {
                Ok(addr) => {
                    phys_addr = addr;
                }
                // We dont want to interrupt the whole debugging process because of an invalid address
                // This breakpoint simply wont be hit
                Err(_) => {
                    return Ok(());
                }
            }
        }
        // A breakpoint at the same physical address has already been placed
        // This is something the user is allowed to do, but shouldn't
        // In this case, however, the second breakpoint would read 0xCC
        // as the valid opcode found at the specific address. This would lead
        // to undefined behaviour.
        if self.breakpoints_phys.contains_key(&phys_addr) {
            opcode = Some(self.breakpoints_phys.get(&phys_addr).unwrap().0);
        }
        if !opcode.is_some() {
            if let Ok(byte) = self.guest_memory.read_obj(GuestAddress(phys_addr)) {
                opcode = Some(byte);
            } else {
                return Err(DebuggerError::MemoryError);
            }

            if self
                .guest_memory
                .write_obj(int3, GuestAddress(phys_addr))
                .is_err()
            {
                return Err(DebuggerError::MemoryError);
            }
        }

        self.breakpoints_linear
            .insert(linear_addr, (opcode.unwrap(), phys_addr, true));
        self.breakpoints_phys
            .insert(phys_addr, (opcode.unwrap(), true));

        Ok(())
    }

    /// We expect the user to be aware of the guest's internal state.
    /// In other words, we expect the user to place a breakpoint
    /// at a physical address when the guest references that code
    /// by a physical address and we expect the user to use a linear
    /// address for a point of execution at which the guest is
    /// virtual-address-aware (it has properly set the page tables).
    /// We cannot know at the moment the breakpoint is set whether
    /// the user does the right thing, but we can figure this out
    /// at the moment when a breakpoint is hit.
    /// Therefore, an invalid state is considered to be one in which
    /// the address contained by the RIP register is not among
    /// any of the addresses at which the user has set a breakpoint.
    /// When this is encountered, this breakpoint is ignored. Otherwise,
    /// it would confuse the client.
    fn invalid_state(&self, rip: u64) -> bool {
        if self.breakpoints_linear.contains_key(&rip)
            && self.breakpoints_linear.get(&rip).unwrap().2
        {
            return false;
        }
        return true;
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
        for item in actions {
            match item.1 {
                ResumeAction::Continue => {
                    // This loop can only be exited as a result of a Ctrl-C or of a
                    // valid breakpoint being hit
                    let mut valid_bp_not_reached = true;
                    while valid_bp_not_reached {
                        if self
                            .vcpu_event_sender
                            .send(DebugEvent::CONTINUE(self.single_step_en))
                            .is_err()
                        {
                            return Err(Self::Error::ChannelError);
                        }
                        self.single_step_en = false;
                        let mut interrupted = false;
                        while !check_gdb_interrupt() {
                            if let Ok(DebugEvent::NOTIFY(state)) =
                                self.vcpu_event_receiver.try_recv()
                            {
                                self.guest_state = state;
                                // Initial breakpoint was not set by the client, we must
                                // remove it manually
                                if self.guest_state.regular_regs.rip == self.entry_addr.0 {
                                    if let Err(e) = self.remove_bp(self.entry_addr.0, None) {
                                        return Err(e);
                                    }
                                    return Ok((SINGLE_THREAD_TID, StopReason::GdbInterrupt));
                                }
                                interrupted = true;
                                valid_bp_not_reached =
                                    self.invalid_state(self.guest_state.regular_regs.rip);
                                if valid_bp_not_reached {
                                    // Normally we shouldn't have to translate an address in order
                                    // to remove a breakpoint, but in early boot the virtual
                                    // address that EIP stores may not be the same one with
                                    // the address the user is thinking of, which would be, indeed,
                                    // an invalid one
                                    match Debugger::virt_to_phys(
                                        self.guest_state.regular_regs.rip,
                                        &self.guest_memory,
                                        &self.guest_state,
                                        &self.e_phdrs,
                                    ) {
                                        Ok(phys_addr) => {
                                            if let Err(e) = self.remove_bp(
                                                self.guest_state.regular_regs.rip,
                                                Some(phys_addr),
                                            ) {
                                                return Err(e);
                                            }
                                        }
                                        Err(e) => return Err(e),
                                    }
                                }
                                break;
                            }
                        }
                        if !interrupted {
                            // This can be reached only as a result of a Ctrl-C signal
                            return Ok((SINGLE_THREAD_TID, StopReason::Halted));
                        }
                    }
                    // A better return value would probably be SwBreak, but
                    // there are some problems regarding the thread id that
                    // gdbstub chooses to return for that case
                    return Ok((SINGLE_THREAD_TID, StopReason::GdbInterrupt));
                }
                ResumeAction::Step => {
                    let prev_rip = self.guest_state.regular_regs.rip;
                    loop {
                        if self
                            .vcpu_event_sender
                            .send(DebugEvent::STEP_INTO(self.single_step_en))
                            .is_err()
                        {
                            return Err(Self::Error::ChannelError);
                        }
                        // Main thread will take care of what it means enabling/disabling single-stepping
                        self.single_step_en = true;
                        let mut interrupted = false;
                        while !check_gdb_interrupt() {
                            if let Ok(DebugEvent::NOTIFY(state)) =
                                self.vcpu_event_receiver.try_recv()
                            {
                                interrupted = true;
                                self.guest_state = state;
                                break;
                            }
                        }
                        if !interrupted {
                            return Ok((SINGLE_THREAD_TID, StopReason::Halted));
                        } else {
                            if prev_rip == self.guest_state.regular_regs.rip {
                                match Debugger::virt_to_phys(
                                    prev_rip,
                                    &self.guest_memory,
                                    &self.guest_state,
                                    &self.e_phdrs,
                                ) {
                                    Ok(phys_addr) => {
                                        if let Err(e) = self.remove_bp(prev_rip, Some(phys_addr)) {
                                            return Err(e);
                                        }
                                    }
                                    Err(e) => return Err(e),
                                }
                            } else {
                                return Ok((SINGLE_THREAD_TID, StopReason::DoneStep));
                            }
                        }
                    }
                }
            }
        }

        Err(Self::Error::InvalidState)
    }

    /// Called when the user or the GDB client requests the guest state
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

        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &arch::x86::reg::X86_64CoreRegs,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Function that is called when the user or the GDB client requests a number of val.len
    /// bytes from the guest memory at address 'addrs'
    fn read_addrs(&mut self, addrs: u64, val: &mut [u8]) -> Result<bool, Self::Error> {
        if let Ok(phys_addr) =
            Debugger::virt_to_phys(addrs, &self.guest_memory, &self.guest_state, &self.e_phdrs)
        {
            for i in 0..val.len() {
                if let Ok(byte) = self
                    .guest_memory
                    .read_obj(GuestAddress(phys_addr + (i as u64)))
                {
                    val[i] = byte;
                } else {
                    return Err(Self::Error::MemoryError);
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn write_addrs(&mut self, start_addr: u64, data: &[u8]) -> Result<bool, Self::Error> {
        Ok(true)
    }

    /// Function called when the user or the GDB client request the insertion/removal of a
    /// software breakpoint
    fn update_sw_breakpoint(&mut self, addr: u64, op: BreakOp) -> Result<bool, Self::Error> {
        return match op {
            BreakOp::Add => self.insert_bp(addr, true),
            BreakOp::Remove => self.remove_bp(addr, None),
        }
        .map(|_| true);
    }

    fn update_hw_breakpoint(&mut self, addr: u64, op: BreakOp) -> OptResult<bool, Self::Error> {
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
