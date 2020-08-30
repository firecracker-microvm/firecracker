use gdbstub::{
    arch, BreakOp, OptResult, ResumeAction, StopReason, Target, Tid, TidSelector, WatchKind, SINGLE_THREAD_TID,
};

use crate::DynResult;
pub struct FirecrackerGDBServer {
}

impl FirecrackerGDBServer {
    pub fn new() -> DynResult<FirecrackerGDBServer> {
        Ok(FirecrackerGDBServer{})
    }
}

impl Target for FirecrackerGDBServer {
    type Arch = arch::x86::X86_64;
    type Error = &'static str;
    
    fn resume(
        &mut self,
        actions: &mut dyn Iterator<Item = (TidSelector, ResumeAction)>,
        check_gdb_interrupt: &mut dyn FnMut() -> bool,
    ) -> Result<(Tid, StopReason<u64>), Self::Error> {
        Ok((SINGLE_THREAD_TID, StopReason::Halted))
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
        addrs: std::ops::Range<u64>,
        val: &mut dyn FnMut(u8),
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn write_addrs(
        &mut self,
        start_addr: u64,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn update_sw_breakpoint(
        &mut self,
        addr: u64,
        op: BreakOp,
    ) -> Result<bool, Self::Error> {
        Ok(false)
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

    fn list_active_threads(
        &mut self,
        thread_is_active: &mut dyn FnMut(Tid),
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn set_current_thread(&mut self, tid: Tid) -> OptResult<(), Self::Error> {
        Ok(())
    }

    fn is_thread_alive(&mut self, tid: Tid) -> OptResult<bool, Self::Error> {
        Ok(false)
    }
}