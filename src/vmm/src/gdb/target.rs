// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, RecvError};
use std::sync::{Arc, Mutex, PoisonError};

use arrayvec::ArrayVec;
use gdbstub::arch::Arch;
use gdbstub::common::{Signal, Tid};
use gdbstub::stub::{BaseStopReason, MultiThreadStopReason};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::base::multithread::{
    MultiThreadBase, MultiThreadResume, MultiThreadResumeOps, MultiThreadSingleStep,
    MultiThreadSingleStepOps,
};
use gdbstub::target::ext::breakpoints::{
    Breakpoints, BreakpointsOps, HwBreakpoint, HwBreakpointOps, SwBreakpoint, SwBreakpointOps,
};
use gdbstub::target::ext::thread_extra_info::{ThreadExtraInfo, ThreadExtraInfoOps};
use gdbstub::target::{Target, TargetError, TargetResult};
#[cfg(target_arch = "aarch64")]
use gdbstub_arch::aarch64::AArch64 as GdbArch;
#[cfg(target_arch = "aarch64")]
use gdbstub_arch::aarch64::reg::AArch64CoreRegs as CoreRegs;
#[cfg(target_arch = "x86_64")]
use gdbstub_arch::x86::X86_64_SSE as GdbArch;
#[cfg(target_arch = "x86_64")]
use gdbstub_arch::x86::reg::X86_64CoreRegs as CoreRegs;
use kvm_ioctls::VcpuFd;
use vm_memory::{Bytes, GuestAddress, GuestMemoryError};

use super::arch;
use crate::arch::GUEST_PAGE_SIZE;
#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::vcpu::VcpuArchError as AarchVcpuError;
use crate::logger::{error, info};
use crate::utils::u64_to_usize;
use crate::vstate::vcpu::VcpuSendEventError;
use crate::{FcExitCode, VcpuEvent, VcpuResponse, Vmm};

#[derive(Debug)]
/// Stores the current state of a Vcpu with a copy of the Vcpu file descriptor
struct VcpuState {
    single_step: bool,
    paused: bool,
    vcpu_fd: VcpuFd,
}

impl VcpuState {
    /// Constructs a new instance of a VcpuState from a VcpuFd
    fn from_vcpu_fd(vcpu_fd: VcpuFd) -> Self {
        Self {
            single_step: false,
            paused: false,
            vcpu_fd,
        }
    }

    /// Disables single stepping on the Vcpu state
    fn reset_vcpu_state(&mut self) {
        self.single_step = false;
    }

    /// Updates the kvm debug flags set against the Vcpu with a check
    fn update_kvm_debug(&self, hw_breakpoints: &[GuestAddress]) -> Result<(), GdbTargetError> {
        if !self.paused {
            info!("Attempted to update kvm debug on a non paused Vcpu");
            return Ok(());
        }

        arch::vcpu_set_debug(&self.vcpu_fd, hw_breakpoints, self.single_step)
    }
}

/// Errors from interactions between GDB and the VMM
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum GdbTargetError {
    /// An error during a GDB request
    GdbRequest,
    /// An error with the queue between the target and the Vcpus
    GdbQueueError,
    /// The response from the Vcpu was not allowed
    VcuRequestError,
    /// No currently paused Vcpu error
    NoPausedVcpu,
    /// Error when setting Vcpu debug flags
    VcpuKvmError,
    /// Server socket Error
    ServerSocketError,
    /// Error with creating GDB thread
    GdbThreadError,
    /// VMM locking error
    VmmLockError,
    /// Vcpu send event error
    VcpuSendEventError(#[from] VcpuSendEventError),
    /// Recieve error from Vcpu channel
    VcpuRecvError(#[from] RecvError),
    /// TID Conversion error
    TidConversionError,
    /// KVM set guest debug error
    KvmIoctlsError(#[from] kvm_ioctls::Error),
    /// Gva no translation available
    GvaTranslateError,
    /// Conversion error with cpu rflags
    RegFlagConversionError,
    #[cfg(target_arch = "aarch64")]
    /// Error retrieving registers from a Vcpu
    ReadRegisterError(#[from] AarchVcpuError),
    #[cfg(target_arch = "aarch64")]
    /// Error retrieving registers from a register vec.
    ReadRegisterVecError,
    /// Error while reading/writing to guest memory
    GuestMemoryError(#[from] GuestMemoryError),
}

impl From<GdbTargetError> for TargetError<GdbTargetError> {
    fn from(error: GdbTargetError) -> Self {
        match error {
            GdbTargetError::VmmLockError => TargetError::Fatal(GdbTargetError::VmmLockError),
            _ => TargetError::NonFatal,
        }
    }
}

impl<E> From<PoisonError<E>> for GdbTargetError {
    fn from(_value: PoisonError<E>) -> Self {
        GdbTargetError::VmmLockError
    }
}

/// Debug Target for firecracker.
///
/// This is used the manage the debug implementation and handle requests sent via GDB
#[derive(Debug)]
pub struct FirecrackerTarget {
    /// A mutex around the VMM to allow communicataion to the Vcpus
    vmm: Arc<Mutex<Vmm>>,
    /// Store the guest entry point
    entry_addr: GuestAddress,

    /// Listener for events sent from the Vcpu
    pub gdb_event: Receiver<usize>,

    /// Used to track the currently configured hardware breakpoints.
    /// Limited to 4 in x86 see:
    /// https://elixir.bootlin.com/linux/v6.1/source/arch/x86/include/asm/kvm_host.h#L210
    hw_breakpoints: ArrayVec<GuestAddress, 4>,
    /// Used to track the currently configured software breakpoints and store the op-code
    /// which was swapped out
    sw_breakpoints: HashMap<<GdbArch as Arch>::Usize, [u8; arch::SW_BP_SIZE]>,

    /// Stores the current state of each Vcpu
    vcpu_state: Vec<VcpuState>,

    /// Stores the current paused thread id, GDB can inact commands without providing us a Tid to
    /// run on and expects us to use the last paused thread.
    paused_vcpu: Option<Tid>,
}

/// Convert the 1 indexed Tid to the 0 indexed Vcpuid
fn tid_to_vcpuid(tid: Tid) -> usize {
    tid.get() - 1
}

/// Converts the inernal index of a Vcpu to
/// the Tid required by GDB
pub fn vcpuid_to_tid(cpu_id: usize) -> Result<Tid, GdbTargetError> {
    Tid::new(get_raw_tid(cpu_id)).ok_or(GdbTargetError::TidConversionError)
}

/// Converts the inernal index of a Vcpu to
/// the 1 indexed value for GDB
pub fn get_raw_tid(cpu_id: usize) -> usize {
    cpu_id + 1
}

impl FirecrackerTarget {
    /// Creates a new Target for GDB stub. This is used as the layer between GDB and the VMM it
    /// will handle requests from GDB and perform the appropriate actions, while also updating GDB
    /// with the state of the VMM / Vcpu's as we hit debug events
    pub fn new(
        vmm: Arc<Mutex<Vmm>>,
        vcpu_fds: Vec<VcpuFd>,
        gdb_event: Receiver<usize>,
        entry_addr: GuestAddress,
    ) -> Self {
        let mut vcpu_state: Vec<_> = vcpu_fds.into_iter().map(VcpuState::from_vcpu_fd).collect();
        // By default vcpu 1 will be paused at the entry point
        vcpu_state[0].paused = true;

        Self {
            vmm,
            entry_addr,
            gdb_event,
            // We only support 4 hw breakpoints on x86 this will need to be configurable on arm
            hw_breakpoints: Default::default(),
            sw_breakpoints: HashMap::new(),
            vcpu_state,

            paused_vcpu: Tid::new(1),
        }
    }

    /// Retrieves the currently paused Vcpu id returns an error if there is no currently paused Vcpu
    fn get_paused_vcpu_id(&self) -> Result<Tid, GdbTargetError> {
        self.paused_vcpu.ok_or(GdbTargetError::NoPausedVcpu)
    }

    /// Retrieves the currently paused Vcpu state returns an error if there is no currently paused
    /// Vcpu
    fn get_paused_vcpu(&self) -> Result<&VcpuState, GdbTargetError> {
        let vcpu_index = tid_to_vcpuid(self.get_paused_vcpu_id()?);
        Ok(&self.vcpu_state[vcpu_index])
    }

    /// Updates state to reference the currently paused Vcpu and store that the cpu is currently
    /// paused
    pub fn set_paused_vcpu(&mut self, tid: Tid) {
        self.vcpu_state[tid_to_vcpuid(tid)].paused = true;
        self.paused_vcpu = Some(tid);
    }

    /// Resumes execution of all paused Vcpus, update them with current kvm debug info
    /// and resumes
    fn resume_all_vcpus(&mut self) -> Result<(), GdbTargetError> {
        self.vcpu_state
            .iter()
            .try_for_each(|state| state.update_kvm_debug(&self.hw_breakpoints))?;

        for cpu_id in 0..self.vcpu_state.len() {
            let tid = vcpuid_to_tid(cpu_id)?;
            self.resume_vcpu(tid)?;
        }

        self.paused_vcpu = None;

        Ok(())
    }

    /// Resets all Vcpus to their base state
    fn reset_all_vcpu_states(&mut self) {
        for value in self.vcpu_state.iter_mut() {
            value.reset_vcpu_state();
        }
    }

    /// Shuts down the VMM
    pub fn shutdown_vmm(&self) {
        self.vmm
            .lock()
            .expect("error unlocking vmm")
            .stop(FcExitCode::Ok)
    }

    /// Pauses the requested Vcpu
    pub fn pause_vcpu(&mut self, tid: Tid) -> Result<(), GdbTargetError> {
        let vcpu_state = &mut self.vcpu_state[tid_to_vcpuid(tid)];

        if vcpu_state.paused {
            info!("Attempted to pause a vcpu already paused.");
            // Pausing an already paused vcpu is not considered an error case from GDB
            return Ok(());
        }

        let cpu_handle = &self.vmm.lock()?.vcpus_handles[tid_to_vcpuid(tid)];

        cpu_handle.send_event(VcpuEvent::Pause)?;
        let _ = cpu_handle.response_receiver().recv()?;

        vcpu_state.paused = true;
        Ok(())
    }

    /// A helper function to allow the event loop to inject this breakpoint back into the Vcpu
    pub fn inject_bp_to_guest(&mut self, tid: Tid) -> Result<(), GdbTargetError> {
        let vcpu_state = &mut self.vcpu_state[tid_to_vcpuid(tid)];
        arch::vcpu_inject_bp(&vcpu_state.vcpu_fd, &self.hw_breakpoints, false)
    }

    /// Resumes the Vcpu, will return early if the Vcpu is already running
    pub fn resume_vcpu(&mut self, tid: Tid) -> Result<(), GdbTargetError> {
        let vcpu_state = &mut self.vcpu_state[tid_to_vcpuid(tid)];

        if !vcpu_state.paused {
            info!("Attempted to resume a vcpu already running.");
            // Resuming an already running Vcpu is not considered an error case from GDB
            return Ok(());
        }

        let cpu_handle = &self.vmm.lock()?.vcpus_handles[tid_to_vcpuid(tid)];
        cpu_handle.send_event(VcpuEvent::Resume)?;

        let response = cpu_handle.response_receiver().recv()?;
        if let VcpuResponse::NotAllowed(message) = response {
            error!("Response resume : {message}");
            return Err(GdbTargetError::VcuRequestError);
        }

        vcpu_state.paused = false;
        Ok(())
    }

    /// Identifies why the specific core was paused to be returned to GDB if None is returned this
    /// indicates to handle this internally and don't notify GDB
    pub fn get_stop_reason(
        &self,
        tid: Tid,
    ) -> Result<Option<BaseStopReason<Tid, u64>>, GdbTargetError> {
        let vcpu_state = &self.vcpu_state[tid_to_vcpuid(tid)];
        if vcpu_state.single_step {
            return Ok(Some(MultiThreadStopReason::SignalWithThread {
                tid,
                signal: Signal::SIGTRAP,
            }));
        }

        let Ok(ip) = arch::get_instruction_pointer(&vcpu_state.vcpu_fd) else {
            // If we error here we return an arbitrary Software Breakpoint, GDB will handle
            // this gracefully
            return Ok(Some(MultiThreadStopReason::SwBreak(tid)));
        };

        let gpa = arch::translate_gva(&vcpu_state.vcpu_fd, ip, &self.vmm.lock().unwrap())?;
        if self.sw_breakpoints.contains_key(&gpa) {
            return Ok(Some(MultiThreadStopReason::SwBreak(tid)));
        }

        if self.hw_breakpoints.contains(&GuestAddress(ip)) {
            return Ok(Some(MultiThreadStopReason::HwBreak(tid)));
        }

        if ip == self.entry_addr.0 {
            return Ok(Some(MultiThreadStopReason::HwBreak(tid)));
        }

        // This is not a breakpoint we've set, likely one set by the guest
        Ok(None)
    }
}

impl Target for FirecrackerTarget {
    type Error = GdbTargetError;
    type Arch = GdbArch;

    #[inline(always)]
    fn base_ops(&mut self) -> BaseOps<Self::Arch, Self::Error> {
        BaseOps::MultiThread(self)
    }

    #[inline(always)]
    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<Self>> {
        Some(self)
    }

    /// We disable implicit sw breakpoints as we want to manage these internally so we can inject
    /// breakpoints back into the guest if we didn't create them
    #[inline(always)]
    fn guard_rail_implicit_sw_breakpoints(&self) -> bool {
        false
    }
}

impl MultiThreadBase for FirecrackerTarget {
    /// Reads the registers for the Vcpu
    fn read_registers(&mut self, regs: &mut CoreRegs, tid: Tid) -> TargetResult<(), Self> {
        arch::read_registers(&self.vcpu_state[tid_to_vcpuid(tid)].vcpu_fd, regs)?;

        Ok(())
    }

    /// Writes to the registers for the Vcpu
    fn write_registers(&mut self, regs: &CoreRegs, tid: Tid) -> TargetResult<(), Self> {
        arch::write_registers(&self.vcpu_state[tid_to_vcpuid(tid)].vcpu_fd, regs)?;

        Ok(())
    }

    /// Writes data to a guest virtual address for the Vcpu
    fn read_addrs(
        &mut self,
        mut gva: <Self::Arch as Arch>::Usize,
        mut data: &mut [u8],
        tid: Tid,
    ) -> TargetResult<usize, Self> {
        let data_len = data.len();
        let vcpu_state = &self.vcpu_state[tid_to_vcpuid(tid)];

        let vmm = &self.vmm.lock().expect("Error locking vmm in read addr");

        while !data.is_empty() {
            let gpa = arch::translate_gva(&vcpu_state.vcpu_fd, gva, &vmm).map_err(|e| {
                error!("Error {e:?} translating gva on read address: {gva:#X}");
            })?;

            // Compute the amount space left in the page after the gpa
            let read_len = std::cmp::min(
                data.len(),
                GUEST_PAGE_SIZE - (u64_to_usize(gpa) & (GUEST_PAGE_SIZE - 1)),
            );

            vmm.vm
                .guest_memory()
                .read(&mut data[..read_len], GuestAddress(gpa as u64))
                .map_err(|e| {
                    error!("Error reading memory {e:?} gpa is {gpa}");
                })?;

            data = &mut data[read_len..];
            gva += read_len as u64;
        }

        Ok(data_len)
    }

    /// Writes data at a guest virtual address for the Vcpu
    fn write_addrs(
        &mut self,
        mut gva: <Self::Arch as Arch>::Usize,
        mut data: &[u8],
        tid: Tid,
    ) -> TargetResult<(), Self> {
        let vcpu_state = &self.vcpu_state[tid_to_vcpuid(tid)];
        let vmm = &self.vmm.lock().expect("Error locking vmm in write addr");

        while !data.is_empty() {
            let gpa = arch::translate_gva(&vcpu_state.vcpu_fd, gva, &vmm).map_err(|e| {
                error!("Error {e:?} translating gva on read address: {gva:#X}");
            })?;

            // Compute the amount space left in the page after the gpa
            let write_len = std::cmp::min(
                data.len(),
                GUEST_PAGE_SIZE - (u64_to_usize(gpa) & (GUEST_PAGE_SIZE - 1)),
            );

            vmm.vm
                .guest_memory()
                .write(&data[..write_len], GuestAddress(gpa))
                .map_err(|e| {
                    error!("Error {e:?} writing memory at {gpa:#X}");
                })?;

            data = &data[write_len..];
            gva += write_len as u64;
        }

        Ok(())
    }

    #[inline(always)]
    /// Makes the callback provided with each Vcpu
    /// GDB expects us to return all threads currently running with this command, for firecracker
    /// this is all Vcpus
    fn list_active_threads(
        &mut self,
        thread_is_active: &mut dyn FnMut(Tid),
    ) -> Result<(), Self::Error> {
        for id in 0..self.vcpu_state.len() {
            thread_is_active(vcpuid_to_tid(id)?)
        }

        Ok(())
    }

    #[inline(always)]
    fn support_resume(&mut self) -> Option<MultiThreadResumeOps<Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_thread_extra_info(&mut self) -> Option<ThreadExtraInfoOps<'_, Self>> {
        Some(self)
    }
}

impl MultiThreadResume for FirecrackerTarget {
    /// Disables single step on the Vcpu
    fn set_resume_action_continue(
        &mut self,
        tid: Tid,
        _signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        self.vcpu_state[tid_to_vcpuid(tid)].single_step = false;

        Ok(())
    }

    /// Resumes the execution of all currently paused Vcpus
    fn resume(&mut self) -> Result<(), Self::Error> {
        self.resume_all_vcpus()
    }

    /// Clears the state of all Vcpus setting it back to base config
    fn clear_resume_actions(&mut self) -> Result<(), Self::Error> {
        self.reset_all_vcpu_states();

        Ok(())
    }

    #[inline(always)]
    fn support_single_step(&mut self) -> Option<MultiThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl MultiThreadSingleStep for FirecrackerTarget {
    /// Enabled single step on the Vcpu
    fn set_resume_action_step(
        &mut self,
        tid: Tid,
        _signal: Option<Signal>,
    ) -> Result<(), Self::Error> {
        self.vcpu_state[tid_to_vcpuid(tid)].single_step = true;

        Ok(())
    }
}

impl Breakpoints for FirecrackerTarget {
    #[inline(always)]
    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<Self>> {
        Some(self)
    }
}

impl HwBreakpoint for FirecrackerTarget {
    /// Adds a hardware breakpoint The breakpoint addresses are
    /// stored in state so we can track the reason for an exit.
    fn add_hw_breakpoint(
        &mut self,
        gva: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        let ga = GuestAddress(gva);
        if self.hw_breakpoints.contains(&ga) {
            return Ok(true);
        }

        if self.hw_breakpoints.try_push(ga).is_err() {
            return Ok(false);
        }

        let state = self.get_paused_vcpu()?;
        state.update_kvm_debug(&self.hw_breakpoints)?;

        Ok(true)
    }

    /// Removes a hardware breakpoint.
    fn remove_hw_breakpoint(
        &mut self,
        gva: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        match self.hw_breakpoints.iter().position(|&b| b.0 == gva) {
            None => return Ok(false),
            Some(pos) => self.hw_breakpoints.remove(pos),
        };

        let state = self.get_paused_vcpu()?;
        state.update_kvm_debug(&self.hw_breakpoints)?;

        Ok(true)
    }
}

impl SwBreakpoint for FirecrackerTarget {
    /// Inserts a software breakpoint.
    /// We initially translate the guest virtual address to a guest physical address and then check
    /// if this is already present, if so we return early. Otherwise we store the opcode at the
    /// specified guest physical address in our store and replace it with the `X86_SW_BP_OP`
    fn add_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        let gpa = arch::translate_gva(
            &self.get_paused_vcpu()?.vcpu_fd,
            addr,
            &self.vmm.lock().unwrap(),
        )?;

        if self.sw_breakpoints.contains_key(&gpa) {
            return Ok(true);
        }

        let paused_vcpu_id = self.get_paused_vcpu_id()?;

        let mut saved_register = [0; arch::SW_BP_SIZE];
        self.read_addrs(addr, &mut saved_register, paused_vcpu_id)?;
        self.sw_breakpoints.insert(gpa, saved_register);

        self.write_addrs(addr, &arch::SW_BP, paused_vcpu_id)?;
        Ok(true)
    }

    /// Removes a software breakpoint.
    /// We firstly translate the guest virtual address to a guest physical address, we then check if
    /// the resulting gpa is in our store, if so we load the stored opcode and write this back
    fn remove_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        let gpa = arch::translate_gva(
            &self.get_paused_vcpu()?.vcpu_fd,
            addr,
            &self.vmm.lock().unwrap(),
        )?;

        if let Some(removed) = self.sw_breakpoints.remove(&gpa) {
            self.write_addrs(addr, &removed, self.get_paused_vcpu_id()?)?;
            return Ok(true);
        }

        Ok(false)
    }
}

impl ThreadExtraInfo for FirecrackerTarget {
    /// Allows us to configure the formatting of the thread information, we just return the ID of
    /// the Vcpu
    fn thread_extra_info(&self, tid: Tid, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let info = format!("Vcpu ID: {}", tid_to_vcpuid(tid));
        let size = buf.len().min(info.len());

        buf[..size].copy_from_slice(&info.as_bytes()[..size]);
        Ok(size)
    }
}
