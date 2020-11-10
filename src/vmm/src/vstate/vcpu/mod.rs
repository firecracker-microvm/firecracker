// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use libc::{c_int, c_void, siginfo_t};
#[cfg(not(test))]
use std::sync::Barrier;
use std::{
    cell::Cell,
    fmt::{Display, Formatter},
    io, result,
    sync::atomic::{fence, Ordering},
    sync::mpsc::{channel, Receiver, Sender, TryRecvError},
    thread,
};

use crate::{
    vmm_config::machine_config::CpuFeaturesTemplate, vstate::vm::Vm, FC_EXIT_CODE_GENERIC_ERROR,
    FC_EXIT_CODE_OK,
};
use kvm_ioctls::VcpuExit;
use logger::{error, info, IncMetric, METRICS};
use seccomp::{BpfProgram, SeccompFilter};
use utils::{
    eventfd::EventFd,
    signal::{register_signal_handler, sigrtmin, Killable},
    sm::StateMachine,
};

#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64;
#[cfg(target_arch = "x86_64")]
pub(crate) mod x86_64;

#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::{Error as VcpuError, *};
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::{Error as VcpuError, *};

/// Signal number (SIGRTMIN) used to kick Vcpus.
pub(crate) const VCPU_RTSIG_OFFSET: i32 = 0;

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug)]
pub enum Error {
    /// Error triggered by the KVM subsystem.
    FaultyKvmExit(String),
    /// Failed to signal Vcpu.
    SignalVcpu(utils::errno::Error),
    /// Kvm Exit is not handled by our implementation.
    UnhandledKvmExit(String),
    /// Wrapper over error triggered by some vcpu action.
    VcpuResponse(VcpuError),
    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(io::Error),
    /// Cannot cleanly initialize vcpu TLS.
    VcpuTlsInit,
    /// Vcpu not present in TLS.
    VcpuTlsNotPresent,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            FaultyKvmExit(ref e) => write!(f, "Received error signaling kvm exit: {}", e),
            SignalVcpu(e) => write!(f, "Failed to signal vcpu: {}", e),
            UnhandledKvmExit(ref e) => write!(f, "Unexpected kvm exit received: {}", e),
            VcpuResponse(e) => write!(f, "Failed to run action on vcpu: {}", e),
            VcpuSpawn(e) => write!(f, "Cannot spawn a new vCPU thread: {}", e),
            VcpuTlsInit => write!(f, "Cannot clean init vcpu TLS"),
            VcpuTlsNotPresent => write!(f, "Vcpu not present in TLS"),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

/// Encapsulates configuration parameters for the guest vCPUS.
#[derive(Debug, PartialEq)]
pub struct VcpuConfig {
    /// Number of guest VCPUs.
    pub vcpu_count: u8,
    /// Enable hyperthreading in the CPUID configuration.
    pub ht_enabled: bool,
    /// CPUID template to use.
    pub cpu_template: Option<CpuFeaturesTemplate>,
}

// Using this for easier explicit type-casting to help IDEs interpret the code.
type VcpuCell = Cell<Option<*const Vcpu>>;

/// A wrapper around creating and using a vcpu.
pub struct Vcpu {
    // Offers kvm-arch specific functionality.
    pub kvm_vcpu: KvmVcpu,

    // File descriptor for triggering exit event.
    exit_evt: EventFd,
    // The receiving end of events channel owned by the vcpu side.
    event_receiver: Receiver<VcpuEvent>,
    // The transmitting end of the events channel which will be given to the handler.
    event_sender: Option<Sender<VcpuEvent>>,
    // The receiving end of the responses channel which will be given to the handler.
    response_receiver: Option<Receiver<VcpuResponse>>,
    // The transmitting end of the responses channel owned by the vcpu side.
    response_sender: Sender<VcpuResponse>,
}

impl Vcpu {
    thread_local!(static TLS_VCPU_PTR: VcpuCell = Cell::new(None));

    /// Associates `self` with the current thread.
    ///
    /// It is a prerequisite to successfully run `init_thread_local_data()` before using
    /// `run_on_thread_local()` on the current thread.
    /// This function will return an error if there already is a `Vcpu` present in the TLS.
    fn init_thread_local_data(&mut self) -> Result<()> {
        Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| {
            if cell.get().is_some() {
                return Err(Error::VcpuTlsInit);
            }
            cell.set(Some(self as *const Vcpu));
            Ok(())
        })
    }

    /// Deassociates `self` from the current thread.
    ///
    /// Should be called if the current `self` had called `init_thread_local_data()` and
    /// now needs to move to a different thread.
    ///
    /// Fails if `self` was not previously associated with the current thread.
    fn reset_thread_local_data(&mut self) -> Result<()> {
        // Best-effort to clean up TLS. If the `Vcpu` was moved to another thread
        // _before_ running this, then there is nothing we can do.
        Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| {
            if let Some(vcpu_ptr) = cell.get() {
                if vcpu_ptr == self as *const Vcpu {
                    Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| cell.take());
                    return Ok(());
                }
            }
            Err(Error::VcpuTlsNotPresent)
        })
    }

    /// Runs `func` for the `Vcpu` associated with the current thread.
    ///
    /// It requires that `init_thread_local_data()` was run on this thread.
    ///
    /// Fails if there is no `Vcpu` associated with the current thread.
    ///
    /// # Safety
    ///
    /// This is marked unsafe as it allows temporary aliasing through
    /// dereferencing from pointer an already borrowed `Vcpu`.
    unsafe fn run_on_thread_local<F>(func: F) -> Result<()>
    where
        F: FnOnce(&Vcpu),
    {
        Self::TLS_VCPU_PTR.with(|cell: &VcpuCell| {
            if let Some(vcpu_ptr) = cell.get() {
                // Dereferencing here is safe since `TLS_VCPU_PTR` is populated/non-empty,
                // and it is being cleared on `Vcpu::drop` so there is no dangling pointer.
                let vcpu_ref: &Vcpu = &*vcpu_ptr;
                func(vcpu_ref);
                Ok(())
            } else {
                Err(Error::VcpuTlsNotPresent)
            }
        })
    }

    /// Registers a signal handler which makes use of TLS and kvm immediate exit to
    /// kick the vcpu running on the current thread, if there is one.
    pub fn register_kick_signal_handler() {
        extern "C" fn handle_signal(_: c_int, _: *mut siginfo_t, _: *mut c_void) {
            // This is safe because it's temporarily aliasing the `Vcpu` object, but we are
            // only reading `vcpu.fd` which does not change for the lifetime of the `Vcpu`.
            unsafe {
                let _ = Vcpu::run_on_thread_local(|vcpu| {
                    vcpu.kvm_vcpu.fd.set_kvm_immediate_exit(1);
                    fence(Ordering::Release);
                });
            }
        }

        register_signal_handler(sigrtmin() + VCPU_RTSIG_OFFSET, handle_signal)
            .expect("Failed to register vcpu signal handler");
    }

    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm_fd` - The kvm `VmFd` for the virtual machine this vcpu will get attached to.
    /// * `msr_list` - The `MsrList` listing the supported MSRs for this vcpu.
    /// * `exit_evt` - An `EventFd` that will be written into when this vcpu exits.
    pub fn new(index: u8, vm: &Vm, exit_evt: EventFd) -> Result<Self> {
        let (event_sender, event_receiver) = channel();
        let (response_sender, response_receiver) = channel();
        let kvm_vcpu = KvmVcpu::new(index, vm).unwrap();

        Ok(Vcpu {
            exit_evt,
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
            kvm_vcpu,
        })
    }

    /// Sets a MMIO bus for this vcpu.
    pub fn set_mmio_bus(&mut self, mmio_bus: devices::Bus) {
        self.kvm_vcpu.mmio_bus = Some(mmio_bus);
    }

    /// Moves the vcpu to its own thread and constructs a VcpuHandle.
    /// The handle can be used to control the remote vcpu.
    pub fn start_threaded(mut self, seccomp_filter: BpfProgram) -> Result<VcpuHandle> {
        let event_sender = self.event_sender.take().expect("vCPU already started");
        let response_receiver = self.response_receiver.take().unwrap();
        let vcpu_thread = thread::Builder::new()
            .name(format!("fc_vcpu {}", self.kvm_vcpu.index))
            .spawn(move || {
                self.init_thread_local_data()
                    .expect("Cannot cleanly initialize vcpu TLS.");

                self.run(seccomp_filter);
            })
            .map_err(Error::VcpuSpawn)?;

        Ok(VcpuHandle::new(
            event_sender,
            response_receiver,
            vcpu_thread,
        ))
    }

    /// Main loop of the vCPU thread.
    ///
    /// Runs the vCPU in KVM context in a loop. Handles KVM_EXITs then goes back in.
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    pub fn run(&mut self, seccomp_filter: BpfProgram) {
        // Load seccomp filters for this vCPU thread.
        // Execution panics if filters cannot be loaded, use --seccomp-level=0 if skipping filters
        // altogether is the desired behaviour.
        if let Err(e) = SeccompFilter::apply(seccomp_filter) {
            panic!(
                "Failed to set the requested seccomp filters on vCPU {}: Error: {}",
                self.kvm_vcpu.index, e
            );
        }

        // Start running the machine state in the `Paused` state.
        StateMachine::run(self, Self::paused);
    }

    // This is the main loop of the `Running` state.
    fn running(&mut self) -> StateMachine<Self> {
        // This loop is here just for optimizing the emulation path.
        // No point in ticking the state machine if there are no external events.
        loop {
            match self.run_emulation() {
                // Emulation ran successfully, continue.
                Ok(VcpuEmulation::Handled) => (),
                // Emulation was interrupted, check external events.
                Ok(VcpuEmulation::Interrupted) => break,
                // If the guest was rebooted or halted:
                // - vCPU0 will always exit out of `KVM_RUN` with KVM_EXIT_SHUTDOWN or
                //   KVM_EXIT_HLT.
                // - the other vCPUs won't ever exit out of `KVM_RUN`, but they won't consume CPU.
                // Moreover if we allow the vCPU0 thread to finish execution, this might generate a
                // seccomp failure because musl calls `sigprocmask` as part of `pthread_exit`.
                // So we pause vCPU0 and send a signal to the emulation thread to stop the VMM.
                Ok(VcpuEmulation::Stopped) => return self.exit(FC_EXIT_CODE_OK),
                // Emulation errors lead to vCPU exit.
                Err(_) => return self.exit(FC_EXIT_CODE_GENERIC_ERROR),
            }
        }

        // By default don't change state.
        let mut state = StateMachine::next(Self::running);

        // Break this emulation loop on any transition request/external event.
        match self.event_receiver.try_recv() {
            // Running ---- Pause ----> Paused
            Ok(VcpuEvent::Pause) => {
                // Nothing special to do.
                self.response_sender
                    .send(VcpuResponse::Paused)
                    .expect("failed to send pause status");

                // TODO: we should call `KVM_KVMCLOCK_CTRL` here to make sure
                // TODO continued: the guest soft lockup watchdog does not panic on Resume.

                // Move to 'paused' state.
                state = StateMachine::next(Self::paused);
            }
            Ok(VcpuEvent::Resume) => {
                self.response_sender
                    .send(VcpuResponse::Resumed)
                    .expect("failed to send resume status");
            }
            // SaveState or RestoreState cannot be performed on a running Vcpu.
            Ok(VcpuEvent::SaveState) | Ok(VcpuEvent::RestoreState(_)) => {
                self.response_sender
                    .send(VcpuResponse::NotAllowed(String::from(
                        "save/restore unavailable while running",
                    )))
                    .expect("failed to send save not allowed status");
            }
            Ok(VcpuEvent::Exit) => return self.exit(FC_EXIT_CODE_GENERIC_ERROR),
            // Unhandled exit of the other end.
            Err(TryRecvError::Disconnected) => {
                // Move to 'exited' state.
                state = self.exit(FC_EXIT_CODE_GENERIC_ERROR);
            }
            // All other events or lack thereof have no effect on current 'running' state.
            Err(TryRecvError::Empty) => (),
        }

        state
    }

    // This is the main loop of the `Paused` state.
    fn paused(&mut self) -> StateMachine<Self> {
        match self.event_receiver.recv() {
            // Paused ---- Resume ----> Running
            Ok(VcpuEvent::Resume) => {
                // Nothing special to do.
                self.response_sender
                    .send(VcpuResponse::Resumed)
                    .expect("vcpu channel unexpectedly closed");
                // Move to 'running' state.
                StateMachine::next(Self::running)
            }
            Ok(VcpuEvent::Pause) => {
                self.response_sender
                    .send(VcpuResponse::Paused)
                    .expect("vcpu channel unexpectedly closed");
                StateMachine::next(Self::paused)
            }
            Ok(VcpuEvent::SaveState) => {
                // Save vcpu state.
                self.kvm_vcpu
                    .save_state()
                    .map(|vcpu_state| {
                        self.response_sender
                            .send(VcpuResponse::SavedState(Box::new(vcpu_state)))
                            .expect("vcpu channel unexpectedly closed");
                    })
                    .unwrap_or_else(|e| {
                        self.response_sender
                            .send(VcpuResponse::Error(Error::VcpuResponse(e)))
                            .expect("vcpu channel unexpectedly closed");
                    });

                StateMachine::next(Self::paused)
            }
            Ok(VcpuEvent::RestoreState(vcpu_state)) => {
                self.kvm_vcpu
                    .restore_state(&vcpu_state)
                    .map(|()| {
                        self.response_sender
                            .send(VcpuResponse::RestoredState)
                            .expect("vcpu channel unexpectedly closed");
                    })
                    .unwrap_or_else(|e| {
                        self.response_sender
                            .send(VcpuResponse::Error(Error::VcpuResponse(e)))
                            .expect("vcpu channel unexpectedly closed")
                    });

                StateMachine::next(Self::paused)
            }
            Ok(VcpuEvent::Exit) => self.exit(FC_EXIT_CODE_GENERIC_ERROR),
            // Unhandled exit of the other end.
            Err(_) => {
                // Move to 'exited' state.
                self.exit(FC_EXIT_CODE_GENERIC_ERROR)
            }
        }
    }

    #[cfg(not(test))]
    // Transition to the exited state.
    fn exit(&mut self, exit_code: u8) -> StateMachine<Self> {
        self.response_sender
            .send(VcpuResponse::Exited(exit_code))
            .expect("vcpu channel unexpectedly closed");

        if let Err(e) = self.exit_evt.write(1) {
            METRICS.vcpu.failures.inc();
            error!("Failed signaling vcpu exit event: {}", e);
        }

        // State machine reached its end.
        StateMachine::next(Self::exited)
    }

    #[cfg(not(test))]
    // This is the main loop of the `Exited` state.
    fn exited(&mut self) -> StateMachine<Self> {
        // Wait indefinitely.
        // The VMM thread will kill the entire process.
        let barrier = Barrier::new(2);
        barrier.wait();

        StateMachine::finish()
    }

    #[cfg(test)]
    // In tests the main/vmm thread exits without 'exit()'ing the whole process.
    // All channels get closed on the other side while this Vcpu thread is still running.
    // This Vcpu thread should just do a clean finish without reporting back to the main thread.
    fn exit(&mut self, _: u8) -> StateMachine<Self> {
        self.exit_evt.write(1).unwrap();
        // State machine reached its end.
        StateMachine::finish()
    }

    /// Runs the vCPU in KVM context and handles the kvm exit reason.
    ///
    /// Returns error or enum specifying whether emulation was handled or interrupted.
    pub fn run_emulation(&self) -> Result<VcpuEmulation> {
        match self.kvm_vcpu.fd.run() {
            Ok(run) => match run {
                VcpuExit::MmioRead(addr, data) => {
                    if let Some(mmio_bus) = &self.kvm_vcpu.mmio_bus {
                        mmio_bus.read(addr, data);
                        METRICS.vcpu.exit_mmio_read.inc();
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if let Some(mmio_bus) = &self.kvm_vcpu.mmio_bus {
                        mmio_bus.write(addr, data);
                        METRICS.vcpu.exit_mmio_write.inc();
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::Hlt => {
                    info!("Received KVM_EXIT_HLT signal");
                    Ok(VcpuEmulation::Stopped)
                }
                VcpuExit::Shutdown => {
                    info!("Received KVM_EXIT_SHUTDOWN signal");
                    Ok(VcpuEmulation::Stopped)
                }
                // Documentation specifies that below kvm exits are considered
                // errors.
                VcpuExit::FailEntry => {
                    // Hardware entry failure.
                    METRICS.vcpu.failures.inc();
                    error!("Received KVM_EXIT_FAIL_ENTRY signal");
                    Err(Error::FaultyKvmExit(format!("{:?}", VcpuExit::FailEntry)))
                }
                VcpuExit::InternalError => {
                    // Failure from the Linux KVM subsystem rather than from the hardware.
                    METRICS.vcpu.failures.inc();
                    error!("Received KVM_EXIT_INTERNAL_ERROR signal");
                    Err(Error::FaultyKvmExit(format!(
                        "{:?}",
                        VcpuExit::InternalError
                    )))
                }
                arch_specific_reason => {
                    // run specific architecture emulation.
                    self.kvm_vcpu.run_arch_emulation(arch_specific_reason)
                }
            },
            // The unwrap on raw_os_error can only fail if we have a logic
            // error in our code in which case it is better to panic.
            Err(ref e) => {
                match e.errno() {
                    libc::EAGAIN => Ok(VcpuEmulation::Handled),
                    libc::EINTR => {
                        self.kvm_vcpu.fd.set_kvm_immediate_exit(0);
                        // Notify that this KVM_RUN was interrupted.
                        Ok(VcpuEmulation::Interrupted)
                    }
                    _ => {
                        METRICS.vcpu.failures.inc();
                        error!("Failure during vcpu run: {}", e);
                        Err(Error::FaultyKvmExit(format!("{}", e)))
                    }
                }
            }
        }
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        let _ = self.reset_thread_local_data();
    }
}

#[derive(Clone)]
/// List of events that the Vcpu can receive.
pub enum VcpuEvent {
    /// The vCPU will go to exited state when receiving this message.
    Exit,
    /// Pause the Vcpu.
    Pause,
    /// Event to resume the Vcpu.
    Resume,
    /// Event to restore the state of a paused Vcpu.
    RestoreState(Box<VcpuState>),
    /// Event to save the state of a paused Vcpu.
    SaveState,
}

/// List of responses that the Vcpu reports.
pub enum VcpuResponse {
    /// Requested action encountered an error.
    Error(Error),
    /// Vcpu is stopped.
    Exited(u8),
    /// Requested action not allowed.
    NotAllowed(String),
    /// Vcpu is paused.
    Paused,
    /// Vcpu is resumed.
    Resumed,
    /// Vcpu state is restored.
    RestoredState,
    /// Vcpu state is saved.
    SavedState(Box<VcpuState>),
}

/// Wrapper over Vcpu that hides the underlying interactions with the Vcpu thread.
pub struct VcpuHandle {
    event_sender: Sender<VcpuEvent>,
    response_receiver: Receiver<VcpuResponse>,
    // Rust JoinHandles have to be wrapped in Option if you ever plan on 'join()'ing them.
    // We want to be able to join these threads in tests.
    vcpu_thread: Option<thread::JoinHandle<()>>,
}

impl VcpuHandle {
    pub fn new(
        event_sender: Sender<VcpuEvent>,
        response_receiver: Receiver<VcpuResponse>,
        vcpu_thread: thread::JoinHandle<()>,
    ) -> Self {
        Self {
            event_sender,
            response_receiver,
            vcpu_thread: Some(vcpu_thread),
        }
    }

    pub fn send_event(&self, event: VcpuEvent) -> Result<()> {
        // Use expect() to crash if the other thread closed this channel.
        self.event_sender
            .send(event)
            .expect("event sender channel closed on vcpu end.");
        // Kick the vcpu so it picks up the message.
        self.vcpu_thread
            .as_ref()
            // Safe to unwrap since constructor make this 'Some'.
            .unwrap()
            .kill(sigrtmin() + VCPU_RTSIG_OFFSET)
            .map_err(Error::SignalVcpu)?;
        Ok(())
    }

    pub fn response_receiver(&self) -> &Receiver<VcpuResponse> {
        &self.response_receiver
    }
}

pub enum VcpuEmulation {
    Handled,
    Interrupted,
    Stopped,
}

#[cfg(test)]
mod tests {
    use std::{
        convert::TryInto,
        fmt,
        sync::{Arc, Barrier},
        time::Duration,
    };

    use super::*;
    use crate::vstate::vm::{tests::setup_vm, Vm};
    use utils::signal::validate_signal_num;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    impl PartialEq for VcpuResponse {
        fn eq(&self, other: &Self) -> bool {
            use crate::VcpuResponse::*;
            // Guard match with no wildcard to make sure we catch new enum variants.
            match self {
                Paused | Resumed | Exited(_) => (),
                Error(_) | NotAllowed(_) | RestoredState | SavedState(_) => (),
            };
            match (self, other) {
                (Paused, Paused) | (Resumed, Resumed) => true,
                (Exited(code), Exited(other_code)) => code == other_code,
                (NotAllowed(_), NotAllowed(_))
                | (RestoredState, RestoredState)
                | (SavedState(_), SavedState(_)) => true,
                (Error(ref err), Error(ref other_err)) => {
                    format!("{:?}", err) == format!("{:?}", other_err)
                }
                _ => false,
            }
        }
    }

    impl fmt::Debug for VcpuResponse {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use crate::VcpuResponse::*;
            match self {
                Paused => write!(f, "VcpuResponse::Paused"),
                Resumed => write!(f, "VcpuResponse::Resumed"),
                Exited(code) => write!(f, "VcpuResponse::Exited({:?})", code),
                RestoredState => write!(f, "VcpuResponse::RestoredState"),
                SavedState(_) => write!(f, "VcpuResponse::SavedState"),
                Error(ref err) => write!(f, "VcpuResponse::Error({:?})", err),
                NotAllowed(ref reason) => write!(f, "VcpuResponse::NotAllowed({})", reason),
            }
        }
    }

    // In tests we need to close any pending Vcpu threads on test completion.
    impl Drop for VcpuHandle {
        fn drop(&mut self) {
            // Make sure the Vcpu is out of KVM_RUN.
            self.send_event(VcpuEvent::Pause).unwrap();
            // Close the original channel so that the Vcpu thread errors and goes to exit state.
            let (event_sender, _event_receiver) = channel();
            self.event_sender = event_sender;
            // Wait for the Vcpu thread to finish execution
            self.vcpu_thread.take().unwrap().join().unwrap();
        }
    }

    // Auxiliary function being used throughout the tests.
    #[allow(unused_mut)]
    pub(crate) fn setup_vcpu(mem_size: usize) -> (Vm, Vcpu, GuestMemoryMmap) {
        let (mut vm, gm) = setup_vm(mem_size);

        let exit_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let vcpu;
        #[cfg(target_arch = "aarch64")]
        {
            vcpu = Vcpu::new(1, &vm, exit_evt).unwrap();
            vm.setup_irqchip(1).unwrap();
        }
        #[cfg(target_arch = "x86_64")]
        {
            vm.setup_irqchip().unwrap();
            vcpu = Vcpu::new(1, &vm, exit_evt).unwrap();
        }
        (vm, vcpu, gm)
    }

    fn load_good_kernel(vm_memory: &GuestMemoryMmap) -> GuestAddress {
        use std::{fs::File, path::PathBuf};

        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let parent = path.parent().unwrap();

        #[cfg(target_arch = "x86_64")]
        let kernel_path: PathBuf = [parent.to_str().unwrap(), "kernel/src/loader/test_elf.bin"]
            .iter()
            .collect();
        #[cfg(target_arch = "aarch64")]
        let kernel_path: PathBuf = [parent.to_str().unwrap(), "kernel/src/loader/test_pe.bin"]
            .iter()
            .collect();

        let mut kernel_file = File::open(kernel_path).expect("Cannot open kernel file");

        kernel::loader::load_kernel(vm_memory, &mut kernel_file, 0).expect("Failed to load kernel")
    }

    fn vcpu_configured_for_boot() -> (VcpuHandle, utils::eventfd::EventFd) {
        Vcpu::register_kick_signal_handler();
        // Need enough mem to boot linux.
        let mem_size = 64 << 20;
        let (vm, mut vcpu, vm_mem) = setup_vcpu(mem_size);

        let vcpu_exit_evt = vcpu.exit_evt.try_clone().unwrap();

        // Needs a kernel since we'll actually run this vcpu.
        let entry_addr = load_good_kernel(&vm_mem);

        #[cfg(target_arch = "aarch64")]
        vcpu.kvm_vcpu
            .configure(&vm.fd(), &vm_mem, entry_addr)
            .expect("failed to configure vcpu");
        #[cfg(target_arch = "x86_64")]
        {
            let vcpu_config = VcpuConfig {
                vcpu_count: 1,
                ht_enabled: false,
                cpu_template: None,
            };
            vcpu.kvm_vcpu
                .configure(
                    &vm_mem,
                    entry_addr,
                    &vcpu_config,
                    vm.supported_cpuid().clone(),
                )
                .expect("failed to configure vcpu");
        }

        let seccomp_filter = seccomp::SeccompFilter::empty().try_into().unwrap();
        let vcpu_handle = vcpu
            .start_threaded(seccomp_filter)
            .expect("failed to start vcpu");

        (vcpu_handle, vcpu_exit_evt)
    }

    #[test]
    fn test_set_mmio_bus() {
        let (_, mut vcpu, _) = setup_vcpu(0x1000);
        assert!(vcpu.kvm_vcpu.mmio_bus.is_none());
        vcpu.set_mmio_bus(devices::Bus::new());
        assert!(vcpu.kvm_vcpu.mmio_bus.is_some());
    }

    #[test]
    fn test_vcpu_tls() {
        let (_, mut vcpu, _) = setup_vcpu(0x1000);

        // Running on the TLS vcpu should fail before we actually initialize it.
        unsafe {
            assert!(Vcpu::run_on_thread_local(|_| ()).is_err());
        }

        // Initialize vcpu TLS.
        vcpu.init_thread_local_data().unwrap();

        // Validate TLS vcpu is the local vcpu by changing the `id` then validating against
        // the one in TLS.
        vcpu.kvm_vcpu.index = 12;
        unsafe {
            assert!(Vcpu::run_on_thread_local(|v| assert_eq!(v.kvm_vcpu.index, 12)).is_ok());
        }

        // Reset vcpu TLS.
        assert!(vcpu.reset_thread_local_data().is_ok());

        // Running on the TLS vcpu after TLS reset should fail.
        unsafe {
            assert!(Vcpu::run_on_thread_local(|_| ()).is_err());
        }

        // Second reset should return error.
        assert!(vcpu.reset_thread_local_data().is_err());
    }

    #[test]
    fn test_invalid_tls() {
        let (_, mut vcpu, _) = setup_vcpu(0x1000);
        // Initialize vcpu TLS.
        vcpu.init_thread_local_data().unwrap();
        // Trying to initialize non-empty TLS should error.
        vcpu.init_thread_local_data().unwrap_err();
    }

    #[test]
    fn test_vcpu_kick() {
        Vcpu::register_kick_signal_handler();
        let (vm, mut vcpu, _) = setup_vcpu(0x1000);

        let kvm_run =
            kvm_ioctls::KvmRunWrapper::mmap_from_fd(&vcpu.kvm_vcpu.fd, vm.fd().run_size())
                .expect("cannot mmap kvm-run");
        let success = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let vcpu_success = success.clone();
        let barrier = Arc::new(Barrier::new(2));
        let vcpu_barrier = barrier.clone();
        // Start Vcpu thread which will be kicked with a signal.
        let handle = std::thread::Builder::new()
            .name("test_vcpu_kick".to_string())
            .spawn(move || {
                vcpu.init_thread_local_data().unwrap();
                // Notify TLS was populated.
                vcpu_barrier.wait();
                // Loop for max 1 second to check if the signal handler has run.
                for _ in 0..10 {
                    if kvm_run.as_mut_ref().immediate_exit == 1 {
                        // Signal handler has run and set immediate_exit to 1.
                        vcpu_success.store(true, Ordering::Release);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            })
            .expect("cannot start thread");

        // Wait for the vcpu to initialize its TLS.
        barrier.wait();
        // Kick the Vcpu using the custom signal.
        handle
            .kill(sigrtmin() + VCPU_RTSIG_OFFSET)
            .expect("failed to signal thread");
        handle.join().expect("failed to join thread");
        // Verify that the Vcpu saw its kvm immediate-exit as set.
        assert!(success.load(Ordering::Acquire));
    }

    // Sends an event to a vcpu and expects a particular response.
    fn queue_event_expect_response(handle: &VcpuHandle, event: VcpuEvent, response: VcpuResponse) {
        handle
            .send_event(event)
            .expect("failed to send event to vcpu");
        assert_eq!(
            handle
                .response_receiver()
                .recv_timeout(Duration::from_millis(1000))
                .expect("did not receive event response from vcpu"),
            response
        );
    }

    #[test]
    fn test_vcpu_pause_resume() {
        let (vcpu_handle, vcpu_exit_evt) = vcpu_configured_for_boot();

        // Queue a Resume event, expect a response.
        queue_event_expect_response(&vcpu_handle, VcpuEvent::Resume, VcpuResponse::Resumed);

        // Queue a Pause event, expect a response.
        queue_event_expect_response(&vcpu_handle, VcpuEvent::Pause, VcpuResponse::Paused);

        // Validate vcpu handled the EINTR gracefully and didn't exit.
        let err = vcpu_exit_evt.read().unwrap_err();
        assert_eq!(err.raw_os_error().unwrap(), libc::EAGAIN);

        // Queue another Pause event, expect a response.
        queue_event_expect_response(&vcpu_handle, VcpuEvent::Pause, VcpuResponse::Paused);

        // Queue a Resume event, expect a response.
        queue_event_expect_response(&vcpu_handle, VcpuEvent::Resume, VcpuResponse::Resumed);

        // Queue another Resume event, expect a response.
        queue_event_expect_response(&vcpu_handle, VcpuEvent::Resume, VcpuResponse::Resumed);

        // Queue another Pause event, expect a response.
        queue_event_expect_response(&vcpu_handle, VcpuEvent::Pause, VcpuResponse::Paused);

        // Queue a Resume event, expect a response.
        queue_event_expect_response(&vcpu_handle, VcpuEvent::Resume, VcpuResponse::Resumed);
    }

    #[test]
    fn test_vcpu_save_restore_state_events() {
        let (vcpu_handle, _vcpu_exit_evt) = vcpu_configured_for_boot();

        // Queue a Resume event, expect a response.
        queue_event_expect_response(&vcpu_handle, VcpuEvent::Resume, VcpuResponse::Resumed);

        // Queue a SaveState event, expect a response.
        queue_event_expect_response(
            &vcpu_handle,
            VcpuEvent::SaveState,
            VcpuResponse::NotAllowed(String::new()),
        );

        // Queue another Pause event, expect a response.
        queue_event_expect_response(&vcpu_handle, VcpuEvent::Pause, VcpuResponse::Paused);

        // Queue a SaveState event, get the response.
        vcpu_handle
            .send_event(VcpuEvent::SaveState)
            .expect("failed to send event to vcpu");
        let vcpu_state = match vcpu_handle
            .response_receiver()
            .recv_timeout(Duration::from_millis(1000))
            .expect("did not receive event response from vcpu")
        {
            #[cfg(target_arch = "x86_64")]
            VcpuResponse::SavedState(state) => state,
            #[cfg(target_arch = "aarch64")]
            VcpuResponse::Error(e) => {
                assert_eq!(e.to_string(), "Failed to run action on vcpu: Saving the state is not yet supported on this architecture".to_string());
                Box::new(VcpuState::default())
            }
            _ => panic!("unexpected response"),
        };

        // Queue a RestoreState event, expect success.
        queue_event_expect_response(
            &vcpu_handle,
            VcpuEvent::RestoreState(vcpu_state),
            #[cfg(target_arch = "x86_64")]
            VcpuResponse::RestoredState,
            #[cfg(target_arch = "aarch64")]
            VcpuResponse::Error(Error::VcpuResponse(
                crate::vstate::vcpu::VcpuError::UnsupportedAction("Restoring the state"),
            )),
        );
    }

    #[test]
    fn test_vcpu_rtsig_offset() {
        assert!(validate_signal_num(sigrtmin() + VCPU_RTSIG_OFFSET).is_ok());
    }
}
