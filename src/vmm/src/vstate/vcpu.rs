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
    sync::{
        atomic::{fence, Ordering},
        mpsc::{channel, Receiver, Sender, TryRecvError},
    },
    thread,
};

use crate::vmm_config::machine_config::CpuFeaturesTemplate;
use crate::{FC_EXIT_CODE_GENERIC_ERROR, FC_EXIT_CODE_OK};
#[cfg(target_arch = "x86_64")]
use cpuid::{c3, filter_cpuid, t2, VmSpec};
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{
    kvm_debugregs, kvm_lapic_state, kvm_mp_state, kvm_regs, kvm_sregs, kvm_vcpu_events, kvm_xcrs,
    kvm_xsave, CpuId, MsrList, Msrs,
};
use kvm_ioctls::*;
use logger::{error, info, Metric, METRICS};
use seccomp::{BpfProgram, SeccompFilter};
use utils::{
    eventfd::EventFd,
    signal::{register_signal_handler, sigrtmin, Killable},
    sm::StateMachine,
};
#[cfg(target_arch = "x86_64")]
use versionize::{VersionMap, Versionize, VersionizeResult};
#[cfg(target_arch = "x86_64")]
use versionize_derive::Versionize;
use vm_memory::{Address, GuestAddress, GuestMemoryError, GuestMemoryMmap};

/// Signal number (SIGRTMIN) used to kick Vcpus.
pub(crate) const VCPU_RTSIG_OFFSET: i32 = 0;

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug)]
pub enum Error {
    #[cfg(target_arch = "x86_64")]
    /// A call to cpuid instruction failed.
    CpuId(cpuid::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the floating point related registers
    FPUConfiguration(arch::x86_64::regs::Error),
    /// Invalid guest memory configuration.
    GuestMemoryMmap(GuestMemoryError),
    /// Hyperthreading flag is not initialized.
    HTNotInitialized,
    /// Cannot configure the IRQ.
    Irq(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Cannot set the local interruption due to bad configuration.
    LocalIntConfiguration(arch::x86_64::interrupts::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the MSR registers
    MSRSConfiguration(arch::x86_64::msr::Error),
    /// The number of configured slots is bigger than the maximum reported by KVM.
    NotEnoughMemorySlots,
    #[cfg(target_arch = "aarch64")]
    /// Error configuring the general purpose aarch64 registers.
    REGSConfiguration(arch::aarch64::regs::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the general purpose registers
    REGSConfiguration(arch::x86_64::regs::Error),
    /// Failed to signal Vcpu.
    SignalVcpu(utils::errno::Error),
    #[cfg(target_arch = "x86_64")]
    /// Error configuring the special registers
    SREGSConfiguration(arch::x86_64::regs::Error),
    #[cfg(target_arch = "aarch64")]
    /// Error doing Vcpu Init on Arm.
    VcpuArmInit(kvm_ioctls::Error),
    #[cfg(target_arch = "aarch64")]
    /// Error getting the Vcpu preferred target on Arm.
    VcpuArmPreferredTarget(kvm_ioctls::Error),
    /// vCPU count is not initialized.
    VcpuCountNotInitialized,
    /// Cannot open the VCPU file descriptor.
    VcpuFd(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu debug regs.
    VcpuGetDebugRegs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu lapic.
    VcpuGetLapic(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu mp state.
    VcpuGetMpState(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu msrs.
    VcpuGetMsrs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu regs.
    VcpuGetRegs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu sregs.
    VcpuGetSregs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu event.
    VcpuGetVcpuEvents(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu xcrs.
    VcpuGetXcrs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu xsave.
    VcpuGetXsave(kvm_ioctls::Error),
    /// Cannot run the VCPUs.
    VcpuRun(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu cpuid.
    VcpuGetCpuid(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu cpuid.
    VcpuSetCpuid(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu debug regs.
    VcpuSetDebugRegs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu lapic.
    VcpuSetLapic(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu mp state.
    VcpuSetMpState(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu msrs.
    VcpuSetMsrs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu regs.
    VcpuSetRegs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu sregs.
    VcpuSetSregs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu event.
    VcpuSetVcpuEvents(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu xcrs.
    VcpuSetXcrs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vcpu xsave.
    VcpuSetXsave(kvm_ioctls::Error),
    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(io::Error),
    /// Cannot cleanly initialize vcpu TLS.
    VcpuTlsInit,
    /// Vcpu not present in TLS.
    VcpuTlsNotPresent,
    /// Unexpected KVM_RUN exit reason
    VcpuUnhandledKvmExit,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            #[cfg(target_arch = "x86_64")]
            CpuId(e) => write!(f, "Cpuid error: {:?}", e),
            GuestMemoryMmap(e) => write!(f, "Guest memory error: {:?}", e),
            HTNotInitialized => write!(f, "Hyperthreading flag is not initialized"),
            VcpuCountNotInitialized => write!(f, "vCPU count is not initialized"),
            VcpuFd(e) => write!(f, "Cannot open the VCPU file descriptor: {}", e),
            VcpuRun(e) => write!(f, "Cannot run the VCPUs: {}", e),
            NotEnoughMemorySlots => write!(
                f,
                "The number of configured SetUserMemoryRegionslots is bigger than the maximum reported by KVM"
            ),
            #[cfg(target_arch = "x86_64")]
            LocalIntConfiguration(e) => write!(
                f,
                "Cannot set the local interruption due to bad configuration: {:?}",
                e
            ),
            SignalVcpu(e) => write!(f, "Failed to signal Vcpu: {}", e),
            #[cfg(target_arch = "x86_64")]
            MSRSConfiguration(e) => write!(f, "Error configuring the MSR registers: {:?}", e),
            #[cfg(target_arch = "aarch64")]
            REGSConfiguration(e) => write!(
                f,
                "Error configuring the general purpose aarch64 registers: {:?}",
                e
            ),
            #[cfg(target_arch = "x86_64")]
            REGSConfiguration(e) => write!(
                f,
                "Error configuring the general purpose registers: {:?}",
                e
            ),
            #[cfg(target_arch = "x86_64")]
            SREGSConfiguration(e) => write!(f, "Error configuring the special registers: {:?}", e),
            #[cfg(target_arch = "x86_64")]
            FPUConfiguration(e) => write!(
                f,
                "Error configuring the floating point related registers: {:?}",
                e
            ),
            Irq(e) => write!(f, "Cannot configure the IRQ: {}", e),
            #[cfg(target_arch = "aarch64")]
            VcpuArmPreferredTarget(e) => {
                write!(f, "Error getting the Vcpu preferred target on Arm: {}", e)
            }
            #[cfg(target_arch = "aarch64")]
            VcpuArmInit(e) => write!(f, "Error doing Vcpu Init on Arm: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuGetDebugRegs(e) => write!(f, "Failed to get KVM vcpu debug regs: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuGetLapic(e) => write!(f, "Failed to get KVM vcpu lapic: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuGetMpState(e) => write!(f, "Failed to get KVM vcpu mp state: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuGetMsrs(e) => write!(f, "Failed to get KVM vcpu msrs: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuGetRegs(e) => write!(f, "Failed to get KVM vcpu regs: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuGetSregs(e) => write!(f, "Failed to get KVM vcpu sregs: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuGetVcpuEvents(e) => write!(f, "Failed to get KVM vcpu event: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuGetXcrs(e) => write!(f, "Failed to get KVM vcpu xcrs: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuGetXsave(e) => write!(f, "Failed to get KVM vcpu xsave: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuGetCpuid(e) => write!(f, "Failed to get KVM vcpu cpuid: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuSetCpuid(e) => write!(f, "Failed to set KVM vcpu cpuid: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuSetDebugRegs(e) => write!(f, "Failed to set KVM vcpu debug regs: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuSetLapic(e) => write!(f, "Failed to set KVM vcpu lapic: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuSetMpState(e) => write!(f, "Failed to set KVM vcpu mp state: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuSetMsrs(e) => write!(f, "Failed to set KVM vcpu msrs: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuSetRegs(e) => write!(f, "Failed to set KVM vcpu regs: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuSetSregs(e) => write!(f, "Failed to set KVM vcpu sregs: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuSetVcpuEvents(e) => write!(f, "Failed to set KVM vcpu event: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuSetXcrs(e) => write!(f, "Failed to set KVM vcpu xcrs: {}", e),
            #[cfg(target_arch = "x86_64")]
            VcpuSetXsave(e) => write!(f, "Failed to set KVM vcpu xsave: {}", e),
            VcpuSpawn(e) => write!(f, "Cannot spawn a new vCPU thread: {}", e),
            VcpuTlsInit => write!(f, "Cannot clean init vcpu TLS"),
            VcpuTlsNotPresent => write!(f, "Vcpu not present in TLS"),
            VcpuUnhandledKvmExit => write!(f, "Unexpected KVM_RUN exit reason"),
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

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    fd: VcpuFd,
    index: u8,
    mmio_bus: Option<devices::Bus>,
    exit_evt: EventFd,

    #[cfg(target_arch = "x86_64")]
    pio_bus: Option<devices::Bus>,
    #[cfg(target_arch = "x86_64")]
    msr_list: MsrList,

    #[cfg(target_arch = "aarch64")]
    mpidr: u64,

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
                    vcpu.fd.set_kvm_immediate_exit(1);
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
    #[cfg(target_arch = "x86_64")]
    pub fn new_x86_64(
        index: u8,
        vm_fd: &VmFd,
        msr_list: MsrList,
        exit_evt: EventFd,
    ) -> Result<Self> {
        let kvm_vcpu = vm_fd.create_vcpu(index).map_err(Error::VcpuFd)?;
        let (event_sender, event_receiver) = channel();
        let (response_sender, response_receiver) = channel();

        Ok(Vcpu {
            fd: kvm_vcpu,
            index,
            mmio_bus: None,
            exit_evt,
            pio_bus: None,
            msr_list,
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
        })
    }

    /// Constructs a new VCPU for `vm`.
    ///
    /// # Arguments
    ///
    /// * `id` - Represents the CPU number between [0, max vcpus).
    /// * `vm_fd` - The kvm `VmFd` for the virtual machine this vcpu will get attached to.
    /// * `exit_evt` - An `EventFd` that will be written into when this vcpu exits.
    #[cfg(target_arch = "aarch64")]
    pub fn new_aarch64(id: u8, vm_fd: &VmFd, exit_evt: EventFd) -> Result<Self> {
        let kvm_vcpu = vm_fd.create_vcpu(id).map_err(Error::VcpuFd)?;
        let (event_sender, event_receiver) = channel();
        let (response_sender, response_receiver) = channel();

        Ok(Vcpu {
            fd: kvm_vcpu,
            index: id,
            mmio_bus: None,
            exit_evt,
            mpidr: 0,
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
        })
    }

    /// Returns the cpu index as seen by the guest OS.
    pub fn cpu_index(&self) -> u8 {
        self.index
    }

    /// Gets the MPIDR register value.
    #[cfg(target_arch = "aarch64")]
    pub fn get_mpidr(&self) -> u64 {
        self.mpidr
    }

    #[cfg(target_arch = "x86_64")]
    /// Sets a PIO bus for this vcpu.
    pub fn set_pio_bus(&mut self, pio_bus: devices::Bus) {
        self.pio_bus = Some(pio_bus);
    }

    /// Sets a MMIO bus for this vcpu.
    pub fn set_mmio_bus(&mut self, mmio_bus: devices::Bus) {
        self.mmio_bus = Some(mmio_bus);
    }

    #[cfg(target_arch = "x86_64")]
    /// Configures a x86_64 specific vcpu for booting Linux and should be called once per vcpu.
    ///
    /// # Arguments
    ///
    /// * `machine_config` - The machine configuration of this microvm needed for the CPUID configuration.
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_start_addr` - Offset from `guest_mem` at which the kernel starts.
    /// * `vcpu_config` - The vCPU configuration.
    /// * `cpuid` - The capabilities exposed by this vCPU.
    pub fn configure_x86_64_for_boot(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        kernel_start_addr: GuestAddress,
        vcpu_config: &VcpuConfig,
        mut cpuid: CpuId,
    ) -> Result<()> {
        let cpuid_vm_spec = VmSpec::new(self.index, vcpu_config.vcpu_count, vcpu_config.ht_enabled)
            .map_err(Error::CpuId)?;

        filter_cpuid(&mut cpuid, &cpuid_vm_spec).map_err(|e| {
            METRICS.vcpu.filter_cpuid.inc();
            error!(
                "Failure in configuring CPUID for vcpu {}: {:?}",
                self.index, e
            );
            Error::CpuId(e)
        })?;

        if let Some(template) = vcpu_config.cpu_template {
            match template {
                CpuFeaturesTemplate::T2 => {
                    t2::set_cpuid_entries(&mut cpuid, &cpuid_vm_spec).map_err(Error::CpuId)?
                }
                CpuFeaturesTemplate::C3 => {
                    c3::set_cpuid_entries(&mut cpuid, &cpuid_vm_spec).map_err(Error::CpuId)?
                }
            }
        }

        self.fd.set_cpuid2(&cpuid).map_err(Error::VcpuSetCpuid)?;

        arch::x86_64::msr::setup_msrs(&self.fd).map_err(Error::MSRSConfiguration)?;
        arch::x86_64::regs::setup_regs(&self.fd, kernel_start_addr.raw_value() as u64)
            .map_err(Error::REGSConfiguration)?;
        arch::x86_64::regs::setup_fpu(&self.fd).map_err(Error::FPUConfiguration)?;
        arch::x86_64::regs::setup_sregs(guest_mem, &self.fd).map_err(Error::SREGSConfiguration)?;
        arch::x86_64::interrupts::set_lint(&self.fd).map_err(Error::LocalIntConfiguration)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Configures an aarch64 specific vcpu for booting Linux.
    ///
    /// # Arguments
    ///
    /// * `vm_fd` - The kvm `VmFd` for this microvm.
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_load_addr` - Offset from `guest_mem` at which the kernel is loaded.
    pub fn configure_aarch64_for_boot(
        &mut self,
        vm_fd: &VmFd,
        guest_mem: &GuestMemoryMmap,
        kernel_load_addr: GuestAddress,
    ) -> Result<()> {
        let mut kvi: kvm_bindings::kvm_vcpu_init = kvm_bindings::kvm_vcpu_init::default();

        // This reads back the kernel's preferred target type.
        vm_fd
            .get_preferred_target(&mut kvi)
            .map_err(Error::VcpuArmPreferredTarget)?;
        // We already checked that the capability is supported.
        kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
        // Non-boot cpus are powered off initially.
        if self.index > 0 {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }

        self.fd.vcpu_init(&kvi).map_err(Error::VcpuArmInit)?;
        arch::aarch64::regs::setup_boot_regs(
            &self.fd,
            self.index,
            kernel_load_addr.raw_value(),
            guest_mem,
        )
        .map_err(Error::REGSConfiguration)?;

        self.mpidr = arch::aarch64::regs::read_mpidr(&self.fd).map_err(Error::REGSConfiguration)?;

        Ok(())
    }

    /// Moves the vcpu to its own thread and constructs a VcpuHandle.
    /// The handle can be used to control the remote vcpu.
    pub fn start_threaded(mut self, seccomp_filter: BpfProgram) -> Result<VcpuHandle> {
        let event_sender = self.event_sender.take().expect("vCPU already started");
        let response_receiver = self.response_receiver.take().unwrap();
        let vcpu_thread = thread::Builder::new()
            .name(format!("fc_vcpu {}", self.cpu_index()))
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

    #[cfg(target_arch = "x86_64")]
    fn save_state(&self) -> Result<VcpuState> {
        /*
         * Ordering requirements:
         *
         * KVM_GET_MP_STATE calls kvm_apic_accept_events(), which might modify
         * vCPU/LAPIC state. As such, it must be done before most everything
         * else, otherwise we cannot restore everything and expect it to work.
         *
         * KVM_GET_VCPU_EVENTS/KVM_SET_VCPU_EVENTS is unsafe if other vCPUs are
         * still running.
         *
         * KVM_GET_LAPIC may change state of LAPIC before returning it.
         *
         * GET_VCPU_EVENTS should probably be last to save. The code looks as
         * it might as well be affected by internal state modifications of the
         * GET ioctls.
         *
         * SREGS saves/restores a pending interrupt, similar to what
         * VCPU_EVENTS also does.
         *
         * GET_MSRS requires a pre-populated data structure to do something
         * meaningful. For SET_MSRS it will then contain good data.
         */

        // Build the list of MSRs we want to save.
        let num_msrs = self.msr_list.as_fam_struct_ref().nmsrs as usize;
        let mut msrs = Msrs::new(num_msrs);
        {
            let indices = self.msr_list.as_slice();
            let msr_entries = msrs.as_mut_slice();
            assert_eq!(indices.len(), msr_entries.len());
            for (pos, index) in indices.iter().enumerate() {
                msr_entries[pos].index = *index;
            }
        }
        let mp_state = self.fd.get_mp_state().map_err(Error::VcpuGetMpState)?;
        let regs = self.fd.get_regs().map_err(Error::VcpuGetRegs)?;
        let sregs = self.fd.get_sregs().map_err(Error::VcpuGetSregs)?;
        let xsave = self.fd.get_xsave().map_err(Error::VcpuGetXsave)?;
        let xcrs = self.fd.get_xcrs().map_err(Error::VcpuGetXcrs)?;
        let debug_regs = self.fd.get_debug_regs().map_err(Error::VcpuGetDebugRegs)?;
        let lapic = self.fd.get_lapic().map_err(Error::VcpuGetLapic)?;
        let nmsrs = self.fd.get_msrs(&mut msrs).map_err(Error::VcpuGetMsrs)?;
        assert_eq!(nmsrs, num_msrs);
        let vcpu_events = self
            .fd
            .get_vcpu_events()
            .map_err(Error::VcpuGetVcpuEvents)?;

        Ok(VcpuState {
            cpuid: self
                .fd
                .get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
                .map_err(Error::VcpuGetCpuid)?,
            msrs,
            debug_regs,
            lapic,
            mp_state,
            regs,
            sregs,
            vcpu_events,
            xcrs,
            xsave,
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn restore_state(&self, state: &VcpuState) -> Result<()> {
        /*
         * Ordering requirements:
         *
         * KVM_GET_VCPU_EVENTS/KVM_SET_VCPU_EVENTS is unsafe if other vCPUs are
         * still running.
         *
         * Some SET ioctls (like set_mp_state) depend on kvm_vcpu_is_bsp(), so
         * if we ever change the BSP, we have to do that before restoring anything.
         * The same seems to be true for CPUID stuff.
         *
         * SREGS saves/restores a pending interrupt, similar to what
         * VCPU_EVENTS also does.
         *
         * SET_REGS clears pending exceptions unconditionally, thus, it must be
         * done before SET_VCPU_EVENTS, which restores it.
         *
         * SET_LAPIC must come after SET_SREGS, because the latter restores
         * the apic base msr.
         *
         * SET_LAPIC must come before SET_MSRS, because the TSC deadline MSR
         * only restores successfully, when the LAPIC is correctly configured.
         */
        self.fd
            .set_cpuid2(&state.cpuid)
            .map_err(Error::VcpuSetCpuid)?;
        self.fd
            .set_mp_state(state.mp_state)
            .map_err(Error::VcpuSetMpState)?;
        self.fd.set_regs(&state.regs).map_err(Error::VcpuSetRegs)?;
        self.fd
            .set_sregs(&state.sregs)
            .map_err(Error::VcpuSetSregs)?;
        self.fd
            .set_xsave(&state.xsave)
            .map_err(Error::VcpuSetXsave)?;
        self.fd.set_xcrs(&state.xcrs).map_err(Error::VcpuSetXcrs)?;
        self.fd
            .set_debug_regs(&state.debug_regs)
            .map_err(Error::VcpuSetDebugRegs)?;
        self.fd
            .set_lapic(&state.lapic)
            .map_err(Error::VcpuSetLapic)?;
        self.fd.set_msrs(&state.msrs).map_err(Error::VcpuSetMsrs)?;
        self.fd
            .set_vcpu_events(&state.vcpu_events)
            .map_err(Error::VcpuSetVcpuEvents)?;
        Ok(())
    }

    /// Runs the vCPU in KVM context and handles the kvm exit reason.
    ///
    /// Returns error or enum specifying whether emulation was handled or interrupted.
    fn run_emulation(&mut self) -> Result<VcpuEmulation> {
        match self.fd.run() {
            Ok(run) => match run {
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoIn(addr, data) => {
                    if let Some(pio_bus) = &self.pio_bus {
                        pio_bus.read(u64::from(addr), data);
                        METRICS.vcpu.exit_io_in.inc();
                    }
                    Ok(VcpuEmulation::Handled)
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoOut(addr, data) => {
                    if let Some(pio_bus) = &self.pio_bus {
                        pio_bus.write(u64::from(addr), data);
                        METRICS.vcpu.exit_io_out.inc();
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::MmioRead(addr, data) => {
                    if let Some(mmio_bus) = &self.mmio_bus {
                        mmio_bus.read(addr, data);
                        METRICS.vcpu.exit_mmio_read.inc();
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if let Some(mmio_bus) = &self.mmio_bus {
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
                    METRICS.vcpu.failures.inc();
                    error!("Received KVM_EXIT_FAIL_ENTRY signal");
                    Err(Error::VcpuUnhandledKvmExit)
                }
                VcpuExit::InternalError => {
                    METRICS.vcpu.failures.inc();
                    error!("Received KVM_EXIT_INTERNAL_ERROR signal");
                    Err(Error::VcpuUnhandledKvmExit)
                }
                r => {
                    METRICS.vcpu.failures.inc();
                    // TODO: Are we sure we want to finish running a vcpu upon
                    // receiving a vm exit that is not necessarily an error?
                    error!("Unexpected exit reason on vcpu run: {:?}", r);
                    Err(Error::VcpuUnhandledKvmExit)
                }
            },
            // The unwrap on raw_os_error can only fail if we have a logic
            // error in our code in which case it is better to panic.
            Err(ref e) => {
                match e.errno() {
                    libc::EAGAIN => Ok(VcpuEmulation::Handled),
                    libc::EINTR => {
                        self.fd.set_kvm_immediate_exit(0);
                        // Notify that this KVM_RUN was interrupted.
                        Ok(VcpuEmulation::Interrupted)
                    }
                    _ => {
                        METRICS.vcpu.failures.inc();
                        error!("Failure during vcpu run: {}", e);
                        Err(Error::VcpuUnhandledKvmExit)
                    }
                }
            }
        }
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
                self.index, e
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
            #[cfg(target_arch = "x86_64")]
            Ok(VcpuEvent::SaveState) | Ok(VcpuEvent::RestoreState(_)) => {
                self.response_sender
                    .send(VcpuResponse::NotAllowed)
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
            #[cfg(target_arch = "x86_64")]
            Ok(VcpuEvent::SaveState) => {
                // Save vcpu state.
                self.save_state()
                    .map(|vcpu_state| {
                        self.response_sender
                            .send(VcpuResponse::SavedState(Box::new(vcpu_state)))
                            .expect("vcpu channel unexpectedly closed");
                    })
                    .map_err(|e| self.response_sender.send(VcpuResponse::Error(e)))
                    .expect("vcpu channel unexpectedly closed");

                StateMachine::next(Self::paused)
            }
            #[cfg(target_arch = "x86_64")]
            Ok(VcpuEvent::RestoreState(vcpu_state)) => {
                self.restore_state(&vcpu_state)
                    .map(|()| {
                        self.response_sender
                            .send(VcpuResponse::RestoredState)
                            .expect("vcpu channel unexpectedly closed");
                    })
                    .unwrap_or_else(|e| {
                        self.response_sender
                            .send(VcpuResponse::Error(e))
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
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        let _ = self.reset_thread_local_data();
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Versionize)]
/// Structure holding VCPU kvm state.
pub struct VcpuState {
    cpuid: CpuId,
    msrs: Msrs,
    debug_regs: kvm_debugregs,
    lapic: kvm_lapic_state,
    mp_state: kvm_mp_state,
    regs: kvm_regs,
    sregs: kvm_sregs,
    vcpu_events: kvm_vcpu_events,
    xcrs: kvm_xcrs,
    xsave: kvm_xsave,
}

#[derive(Clone)]
/// List of events that the Vcpu can receive.
pub enum VcpuEvent {
    /// Pause the Vcpu.
    Pause,
    /// Event to resume the Vcpu.
    Resume,
    /// Event to restore the state of a paused Vcpu.
    #[cfg(target_arch = "x86_64")]
    RestoreState(Box<VcpuState>),
    /// Event to save the state of a paused Vcpu.
    #[cfg(target_arch = "x86_64")]
    SaveState,
    /// The vCPU will go to exited state when receiving this message.
    Exit,
}

/// List of responses that the Vcpu reports.
pub enum VcpuResponse {
    /// Requested action encountered an error.
    #[cfg(target_arch = "x86_64")]
    Error(Error),
    /// Vcpu is stopped.
    Exited(u8),
    /// Requested action not allowed.
    #[cfg(target_arch = "x86_64")]
    NotAllowed,
    /// Vcpu is paused.
    Paused,
    /// Vcpu is resumed.
    Resumed,
    /// Vcpu state is restored.
    #[cfg(target_arch = "x86_64")]
    RestoredState,
    /// Vcpu state is saved.
    #[cfg(target_arch = "x86_64")]
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

enum VcpuEmulation {
    Handled,
    Interrupted,
    Stopped,
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fmt;
    use std::sync::{Arc, Barrier};
    #[cfg(target_arch = "x86_64")]
    use std::{convert::TryInto, fs::File, os::unix::io::AsRawFd, path::PathBuf, time::Duration};

    use super::*;
    use crate::vstate::{system::KvmContext, vm::Vm};
    use utils::signal::validate_signal_num;

    impl PartialEq for VcpuResponse {
        fn eq(&self, other: &Self) -> bool {
            use crate::VcpuResponse::*;
            // Guard match with no wildcard to make sure we catch new enum variants.
            match self {
                Paused | Resumed | Exited(_) => (),
                #[cfg(target_arch = "x86_64")]
                Error(_) | NotAllowed | RestoredState | SavedState(_) => (),
            };
            match (self, other) {
                (Paused, Paused) | (Resumed, Resumed) => true,
                (Exited(code), Exited(other_code)) => code == other_code,
                #[cfg(target_arch = "x86_64")]
                (NotAllowed, NotAllowed)
                | (RestoredState, RestoredState)
                | (SavedState(_), SavedState(_)) => true,
                #[cfg(target_arch = "x86_64")]
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
                #[cfg(target_arch = "x86_64")]
                RestoredState => write!(f, "VcpuResponse::RestoredState"),
                #[cfg(target_arch = "x86_64")]
                SavedState(_) => write!(f, "VcpuResponse::SavedState"),
                #[cfg(target_arch = "x86_64")]
                Error(ref err) => write!(f, "VcpuResponse::Error({:?})", err),
                #[cfg(target_arch = "x86_64")]
                NotAllowed => write!(f, "VcpuResponse::NotAllowed"),
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
    fn setup_vcpu(mem_size: usize) -> (Vm, Vcpu, GuestMemoryMmap) {
        let kvm = KvmContext::new().unwrap();
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), mem_size)]).unwrap();
        let mut vm = Vm::new(kvm.fd()).expect("Cannot create new vm");
        assert!(vm.memory_init(&gm, kvm.max_memslots(), false).is_ok());

        let exit_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();

        let vcpu;
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            vm.setup_irqchip().unwrap();
            vcpu = Vcpu::new_x86_64(1, vm.fd(), vm.supported_msrs().clone(), exit_evt).unwrap();
        }
        #[cfg(target_arch = "aarch64")]
        {
            vcpu = Vcpu::new_aarch64(1, vm.fd(), exit_evt).unwrap();
            vm.setup_irqchip(1).expect("Cannot setup irqchip");
        }

        (vm, vcpu, gm)
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn default_vcpu_state() -> VcpuState {
        VcpuState {
            cpuid: CpuId::new(1),
            msrs: Msrs::new(1),
            debug_regs: Default::default(),
            lapic: Default::default(),
            mp_state: Default::default(),
            regs: Default::default(),
            sregs: Default::default(),
            vcpu_events: Default::default(),
            xcrs: Default::default(),
            xsave: Default::default(),
        }
    }

    #[test]
    fn test_set_mmio_bus() {
        let (_, mut vcpu, _) = setup_vcpu(0x1000);
        assert!(vcpu.mmio_bus.is_none());
        vcpu.set_mmio_bus(devices::Bus::new());
        assert!(vcpu.mmio_bus.is_some());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_setup_irqchip() {
        let kvm_context = KvmContext::new().unwrap();
        let vm = Vm::new(kvm_context.fd()).expect("Cannot create new vm");

        vm.setup_irqchip().expect("Cannot setup irqchip");
        // Trying to setup two irqchips will result in EEXIST error. At the moment
        // there is no good way of testing the actual error because io::Error does not implement
        // PartialEq.
        assert!(vm.setup_irqchip().is_err());

        let _vcpu = Vcpu::new_x86_64(
            1,
            vm.fd(),
            vm.supported_msrs().clone(),
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();
        // Trying to setup irqchip after KVM_VCPU_CREATE was called will result in error.
        assert!(vm.setup_irqchip().is_err());
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_setup_irqchip() {
        let kvm = KvmContext::new().unwrap();

        let mut vm = Vm::new(kvm.fd()).expect("Cannot create new vm");
        let vcpu_count = 1;
        let _vcpu =
            Vcpu::new_aarch64(1, vm.fd(), EventFd::new(libc::EFD_NONBLOCK).unwrap()).unwrap();

        vm.setup_irqchip(vcpu_count).expect("Cannot setup irqchip");
        // Trying to setup two irqchips will result in EEXIST error.
        assert!(vm.setup_irqchip(vcpu_count).is_err());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_configure_vcpu() {
        let (_vm, mut vcpu, vm_mem) = setup_vcpu(0x10000);

        let mut vcpu_config = VcpuConfig {
            vcpu_count: 1,
            ht_enabled: false,
            cpu_template: None,
        };

        assert!(vcpu
            .configure_x86_64_for_boot(
                &vm_mem,
                GuestAddress(0),
                &vcpu_config,
                _vm.supported_cpuid().clone()
            )
            .is_ok());

        // Test configure while using the T2 template.
        vcpu_config.cpu_template = Some(CpuFeaturesTemplate::T2);
        assert!(vcpu
            .configure_x86_64_for_boot(
                &vm_mem,
                GuestAddress(0),
                &vcpu_config,
                _vm.supported_cpuid().clone(),
            )
            .is_ok());

        // Test configure while using the C3 template.
        vcpu_config.cpu_template = Some(CpuFeaturesTemplate::C3);
        assert!(vcpu
            .configure_x86_64_for_boot(
                &vm_mem,
                GuestAddress(0),
                &vcpu_config,
                _vm.supported_cpuid().clone(),
            )
            .is_ok());
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_configure_vcpu() {
        let kvm = KvmContext::new().unwrap();
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut vm = Vm::new(kvm.fd()).expect("new vm failed");
        assert!(vm.memory_init(&gm, kvm.max_memslots(), false).is_ok());

        // Try it for when vcpu id is 0.
        let mut vcpu =
            Vcpu::new_aarch64(0, vm.fd(), EventFd::new(libc::EFD_NONBLOCK).unwrap()).unwrap();

        assert!(vcpu
            .configure_aarch64_for_boot(vm.fd(), &gm, GuestAddress(0))
            .is_ok());

        // Try it for when vcpu id is NOT 0.
        let mut vcpu =
            Vcpu::new_aarch64(1, vm.fd(), EventFd::new(libc::EFD_NONBLOCK).unwrap()).unwrap();

        assert!(vcpu
            .configure_aarch64_for_boot(vm.fd(), &gm, GuestAddress(0))
            .is_ok());
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
        vcpu.index = 12;
        unsafe {
            assert!(Vcpu::run_on_thread_local(|v| assert_eq!(v.index, 12)).is_ok());
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
        let (vm, mut vcpu, _mem) = setup_vcpu(0x1000);

        let kvm_run =
            KvmRunWrapper::mmap_from_fd(&vcpu.fd, vm.fd().run_size()).expect("cannot mmap kvm-run");
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

    #[cfg(target_arch = "x86_64")]
    fn load_good_kernel(vm_memory: &GuestMemoryMmap) -> GuestAddress {
        use crate::vmm_config::boot_source::DEFAULT_KERNEL_CMDLINE;

        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let parent = path.parent().unwrap();

        let kernel_path: PathBuf = [parent.to_str().unwrap(), "kernel/src/loader/test_elf.bin"]
            .iter()
            .collect();

        let mut kernel_file = File::open(kernel_path).expect("Cannot open kernel file");
        let mut cmdline = kernel::cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
        assert!(cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).is_ok());
        let cmdline_addr = GuestAddress(arch::x86_64::layout::CMDLINE_START);

        let entry_addr = kernel::loader::load_kernel(
            vm_memory,
            &mut kernel_file,
            arch::x86_64::layout::HIMEM_START,
        )
        .expect("failed to load kernel");

        kernel::loader::load_cmdline(
            vm_memory,
            cmdline_addr,
            &cmdline.as_cstring().expect("failed to convert to cstring"),
        )
        .expect("failed to load cmdline");

        entry_addr
    }

    #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "x86_64")]
    fn vcpu_configured_for_boot() -> (VcpuHandle, utils::eventfd::EventFd) {
        Vcpu::register_kick_signal_handler();
        // Need enough mem to boot linux.
        let mem_size = 64 << 20;
        let (_vm, mut vcpu, vm_mem) = setup_vcpu(mem_size);

        let vcpu_exit_evt = vcpu.exit_evt.try_clone().unwrap();

        // Needs a kernel since we'll actually run this vcpu.
        let entry_addr = load_good_kernel(&vm_mem);

        let vcpu_config = VcpuConfig {
            vcpu_count: 1,
            ht_enabled: false,
            cpu_template: None,
        };
        vcpu.configure_x86_64_for_boot(
            &vm_mem,
            entry_addr,
            &vcpu_config,
            _vm.supported_cpuid().clone(),
        )
        .expect("failed to configure vcpu");

        let seccomp_filter = seccomp::SeccompFilter::empty().try_into().unwrap();
        let vcpu_handle = vcpu
            .start_threaded(seccomp_filter)
            .expect("failed to start vcpu");

        (vcpu_handle, vcpu_exit_evt)
    }

    #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_vcpu_save_restore_state_events() {
        let (vcpu_handle, _vcpu_exit_evt) = vcpu_configured_for_boot();

        // Queue a Resume event, expect a response.
        queue_event_expect_response(&vcpu_handle, VcpuEvent::Resume, VcpuResponse::Resumed);

        // Queue a SaveState event, expect a response.
        queue_event_expect_response(&vcpu_handle, VcpuEvent::SaveState, VcpuResponse::NotAllowed);

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
            VcpuResponse::SavedState(state) => state,
            _ => panic!("unexpected response"),
        };

        // Queue a RestoreState event, expect success.
        queue_event_expect_response(
            &vcpu_handle,
            VcpuEvent::RestoreState(vcpu_state),
            VcpuResponse::RestoredState,
        );
    }

    #[test]
    fn test_vcpu_rtsig_offset() {
        assert!(validate_signal_num(sigrtmin() + VCPU_RTSIG_OFFSET).is_ok());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_vcpu_save_restore_state() {
        let (_vm, vcpu, _mem) = setup_vcpu(0x1000);
        let state = vcpu.save_state().unwrap();
        assert!(vcpu.restore_state(&state).is_ok());

        unsafe { libc::close(vcpu.fd.as_raw_fd()) };
        let state = default_vcpu_state();
        // Setting default state should always fail.
        assert!(vcpu.restore_state(&state).is_err());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_vcpu_cpuid_restore() {
        let (_vm, vcpu, _mem) = setup_vcpu(0x1000);
        let mut state = vcpu.save_state().unwrap();
        // Mutate the cpuid.
        state.cpuid.as_mut_slice()[0].eax = 0x1234_5678;
        assert!(vcpu.restore_state(&state).is_ok());

        unsafe { libc::close(vcpu.fd.as_raw_fd()) };

        let (_vm, vcpu, _mem) = setup_vcpu(0x1000);
        assert!(vcpu.restore_state(&state).is_ok());

        // Validate the mutated cpuid is saved.
        assert!(vcpu.save_state().unwrap().cpuid.as_slice()[0].eax == 0x1234_5678);
    }
}
