// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use libc::{c_int, c_void, siginfo_t};
use std::cell::Cell;
use std::io;
use std::result;
use std::sync::atomic::{fence, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::thread;

use super::TimestampUs;
#[cfg(target_arch = "x86_64")]
use super::VcpuConfig;
use super::{FC_EXIT_CODE_GENERIC_ERROR, FC_EXIT_CODE_OK};
use arch;
#[cfg(target_arch = "aarch64")]
use arch::aarch64::gic::GICDevice;
#[cfg(target_arch = "x86_64")]
use cpuid::{c3, filter_cpuid, t2, VmSpec};
#[cfg(target_arch = "x86_64")]
use kvm_bindings::{
    kvm_clock_data, kvm_debugregs, kvm_irqchip, kvm_lapic_state, kvm_mp_state, kvm_pit_config,
    kvm_pit_state2, kvm_regs, kvm_sregs, kvm_vcpu_events, kvm_xcrs, kvm_xsave, CpuId, MsrList,
    Msrs, KVM_CLOCK_TSC_STABLE, KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE,
    KVM_MAX_CPUID_ENTRIES, KVM_PIT_SPEAKER_DUMMY,
};
use kvm_bindings::{kvm_userspace_memory_region, KVM_API_VERSION};
use kvm_ioctls::*;
use logger::{Metric, METRICS};
use seccomp::{BpfProgram, SeccompFilter};
use std::sync::Barrier;
use utils::eventfd::EventFd;
use utils::signal::{register_signal_handler, sigrtmin, Killable};
use utils::sm::StateMachine;
use vm_memory::{
    Address, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion,
};
#[cfg(target_arch = "x86_64")]
use vmm_config::machine_config::CpuFeaturesTemplate;

#[cfg(target_arch = "x86_64")]
const MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE: u64 = 0x03f0;
#[cfg(target_arch = "aarch64")]
const MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE: u64 = 0x40000000;
const MAGIC_VALUE_SIGNAL_GUEST_BOOT_COMPLETE: u8 = 123;

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
    #[cfg(target_arch = "x86_64")]
    /// Retrieving supported guest MSRs fails.
    GuestMSRs(arch::x86_64::msr::Error),
    /// Hyperthreading flag is not initialized.
    HTNotInitialized,
    /// Cannot configure the IRQ.
    Irq(kvm_ioctls::Error),
    /// The host kernel reports an invalid KVM API version.
    KvmApiVersion(i32),
    /// Cannot initialize the KVM context due to missing capabilities.
    KvmCap(kvm_ioctls::Cap),
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
    #[cfg(target_arch = "aarch64")]
    /// Error setting up the global interrupt controller.
    SetupGIC(arch::aarch64::gic::Error),
    /// Cannot set the memory regions.
    SetUserMemoryRegion(kvm_ioctls::Error),
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
    /// Failed to get KVM vcpu evenct.
    VcpuGetVcpuEvents(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu xcrs.
    VcpuGetXcrs(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vcpu xsave.
    VcpuGetXsave(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Cannot run the VCPUs.
    VcpuRun(kvm_ioctls::Error),
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
    /// Failed to set KVM vcpu evenct.
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
    /// Cannot open the VM file descriptor.
    VmFd(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vm pit state.
    VmGetPit2(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vm clock.
    VmGetClock(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to get KVM vm irqchip.
    VmGetIrqChip(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vm pit state.
    VmSetPit2(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vm clock.
    VmSetClock(kvm_ioctls::Error),
    #[cfg(target_arch = "x86_64")]
    /// Failed to set KVM vm irqchip.
    VmSetIrqChip(kvm_ioctls::Error),
    /// Cannot configure the microvm.
    VmSetup(kvm_ioctls::Error),
}
pub type Result<T> = result::Result<T, Error>;

/// Describes a KVM context that gets attached to the microVM.
/// It gives access to the functionality of the KVM wrapper as
/// long as every required KVM capability is present on the host.
pub struct KvmContext {
    kvm: Kvm,
    max_memslots: usize,
}

impl KvmContext {
    pub fn new() -> Result<Self> {
        use kvm_ioctls::Cap::*;
        let kvm = Kvm::new().expect("Error creating the Kvm object");

        // Check that KVM has the correct version.
        if kvm.get_api_version() != KVM_API_VERSION as i32 {
            return Err(Error::KvmApiVersion(kvm.get_api_version()));
        }

        // A list of KVM capabilities we want to check.
        #[cfg(target_arch = "x86_64")]
        let capabilities = vec![Irqchip, Ioeventfd, Irqfd, UserMemory, SetTssAddr];

        #[cfg(target_arch = "aarch64")]
        let capabilities = vec![Irqchip, Ioeventfd, Irqfd, UserMemory, ArmPsci02];

        // Check that all desired capabilities are supported.
        match capabilities
            .iter()
            .find(|&capability| !kvm.check_extension(*capability))
        {
            None => {
                let max_memslots = kvm.get_nr_memslots();
                Ok(KvmContext { kvm, max_memslots })
            }

            Some(c) => Err(Error::KvmCap(*c)),
        }
    }

    pub fn fd(&self) -> &Kvm {
        &self.kvm
    }

    /// Get the maximum number of memory slots reported by this KVM context.
    pub fn max_memslots(&self) -> usize {
        self.max_memslots
    }
}

/// A wrapper around creating and using a VM.
pub struct Vm {
    fd: VmFd,
    // TODO: remove the Option, keep a single reference instead of both Vmm and Vm.
    guest_mem: Option<GuestMemoryMmap>,

    // X86 specific fields.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    supported_cpuid: CpuId,
    #[cfg(target_arch = "x86_64")]
    supported_msrs: MsrList,

    // Arm specific fields.
    // On aarch64 we need to keep around the fd obtained by creating the VGIC device.
    #[cfg(target_arch = "aarch64")]
    irqchip_handle: Option<Box<dyn GICDevice>>,
}

impl Vm {
    /// Constructs a new `Vm` using the given `Kvm` instance.
    pub fn new(kvm: &Kvm) -> Result<Self> {
        //create fd for interacting with kvm-vm specific functions
        let vm_fd = kvm.create_vm().map_err(Error::VmFd)?;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let supported_cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::VmFd)?;
        #[cfg(target_arch = "x86_64")]
        let supported_msrs =
            arch::x86_64::msr::supported_guest_msrs(kvm).map_err(Error::GuestMSRs)?;

        Ok(Vm {
            fd: vm_fd,
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            supported_cpuid,
            #[cfg(target_arch = "x86_64")]
            supported_msrs,
            guest_mem: None,
            #[cfg(target_arch = "aarch64")]
            irqchip_handle: None,
        })
    }

    /// Returns a ref to the supported `CpuId` for this Vm.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn supported_cpuid(&self) -> &CpuId {
        &self.supported_cpuid
    }

    /// Returns a ref to the supported `MsrList` for this Vm.
    #[cfg(target_arch = "x86_64")]
    pub fn supported_msrs(&self) -> &MsrList {
        &self.supported_msrs
    }

    /// Initializes the guest memory.
    pub fn memory_init(
        &mut self,
        guest_mem: GuestMemoryMmap,
        kvm_max_memslots: usize,
    ) -> Result<()> {
        if guest_mem.num_regions() > kvm_max_memslots {
            return Err(Error::NotEnoughMemorySlots);
        }
        guest_mem
            .with_regions(|index, region| {
                // It's safe to unwrap because the guest address is valid.
                let host_addr = guest_mem.get_host_address(region.start_addr()).unwrap();
                info!("Guest memory starts at {:x?}", host_addr);

                let memory_region = kvm_userspace_memory_region {
                    slot: index as u32,
                    guest_phys_addr: region.start_addr().raw_value() as u64,
                    memory_size: region.len() as u64,
                    userspace_addr: host_addr as u64,
                    flags: 0,
                };
                // Safe because we mapped the memory region, we made sure that the regions
                // are not overlapping.
                unsafe { self.fd.set_user_memory_region(memory_region) }
            })
            .map_err(Error::SetUserMemoryRegion)?;
        self.guest_mem = Some(guest_mem);

        #[cfg(target_arch = "x86_64")]
        self.fd
            .set_tss_address(arch::x86_64::layout::KVM_TSS_ADDRESS as usize)
            .map_err(Error::VmSetup)?;

        Ok(())
    }

    /// Creates the irq chip and an in-kernel device model for the PIT.
    #[cfg(target_arch = "x86_64")]
    pub fn setup_irqchip(&self) -> Result<()> {
        self.fd.create_irq_chip().map_err(Error::VmSetup)?;
        let mut pit_config = kvm_pit_config::default();
        // We need to enable the emulation of a dummy speaker port stub so that writing to port 0x61
        // (i.e. KVM_SPEAKER_BASE_ADDRESS) does not trigger an exit to user space.
        pit_config.flags = KVM_PIT_SPEAKER_DUMMY;
        self.fd.create_pit2(pit_config).map_err(Error::VmSetup)
    }

    /// Creates the GIC (Global Interrupt Controller).
    #[cfg(target_arch = "aarch64")]
    pub fn setup_irqchip(&mut self, vcpu_count: u8) -> Result<()> {
        self.irqchip_handle = Some(
            arch::aarch64::gic::create_gic(&self.fd, vcpu_count.into()).map_err(Error::SetupGIC)?,
        );
        Ok(())
    }

    /// Gets a reference to the irqchip of the VM
    #[cfg(target_arch = "aarch64")]
    pub fn get_irqchip(&self) -> &Box<dyn GICDevice> {
        &self.irqchip_handle.as_ref().unwrap()
    }

    /// Gets a reference to the guest memory owned by this VM.
    ///
    /// Note that `GuestMemoryMmap` does not include any device memory that may have been added after
    /// this VM was constructed.
    pub fn memory(&self) -> Option<&GuestMemoryMmap> {
        self.guest_mem.as_ref()
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    pub fn fd(&self) -> &VmFd {
        &self.fd
    }

    #[allow(unused)]
    #[cfg(target_arch = "x86_64")]
    /// Saves and returns the Kvm Vm state.
    pub fn save_state(&self) -> Result<VmState> {
        let pitstate = self.fd.get_pit2().map_err(Error::VmGetPit2)?;

        let mut clock = self.fd.get_clock().map_err(Error::VmGetClock)?;
        // This bit is not accepted in SET_CLOCK, clear it.
        clock.flags &= !KVM_CLOCK_TSC_STABLE;

        let mut pic_master = kvm_irqchip::default();
        pic_master.chip_id = KVM_IRQCHIP_PIC_MASTER;
        self.fd
            .get_irqchip(&mut pic_master)
            .map_err(Error::VmGetIrqChip)?;

        let mut pic_slave = kvm_irqchip::default();
        pic_slave.chip_id = KVM_IRQCHIP_PIC_SLAVE;
        self.fd
            .get_irqchip(&mut pic_slave)
            .map_err(Error::VmGetIrqChip)?;

        let mut ioapic = kvm_irqchip::default();
        ioapic.chip_id = KVM_IRQCHIP_IOAPIC;
        self.fd
            .get_irqchip(&mut ioapic)
            .map_err(Error::VmGetIrqChip)?;

        Ok(VmState {
            pitstate,
            clock,
            pic_master,
            pic_slave,
            ioapic,
        })
    }

    #[allow(unused)]
    #[cfg(target_arch = "x86_64")]
    /// Restores the Kvm Vm state.
    pub fn restore_state(&self, state: &VmState) -> Result<()> {
        self.fd
            .set_pit2(&state.pitstate)
            .map_err(Error::VmSetPit2)?;
        self.fd.set_clock(&state.clock).map_err(Error::VmSetClock)?;
        self.fd
            .set_irqchip(&state.pic_master)
            .map_err(Error::VmSetIrqChip)?;
        self.fd
            .set_irqchip(&state.pic_slave)
            .map_err(Error::VmSetIrqChip)?;
        self.fd
            .set_irqchip(&state.ioapic)
            .map_err(Error::VmSetIrqChip)?;
        Ok(())
    }
}

#[allow(unused)]
#[cfg(target_arch = "x86_64")]
/// Structure holding VM kvm state.
pub struct VmState {
    pitstate: kvm_pit_state2,
    clock: kvm_clock_data,
    pic_master: kvm_irqchip,
    pic_slave: kvm_irqchip,
    ioapic: kvm_irqchip,
}

// Using this for easier explicit type-casting to help IDEs interpret the code.
type VcpuCell = Cell<Option<*const Vcpu>>;

/// A wrapper around creating and using a kvm-based VCPU.
pub struct Vcpu {
    fd: VcpuFd,
    id: u8,
    create_ts: TimestampUs,
    mmio_bus: Option<devices::Bus>,
    exit_evt: EventFd,

    #[cfg(target_arch = "x86_64")]
    io_bus: devices::Bus,
    #[cfg(target_arch = "x86_64")]
    cpuid: CpuId,
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
    /// * `cpuid` - The `CpuId` listing the supported capabilities of this vcpu.
    /// * `msr_list` - The `MsrList` listing the supported MSRs for this vcpu.
    /// * `io_bus` - The io-bus used to access port-io devices.
    /// * `exit_evt` - An `EventFd` that will be written into when this vcpu exits.
    /// * `create_ts` - A timestamp used by the vcpu to calculate its lifetime.
    #[cfg(target_arch = "x86_64")]
    pub fn new_x86_64(
        id: u8,
        vm_fd: &VmFd,
        cpuid: CpuId,
        msr_list: MsrList,
        io_bus: devices::Bus,
        exit_evt: EventFd,
        create_ts: TimestampUs,
    ) -> Result<Self> {
        let kvm_vcpu = vm_fd.create_vcpu(id).map_err(Error::VcpuFd)?;
        let (event_sender, event_receiver) = channel();
        let (response_sender, response_receiver) = channel();

        // Initially the cpuid per vCPU is the one supported by this VM.
        Ok(Vcpu {
            fd: kvm_vcpu,
            id,
            create_ts,
            mmio_bus: None,
            exit_evt,
            io_bus,
            cpuid,
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
    /// * `create_ts` - A timestamp used by the vcpu to calculate its lifetime.
    #[cfg(target_arch = "aarch64")]
    pub fn new_aarch64(
        id: u8,
        vm_fd: &VmFd,
        exit_evt: EventFd,
        create_ts: TimestampUs,
    ) -> Result<Self> {
        let kvm_vcpu = vm_fd.create_vcpu(id).map_err(Error::VcpuFd)?;
        let (event_sender, event_receiver) = channel();
        let (response_sender, response_receiver) = channel();

        Ok(Vcpu {
            fd: kvm_vcpu,
            id,
            create_ts,
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
        self.id
    }

    /// Gets the MPIDR register value.
    #[cfg(target_arch = "aarch64")]
    pub fn get_mpidr(&self) -> u64 {
        self.mpidr
    }

    /// Sets a MMIO bus for this vcpu.
    pub fn set_mmio_bus(&mut self, mmio_bus: devices::Bus) {
        self.mmio_bus = Some(mmio_bus);
    }

    #[cfg(target_arch = "x86_64")]
    /// Configures a x86_64 specific vcpu and should be called once per vcpu.
    ///
    /// # Arguments
    ///
    /// * `machine_config` - The machine configuration of this microvm needed for the CPUID configuration.
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_start_addr` - Offset from `guest_mem` at which the kernel starts.
    pub fn configure_x86_64(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        kernel_start_addr: GuestAddress,
        vcpu_config: &VcpuConfig,
    ) -> Result<()> {
        let cpuid_vm_spec = VmSpec::new(self.id, vcpu_config.vcpu_count, vcpu_config.ht_enabled)
            .map_err(Error::CpuId)?;

        filter_cpuid(&mut self.cpuid, &cpuid_vm_spec).map_err(|e| {
            METRICS.vcpu.filter_cpuid.inc();
            error!("Failure in configuring CPUID for vcpu {}: {:?}", self.id, e);
            Error::CpuId(e)
        })?;

        if let Some(template) = vcpu_config.cpu_template {
            match template {
                CpuFeaturesTemplate::T2 => {
                    t2::set_cpuid_entries(&mut self.cpuid, &cpuid_vm_spec).map_err(Error::CpuId)?
                }
                CpuFeaturesTemplate::C3 => {
                    c3::set_cpuid_entries(&mut self.cpuid, &cpuid_vm_spec).map_err(Error::CpuId)?
                }
            }
        }

        self.fd
            .set_cpuid2(&self.cpuid)
            .map_err(Error::VcpuSetCpuid)?;

        arch::x86_64::msr::setup_msrs(&self.fd).map_err(Error::MSRSConfiguration)?;
        arch::x86_64::regs::setup_regs(&self.fd, kernel_start_addr.raw_value() as u64)
            .map_err(Error::REGSConfiguration)?;
        arch::x86_64::regs::setup_fpu(&self.fd).map_err(Error::FPUConfiguration)?;
        arch::x86_64::regs::setup_sregs(guest_mem, &self.fd).map_err(Error::SREGSConfiguration)?;
        arch::x86_64::interrupts::set_lint(&self.fd).map_err(Error::LocalIntConfiguration)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Configures an aarch64 specific vcpu.
    ///
    /// # Arguments
    ///
    /// * `vm_fd` - The kvm `VmFd` for this microvm.
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_load_addr` - Offset from `guest_mem` at which the kernel is loaded.
    pub fn configure_aarch64(
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
        if self.id > 0 {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }

        self.fd.vcpu_init(&kvi).map_err(Error::VcpuArmInit)?;
        arch::aarch64::regs::setup_regs(&self.fd, self.id, kernel_load_addr.raw_value(), guest_mem)
            .map_err(Error::REGSConfiguration)?;

        self.mpidr = arch::aarch64::regs::read_mpidr(&self.fd).map_err(Error::REGSConfiguration)?;

        Ok(())
    }

    /// Moves the vcpu to its own thread and constructs a VcpuHandle.
    /// The handle can be used to control the remote vcpu.
    pub fn start_threaded(mut self, seccomp_filter: BpfProgram) -> Result<VcpuHandle> {
        let event_sender = self.event_sender.take().unwrap();
        let response_receiver = self.response_receiver.take().unwrap();
        let vcpu_thread = thread::Builder::new()
            .name(format!("fc_vcpu {}", self.cpu_index()))
            .spawn(move || {
                self.init_thread_local_data()
                    .expect("Cannot cleanly initialize vcpu TLS.");

                self.run(seccomp_filter);
            })
            .map_err(Error::VcpuSpawn)?;

        Ok(VcpuHandle {
            event_sender,
            response_receiver,
            vcpu_thread,
        })
    }

    fn check_boot_complete_signal(&self, addr: u64, data: &[u8]) {
        if addr == MAGIC_IOPORT_SIGNAL_GUEST_BOOT_COMPLETE
            && data[0] == MAGIC_VALUE_SIGNAL_GUEST_BOOT_COMPLETE
        {
            super::Vmm::log_boot_time(&self.create_ts);
        }
    }

    #[allow(unused)]
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
            cpuid: self.cpuid.clone(),
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

    #[allow(unused)]
    #[cfg(target_arch = "x86_64")]
    fn restore_state(&self, state: VcpuState) -> Result<()> {
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
                    self.io_bus.read(u64::from(addr), data);
                    METRICS.vcpu.exit_io_in.inc();
                    Ok(VcpuEmulation::Handled)
                }
                #[cfg(target_arch = "x86_64")]
                VcpuExit::IoOut(addr, data) => {
                    self.check_boot_complete_signal(u64::from(addr), data);

                    self.io_bus.write(u64::from(addr), data);
                    METRICS.vcpu.exit_io_out.inc();
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::MmioRead(addr, data) => {
                    if let Some(ref mmio_bus) = self.mmio_bus {
                        mmio_bus.read(addr, data);
                        METRICS.vcpu.exit_mmio_read.inc();
                    }
                    Ok(VcpuEmulation::Handled)
                }
                VcpuExit::MmioWrite(addr, data) => {
                    if let Some(ref mmio_bus) = self.mmio_bus {
                        #[cfg(target_arch = "aarch64")]
                        self.check_boot_complete_signal(addr, data);

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
                self.id, e
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
                    .expect("failed to send resume status");
                // Move to 'running' state.
                StateMachine::next(Self::running)
            }
            // All other events have no effect on current 'paused' state.
            Ok(_) => StateMachine::next(Self::paused),
            // Unhandled exit of the other end.
            Err(_) => {
                // Move to 'exited' state.
                self.exit(FC_EXIT_CODE_GENERIC_ERROR)
            }
        }
    }

    // Transition to the exited state
    fn exit(&mut self, exit_code: u8) -> StateMachine<Self> {
        self.response_sender
            .send(VcpuResponse::Exited(exit_code))
            .expect("failed to send Exited status");

        if let Err(e) = self.exit_evt.write(1) {
            METRICS.vcpu.failures.inc();
            error!("Failed signaling vcpu exit event: {}", e);
        }

        // State machine reached its end.
        StateMachine::next(Self::exited)
    }

    // This is the main loop of the `Exited` state.
    fn exited(&mut self) -> StateMachine<Self> {
        // Wait indefinitely.
        // The VMM thread will kill the entire process.
        let barrier = Barrier::new(2);
        barrier.wait();

        StateMachine::finish()
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        let _ = self.reset_thread_local_data();
    }
}

#[cfg(target_arch = "x86_64")]
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

// Allow currently unused Pause and Exit events. These will be used by the vmm later on.
#[allow(unused)]
#[derive(Debug)]
/// List of events that the Vcpu can receive.
pub enum VcpuEvent {
    /// Pause the Vcpu.
    Pause,
    /// Event that should resume the Vcpu.
    Resume,
    // Serialize and Deserialize to follow after we get the support from kvm-ioctls.
}

#[derive(Debug, PartialEq)]
/// List of responses that the Vcpu reports.
pub enum VcpuResponse {
    /// Vcpu is paused.
    Paused,
    /// Vcpu is resumed.
    Resumed,
    /// Vcpu is stopped.
    Exited(u8),
}

/// Wrapper over Vcpu that hides the underlying interactions with the Vcpu thread.
pub struct VcpuHandle {
    event_sender: Sender<VcpuEvent>,
    response_receiver: Receiver<VcpuResponse>,
    vcpu_thread: thread::JoinHandle<()>,
}

impl VcpuHandle {
    pub fn send_event(&self, event: VcpuEvent) -> Result<()> {
        // Use expect() to crash if the other thread closed this channel.
        self.event_sender
            .send(event)
            .expect("event sender channel closed on vcpu end.");
        // Kick the vcpu so it picks up the message.
        self.vcpu_thread
            .kill(sigrtmin() + VCPU_RTSIG_OFFSET)
            .map_err(Error::SignalVcpu)?;
        Ok(())
    }

    pub fn response_receiver(&self) -> &Receiver<VcpuResponse> {
        &self.response_receiver
    }

    #[allow(dead_code)]
    pub fn join_vcpu_thread(self) -> thread::Result<()> {
        self.vcpu_thread.join()
    }
}

enum VcpuEmulation {
    Handled,
    Interrupted,
    Stopped,
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    use std::convert::TryInto;
    use std::fs::File;
    #[cfg(target_arch = "x86_64")]
    use std::os::unix::io::AsRawFd;
    #[cfg(target_arch = "x86_64")]
    use std::path::PathBuf;
    use std::sync::{mpsc, Arc, Barrier};
    #[cfg(target_arch = "x86_64")]
    use std::time::Duration;

    use super::super::devices;
    use super::*;

    use utils::signal::validate_signal_num;
    use vmm_config::boot_source::DEFAULT_KERNEL_CMDLINE;

    // Auxiliary function being used throughout the tests.
    fn setup_vcpu(mem_size: usize) -> (Vm, Vcpu) {
        let kvm = KvmContext::new().unwrap();
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), mem_size)]).unwrap();
        let mut vm = Vm::new(kvm.fd()).expect("Cannot create new vm");
        assert!(vm.memory_init(gm, kvm.max_memslots()).is_ok());

        let exit_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();

        let vcpu;
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            vm.setup_irqchip().unwrap();
            vcpu = Vcpu::new_x86_64(
                1,
                vm.fd(),
                vm.supported_cpuid().clone(),
                vm.supported_msrs().clone(),
                devices::Bus::new(),
                exit_evt,
                super::super::TimestampUs::default(),
            )
            .unwrap();
        }
        #[cfg(target_arch = "aarch64")]
        {
            vcpu = Vcpu::new_aarch64(1, vm.fd(), exit_evt, super::super::TimestampUs::default())
                .unwrap();
            vm.setup_irqchip(1).expect("Cannot setup irqchip");
        }

        (vm, vcpu)
    }

    #[test]
    fn test_set_mmio_bus() {
        let (_, mut vcpu) = setup_vcpu(0x1000);
        assert!(vcpu.mmio_bus.is_none());
        vcpu.set_mmio_bus(devices::Bus::new());
        assert!(vcpu.mmio_bus.is_some());
    }

    #[test]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn test_get_supported_cpuid() {
        let kvm = KvmContext::new().unwrap();
        let vm = Vm::new(kvm.fd()).expect("Cannot create new vm");
        let cpuid = kvm
            .kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .expect("Cannot get supported cpuid");
        assert_eq!(vm.supported_cpuid().as_slice(), cpuid.as_slice());
    }

    #[test]
    fn test_vm_memory_init() {
        let mut kvm_context = KvmContext::new().unwrap();
        let mut vm = Vm::new(kvm_context.fd()).expect("Cannot create new vm");

        // Create valid memory region and test that the initialization is successful.
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        assert!(vm.memory_init(gm, kvm_context.max_memslots()).is_ok());

        // Set the maximum number of memory slots to 1 in KvmContext to check the error
        // path of memory_init. Create 2 non-overlapping memory slots.
        kvm_context.max_memslots = 1;
        let gm = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0x0), 0x1000),
            (GuestAddress(0x1001), 0x2000),
        ])
        .unwrap();
        assert!(vm.memory_init(gm, kvm_context.max_memslots()).is_err());
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
            vm.supported_cpuid().clone(),
            vm.supported_msrs().clone(),
            devices::Bus::new(),
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            super::super::TimestampUs::default(),
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
        let _vcpu = Vcpu::new_aarch64(
            1,
            vm.fd(),
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            super::super::TimestampUs::default(),
        )
        .unwrap();

        vm.setup_irqchip(vcpu_count).expect("Cannot setup irqchip");
        // Trying to setup two irqchips will result in EEXIST error.
        assert!(vm.setup_irqchip(vcpu_count).is_err());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_configure_vcpu() {
        let (vm, mut vcpu) = setup_vcpu(0x10000);

        let mut vcpu_config = VcpuConfig {
            vcpu_count: 1,
            ht_enabled: false,
            cpu_template: None,
        };

        let vm_mem = vm.memory().unwrap();

        assert!(vcpu
            .configure_x86_64(vm_mem, GuestAddress(0), &vcpu_config)
            .is_ok());

        // Test configure while using the T2 template.
        vcpu_config.cpu_template = Some(CpuFeaturesTemplate::T2);
        assert!(vcpu
            .configure_x86_64(vm_mem, GuestAddress(0), &vcpu_config)
            .is_ok());

        // Test configure while using the C3 template.
        vcpu_config.cpu_template = Some(CpuFeaturesTemplate::C3);
        assert!(vcpu
            .configure_x86_64(vm_mem, GuestAddress(0), &vcpu_config)
            .is_ok());
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_configure_vcpu() {
        let kvm = KvmContext::new().unwrap();
        let gm = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut vm = Vm::new(kvm.fd()).expect("new vm failed");
        assert!(vm.memory_init(gm, kvm.max_memslots()).is_ok());
        let vm_mem = vm.memory().unwrap();

        // Try it for when vcpu id is 0.
        let mut vcpu = Vcpu::new_aarch64(
            0,
            vm.fd(),
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            super::super::TimestampUs::default(),
        )
        .unwrap();

        assert!(vcpu
            .configure_aarch64(vm.fd(), vm_mem, GuestAddress(0))
            .is_ok());

        // Try it for when vcpu id is NOT 0.
        let mut vcpu = Vcpu::new_aarch64(
            1,
            vm.fd(),
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            super::super::TimestampUs::default(),
        )
        .unwrap();

        assert!(vcpu
            .configure_aarch64(vm.fd(), vm_mem, GuestAddress(0))
            .is_ok());
    }

    #[test]
    fn test_kvm_context() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let c = KvmContext::new().unwrap();

        assert!(c.max_memslots >= 32);

        let kvm = Kvm::new().unwrap();
        let f = unsafe { File::from_raw_fd(kvm.as_raw_fd()) };
        let m1 = f.metadata().unwrap();
        let m2 = File::open("/dev/kvm").unwrap().metadata().unwrap();

        assert_eq!(m1.dev(), m2.dev());
        assert_eq!(m1.ino(), m2.ino());
    }

    #[test]
    fn test_vcpu_tls() {
        let (_, mut vcpu) = setup_vcpu(0x1000);

        // Running on the TLS vcpu should fail before we actually initialize it.
        unsafe {
            assert!(Vcpu::run_on_thread_local(|_| ()).is_err());
        }

        // Initialize vcpu TLS.
        vcpu.init_thread_local_data().unwrap();

        // Validate TLS vcpu is the local vcpu by changing the `id` then validating against
        // the one in TLS.
        vcpu.id = 12;
        unsafe {
            assert!(Vcpu::run_on_thread_local(|v| assert_eq!(v.id, 12)).is_ok());
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
        let (_, mut vcpu) = setup_vcpu(0x1000);
        // Initialize vcpu TLS.
        vcpu.init_thread_local_data().unwrap();
        // Trying to initialize non-empty TLS should error.
        vcpu.init_thread_local_data().unwrap_err();
    }

    #[test]
    fn test_vcpu_kick() {
        Vcpu::register_kick_signal_handler();
        let (vm, mut vcpu) = setup_vcpu(0x1000);

        let kvm_run =
            KvmRunWrapper::mmap_from_fd(&vcpu.fd, vm.fd.run_size()).expect("cannot mmap kvm-run");
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
    fn load_good_kernel(vm: &Vm) -> GuestAddress {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let parent = path.parent().unwrap();

        let kernel_path: PathBuf = [parent.to_str().unwrap(), "kernel/src/loader/test_elf.bin"]
            .iter()
            .collect();

        let vm_memory = vm.memory().expect("vm memory not initialized");

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
                .recv_timeout(Duration::from_millis(100))
                .expect("did not receive event response from vcpu"),
            response
        );
    }

    #[cfg(target_arch = "x86_64")]
    // Sends an event to a vcpu and expects no response.
    fn queue_event_expect_timeout(handle: &VcpuHandle, event: VcpuEvent) {
        handle
            .send_event(event)
            .expect("failed to send event to vcpu");
        assert_eq!(
            handle
                .response_receiver()
                .recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn vcpu_pause_resume() {
        Vcpu::register_kick_signal_handler();
        // Need enough mem to boot linux.
        let mem_size = 64 << 20;
        let (vm, mut vcpu) = setup_vcpu(mem_size);

        let vcpu_exit_evt = vcpu.exit_evt.try_clone().unwrap();

        // Needs a kernel since we'll actually run this vcpu.
        let entry_addr = load_good_kernel(&vm);

        let vcpu_config = VcpuConfig {
            vcpu_count: 1,
            ht_enabled: false,
            cpu_template: None,
        };
        let vm_mem = vm.memory().unwrap();
        vcpu.configure_x86_64(vm_mem, entry_addr, &vcpu_config)
            .expect("failed to configure vcpu");

        let seccomp_filter = seccomp::SeccompFilter::empty().try_into().unwrap();
        let vcpu_handle = vcpu
            .start_threaded(seccomp_filter)
            .expect("failed to start vcpu");

        // Queue a Resume event, expect a response.
        queue_event_expect_response(&vcpu_handle, VcpuEvent::Resume, VcpuResponse::Resumed);

        // Queue a Pause event, expect a response.
        queue_event_expect_response(&vcpu_handle, VcpuEvent::Pause, VcpuResponse::Paused);

        // Validate vcpu handled the EINTR gracefully and didn't exit.
        let err = vcpu_exit_evt.read().unwrap_err();
        assert_eq!(err.raw_os_error().unwrap(), libc::EAGAIN);

        // Queue another Pause event, expect no answer.
        queue_event_expect_timeout(&vcpu_handle, VcpuEvent::Pause);

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
    fn test_vcpu_rtsig_offset() {
        assert!(validate_signal_num(sigrtmin() + VCPU_RTSIG_OFFSET).is_ok());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_vm_save_restore_state() {
        let kvm_fd = Kvm::new().unwrap();
        let vm = Vm::new(&kvm_fd).expect("new vm failed");
        // Irqchips, clock and pitstate are not configured so trying to save state should fail.
        assert!(vm.save_state().is_err());

        let (vm, _) = setup_vcpu(0x1000);
        let vm_state = vm.save_state().unwrap();
        assert_eq!(
            vm_state.pitstate.flags | KVM_PIT_SPEAKER_DUMMY,
            KVM_PIT_SPEAKER_DUMMY
        );
        assert_eq!(vm_state.clock.flags & KVM_CLOCK_TSC_STABLE, 0);
        assert_eq!(vm_state.pic_master.chip_id, KVM_IRQCHIP_PIC_MASTER);
        assert_eq!(vm_state.pic_slave.chip_id, KVM_IRQCHIP_PIC_SLAVE);
        assert_eq!(vm_state.ioapic.chip_id, KVM_IRQCHIP_IOAPIC);

        let (vm, _) = setup_vcpu(0x1000);
        assert!(vm.restore_state(&vm_state).is_ok());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_vcpu_save_restore_state() {
        let (_vm, vcpu) = setup_vcpu(0x1000);
        let state = vcpu.save_state();
        assert!(state.is_ok());
        assert!(vcpu.restore_state(state.unwrap()).is_ok());

        unsafe { libc::close(vcpu.fd.as_raw_fd()) };
        let state = VcpuState {
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
        };
        // Setting default state should always fail.
        assert!(vcpu.restore_state(state).is_err());
    }
}
