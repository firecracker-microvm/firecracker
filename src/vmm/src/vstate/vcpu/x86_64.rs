// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::{fmt, result};

use arch::x86_64::interrupts;
use arch::x86_64::msr::SetMSRsError;
use arch::x86_64::regs::{SetupFpuError, SetupRegistersError, SetupSpecialRegistersError};
use cpuid::{c3, filter_cpuid, msrs_to_save_by_cpuid, t2, t2a, t2cl, t2s, VmSpec};
use kvm_bindings::{
    kvm_debugregs, kvm_lapic_state, kvm_mp_state, kvm_regs, kvm_sregs, kvm_vcpu_events, kvm_xcrs,
    kvm_xsave, CpuId, Msrs, KVM_MAX_MSR_ENTRIES,
};
use kvm_ioctls::{VcpuExit, VcpuFd};
use logger::{error, warn, IncMetric, METRICS};
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;
use vm_memory::{Address, GuestAddress, GuestMemoryMmap};

use crate::vmm_config::machine_config::CpuFeaturesTemplate;
use crate::vstate::vcpu::{VcpuConfig, VcpuEmulation};
use crate::vstate::vm::Vm;

// Tolerance for TSC frequency expected variation.
// The value of 250 parts per million is based on
// the QEMU approach, more details here:
// https://bugzilla.redhat.com/show_bug.cgi?id=1839095
const TSC_KHZ_TOL: f64 = 250.0 / 1_000_000.0;

/// Errors associated with the wrappers over KVM ioctls.
#[derive(Debug)]
pub enum Error {
    /// A call to cpuid instruction failed.
    CpuId(cpuid::Error),
    /// A FamStructWrapper operation has failed.
    Fam(utils::fam::Error),
    /// Error configuring the floating point related registers
    FPUConfiguration(arch::x86_64::regs::Error),
    /// Cannot set the local interruption due to bad configuration.
    LocalIntConfiguration(arch::x86_64::interrupts::Error),
    /// Error configuring the MSR registers
    MSRSConfiguration(arch::x86_64::msr::Error),
    /// Error configuring the general purpose registers
    REGSConfiguration(arch::x86_64::regs::Error),
    /// Error configuring the special registers
    SREGSConfiguration(arch::x86_64::regs::Error),
    /// Cannot open the VCPU file descriptor.
    VcpuFd(kvm_ioctls::Error),
    /// Failed to get KVM vcpu debug regs.
    VcpuGetDebugRegs(kvm_ioctls::Error),
    /// Failed to get KVM vcpu lapic.
    VcpuGetLapic(kvm_ioctls::Error),
    /// Failed to get KVM vcpu mp state.
    VcpuGetMpState(kvm_ioctls::Error),
    /// The number of MSRS returned by the kernel is unexpected.
    VcpuGetMSRSIncomplete,
    /// Failed to get KVM vcpu msrs.
    VcpuGetMsrs(kvm_ioctls::Error),
    /// Failed to get KVM vcpu regs.
    VcpuGetRegs(kvm_ioctls::Error),
    /// Failed to get KVM vcpu sregs.
    VcpuGetSregs(kvm_ioctls::Error),
    /// Failed to get KVM vcpu event.
    VcpuGetVcpuEvents(kvm_ioctls::Error),
    /// Failed to get KVM vcpu xcrs.
    VcpuGetXcrs(kvm_ioctls::Error),
    /// Failed to get KVM vcpu xsave.
    VcpuGetXsave(kvm_ioctls::Error),
    /// Failed to get KVM vcpu cpuid.
    VcpuGetCpuid(kvm_ioctls::Error),
    /// Failed to get KVM TSC freq.
    VcpuGetTSC(kvm_ioctls::Error),
    /// Failed to set KVM vcpu cpuid.
    VcpuSetCpuid(kvm_ioctls::Error),
    /// Failed to set KVM vcpu debug regs.
    VcpuSetDebugRegs(kvm_ioctls::Error),
    /// Failed to set KVM vcpu lapic.
    VcpuSetLapic(kvm_ioctls::Error),
    /// Failed to set KVM vcpu mp state.
    VcpuSetMpState(kvm_ioctls::Error),
    /// Failed to set KVM vcpu msrs.
    VcpuSetMsrs(kvm_ioctls::Error),
    /// Failed to set all KVM vcpu MSRs. Only a partial set was done.
    VcpuSetMSRSIncomplete,
    /// Failed to set KVM vcpu regs.
    VcpuSetRegs(kvm_ioctls::Error),
    /// Failed to set KVM vcpu sregs.
    VcpuSetSregs(kvm_ioctls::Error),
    /// Failed to set KVM vcpu event.
    VcpuSetVcpuEvents(kvm_ioctls::Error),
    /// Failed to set KVM vcpu xcrs.
    VcpuSetXcrs(kvm_ioctls::Error),
    /// Failed to set KVM vcpu xsave.
    VcpuSetXsave(kvm_ioctls::Error),
    /// Failed to set KVM TSC freq.
    VcpuSetTSC(kvm_ioctls::Error),
    /// Failed to apply CPU template.
    VcpuTemplateError,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            CpuId(err) => write!(f, "Cpuid error: {:?}", err),
            LocalIntConfiguration(err) => write!(
                f,
                "Cannot set the local interruption due to bad configuration: {:?}",
                err
            ),
            VcpuFd(err) => write!(f, "Cannot open the VCPU file descriptor: {}", err),
            MSRSConfiguration(err) => write!(f, "Error configuring the MSR registers: {:?}", err),
            REGSConfiguration(err) => write!(
                f,
                "Error configuring the general purpose registers: {:?}",
                err
            ),
            SREGSConfiguration(err) => {
                write!(f, "Error configuring the special registers: {:?}", err)
            }
            Fam(err) => write!(f, "Failed FamStructWrapper operation: {:?}", err),
            FPUConfiguration(err) => write!(
                f,
                "Error configuring the floating point related registers: {:?}",
                err
            ),
            VcpuGetDebugRegs(err) => write!(f, "Failed to get KVM vcpu debug regs: {}", err),
            VcpuGetLapic(err) => write!(f, "Failed to get KVM vcpu lapic: {}", err),
            VcpuGetMpState(err) => write!(f, "Failed to get KVM vcpu mp state: {}", err),
            VcpuGetMsrs(err) => write!(f, "Failed to get KVM vcpu msrs: {}", err),
            VcpuGetMSRSIncomplete => write!(f, "Unexpected number of MSRS reported by the kernel"),
            VcpuGetRegs(err) => write!(f, "Failed to get KVM vcpu regs: {}", err),
            VcpuGetSregs(err) => write!(f, "Failed to get KVM vcpu sregs: {}", err),
            VcpuGetVcpuEvents(err) => write!(f, "Failed to get KVM vcpu event: {}", err),
            VcpuGetXcrs(err) => write!(f, "Failed to get KVM vcpu xcrs: {}", err),
            VcpuGetXsave(err) => write!(f, "Failed to get KVM vcpu xsave: {}", err),
            VcpuGetCpuid(err) => write!(f, "Failed to get KVM vcpu cpuid: {}", err),
            VcpuGetTSC(err) => write!(f, "Failed to get KVM TSC frequency: {}", err),
            VcpuSetCpuid(err) => write!(f, "Failed to set KVM vcpu cpuid: {}", err),
            VcpuSetDebugRegs(err) => write!(f, "Failed to set KVM vcpu debug regs: {}", err),
            VcpuSetLapic(err) => write!(f, "Failed to set KVM vcpu lapic: {}", err),
            VcpuSetMpState(err) => write!(f, "Failed to set KVM vcpu mp state: {}", err),
            VcpuSetMsrs(err) => write!(f, "Failed to set KVM vcpu msrs: {}", err),
            VcpuSetMSRSIncomplete => write!(
                f,
                "Failed to set all KVM MSRs for this vCPU. Only a partial write was done."
            ),
            VcpuSetRegs(err) => write!(f, "Failed to set KVM vcpu regs: {}", err),
            VcpuSetSregs(err) => write!(f, "Failed to set KVM vcpu sregs: {}", err),
            VcpuSetVcpuEvents(err) => write!(f, "Failed to set KVM vcpu event: {}", err),
            VcpuSetXcrs(err) => write!(f, "Failed to set KVM vcpu xcrs: {}", err),
            VcpuSetXsave(err) => write!(f, "Failed to set KVM vcpu xsave: {}", err),
            VcpuSetTSC(err) => write!(f, "Failed to set KVM TSC frequency: {}", err),
            VcpuTemplateError => write!(f, "Failed to apply CPU template"),
        }
    }
}

type Result<T> = result::Result<T, Error>;

/// Error type for [`KvmVcpu::get_tsc_khz`] and [`KvmVcpu::is_tsc_scaling_required`].
#[derive(Debug, derive_more::From, PartialEq, Eq)]
pub struct GetTscError(utils::errno::Error);
impl fmt::Display for GetTscError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for GetTscError {}
/// Error type for [`KvmVcpu::set_tsc_khz`].
#[derive(Debug, derive_more::From, PartialEq, Eq)]
pub struct SetTscError(kvm_ioctls::Error);
impl fmt::Display for SetTscError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for SetTscError {}

/// Error type for [`KvmVcpu::configure`].
#[derive(Debug, thiserror::Error)]
pub enum KvmVcpuConfigureError {
    #[error("Failed to create `VmSpec`: {0}")]
    VmSpec(cpuid::Error),
    #[error("Failed to filter CPUID: {0}")]
    FilterCpuid(cpuid::Error),
    #[error("Failed to set CPUID entries: {0}")]
    SetCpuidEntries(cpuid::Error),
    #[error("Failed to set CPUID: {0}")]
    SetCpuid(#[from] utils::errno::Error),
    #[error("Failed to push MSR entry to FamStructWrapper.")]
    PushMsrEntries(utils::fam::Error),
    #[error("Failed to set MSRs: {0}")]
    SetMsrs(#[from] SetMSRsError),
    #[error("Failed to setup registers: {0}")]
    SetupRegisters(#[from] SetupRegistersError),
    #[error("Failed to setup FPU: {0}")]
    SetupFpu(#[from] SetupFpuError),
    #[error("Failed to setup special registers: {0}")]
    SetupSpecialRegisters(#[from] SetupSpecialRegistersError),
    #[error("Faiuled to configure LAPICs: {0}")]
    SetLint(#[from] interrupts::Error),
}

/// A wrapper around creating and using a kvm x86_64 vcpu.
pub struct KvmVcpu {
    pub index: u8,
    pub fd: VcpuFd,

    pub pio_bus: Option<devices::Bus>,
    pub mmio_bus: Option<devices::Bus>,

    msr_list: HashSet<u32>,
}

impl KvmVcpu {
    /// Constructs a new kvm vcpu with arch specific functionality.
    ///
    /// # Arguments
    ///
    /// * `index` - Represents the 0-based CPU index between [0, max vcpus).
    /// * `vm` - The vm to which this vcpu will get attached.
    pub fn new(index: u8, vm: &Vm) -> Result<Self> {
        let kvm_vcpu = vm.fd().create_vcpu(index.into()).map_err(Error::VcpuFd)?;

        Ok(KvmVcpu {
            index,
            fd: kvm_vcpu,
            pio_bus: None,
            mmio_bus: None,
            msr_list: vm.supported_msrs().as_slice().iter().copied().collect(),
        })
    }

    /// Configures a x86_64 specific vcpu for booting Linux and should be called once per vcpu.
    ///
    /// # Arguments
    ///
    /// * `guest_mem` - The guest memory used by this microvm.
    /// * `kernel_start_addr` - Offset from `guest_mem` at which the kernel starts.
    /// * `vcpu_config` - The vCPU configuration.
    /// * `cpuid` - The capabilities exposed by this vCPU.
    pub fn configure(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        kernel_start_addr: GuestAddress,
        vcpu_config: &VcpuConfig,
        mut cpuid: CpuId,
    ) -> std::result::Result<(), KvmVcpuConfigureError> {
        let cpuid_vm_spec = VmSpec::new(self.index, vcpu_config.vcpu_count, vcpu_config.smt)
            .map_err(KvmVcpuConfigureError::VmSpec)?;

        filter_cpuid(&mut cpuid, &cpuid_vm_spec)
            .map_err(|err| {
                METRICS.vcpu.filter_cpuid.inc();
                error!(
                    "Failure in configuring CPUID for vcpu {}: {:?}",
                    self.index, err
                );
                err
            })
            .map_err(KvmVcpuConfigureError::FilterCpuid)?;

        // Update the CPUID based on the template
        match vcpu_config.cpu_template {
            CpuFeaturesTemplate::T2 => t2::set_cpuid_entries(&mut cpuid, &cpuid_vm_spec)
                .map_err(KvmVcpuConfigureError::SetCpuidEntries)?,
            CpuFeaturesTemplate::T2S => t2s::set_cpuid_entries(&mut cpuid, &cpuid_vm_spec)
                .map_err(KvmVcpuConfigureError::SetCpuidEntries)?,
            CpuFeaturesTemplate::T2CL => t2cl::set_cpuid_entries(&mut cpuid, &cpuid_vm_spec)
                .map_err(KvmVcpuConfigureError::SetCpuidEntries)?,
            CpuFeaturesTemplate::T2A => t2a::set_cpuid_entries(&mut cpuid, &cpuid_vm_spec)
                .map_err(KvmVcpuConfigureError::SetCpuidEntries)?,
            CpuFeaturesTemplate::C3 => c3::set_cpuid_entries(&mut cpuid, &cpuid_vm_spec)
                .map_err(KvmVcpuConfigureError::SetCpuidEntries)?,
            CpuFeaturesTemplate::None => {}
        }

        self.fd
            .set_cpuid2(&cpuid)
            .map_err(KvmVcpuConfigureError::SetCpuid)?;

        // Initialize some architectural MSRs that will be set for boot.
        let mut msr_boot_entries = arch::x86_64::msr::create_boot_msr_entries();

        // By this point the Guest CPUID is established. Some CPU features require MSRs
        // to configure and interact with those features. If a MSR is writable from
        // inside the Guest, or is changed by KVM or Firecracker on behalf of the Guest,
        // then we will need to save it every time we take a snapshot, and restore its
        // value when we restore the microVM since the Guest may need that value.
        // Since CPUID tells us what features are enabled for the Guest, we can infer
        // the extra MSRs that we need to save based on a dependency map.
        let extra_msrs =
            msrs_to_save_by_cpuid(&cpuid).map_err(KvmVcpuConfigureError::FilterCpuid)?;
        self.msr_list.extend(extra_msrs);

        // TODO: Some MSRs depend on values of other MSRs. This dependency will need to
        // be implemented. For now we define known dependencies statically in the CPU
        // templates.

        // Depending on which CPU template the user selected, we may need to initialize
        // additional MSRs for boot to correctly enable some CPU features. As stated in
        // the previous comment, we get from the template a static list of MSRs we need
        // to save at snapshot as well.
        // C3, T2 and T2A currently don't have extra MSRs to save/set.
        match vcpu_config.cpu_template {
            CpuFeaturesTemplate::T2S => {
                self.msr_list.extend(t2s::msr_entries_to_save());
                t2s::update_msr_entries(&mut msr_boot_entries);
            }
            CpuFeaturesTemplate::T2CL => {
                self.msr_list.extend(t2cl::msr_entries_to_save());
                t2cl::update_msr_entries(&mut msr_boot_entries);
            }
            _ => (),
        }
        // By this point we know that at snapshot, the list of MSRs we need to
        // save is `architectural MSRs` + `MSRs inferred through CPUID` + `other
        // MSRs defined by the template`

        arch::x86_64::msr::set_msrs(&self.fd, &msr_boot_entries)?;
        arch::x86_64::regs::setup_regs(&self.fd, kernel_start_addr.raw_value())?;
        arch::x86_64::regs::setup_fpu(&self.fd)?;
        arch::x86_64::regs::setup_sregs(guest_mem, &self.fd)?;
        arch::x86_64::interrupts::set_lint(&self.fd)?;
        Ok(())
    }

    /// Sets a Port Mapped IO bus for this vcpu.
    pub fn set_pio_bus(&mut self, pio_bus: devices::Bus) {
        self.pio_bus = Some(pio_bus);
    }

    /// Get the current TSC frequency for this vCPU.
    ///
    /// # Errors
    ///
    /// When [`kvm_ioctls::VcpuFd::get_tsc_khz`] errrors.
    pub fn get_tsc_khz(&self) -> std::result::Result<u32, GetTscError> {
        let res = self.fd.get_tsc_khz()?;
        Ok(res)
    }

    /// Save the KVM internal state.
    pub fn save_state(&self) -> Result<VcpuState> {
        // Ordering requirements:
        //
        // KVM_GET_MP_STATE calls kvm_apic_accept_events(), which might modify
        // vCPU/LAPIC state. As such, it must be done before most everything
        // else, otherwise we cannot restore everything and expect it to work.
        //
        // KVM_GET_VCPU_EVENTS/KVM_SET_VCPU_EVENTS is unsafe if other vCPUs are
        // still running.
        //
        // KVM_GET_LAPIC may change state of LAPIC before returning it.
        //
        // GET_VCPU_EVENTS should probably be last to save. The code looks as
        // it might as well be affected by internal state modifications of the
        // GET ioctls.
        //
        // SREGS saves/restores a pending interrupt, similar to what
        // VCPU_EVENTS also does.
        //
        // GET_MSRS requires a pre-populated data structure to do something
        // meaningful. For SET_MSRS it will then contain good data.

        // Build the list of MSRs we want to save. Sometimes we need to save
        // more than KVM_MAX_MSR_ENTRIES in the snapshot, so we use a Vec<Msrs>
        // to allow an unlimited number.
        let mut all_msrs: Vec<Msrs> = Vec::new();
        let msr_list: Vec<&u32> = self.msr_list.iter().collect();

        // KVM only supports getting KVM_MAX_MSR_ENTRIES at a time so chunk
        // them up into `Msrs` so it's easy to pass to the ioctl.
        for chunk in msr_list.chunks(KVM_MAX_MSR_ENTRIES) {
            let mut msrs = Msrs::new(chunk.len()).map_err(Error::Fam)?;
            let msr_entries = msrs.as_mut_slice();
            assert_eq!(chunk.len(), msr_entries.len());
            for (pos, index) in chunk.iter().enumerate() {
                msr_entries[pos].index = **index;
            }
            all_msrs.push(msrs);
        }

        let mp_state = self.fd.get_mp_state().map_err(Error::VcpuGetMpState)?;
        let regs = self.fd.get_regs().map_err(Error::VcpuGetRegs)?;
        let sregs = self.fd.get_sregs().map_err(Error::VcpuGetSregs)?;
        let xsave = self.fd.get_xsave().map_err(Error::VcpuGetXsave)?;
        let xcrs = self.fd.get_xcrs().map_err(Error::VcpuGetXcrs)?;
        let debug_regs = self.fd.get_debug_regs().map_err(Error::VcpuGetDebugRegs)?;
        let lapic = self.fd.get_lapic().map_err(Error::VcpuGetLapic)?;
        let tsc_khz = self.get_tsc_khz().ok().or_else(|| {
            // v0.25 and newer snapshots without TSC will only work on
            // the same CPU model as the host on which they were taken.
            // TODO: Add negative test for this warning failure.
            warn!("TSC freq not available. Snapshot cannot be loaded on a different CPU model.");
            None
        });
        for msrs in all_msrs.iter_mut() {
            let expected_nmsrs = msrs.as_slice().len();
            let nmsrs = self.fd.get_msrs(msrs).map_err(Error::VcpuGetMsrs)?;
            if nmsrs != expected_nmsrs {
                return Err(Error::VcpuGetMSRSIncomplete);
            }
        }
        let vcpu_events = self
            .fd
            .get_vcpu_events()
            .map_err(Error::VcpuGetVcpuEvents)?;

        Ok(VcpuState {
            cpuid: self
                .fd
                .get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
                .map_err(Error::VcpuGetCpuid)?,
            saved_msrs: all_msrs,
            msrs: Msrs::new(0).map_err(Error::Fam)?,
            debug_regs,
            lapic,
            mp_state,
            regs,
            sregs,
            vcpu_events,
            xcrs,
            xsave,
            tsc_khz,
        })
    }

    /// Checks whether the TSC needs scaling when restoring a snapshot.
    ///
    /// # Errors
    ///
    /// When
    pub fn is_tsc_scaling_required(
        &self,
        state_tsc_freq: u32,
    ) -> std::result::Result<bool, GetTscError> {
        // Compare the current TSC freq to the one found
        // in the state. If they are different, we need to
        // scale the TSC to the freq found in the state.
        // We accept values within a tolerance of 250 parts
        // per million beacuse it is common for TSC frequency
        // to differ due to calibration at boot time.
        let diff = (i64::from(self.get_tsc_khz()?) - i64::from(state_tsc_freq)).abs();
        Ok(diff > (f64::from(state_tsc_freq) * TSC_KHZ_TOL).round() as i64)
    }

    // Scale the TSC frequency of this vCPU to the one provided as a parameter.
    pub fn set_tsc_khz(&self, tsc_freq: u32) -> std::result::Result<(), SetTscError> {
        self.fd.set_tsc_khz(tsc_freq).map_err(SetTscError)
    }

    /// Use provided state to populate KVM internal state.
    pub fn restore_state(&self, state: &VcpuState) -> Result<()> {
        // Ordering requirements:
        //
        // KVM_GET_VCPU_EVENTS/KVM_SET_VCPU_EVENTS is unsafe if other vCPUs are
        // still running.
        //
        // Some SET ioctls (like set_mp_state) depend on kvm_vcpu_is_bsp(), so
        // if we ever change the BSP, we have to do that before restoring anything.
        // The same seems to be true for CPUID stuff.
        //
        // SREGS saves/restores a pending interrupt, similar to what
        // VCPU_EVENTS also does.
        //
        // SET_REGS clears pending exceptions unconditionally, thus, it must be
        // done before SET_VCPU_EVENTS, which restores it.
        //
        // SET_LAPIC must come after SET_SREGS, because the latter restores
        // the apic base msr.
        //
        // SET_LAPIC must come before SET_MSRS, because the TSC deadline MSR
        // only restores successfully, when the LAPIC is correctly configured.

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
        for msrs in &state.saved_msrs {
            let nmsrs = self.fd.set_msrs(msrs).map_err(Error::VcpuSetMsrs)?;
            if nmsrs < msrs.as_fam_struct_ref().nmsrs as usize {
                return Err(Error::VcpuSetMSRSIncomplete);
            }
        }
        self.fd
            .set_vcpu_events(&state.vcpu_events)
            .map_err(Error::VcpuSetVcpuEvents)?;
        Ok(())
    }

    /// Runs the vCPU in KVM context and handles the kvm exit reason.
    ///
    /// Returns error or enum specifying whether emulation was handled or interrupted.
    pub fn run_arch_emulation(&self, exit: VcpuExit) -> super::Result<VcpuEmulation> {
        match exit {
            VcpuExit::IoIn(addr, data) => {
                if let Some(pio_bus) = &self.pio_bus {
                    pio_bus.read(u64::from(addr), data);
                    METRICS.vcpu.exit_io_in.inc();
                }
                Ok(VcpuEmulation::Handled)
            }
            VcpuExit::IoOut(addr, data) => {
                if let Some(pio_bus) = &self.pio_bus {
                    pio_bus.write(u64::from(addr), data);
                    METRICS.vcpu.exit_io_out.inc();
                }
                Ok(VcpuEmulation::Handled)
            }
            unexpected_exit => {
                METRICS.vcpu.failures.inc();
                // TODO: Are we sure we want to finish running a vcpu upon
                // receiving a vm exit that is not necessarily an error?
                error!("Unexpected exit reason on vcpu run: {:?}", unexpected_exit);
                Err(super::Error::UnhandledKvmExit(format!(
                    "{:?}",
                    unexpected_exit
                )))
            }
        }
    }
}

#[derive(Clone, Versionize)]
/// Structure holding VCPU kvm state.
// NOTICE: Any changes to this structure require a snapshot version bump.
pub struct VcpuState {
    pub cpuid: CpuId,
    #[version(end = 3, default_fn = "default_msrs")]
    msrs: Msrs,
    #[version(start = 3, de_fn = "de_saved_msrs", ser_fn = "ser_saved_msrs")]
    saved_msrs: Vec<Msrs>,
    debug_regs: kvm_debugregs,
    lapic: kvm_lapic_state,
    mp_state: kvm_mp_state,
    regs: kvm_regs,
    sregs: kvm_sregs,
    vcpu_events: kvm_vcpu_events,
    xcrs: kvm_xcrs,
    xsave: kvm_xsave,
    #[version(start = 2, default_fn = "default_tsc_khz", ser_fn = "ser_tsc")]
    pub tsc_khz: Option<u32>,
}

impl VcpuState {
    fn default_tsc_khz(_: u16) -> Option<u32> {
        warn!("CPU TSC freq not found in snapshot");
        None
    }

    fn ser_tsc(&mut self, _target_version: u16) -> VersionizeResult<()> {
        // v0.24 and older versions do not support TSC scaling.
        warn!(
            "Saving to older snapshot version, TSC freq {}",
            self.tsc_khz
                .map(|freq| freq.to_string() + "KHz not included in snapshot.")
                .unwrap_or_else(|| "not available.".to_string())
        );

        Ok(())
    }

    fn default_msrs(_source_version: u16) -> Msrs {
        // Safe to unwrap since Msrs::new() only returns an error if the number
        // of elements exceeds KVM_MAX_MSR_ENTRIES
        Msrs::new(0).unwrap()
    }

    fn de_saved_msrs(&mut self, source_version: u16) -> VersionizeResult<()> {
        if source_version < 3 {
            self.saved_msrs.push(self.msrs.clone());
        }
        Ok(())
    }

    fn ser_saved_msrs(&mut self, target_version: u16) -> VersionizeResult<()> {
        match self.saved_msrs.len() {
            0 => Err(VersionizeError::Serialize(
                "Cannot serialize MSRs because the MSR list is empty".to_string(),
            )),
            1 => {
                if target_version < 3 {
                    self.msrs = self.saved_msrs[0].clone();
                    Ok(())
                } else {
                    Err(VersionizeError::Serialize(format!(
                        "Cannot serialize MSRs to target version {}",
                        target_version
                    )))
                }
            }
            _ => Err(VersionizeError::Serialize(
                "Cannot serialize MSRs. The uVM state needs to save
                 more MSRs than the target snapshot version supports."
                    .to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]
    extern crate cpuid;

    use std::os::unix::io::AsRawFd;

    use arch::x86_64::cpu_model::CpuModel;
    use cpuid::common::{get_vendor_id_from_host, VENDOR_ID_AMD, VENDOR_ID_INTEL};
    use kvm_ioctls::Cap;

    use super::*;
    use crate::vstate::vm::tests::setup_vm;
    use crate::vstate::vm::Vm;

    impl Default for VcpuState {
        fn default() -> Self {
            VcpuState {
                cpuid: CpuId::new(1).unwrap(),
                msrs: Msrs::new(1).unwrap(),
                saved_msrs: vec![Msrs::new(1).unwrap()],
                debug_regs: Default::default(),
                lapic: Default::default(),
                mp_state: Default::default(),
                regs: Default::default(),
                sregs: Default::default(),
                vcpu_events: Default::default(),
                xcrs: Default::default(),
                xsave: Default::default(),
                tsc_khz: Some(0),
            }
        }
    }

    fn setup_vcpu(mem_size: usize) -> (Vm, KvmVcpu, GuestMemoryMmap) {
        let (vm, vm_mem) = setup_vm(mem_size);
        vm.setup_irqchip().unwrap();
        let vcpu = KvmVcpu::new(0, &vm).unwrap();
        (vm, vcpu, vm_mem)
    }

    fn is_at_least_cascade_lake() -> bool {
        CpuModel::get_cpu_model()
            >= (CpuModel {
                extended_family: 0,
                extended_model: 5,
                family: 6,
                model: 5,
                stepping: 7,
            })
    }

    #[test]
    fn test_configure_vcpu() {
        let (vm, mut vcpu, vm_mem) = setup_vcpu(0x10000);

        let mut vcpu_config = VcpuConfig {
            vcpu_count: 1,
            smt: false,
            cpu_template: CpuFeaturesTemplate::None,
        };

        assert!(vcpu
            .configure(
                &vm_mem,
                GuestAddress(0),
                &vcpu_config,
                vm.supported_cpuid().clone()
            )
            .is_ok());

        // Test configure while using the T2 template.
        vcpu_config.cpu_template = CpuFeaturesTemplate::T2;
        let t2_res = vcpu.configure(
            &vm_mem,
            GuestAddress(arch::get_kernel_start()),
            &vcpu_config,
            vm.supported_cpuid().clone(),
        );

        // Test configure while using the C3 template.
        vcpu_config.cpu_template = CpuFeaturesTemplate::C3;
        let c3_res = vcpu.configure(
            &vm_mem,
            GuestAddress(0),
            &vcpu_config,
            vm.supported_cpuid().clone(),
        );

        // Test configure while using the T2S template.
        vcpu_config.cpu_template = CpuFeaturesTemplate::T2S;
        let t2s_res = vcpu.configure(
            &vm_mem,
            GuestAddress(0),
            &vcpu_config,
            vm.supported_cpuid().clone(),
        );

        let mut t2cl_res = Ok(());
        if is_at_least_cascade_lake() {
            // Test configure while using the T2CL template.
            vcpu_config.cpu_template = CpuFeaturesTemplate::T2CL;
            t2cl_res = vcpu.configure(
                &vm_mem,
                GuestAddress(0),
                &vcpu_config,
                vm.supported_cpuid().clone(),
            );
        }

        // Test configure while using the T2S template.
        vcpu_config.cpu_template = CpuFeaturesTemplate::T2A;
        let t2a_res = vcpu.configure(
            &vm_mem,
            GuestAddress(0),
            &vcpu_config,
            vm.supported_cpuid().clone(),
        );

        match &get_vendor_id_from_host().unwrap() {
            VENDOR_ID_INTEL => {
                assert!(t2_res.is_ok());
                assert!(c3_res.is_ok());
                assert!(t2s_res.is_ok());
                assert!(t2cl_res.is_ok());
                assert!(t2a_res.is_err());
            }
            VENDOR_ID_AMD => {
                assert!(t2_res.is_err());
                assert!(c3_res.is_err());
                assert!(t2s_res.is_err());
                assert!(t2cl_res.is_err());
                assert!(t2a_res.is_ok());
            }
            _ => {
                assert!(t2_res.is_err());
                assert!(c3_res.is_err());
                assert!(t2s_res.is_err());
                assert!(t2cl_res.is_err());
                assert!(t2a_res.is_err());
            }
        }
    }

    #[test]
    fn test_vcpu_cpuid_restore() {
        let (_vm, vcpu, _) = setup_vcpu(0x1000);
        let mut state = vcpu.save_state().unwrap();
        // Mutate the cpuid.
        state.cpuid.as_mut_slice()[0].eax = 0x1234_5678;
        assert!(vcpu.restore_state(&state).is_ok());

        unsafe { libc::close(vcpu.fd.as_raw_fd()) };
        let (_vm, vcpu, _) = setup_vcpu(0x1000);
        assert!(vcpu.restore_state(&state).is_ok());

        // Validate the mutated cpuid is saved.
        assert!(vcpu.save_state().unwrap().cpuid.as_slice()[0].eax == 0x1234_5678);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn test_is_tsc_scaling_required() {
        // Test `is_tsc_scaling_required` as if it were on the same
        // CPU model as the one in the snapshot state.
        let (_vm, vcpu, _) = setup_vcpu(0x1000);
        let orig_state = vcpu.save_state().unwrap();

        {
            // The frequency difference is within tolerance.
            let mut state = orig_state.clone();
            state.tsc_khz = Some(state.tsc_khz.unwrap() + (TSC_KHZ_TOL / 2.0).round() as u32);
            assert!(!vcpu
                .is_tsc_scaling_required(state.tsc_khz.unwrap())
                .unwrap());
        }

        {
            // The frequency difference is over the tolerance.
            let mut state = orig_state;
            state.tsc_khz = Some(state.tsc_khz.unwrap() + (TSC_KHZ_TOL * 2.0).round() as u32);
            assert!(!vcpu
                .is_tsc_scaling_required(state.tsc_khz.unwrap())
                .unwrap());
        }
    }

    #[test]
    fn test_set_tsc() {
        let (vm, vcpu, _) = setup_vcpu(0x1000);
        let mut state = vcpu.save_state().unwrap();
        state.tsc_khz = Some(state.tsc_khz.unwrap() + (TSC_KHZ_TOL * 2.0).round() as u32);

        if vm.fd().check_extension(Cap::TscControl) {
            assert!(vcpu.set_tsc_khz(state.tsc_khz.unwrap()).is_ok());
            if vm.fd().check_extension(Cap::GetTscKhz) {
                assert_eq!(vcpu.get_tsc_khz().ok(), state.tsc_khz);
            } else {
                assert!(vcpu.get_tsc_khz().is_err());
            }
        } else {
            assert!(vcpu.set_tsc_khz(state.tsc_khz.unwrap()).is_err());
        }
    }
}
