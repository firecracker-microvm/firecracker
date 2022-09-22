// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::{fmt, result};

use arch::x86_64::interrupts;
use arch::x86_64::msr::SetMSRsError;
use arch::x86_64::regs::{SetupFpuError, SetupRegistersError, SetupSpecialRegistersError};
use cpuid::FeatureComparison;
use kvm_bindings::{
    kvm_debugregs, kvm_lapic_state, kvm_mp_state, kvm_regs, kvm_sregs, kvm_vcpu_events, kvm_xcrs,
    kvm_xsave, CpuId, MsrList, Msrs,
};
use kvm_ioctls::{VcpuExit, VcpuFd};
use logger::{error, warn, IncMetric, METRICS};
use versionize::{VersionMap, Versionize, VersionizeResult};
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
    FamError(utils::fam::Error),
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
            FamError(err) => write!(f, "Failed FamStructWrapper operation: {:?}", err),
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
#[derive(Debug, derive_more::From, PartialEq)]
pub struct GetTscError(utils::errno::Error);
impl fmt::Display for GetTscError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for GetTscError {}
/// Error type for [`KvmVcpu::set_tsc_khz`].
#[derive(Debug, derive_more::From, PartialEq)]
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
    /// Failed to construct `cpuid::RawCpuid` from `kvm_bindings::CpuId`
    #[error("Failed to construct `cpuid::RawCpuid` from `kvm_bindings::CpuId`")]
    RawCpuid(#[from] cpuid::CpuidNewError),
    /// Failed to apply `VmSpec`.
    #[error("Failed to apply `VmSpec`: {0}")]
    ApplyVmSpec(#[from] cpuid::ApplyVmSpecError),
    /// Failed to create `VmSpec`.
    #[error("Failed to create `VmSpec`: {0}")]
    VmSpec(#[from] cpuid::common::GetCpuidError),
    /// Failed get KVM supported CPUID structure.
    #[error("Failed to get KVM supported CPUID structure: {0}")]
    KvmGetSupportedCpuid(#[from] cpuid::KvmGetSupportedCpuidError),
    #[error("KVM does not support the given CPUID or specified template.")]
    KvmUnsupportedCpuid,
    #[error("KVM could not check support for the given CPUID or specified template.")]
    KvmIncomparableCpuid,
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
    #[error("Failed to configure LAPICs: {0}")]
    SetLint(#[from] interrupts::Error),
}

/// A wrapper around creating and using a kvm x86_64 vcpu.
pub struct KvmVcpu {
    pub index: u8,
    pub fd: VcpuFd,

    pub pio_bus: Option<devices::Bus>,
    pub mmio_bus: Option<devices::Bus>,

    msr_list: MsrList,
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
            msr_list: vm.supported_msrs().clone(),
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
        // If a template is specified, get the CPUID template, else use `cpuid`.
        let mut config_cpuid = match vcpu_config.cpu_template {
            #[cfg(feature = "t2")]
            CpuFeaturesTemplate::T2 => cpuid::Cpuid::T2,
            #[cfg(feature = "t2s")]
            CpuFeaturesTemplate::T2S => cpuid::Cpuid::T2S,
            #[cfg(feature = "c3")]
            CpuFeaturesTemplate::C3 => cpuid::Cpuid::C3,
            // If a template is not supplied we use the given `cpuid` as the base.
            CpuFeaturesTemplate::None => {
                cpuid::Cpuid::try_from(cpuid::RawCpuid::from(cpuid.clone()))?
            }
        };

        // Apply adjustments based on `vm_spec`.
        {
            let cpuid_vm_spec =
                cpuid::VmSpec::new(self.index, vcpu_config.vcpu_count, vcpu_config.smt)?;
            config_cpuid.apply_vm_spec(&cpuid_vm_spec)?;
        }

        // Check support and set our CPUID.
        {
            // Get KVM supported CPUID.
            let supported_cpuid = cpuid::Cpuid::kvm_get_supported_cpuid()?;
            // Check CPUID template is supported by KVM.
            // If a comparison could be made between support.
            if let Some(cmp) = supported_cpuid.feature_cmp(&config_cpuid) {
                // If the KVM supports a subset of what `template` specifies.
                if let cpuid::FeatureRelation::Subset = cmp {
                    // Return an error denoting the KVM does not support everything required by the
                    // given CPUID.
                    return Err(KvmVcpuConfigureError::KvmUnsupportedCpuid);
                }
            } else {
                // Return an error denoting we compare KVM support to support required by the given
                // CPUID.
                return Err(KvmVcpuConfigureError::KvmIncomparableCpuid);
            }

            let kvm_cpuid = kvm_bindings::CpuId::from(config_cpuid);
            // Set CPUID.
            cpuid = kvm_cpuid;
        }

        // Set CPUID in the KVM
        self.fd
            .set_cpuid2(&cpuid)
            .map_err(KvmVcpuConfigureError::SetCpuid)?;

        // Set MSRs
        let mut msr_boot_entries = arch::x86_64::msr::create_boot_msr_entries();
        #[cfg(feature = "t2s")]
        if vcpu_config.cpu_template == CpuFeaturesTemplate::T2S {
            for msr in cpuid::t2s::msr_entries_to_save() {
                self.msr_list
                    .push(*msr)
                    .map_err(KvmVcpuConfigureError::PushMsrEntries)?;
            }
            cpuid::t2s::update_msr_entries(&mut msr_boot_entries);
        }

        arch::x86_64::msr::set_msrs(&self.fd, &msr_boot_entries)?;
        arch::x86_64::regs::setup_regs(&self.fd, kernel_start_addr.raw_value() as u64)?;
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

        // Build the list of MSRs we want to save.
        let num_msrs = self.msr_list.as_fam_struct_ref().nmsrs as usize;
        let mut msrs = Msrs::new(num_msrs).map_err(Error::FamError)?;
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
        let tsc_khz = self.get_tsc_khz().ok().or_else(|| {
            // v0.25 and newer snapshots without TSC will only work on
            // the same CPU model as the host on which they were taken.
            // TODO: Add negative test for this warning failure.
            warn!("TSC freq not available. Snapshot cannot be loaded on a different CPU model.");
            None
        });
        let nmsrs = self.fd.get_msrs(&mut msrs).map_err(Error::VcpuGetMsrs)?;
        if nmsrs != num_msrs {
            return Err(Error::VcpuGetMSRSIncomplete);
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
            msrs,
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
        let diff = (self.get_tsc_khz()? as i64 - state_tsc_freq as i64).abs();
        Ok(diff > (state_tsc_freq as f64 * TSC_KHZ_TOL).round() as i64)
    }

    // Scale the TSC frequency of this vCPU to the one provided as a parameter.
    pub fn set_tsc_khz(&self, tsc_freq: u32) -> std::result::Result<(), SetTscError> {
        let res = self.fd.set_tsc_khz(tsc_freq)?;
        Ok(res)
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
        self.fd.set_msrs(&state.msrs).map_err(Error::VcpuSetMsrs)?;
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
    msrs: Msrs,
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
                .clone()
                .map(|freq| freq.to_string() + "KHz not included in snapshot.")
                .unwrap_or_else(|| "not available.".to_string())
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate cpuid;

    use std::os::unix::io::AsRawFd;

    use cpuid::common::{get_vendor_id_from_host, VENDOR_ID_INTEL};
    use kvm_ioctls::Cap;

    use super::*;
    use crate::vstate::vm::tests::setup_vm;
    use crate::vstate::vm::Vm;

    impl Default for VcpuState {
        fn default() -> Self {
            VcpuState {
                cpuid: CpuId::new(1).unwrap(),
                msrs: Msrs::new(1).unwrap(),
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

        match &get_vendor_id_from_host().unwrap() {
            VENDOR_ID_INTEL => {
                assert!(t2_res.is_ok());
                assert!(c3_res.is_ok());
                assert!(t2s_res.is_ok());
            }
            _ => {
                assert!(t2_res.is_err());
                assert!(c3_res.is_err());
                assert!(t2s_res.is_err());
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
