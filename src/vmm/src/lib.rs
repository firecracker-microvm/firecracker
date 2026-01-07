// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Virtual Machine Monitor that leverages the Linux Kernel-based Virtual Machine (KVM),
//! and other virtualization features to run a single lightweight micro-virtual
//! machine (microVM).
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![allow(clippy::blanket_clippy_restriction_lints)]

/// Implements platform specific functionality.
/// Supported platforms: x86_64 and aarch64.
pub mod arch;

/// High-level interface over Linux io_uring.
///
/// Aims to provide an easy-to-use interface, while making some Firecracker-specific simplifying
/// assumptions. The crate does not currently aim at supporting all io_uring features and use
/// cases. For example, it only works with pre-registered fds and read/write/fsync requests.
///
/// Requires at least kernel version 5.10.51.
/// For more information on io_uring, refer to the man pages.
/// [This pdf](https://kernel.dk/io_uring.pdf) is also very useful, though outdated at times.
pub mod io_uring;

/// # Rate Limiter
///
/// Provides a rate limiter written in Rust useful for IO operations that need to
/// be throttled.
///
/// ## Behavior
///
/// The rate limiter starts off as 'unblocked' with two token buckets configured
/// with the values passed in the `RateLimiter::new()` constructor.
/// All subsequent accounting is done independently for each token bucket based
/// on the `TokenType` used. If any of the buckets runs out of budget, the limiter
/// goes in the 'blocked' state. At this point an internal timer is set up which
/// will later 'wake up' the user in order to retry sending data. The 'wake up'
/// notification will be dispatched as an event on the FD provided by the `AsRawFD`
/// trait implementation.
///
/// The contract is that the user shall also call the `event_handler()` method on
/// receipt of such an event.
///
/// The token buckets are replenished when a called `consume()` doesn't find enough
/// tokens in the bucket. The amount of tokens replenished is automatically calculated
/// to respect the `complete_refill_time` configuration parameter provided by the user.
/// The token buckets will never replenish above their respective `size`.
///
/// Each token bucket can start off with a `one_time_burst` initial extra capacity
/// on top of their `size`. This initial extra credit does not replenish and
/// can be used for an initial burst of data.
///
/// The granularity for 'wake up' events when the rate limiter is blocked is
/// currently hardcoded to `100 milliseconds`.
///
/// ## Limitations
///
/// This rate limiter implementation relies on the *Linux kernel's timerfd* so its
/// usage is limited to Linux systems.
///
/// Another particularity of this implementation is that it is not self-driving.
/// It is meant to be used in an external event loop and thus implements the `AsRawFd`
/// trait and provides an *event-handler* as part of its API. This *event-handler*
/// needs to be called by the user on every event on the rate limiter's `AsRawFd` FD.
pub mod rate_limiter;

/// Module for handling ACPI tables.
/// Currently, we only use ACPI on x86 microVMs.
#[cfg(target_arch = "x86_64")]
pub mod acpi;
/// Handles setup and initialization a `Vmm` object.
pub mod builder;
/// Types for guest configuration.
pub mod cpu_config;
pub(crate) mod device_manager;
/// Emulates virtual and hardware devices.
#[allow(missing_docs)]
pub mod devices;
/// minimalist HTTP/TCP/IPv4 stack named DUMBO
pub mod dumbo;
/// Support for GDB debugging the guest
#[cfg(feature = "gdb")]
pub mod gdb;
/// Logger
pub mod logger;
/// microVM Metadata Service MMDS
pub mod mmds;
/// PCI specific emulation code.
pub mod pci;
/// Save/restore utilities.
pub mod persist;
/// Resource store for configured microVM resources.
pub mod resources;
/// microVM RPC API adapters.
pub mod rpc_interface;
/// Seccomp filter utilities.
pub mod seccomp;
/// Signal handling utilities.
pub mod signal_handler;
/// Serialization and deserialization facilities
pub mod snapshot;
/// Utility functions for integration and benchmark testing
pub mod test_utils;
/// Utility functions and struct
pub mod utils;
/// Wrappers over structures used to configure the VMM.
pub mod vmm_config;
/// Module with virtual state structs.
pub mod vstate;

/// Module with initrd.
pub mod initrd;

use std::collections::HashMap;
use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use device_manager::DeviceManager;
use event_manager::{EventManager as BaseEventManager, EventOps, Events, MutEventSubscriber};
use seccomp::BpfProgram;
use snapshot::Persist;
use userfaultfd::Uffd;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::terminal::Terminal;
use vstate::kvm::Kvm;
use vstate::vcpu::{self, StartThreadedError, VcpuSendEventError};

use crate::cpu_config::templates::CpuConfiguration;
use crate::devices::virtio::balloon::device::{HintingStatus, StartHintingCmd};
use crate::devices::virtio::balloon::{
    BALLOON_DEV_ID, Balloon, BalloonConfig, BalloonError, BalloonStats,
};
use crate::devices::virtio::block::BlockError;
use crate::devices::virtio::block::device::Block;
use crate::devices::virtio::mem::{VIRTIO_MEM_DEV_ID, VirtioMem, VirtioMemError, VirtioMemStatus};
use crate::devices::virtio::net::Net;
use crate::logger::{METRICS, MetricsError, error, info, warn};
use crate::persist::{MicrovmState, MicrovmStateError, VmInfo};
use crate::rate_limiter::BucketUpdate;
use crate::vmm_config::instance_info::{InstanceInfo, VmState};
use crate::vstate::memory::{GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use crate::vstate::vcpu::VcpuState;
pub use crate::vstate::vcpu::{Vcpu, VcpuConfig, VcpuEvent, VcpuHandle, VcpuResponse};
pub use crate::vstate::vm::Vm;

/// Shorthand type for the EventManager flavour used by Firecracker.
pub type EventManager = BaseEventManager<Arc<Mutex<dyn MutEventSubscriber>>>;

// Since the exit code names e.g. `SIGBUS` are most appropriate yet trigger a test error with the
// clippy lint `upper_case_acronyms` we have disabled this lint for this enum.
/// Vmm exit-code type.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FcExitCode {
    /// Success exit code.
    Ok = 0,
    /// Generic error exit code.
    GenericError = 1,
    /// Generic exit code error; not possible to occur if the program logic is sound.
    UnexpectedError = 2,
    /// Firecracker was shut down after intercepting a restricted system call.
    BadSyscall = 148,
    /// Firecracker was shut down after intercepting `SIGBUS`.
    SIGBUS = 149,
    /// Firecracker was shut down after intercepting `SIGSEGV`.
    SIGSEGV = 150,
    /// Firecracker was shut down after intercepting `SIGXFSZ`.
    SIGXFSZ = 151,
    /// Firecracker was shut down after intercepting `SIGXCPU`.
    SIGXCPU = 154,
    /// Firecracker was shut down after intercepting `SIGPIPE`.
    SIGPIPE = 155,
    /// Firecracker was shut down after intercepting `SIGHUP`.
    SIGHUP = 156,
    /// Firecracker was shut down after intercepting `SIGILL`.
    SIGILL = 157,
    /// Bad configuration for microvm's resources, when using a single json.
    BadConfiguration = 152,
    /// Command line arguments parsing error.
    ArgParsing = 153,
}

/// Timeout used in recv_timeout, when waiting for a vcpu response on
/// Pause/Resume/Save/Restore. A high enough limit that should not be reached during normal usage,
/// used to detect a potential vcpu deadlock.
pub const RECV_TIMEOUT_SEC: Duration = Duration::from_secs(30);

/// Default byte limit of accepted http requests on API and MMDS servers.
pub const HTTP_MAX_PAYLOAD_SIZE: usize = 51200;

/// Errors associated with the VMM internal logic. These errors cannot be generated by direct user
/// input, but can result from bad configuration of the host (for example if Firecracker doesn't
/// have permissions to open the KVM fd).
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmmError {
    #[cfg(target_arch = "aarch64")]
    /// Invalid command line error.
    Cmdline,
    /// Device manager error: {0}
    DeviceManager(#[from] device_manager::DeviceManagerCreateError),
    /// MMIO Device manager error: {0}
    MmioDeviceManager(device_manager::mmio::MmioError),
    /// Error getting the KVM dirty bitmap. {0}
    DirtyBitmap(kvm_ioctls::Error),
    /// I8042 error: {0}
    I8042Error(devices::legacy::I8042DeviceError),
    #[cfg(target_arch = "x86_64")]
    /// Cannot add devices to the legacy I/O Bus. {0}
    LegacyIOBus(device_manager::legacy::LegacyDeviceError),
    /// Metrics error: {0}
    Metrics(MetricsError),
    /// Cannot add a device to the MMIO Bus. {0}
    RegisterMMIODevice(device_manager::mmio::MmioError),
    /// Cannot install seccomp filters: {0}
    SeccompFilters(seccomp::InstallationError),
    /// Error writing to the serial console: {0}
    Serial(io::Error),
    /// Error creating the vcpu: {0}
    VcpuCreate(vstate::vcpu::VcpuError),
    /// Cannot send event to vCPU. {0}
    VcpuEvent(vstate::vcpu::VcpuError),
    /// Cannot create a vCPU handle. {0}
    VcpuHandle(vstate::vcpu::VcpuError),
    /// Failed to start vCPUs
    VcpuStart(StartVcpusError),
    /// Failed to pause the vCPUs.
    VcpuPause,
    /// Failed to exit the vCPUs.
    VcpuExit,
    /// Failed to resume the vCPUs.
    VcpuResume,
    /// Failed to message the vCPUs.
    VcpuMessage,
    /// Cannot spawn Vcpu thread: {0}
    VcpuSpawn(io::Error),
    /// Vm error: {0}
    Vm(#[from] vstate::vm::VmError),
    /// Kvm error: {0}
    Kvm(#[from] vstate::kvm::KvmError),
    /// Failed perform action on device: {0}
    FindDeviceError(#[from] device_manager::FindDeviceError),
    /// Block: {0}
    Block(#[from] BlockError),
    /// Balloon: {0}
    Balloon(#[from] BalloonError),
    /// Failed to create memory hotplug device: {0}
    VirtioMem(#[from] VirtioMemError),
}

/// Shorthand type for KVM dirty page bitmap.
pub type DirtyBitmap = HashMap<u32, Vec<u64>>;

/// Returns the size of guest memory, in MiB.
pub(crate) fn mem_size_mib(guest_memory: &GuestMemoryMmap) -> u64 {
    guest_memory.iter().map(|region| region.len()).sum::<u64>() >> 20
}

// Error type for [`Vmm::emulate_serial_init`].
/// Emulate serial init error: {0}
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub struct EmulateSerialInitError(#[from] std::io::Error);

/// Error type for [`Vmm::start_vcpus`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum StartVcpusError {
    /// VMM observer init error: {0}
    VmmObserverInit(#[from] vmm_sys_util::errno::Error),
    /// Vcpu handle error: {0}
    VcpuHandle(#[from] StartThreadedError),
}

/// Error type for [`Vmm::dump_cpu_config()`]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DumpCpuConfigError {
    /// Failed to send event to vcpu thread: {0}
    SendEvent(#[from] VcpuSendEventError),
    /// Got unexpected response from vcpu thread.
    UnexpectedResponse,
    /// Failed to dump CPU config: {0}
    DumpCpuConfig(#[from] vcpu::VcpuError),
    /// Operation not allowed: {0}
    NotAllowed(String),
}

/// Contains the state and associated methods required for the Firecracker VMM.
#[derive(Debug)]
pub struct Vmm {
    /// The [`InstanceInfo`] state of this [`Vmm`].
    pub instance_info: InstanceInfo,
    shutdown_exit_code: Option<FcExitCode>,

    // Guest VM core resources.
    kvm: Kvm,
    /// VM object
    pub vm: Arc<Vm>,
    // Save UFFD in order to keep it open in the Firecracker process, as well.
    #[allow(unused)]
    uffd: Option<Uffd>,
    /// Handles to the vcpu threads with vcpu_fds inside them.
    pub vcpus_handles: Vec<VcpuHandle>,
    // Used by Vcpus and devices to initiate teardown; Vmm should never write here.
    vcpus_exit_evt: EventFd,
    // Device manager
    device_manager: DeviceManager,
}

impl Vmm {
    /// Gets Vmm version.
    pub fn version(&self) -> String {
        self.instance_info.vmm_version.clone()
    }

    /// Gets Vmm instance info.
    pub fn instance_info(&self) -> InstanceInfo {
        self.instance_info.clone()
    }

    /// Provides the Vmm shutdown exit code if there is one.
    pub fn shutdown_exit_code(&self) -> Option<FcExitCode> {
        self.shutdown_exit_code
    }

    /// Starts the microVM vcpus.
    ///
    /// # Errors
    ///
    /// When:
    /// - [`vmm::VmmEventsObserver::on_vmm_boot`] errors.
    /// - [`vmm::vstate::vcpu::Vcpu::start_threaded`] errors.
    pub fn start_vcpus(
        &mut self,
        mut vcpus: Vec<Vcpu>,
        vcpu_seccomp_filter: Arc<BpfProgram>,
    ) -> Result<(), StartVcpusError> {
        let vcpu_count = vcpus.len();
        let barrier = Arc::new(Barrier::new(vcpu_count + 1));

        let stdin = std::io::stdin().lock();
        // Set raw mode for stdin.
        stdin.set_raw_mode().inspect_err(|&err| {
            warn!("Cannot set raw mode for the terminal. {:?}", err);
        })?;

        // Set non blocking stdin.
        stdin.set_non_block(true).inspect_err(|&err| {
            warn!("Cannot set non block for the terminal. {:?}", err);
        })?;

        self.vcpus_handles.reserve(vcpu_count);

        for mut vcpu in vcpus.drain(..) {
            vcpu.set_mmio_bus(self.vm.common.mmio_bus.clone());
            #[cfg(target_arch = "x86_64")]
            vcpu.kvm_vcpu.set_pio_bus(self.vm.pio_bus.clone());

            self.vcpus_handles.push(vcpu.start_threaded(
                &self.vm,
                vcpu_seccomp_filter.clone(),
                barrier.clone(),
            )?);
        }
        self.instance_info.state = VmState::Paused;
        // Wait for vCPUs to initialize their TLS before moving forward.
        barrier.wait();

        Ok(())
    }

    /// Sends a resume command to the vCPUs.
    pub fn resume_vm(&mut self) -> Result<(), VmmError> {
        self.device_manager.kick_virtio_devices();

        // Send the events.
        self.vcpus_handles
            .iter_mut()
            .try_for_each(|handle| handle.send_event(VcpuEvent::Resume))
            .map_err(|_| VmmError::VcpuMessage)?;

        // Check the responses.
        if self
            .vcpus_handles
            .iter()
            .map(|handle| handle.response_receiver().recv_timeout(RECV_TIMEOUT_SEC))
            .any(|response| !matches!(response, Ok(VcpuResponse::Resumed)))
        {
            return Err(VmmError::VcpuMessage);
        }

        self.instance_info.state = VmState::Running;
        Ok(())
    }

    /// Sends a pause command to the vCPUs.
    pub fn pause_vm(&mut self) -> Result<(), VmmError> {
        // Send the events.
        self.vcpus_handles
            .iter_mut()
            .try_for_each(|handle| handle.send_event(VcpuEvent::Pause))
            .map_err(|_| VmmError::VcpuMessage)?;

        // Check the responses.
        if self
            .vcpus_handles
            .iter()
            .map(|handle| handle.response_receiver().recv_timeout(RECV_TIMEOUT_SEC))
            .any(|response| !matches!(response, Ok(VcpuResponse::Paused)))
        {
            return Err(VmmError::VcpuMessage);
        }

        self.instance_info.state = VmState::Paused;
        Ok(())
    }

    /// Injects CTRL+ALT+DEL keystroke combo in the i8042 device.
    #[cfg(target_arch = "x86_64")]
    pub fn send_ctrl_alt_del(&mut self) -> Result<(), VmmError> {
        self.device_manager
            .legacy_devices
            .i8042
            .lock()
            .expect("i8042 lock was poisoned")
            .trigger_ctrl_alt_del()
            .map_err(VmmError::I8042Error)
    }

    /// Saves the state of a paused Microvm.
    pub fn save_state(&mut self, vm_info: &VmInfo) -> Result<MicrovmState, MicrovmStateError> {
        use self::MicrovmStateError::SaveVmState;
        // We need to save device state before saving KVM state.
        // Some devices, (at the time of writing this comment block device with async engine)
        // might modify the VirtIO transport and send an interrupt to the guest. If we save KVM
        // state before we save device state, that interrupt will never be delivered to the guest
        // upon resuming from the snapshot.
        let device_states = self.device_manager.save();
        let vcpu_states = self.save_vcpu_states()?;
        let kvm_state = self.kvm.save_state();
        let vm_state = {
            #[cfg(target_arch = "x86_64")]
            {
                self.vm.save_state().map_err(SaveVmState)?
            }
            #[cfg(target_arch = "aarch64")]
            {
                let mpidrs = construct_kvm_mpidrs(&vcpu_states);

                self.vm.save_state(&mpidrs).map_err(SaveVmState)?
            }
        };

        Ok(MicrovmState {
            vm_info: vm_info.clone(),
            kvm_state,
            vm_state,
            vcpu_states,
            device_states,
        })
    }

    fn save_vcpu_states(&mut self) -> Result<Vec<VcpuState>, MicrovmStateError> {
        for handle in self.vcpus_handles.iter_mut() {
            handle
                .send_event(VcpuEvent::SaveState)
                .map_err(MicrovmStateError::SignalVcpu)?;
        }

        let vcpu_responses = self
            .vcpus_handles
            .iter()
            // `Iterator::collect` can transform a `Vec<Result>` into a `Result<Vec>`.
            .map(|handle| handle.response_receiver().recv_timeout(RECV_TIMEOUT_SEC))
            .collect::<Result<Vec<VcpuResponse>, RecvTimeoutError>>()
            .map_err(|_| MicrovmStateError::UnexpectedVcpuResponse)?;

        let vcpu_states = vcpu_responses
            .into_iter()
            .map(|response| match response {
                VcpuResponse::SavedState(state) => Ok(*state),
                VcpuResponse::Error(err) => Err(MicrovmStateError::SaveVcpuState(err)),
                VcpuResponse::NotAllowed(reason) => Err(MicrovmStateError::NotAllowed(reason)),
                _ => Err(MicrovmStateError::UnexpectedVcpuResponse),
            })
            .collect::<Result<Vec<VcpuState>, MicrovmStateError>>()?;

        Ok(vcpu_states)
    }

    /// Dumps CPU configuration.
    pub fn dump_cpu_config(&mut self) -> Result<Vec<CpuConfiguration>, DumpCpuConfigError> {
        for handle in self.vcpus_handles.iter_mut() {
            handle
                .send_event(VcpuEvent::DumpCpuConfig)
                .map_err(DumpCpuConfigError::SendEvent)?;
        }

        let vcpu_responses = self
            .vcpus_handles
            .iter()
            .map(|handle| handle.response_receiver().recv_timeout(RECV_TIMEOUT_SEC))
            .collect::<Result<Vec<VcpuResponse>, RecvTimeoutError>>()
            .map_err(|_| DumpCpuConfigError::UnexpectedResponse)?;

        let cpu_configs = vcpu_responses
            .into_iter()
            .map(|response| match response {
                VcpuResponse::DumpedCpuConfig(cpu_config) => Ok(*cpu_config),
                VcpuResponse::Error(err) => Err(DumpCpuConfigError::DumpCpuConfig(err)),
                VcpuResponse::NotAllowed(reason) => Err(DumpCpuConfigError::NotAllowed(reason)),
                _ => Err(DumpCpuConfigError::UnexpectedResponse),
            })
            .collect::<Result<Vec<CpuConfiguration>, DumpCpuConfigError>>()?;

        Ok(cpu_configs)
    }

    /// Updates the path of the host file backing the emulated block device with id `drive_id`.
    /// We update the disk image on the device and its virtio configuration.
    pub fn update_block_device_path(
        &mut self,
        drive_id: &str,
        path_on_host: String,
    ) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(drive_id, |block: &mut Block| {
                block.update_disk_image(path_on_host)
            })??;
        Ok(())
    }

    /// Updates the rate limiter parameters for block device with `drive_id` id.
    pub fn update_block_rate_limiter(
        &mut self,
        drive_id: &str,
        rl_bytes: BucketUpdate,
        rl_ops: BucketUpdate,
    ) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(drive_id, |block: &mut Block| {
                block.update_rate_limiter(rl_bytes, rl_ops)
            })??;
        Ok(())
    }

    /// Updates the rate limiter parameters for block device with `drive_id` id.
    pub fn update_vhost_user_block_config(&mut self, drive_id: &str) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(drive_id, |block: &mut Block| block.update_config())??;
        Ok(())
    }

    /// Updates the rate limiter parameters for net device with `net_id` id.
    pub fn update_net_rate_limiters(
        &mut self,
        net_id: &str,
        rx_bytes: BucketUpdate,
        rx_ops: BucketUpdate,
        tx_bytes: BucketUpdate,
        tx_ops: BucketUpdate,
    ) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(net_id, |net: &mut Net| {
                net.patch_rate_limiters(rx_bytes, rx_ops, tx_bytes, tx_ops)
            })?;
        Ok(())
    }

    /// Returns a reference to the balloon device if present.
    pub fn balloon_config(&self) -> Result<BalloonConfig, VmmError> {
        let config = self
            .device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.config())?;
        Ok(config)
    }

    /// Returns the latest balloon statistics if they are enabled.
    pub fn latest_balloon_stats(&self) -> Result<BalloonStats, VmmError> {
        let stats = self
            .device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.latest_stats())??;
        Ok(stats)
    }

    /// Updates configuration for the balloon device target size.
    pub fn update_balloon_config(&mut self, amount_mib: u32) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| {
                dev.update_size(amount_mib)
            })??;
        Ok(())
    }

    /// Updates configuration for the balloon device as described in `balloon_stats_update`.
    pub fn update_balloon_stats_config(
        &mut self,
        stats_polling_interval_s: u16,
    ) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| {
                dev.update_stats_polling_interval(stats_polling_interval_s)
            })??;
        Ok(())
    }

    /// Returns the current state of the memory hotplug device.
    pub fn memory_hotplug_status(&self) -> Result<VirtioMemStatus, VmmError> {
        self.device_manager
            .with_virtio_device(VIRTIO_MEM_DEV_ID, |dev: &mut VirtioMem| dev.status())
            .map_err(VmmError::FindDeviceError)
    }

    /// Returns the current state of the memory hotplug device.
    pub fn update_memory_hotplug_size(&self, requested_size_mib: usize) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(VIRTIO_MEM_DEV_ID, |dev: &mut VirtioMem| {
                dev.update_requested_size(requested_size_mib)
            })
            .map_err(VmmError::FindDeviceError)??;
        Ok(())
    }

    /// Starts the balloon free page hinting run
    pub fn start_balloon_hinting(&mut self, cmd: StartHintingCmd) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.start_hinting(cmd))??;
        Ok(())
    }

    /// Retrieves the status of the balloon hinting run
    pub fn get_balloon_hinting_status(&mut self) -> Result<HintingStatus, VmmError> {
        let status = self
            .device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.get_hinting_status())??;
        Ok(status)
    }

    /// Stops the balloon free page hinting run
    pub fn stop_balloon_hinting(&mut self) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.stop_hinting())??;
        Ok(())
    }

    /// Signals Vmm to stop and exit.
    pub fn stop(&mut self, exit_code: FcExitCode) {
        info!("Vmm is stopping.");

        // Break the main event loop, propagating the Vmm exit-code.
        self.shutdown_exit_code = Some(exit_code);
    }

    /// Gets a reference to kvm-ioctls Vm
    #[cfg(feature = "gdb")]
    pub fn vm(&self) -> &Vm {
        &self.vm
    }
}

/// Process the content of the MPIDR_EL1 register in order to be able to pass it to KVM
///
/// The kernel expects to find the four affinity levels of the MPIDR in the first 32 bits of the
/// VGIC register attribute:
/// https://elixir.free-electrons.com/linux/v4.14.203/source/virt/kvm/arm/vgic/vgic-kvm-device.c#L445.
///
/// The format of the MPIDR_EL1 register is:
/// | 39 .... 32 | 31 .... 24 | 23 .... 16 | 15 .... 8 | 7 .... 0 |
/// |    Aff3    |    Other   |    Aff2    |    Aff1   |   Aff0   |
///
/// The KVM mpidr format is:
/// | 63 .... 56 | 55 .... 48 | 47 .... 40 | 39 .... 32 |
/// |    Aff3    |    Aff2    |    Aff1    |    Aff0    |
/// As specified in the linux kernel: Documentation/virt/kvm/devices/arm-vgic-v3.rst
#[cfg(target_arch = "aarch64")]
fn construct_kvm_mpidrs(vcpu_states: &[VcpuState]) -> Vec<u64> {
    vcpu_states
        .iter()
        .map(|state| {
            let cpu_affid = ((state.mpidr & 0xFF_0000_0000) >> 8) | (state.mpidr & 0xFF_FFFF);
            cpu_affid << 32
        })
        .collect()
}

impl Drop for Vmm {
    fn drop(&mut self) {
        info!("Killing vCPU threads");

        // Send a "Finish" event to the vCPU threads so that they terminate.
        for (idx, handle) in self.vcpus_handles.iter_mut().enumerate() {
            if let Err(err) = handle.send_event(VcpuEvent::Finish) {
                error!("Failed to send VcpuEvent::Finish to vCPU {}: {}", idx, err);
            }
        }

        // Join the vCPU threads by running VcpuHandle::drop().
        self.vcpus_handles.clear();

        if let Err(err) = std::io::stdin().lock().set_canon_mode() {
            warn!("Cannot set canonical mode for the terminal. {:?}", err);
        }

        // Write the metrics before exiting.
        if let Err(err) = METRICS.write() {
            error!("Failed to write metrics while stopping: {}", err);
        }

        if !self.vcpus_handles.is_empty() {
            error!("Failed to tear down Vmm: the vcpu threads have not finished execution.");
        }
    }
}

impl MutEventSubscriber for Vmm {
    /// Handle a read event (EPOLLIN).
    fn process(&mut self, event: Events, _: &mut EventOps) {
        let source = event.fd();
        let event_set = event.event_set();

        if source == self.vcpus_exit_evt.as_raw_fd() && event_set == EventSet::IN {
            // Exit event handling should never do anything more than call 'self.stop()'.
            let _ = self.vcpus_exit_evt.read();

            let exit_code = 'exit_code: {
                // Query each vcpu for their exit_code.
                for handle in &self.vcpus_handles {
                    // Drain all vcpu responses that are pending from this vcpu until we find an
                    // exit status.
                    for response in handle.response_receiver().try_iter() {
                        if let VcpuResponse::Exited(status) = response {
                            // It could be that some vcpus exited successfully while others
                            // errored out. Thus make sure that error exits from one vcpu always
                            // takes precedence over "ok" exits
                            if status != FcExitCode::Ok {
                                break 'exit_code status;
                            }
                        }
                    }
                }

                // No CPUs exited with error status code, report "Ok"
                FcExitCode::Ok
            };
            self.stop(exit_code);
        } else {
            error!("Spurious EventManager event for handler: Vmm");
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::new(&self.vcpus_exit_evt, EventSet::IN)) {
            error!("Failed to register vmm exit event: {}", err);
        }
    }
}
