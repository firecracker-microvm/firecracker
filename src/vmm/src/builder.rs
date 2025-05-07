// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enables pre-boot setup, instantiation and booting of a Firecracker VMM.

use std::fmt::Debug;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
#[cfg(feature = "gdb")]
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use event_manager::{MutEventSubscriber, SubscriberOps};
use libc::EFD_NONBLOCK;
use linux_loader::cmdline::Cmdline as LoaderKernelCmdline;
use userfaultfd::Uffd;
use utils::time::TimestampUs;
#[cfg(target_arch = "aarch64")]
use vm_memory::GuestAddress;
#[cfg(target_arch = "aarch64")]
use vm_superio::Rtc;
use vm_superio::Serial;
use vmm_sys_util::eventfd::EventFd;

use crate::arch::{ConfigurationError, configure_system_for_boot, load_kernel};
#[cfg(target_arch = "aarch64")]
use crate::construct_kvm_mpidrs;
use crate::cpu_config::templates::{
    GetCpuTemplate, GetCpuTemplateError, GuestConfigError, KvmCapability,
};
use crate::device_manager::acpi::ACPIDeviceManager;
#[cfg(target_arch = "x86_64")]
use crate::device_manager::legacy::PortIODeviceManager;
use crate::device_manager::mmio::{MMIODeviceManager, MmioError};
use crate::device_manager::persist::{
    ACPIDeviceManagerConstructorArgs, ACPIDeviceManagerRestoreError, MMIODevManagerConstructorArgs,
};
use crate::device_manager::resources::ResourceAllocator;
use crate::devices::BusDevice;
use crate::devices::acpi::vmgenid::{VmGenId, VmGenIdError};
#[cfg(target_arch = "aarch64")]
use crate::devices::legacy::RTCDevice;
use crate::devices::legacy::serial::SerialOut;
use crate::devices::legacy::{EventFdTrigger, SerialEventsWrapper, SerialWrapper};
use crate::devices::virtio::balloon::Balloon;
use crate::devices::virtio::block::device::Block;
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::mmio::MmioTransport;
use crate::devices::virtio::net::Net;
use crate::devices::virtio::rng::Entropy;
use crate::devices::virtio::vsock::{Vsock, VsockUnixBackend};
#[cfg(feature = "gdb")]
use crate::gdb;
use crate::initrd::{InitrdConfig, InitrdError};
use crate::logger::{debug, error};
use crate::persist::{MicrovmState, MicrovmStateError};
use crate::resources::VmResources;
use crate::seccomp::BpfThreadMap;
use crate::snapshot::Persist;
use crate::utils::u64_to_usize;
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::MachineConfigError;
use crate::vstate::kvm::Kvm;
use crate::vstate::memory::{GuestRegionMmap, MaybeBounce};
use crate::vstate::vcpu::{Vcpu, VcpuError};
use crate::vstate::vm::{KVM_GMEM_NO_DIRECT_MAP, Vm};
use crate::{EventManager, Vmm, VmmError, device_manager};

/// Errors associated with starting the instance.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum StartMicrovmError {
    /// Unable to attach block device to Vmm: {0}
    AttachBlockDevice(io::Error),
    /// Unable to attach the VMGenID device: {0}
    AttachVmgenidDevice(kvm_ioctls::Error),
    /// System configuration error: {0}
    ConfigureSystem(#[from] ConfigurationError),
    /// Failed to create guest config: {0}
    CreateGuestConfig(#[from] GuestConfigError),
    /// Cannot create network device: {0}
    CreateNetDevice(crate::devices::virtio::net::NetError),
    /// Cannot create RateLimiter: {0}
    CreateRateLimiter(io::Error),
    /// Error creating legacy device: {0}
    #[cfg(target_arch = "x86_64")]
    CreateLegacyDevice(device_manager::legacy::LegacyDeviceError),
    /// Error creating VMGenID device: {0}
    CreateVMGenID(VmGenIdError),
    /// Error enabling pvtime on vcpu: {0}
    #[cfg(target_arch = "aarch64")]
    EnablePVTime(crate::arch::VcpuArchError),
    /// Invalid Memory Configuration: {0}
    GuestMemory(crate::vstate::memory::MemoryError),
    /// Error with initrd initialization: {0}.
    Initrd(#[from] InitrdError),
    /// Internal error while starting microVM: {0}
    Internal(#[from] VmmError),
    /// Failed to get CPU template: {0}
    GetCpuTemplate(#[from] GetCpuTemplateError),
    /// Invalid kernel command line: {0}
    KernelCmdline(String),
    /// Cannot load command line string: {0}
    LoadCommandline(linux_loader::loader::Error),
    /// Cannot start microvm without kernel configuration.
    MissingKernelConfig,
    /// Cannot start microvm without guest mem_size config.
    MissingMemSizeConfig,
    /// No seccomp filter for thread category: {0}
    MissingSeccompFilters(String),
    /// The net device configuration is missing the tap device.
    NetDeviceNotConfigured,
    /// Cannot open the block device backing file: {0}
    OpenBlockDevice(io::Error),
    /// Cannot initialize a MMIO Device or add a device to the MMIO Bus or cmdline: {0}
    RegisterMmioDevice(#[from] device_manager::mmio::MmioError),
    /// Cannot restore microvm state: {0}
    RestoreMicrovmState(MicrovmStateError),
    /// Cannot set vm resources: {0}
    SetVmResources(MachineConfigError),
    /// Cannot create the entropy device: {0}
    CreateEntropyDevice(crate::devices::virtio::rng::EntropyError),
    /// Failed to allocate guest resource: {0}
    AllocateResources(#[from] vm_allocator::Error),
    /// Error starting GDB debug session
    #[cfg(feature = "gdb")]
    GdbServer(gdb::target::GdbTargetError),
    /// Error cloning Vcpu fds
    #[cfg(feature = "gdb")]
    VcpuFdCloneError(#[from] crate::vstate::vcpu::CopyKvmFdError),
}

/// It's convenient to automatically convert `linux_loader::cmdline::Error`s
/// to `StartMicrovmError`s.
impl std::convert::From<linux_loader::cmdline::Error> for StartMicrovmError {
    fn from(err: linux_loader::cmdline::Error) -> StartMicrovmError {
        StartMicrovmError::KernelCmdline(err.to_string())
    }
}

#[cfg_attr(target_arch = "aarch64", allow(unused))]
fn create_vmm_and_vcpus(
    instance_info: &InstanceInfo,
    event_manager: &mut EventManager,
    vcpu_count: u8,
    kvm_capabilities: Vec<KvmCapability>,
    secret_free: bool,
) -> Result<(Vmm, Vec<Vcpu>), VmmError> {
    let kvm = Kvm::new(kvm_capabilities)?;
    // Set up Kvm Vm and register memory regions.
    // Build custom CPU config if a custom template is provided.
    let mut vm = Vm::new(&kvm, secret_free)?;

    let resource_allocator = ResourceAllocator::new()?;

    // Instantiate the MMIO device manager.
    let mmio_device_manager = MMIODeviceManager::new();

    // Instantiate ACPI device manager.
    let acpi_device_manager = ACPIDeviceManager::new();

    let (vcpus, vcpus_exit_evt) = vm.create_vcpus(vcpu_count)?;

    #[cfg(target_arch = "x86_64")]
    let pio_device_manager = {
        // Make stdout non blocking.
        set_stdout_nonblocking();

        // Serial device setup.
        let serial_device = setup_serial_device(event_manager, std::io::stdin(), io::stdout())?;

        // x86_64 uses the i8042 reset event as the Vmm exit event.
        let reset_evt = vcpus_exit_evt.try_clone().map_err(VmmError::EventFd)?;

        // create pio dev manager with legacy devices
        let mut pio_dev_mgr =
            PortIODeviceManager::new(serial_device, reset_evt).map_err(VmmError::LegacyIOBus)?;
        pio_dev_mgr
            .register_devices(vm.fd())
            .map_err(VmmError::LegacyIOBus)?;
        pio_dev_mgr
    };

    let vmm = Vmm {
        events_observer: Some(std::io::stdin()),
        instance_info: instance_info.clone(),
        shutdown_exit_code: None,
        kvm,
        vm,
        uffd: None,
        vcpus_handles: Vec::new(),
        vcpus_exit_evt,
        resource_allocator,
        mmio_device_manager,
        #[cfg(target_arch = "x86_64")]
        pio_device_manager,
        acpi_device_manager,
    };

    Ok((vmm, vcpus))
}

/// Builds and starts a microVM based on the current Firecracker VmResources configuration.
///
/// The built microVM and all the created vCPUs start off in the paused state.
/// To boot the microVM and run those vCPUs, `Vmm::resume_vm()` needs to be
/// called.
pub fn build_microvm_for_boot(
    instance_info: &InstanceInfo,
    vm_resources: &super::resources::VmResources,
    event_manager: &mut EventManager,
    seccomp_filters: &BpfThreadMap,
) -> Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    use self::StartMicrovmError::*;

    // Timestamp for measuring microVM boot duration.
    let request_ts = TimestampUs::default();

    let boot_config = vm_resources
        .boot_source
        .builder
        .as_ref()
        .ok_or(MissingKernelConfig)?;

    // Clone the command-line so that a failed boot doesn't pollute the original.
    #[allow(unused_mut)]
    let mut boot_cmdline = boot_config.cmdline.clone();

    let cpu_template = vm_resources
        .machine_config
        .cpu_template
        .get_cpu_template()?;

    let secret_free = vm_resources.machine_config.secret_free;

    #[cfg(target_arch = "x86_64")]
    if secret_free {
        boot_cmdline.insert_str("no-kvmclock")?;
    }

    let (mut vmm, mut vcpus) = create_vmm_and_vcpus(
        instance_info,
        event_manager,
        vm_resources.machine_config.vcpu_count,
        cpu_template.kvm_capabilities.clone(),
        vm_resources.machine_config.secret_free,
    )?;

    let guest_memfd = match secret_free {
        true => Some(
            vmm.vm
                .create_guest_memfd(vm_resources.memory_size(), KVM_GMEM_NO_DIRECT_MAP)
                .map_err(VmmError::Vm)?,
        ),
        false => None,
    };

    let guest_memory = vm_resources
        .allocate_guest_memory(guest_memfd)
        .map_err(StartMicrovmError::GuestMemory)?;

    vmm.vm
        .register_memory_regions(guest_memory)
        .map_err(VmmError::Vm)?;

    #[cfg(target_arch = "x86_64")]
    vmm.vm.set_memory_private().map_err(VmmError::Vm)?;

    let entry_point = load_kernel(
        MaybeBounce::<_, 4096>::new_persistent(
            boot_config.kernel_file.try_clone().unwrap(),
            secret_free,
        ),
        vmm.vm.guest_memory(),
    )?;
    let initrd = match &boot_config.initrd_file {
        Some(initrd_file) => {
            let size = initrd_file
                .metadata()
                .map_err(InitrdError::Metadata)?
                .size();

            Some(InitrdConfig::from_reader(
                vmm.vm.guest_memory(),
                MaybeBounce::<_, 4096>::new_persistent(initrd_file.as_fd(), secret_free),
                u64_to_usize(size),
            )?)
        }
        None => None,
    };

    #[cfg(feature = "gdb")]
    let (gdb_tx, gdb_rx) = mpsc::channel();
    #[cfg(feature = "gdb")]
    vcpus
        .iter_mut()
        .for_each(|vcpu| vcpu.attach_debug_info(gdb_tx.clone()));
    #[cfg(feature = "gdb")]
    let vcpu_fds = vcpus
        .iter()
        .map(|vcpu| vcpu.copy_kvm_vcpu_fd(vmm.vm()))
        .collect::<Result<Vec<_>, _>>()?;

    // The boot timer device needs to be the first device attached in order
    // to maintain the same MMIO address referenced in the documentation
    // and tests.
    if vm_resources.boot_timer {
        attach_boot_timer_device(&mut vmm, request_ts)?;
    }

    if let Some(balloon) = vm_resources.balloon.get() {
        attach_balloon_device(&mut vmm, &mut boot_cmdline, balloon, event_manager)?;
    }

    attach_block_devices(
        &mut vmm,
        &mut boot_cmdline,
        vm_resources.block.devices.iter(),
        event_manager,
    )?;
    attach_net_devices(
        &mut vmm,
        &mut boot_cmdline,
        vm_resources.net_builder.iter(),
        event_manager,
    )?;

    if let Some(unix_vsock) = vm_resources.vsock.get() {
        attach_unixsock_vsock_device(&mut vmm, &mut boot_cmdline, unix_vsock, event_manager)?;
    }

    if let Some(entropy) = vm_resources.entropy.get() {
        attach_entropy_device(&mut vmm, &mut boot_cmdline, entropy, event_manager)?;
    }

    #[cfg(target_arch = "aarch64")]
    attach_legacy_devices_aarch64(event_manager, &mut vmm, &mut boot_cmdline)?;

    attach_vmgenid_device(&mut vmm)?;

    #[cfg(target_arch = "aarch64")]
    if vcpus[0].kvm_vcpu.supports_pvtime() {
        setup_pvtime(&mut vmm, &mut vcpus)?;
    } else {
        log::warn!("Vcpus do not support pvtime, steal time will not be reported to guest");
    }

    configure_system_for_boot(
        &mut vmm,
        vcpus.as_mut(),
        &vm_resources.machine_config,
        &cpu_template,
        entry_point,
        &initrd,
        boot_cmdline,
    )?;

    let vmm = Arc::new(Mutex::new(vmm));

    #[cfg(feature = "gdb")]
    if let Some(gdb_socket_path) = &vm_resources.machine_config.gdb_socket_path {
        gdb::gdb_thread(
            vmm.clone(),
            vcpu_fds,
            gdb_rx,
            entry_point.entry_addr,
            gdb_socket_path,
        )
        .map_err(GdbServer)?;
    } else {
        debug!("No GDB socket provided not starting gdb server.");
    }

    // Move vcpus to their own threads and start their state machine in the 'Paused' state.
    vmm.lock()
        .unwrap()
        .start_vcpus(
            vcpus,
            seccomp_filters
                .get("vcpu")
                .ok_or_else(|| MissingSeccompFilters("vcpu".to_string()))?
                .clone(),
        )
        .map_err(VmmError::VcpuStart)?;

    // Load seccomp filters for the VMM thread.
    // Execution panics if filters cannot be loaded, use --no-seccomp if skipping filters
    // altogether is the desired behaviour.
    // Keep this as the last step before resuming vcpus.
    crate::seccomp::apply_filter(
        seccomp_filters
            .get("vmm")
            .ok_or_else(|| MissingSeccompFilters("vmm".to_string()))?,
    )
    .map_err(VmmError::SeccompFilters)?;

    event_manager.add_subscriber(vmm.clone());

    Ok(vmm)
}

/// Builds and boots a microVM based on the current Firecracker VmResources configuration.
///
/// This is the default build recipe, one could build other microVM flavors by using the
/// independent functions in this module instead of calling this recipe.
///
/// An `Arc` reference of the built `Vmm` is also plugged in the `EventManager`, while another
/// is returned.
pub fn build_and_boot_microvm(
    instance_info: &InstanceInfo,
    vm_resources: &super::resources::VmResources,
    event_manager: &mut EventManager,
    seccomp_filters: &BpfThreadMap,
) -> Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    debug!("event_start: build microvm for boot");
    let vmm = build_microvm_for_boot(instance_info, vm_resources, event_manager, seccomp_filters)?;
    debug!("event_end: build microvm for boot");
    // The vcpus start off in the `Paused` state, let them run.
    debug!("event_start: boot microvm");
    vmm.lock().unwrap().resume_vm()?;
    debug!("event_end: boot microvm");
    Ok(vmm)
}

/// Error type for [`build_microvm_from_snapshot`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BuildMicrovmFromSnapshotError {
    /// Failed to create microVM and vCPUs: {0}
    CreateMicrovmAndVcpus(#[from] StartMicrovmError),
    /// Could not access KVM: {0}
    KvmAccess(#[from] vmm_sys_util::errno::Error),
    /// Error configuring the TSC, frequency not present in the given snapshot.
    TscFrequencyNotPresent,
    #[cfg(target_arch = "x86_64")]
    /// Could not get TSC to check if TSC scaling was required with the snapshot: {0}
    GetTsc(#[from] crate::arch::GetTscError),
    #[cfg(target_arch = "x86_64")]
    /// Could not set TSC scaling within the snapshot: {0}
    SetTsc(#[from] crate::arch::SetTscError),
    /// Failed to restore microVM state: {0}
    RestoreState(#[from] crate::vstate::vm::ArchVmError),
    /// Failed to update microVM configuration: {0}
    VmUpdateConfig(#[from] MachineConfigError),
    /// Failed to restore MMIO device: {0}
    RestoreMmioDevice(#[from] MicrovmStateError),
    /// Failed to emulate MMIO serial: {0}
    EmulateSerialInit(#[from] crate::EmulateSerialInitError),
    /// Failed to start vCPUs as no vCPU seccomp filter found.
    MissingVcpuSeccompFilters,
    /// Failed to start vCPUs: {0}
    StartVcpus(#[from] crate::StartVcpusError),
    /// Failed to restore vCPUs: {0}
    RestoreVcpus(#[from] VcpuError),
    /// Failed to apply VMM secccomp filter as none found.
    MissingVmmSeccompFilters,
    /// Failed to apply VMM secccomp filter: {0}
    SeccompFiltersInternal(#[from] crate::seccomp::InstallationError),
    /// Failed to restore ACPI device manager: {0}
    ACPIDeviManager(#[from] ACPIDeviceManagerRestoreError),
    /// VMGenID update failed: {0}
    VMGenIDUpdate(std::io::Error),
}

/// Builds and starts a microVM based on the provided MicrovmState.
///
/// An `Arc` reference of the built `Vmm` is also plugged in the `EventManager`, while another
/// is returned.
#[allow(clippy::too_many_arguments)]
pub fn build_microvm_from_snapshot(
    instance_info: &InstanceInfo,
    event_manager: &mut EventManager,
    microvm_state: MicrovmState,
    guest_memory: Vec<GuestRegionMmap>,
    uffd: Option<Uffd>,
    seccomp_filters: &BpfThreadMap,
    vm_resources: &mut VmResources,
) -> Result<Arc<Mutex<Vmm>>, BuildMicrovmFromSnapshotError> {
    // Build Vmm.
    debug!("event_start: build microvm from snapshot");
    let (mut vmm, mut vcpus) = create_vmm_and_vcpus(
        instance_info,
        event_manager,
        vm_resources.machine_config.vcpu_count,
        microvm_state.kvm_state.kvm_cap_modifiers.clone(),
        false,
    )
    .map_err(StartMicrovmError::Internal)?;

    vmm.vm
        .register_memory_regions(guest_memory)
        .map_err(VmmError::Vm)
        .map_err(StartMicrovmError::Internal)?;
    vmm.uffd = uffd;

    #[cfg(target_arch = "x86_64")]
    {
        // Scale TSC to match, extract the TSC freq from the state if specified
        if let Some(state_tsc) = microvm_state.vcpu_states[0].tsc_khz {
            // Scale the TSC frequency for all VCPUs. If a TSC frequency is not specified in the
            // snapshot, by default it uses the host frequency.
            if vcpus[0].kvm_vcpu.is_tsc_scaling_required(state_tsc)? {
                for vcpu in &vcpus {
                    vcpu.kvm_vcpu.set_tsc_khz(state_tsc)?;
                }
            }
        }
    }

    // Restore allocator state
    #[cfg(target_arch = "aarch64")]
    if let Some(pvtime_ipa) = vcpus[0].kvm_vcpu.pvtime_ipa {
        allocate_pvtime_region(
            &mut vmm,
            vcpus.len(),
            vm_allocator::AllocPolicy::ExactMatch(pvtime_ipa.0),
        )?;
    }

    // Restore vcpus kvm state.
    for (vcpu, state) in vcpus.iter_mut().zip(microvm_state.vcpu_states.iter()) {
        vcpu.kvm_vcpu
            .restore_state(state)
            .map_err(VcpuError::VcpuResponse)
            .map_err(BuildMicrovmFromSnapshotError::RestoreVcpus)?;
    }

    #[cfg(target_arch = "aarch64")]
    {
        let mpidrs = construct_kvm_mpidrs(&microvm_state.vcpu_states);
        // Restore kvm vm state.
        vmm.vm.restore_state(&mpidrs, &microvm_state.vm_state)?;
    }

    // Restore kvm vm state.
    #[cfg(target_arch = "x86_64")]
    vmm.vm.restore_state(&microvm_state.vm_state)?;

    // Restore the boot source config paths.
    vm_resources.boot_source.config = microvm_state.vm_info.boot_source;

    // Restore devices states.
    let mmio_ctor_args = MMIODevManagerConstructorArgs {
        mem: vmm.vm.guest_memory(),
        vm: vmm.vm.fd(),
        event_manager,
        resource_allocator: &mut vmm.resource_allocator,
        vm_resources,
        instance_id: &instance_info.id,
        restored_from_file: vmm.uffd.is_none(),
    };

    vmm.mmio_device_manager =
        MMIODeviceManager::restore(mmio_ctor_args, &microvm_state.device_states)
            .map_err(MicrovmStateError::RestoreDevices)?;
    vmm.emulate_serial_init()?;

    {
        let acpi_ctor_args = ACPIDeviceManagerConstructorArgs {
            mem: vmm.vm.guest_memory(),
            resource_allocator: &mut vmm.resource_allocator,
            vm: vmm.vm.fd(),
        };

        vmm.acpi_device_manager =
            ACPIDeviceManager::restore(acpi_ctor_args, &microvm_state.acpi_dev_state)?;

        // Inject the notification to VMGenID that we have resumed from a snapshot.
        // This needs to happen before we resume vCPUs, so that we minimize the time between vCPUs
        // resuming and notification being handled by the driver.
        vmm.acpi_device_manager
            .notify_vmgenid()
            .map_err(BuildMicrovmFromSnapshotError::VMGenIDUpdate)?;
    }

    // Move vcpus to their own threads and start their state machine in the 'Paused' state.
    vmm.start_vcpus(
        vcpus,
        seccomp_filters
            .get("vcpu")
            .ok_or(BuildMicrovmFromSnapshotError::MissingVcpuSeccompFilters)?
            .clone(),
    )?;

    let vmm = Arc::new(Mutex::new(vmm));
    event_manager.add_subscriber(vmm.clone());

    // Load seccomp filters for the VMM thread.
    // Keep this as the last step of the building process.
    crate::seccomp::apply_filter(
        seccomp_filters
            .get("vmm")
            .ok_or(BuildMicrovmFromSnapshotError::MissingVmmSeccompFilters)?,
    )?;
    debug!("event_end: build microvm from snapshot");

    Ok(vmm)
}

/// Sets up the serial device.
pub fn setup_serial_device(
    event_manager: &mut EventManager,
    input: std::io::Stdin,
    out: std::io::Stdout,
) -> Result<Arc<Mutex<BusDevice>>, VmmError> {
    let interrupt_evt = EventFdTrigger::new(EventFd::new(EFD_NONBLOCK).map_err(VmmError::EventFd)?);
    let kick_stdin_read_evt =
        EventFdTrigger::new(EventFd::new(EFD_NONBLOCK).map_err(VmmError::EventFd)?);
    let serial = Arc::new(Mutex::new(BusDevice::Serial(SerialWrapper {
        serial: Serial::with_events(
            interrupt_evt,
            SerialEventsWrapper {
                buffer_ready_event_fd: Some(kick_stdin_read_evt),
            },
            SerialOut::Stdout(out),
        ),
        input: Some(input),
    })));
    event_manager.add_subscriber(serial.clone());
    Ok(serial)
}

/// 64 bytes due to alignment requirement in 3.1 of https://www.kernel.org/doc/html/v5.8/virt/kvm/devices/vcpu.html#attribute-kvm-arm-vcpu-pvtime-ipa
#[cfg(target_arch = "aarch64")]
const STEALTIME_STRUCT_MEM_SIZE: u64 = 64;

/// Helper method to allocate steal time region
#[cfg(target_arch = "aarch64")]
fn allocate_pvtime_region(
    vmm: &mut Vmm,
    vcpu_count: usize,
    policy: vm_allocator::AllocPolicy,
) -> Result<GuestAddress, StartMicrovmError> {
    let size = STEALTIME_STRUCT_MEM_SIZE * vcpu_count as u64;
    let addr = vmm
        .resource_allocator
        .allocate_system_memory(size, STEALTIME_STRUCT_MEM_SIZE, policy)
        .map_err(StartMicrovmError::AllocateResources)?;
    Ok(GuestAddress(addr))
}

/// Sets up pvtime for all vcpus
#[cfg(target_arch = "aarch64")]
fn setup_pvtime(vmm: &mut Vmm, vcpus: &mut [Vcpu]) -> Result<(), StartMicrovmError> {
    // Alloc sys mem for steal time region
    let pvtime_mem: GuestAddress =
        allocate_pvtime_region(vmm, vcpus.len(), vm_allocator::AllocPolicy::LastMatch)?;

    // Register all vcpus with pvtime device
    for (i, vcpu) in vcpus.iter_mut().enumerate() {
        vcpu.kvm_vcpu
            .enable_pvtime(GuestAddress(
                pvtime_mem.0 + i as u64 * STEALTIME_STRUCT_MEM_SIZE,
            ))
            .map_err(StartMicrovmError::EnablePVTime)?;
    }

    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn attach_legacy_devices_aarch64(
    event_manager: &mut EventManager,
    vmm: &mut Vmm,
    cmdline: &mut LoaderKernelCmdline,
) -> Result<(), VmmError> {
    // Serial device setup.
    let cmdline_contains_console = cmdline
        .as_cstring()
        .map_err(|_| VmmError::Cmdline)?
        .into_string()
        .map_err(|_| VmmError::Cmdline)?
        .contains("console=");

    if cmdline_contains_console {
        // Make stdout non-blocking.
        set_stdout_nonblocking();
        let serial = setup_serial_device(event_manager, std::io::stdin(), std::io::stdout())?;
        vmm.mmio_device_manager
            .register_mmio_serial(vmm.vm.fd(), &mut vmm.resource_allocator, serial, None)
            .map_err(VmmError::RegisterMMIODevice)?;
        vmm.mmio_device_manager
            .add_mmio_serial_to_cmdline(cmdline)
            .map_err(VmmError::RegisterMMIODevice)?;
    }

    let rtc = RTCDevice(Rtc::with_events(
        &crate::devices::legacy::rtc_pl031::METRICS,
    ));
    vmm.mmio_device_manager
        .register_mmio_rtc(&mut vmm.resource_allocator, rtc, None)
        .map_err(VmmError::RegisterMMIODevice)
}

/// Attaches a VirtioDevice device to the device manager and event manager.
fn attach_virtio_device<T: 'static + VirtioDevice + MutEventSubscriber + Debug>(
    event_manager: &mut EventManager,
    vmm: &mut Vmm,
    id: String,
    device: Arc<Mutex<T>>,
    cmdline: &mut LoaderKernelCmdline,
    is_vhost_user: bool,
) -> Result<(), MmioError> {
    event_manager.add_subscriber(device.clone());

    if vmm.vm.secret_free() {
        device.lock().unwrap().force_userspace_bounce_buffers();
    }

    // The device mutex mustn't be locked here otherwise it will deadlock.
    let device = MmioTransport::new(vmm.vm.guest_memory().clone(), device, is_vhost_user);
    vmm.mmio_device_manager
        .register_mmio_virtio_for_boot(
            vmm.vm.fd(),
            &mut vmm.resource_allocator,
            id,
            device,
            cmdline,
        )
        .map(|_| ())
}

pub(crate) fn attach_boot_timer_device(
    vmm: &mut Vmm,
    request_ts: TimestampUs,
) -> Result<(), MmioError> {
    let boot_timer = crate::devices::pseudo::BootTimer::new(request_ts);

    vmm.mmio_device_manager
        .register_mmio_boot_timer(&mut vmm.resource_allocator, boot_timer)?;

    Ok(())
}

fn attach_vmgenid_device(vmm: &mut Vmm) -> Result<(), StartMicrovmError> {
    let vmgenid = VmGenId::new(vmm.vm.guest_memory(), &mut vmm.resource_allocator)
        .map_err(StartMicrovmError::CreateVMGenID)?;

    vmm.acpi_device_manager
        .attach_vmgenid(vmgenid, vmm.vm.fd())
        .map_err(StartMicrovmError::AttachVmgenidDevice)?;

    Ok(())
}

fn attach_entropy_device(
    vmm: &mut Vmm,
    cmdline: &mut LoaderKernelCmdline,
    entropy_device: &Arc<Mutex<Entropy>>,
    event_manager: &mut EventManager,
) -> Result<(), MmioError> {
    let id = entropy_device
        .lock()
        .expect("Poisoned lock")
        .id()
        .to_string();

    attach_virtio_device(
        event_manager,
        vmm,
        id,
        entropy_device.clone(),
        cmdline,
        false,
    )
}

fn attach_block_devices<'a, I: Iterator<Item = &'a Arc<Mutex<Block>>> + Debug>(
    vmm: &mut Vmm,
    cmdline: &mut LoaderKernelCmdline,
    blocks: I,
    event_manager: &mut EventManager,
) -> Result<(), StartMicrovmError> {
    for block in blocks {
        let (id, is_vhost_user) = {
            let locked = block.lock().expect("Poisoned lock");
            if locked.root_device() {
                match locked.partuuid() {
                    Some(partuuid) => cmdline.insert_str(format!("root=PARTUUID={}", partuuid))?,
                    None => cmdline.insert_str("root=/dev/vda")?,
                }
                match locked.read_only() {
                    true => cmdline.insert_str("ro")?,
                    false => cmdline.insert_str("rw")?,
                }
            }
            (locked.id().to_string(), locked.is_vhost_user())
        };
        // The device mutex mustn't be locked here otherwise it will deadlock.
        attach_virtio_device(
            event_manager,
            vmm,
            id,
            block.clone(),
            cmdline,
            is_vhost_user,
        )?;
    }
    Ok(())
}

fn attach_net_devices<'a, I: Iterator<Item = &'a Arc<Mutex<Net>>> + Debug>(
    vmm: &mut Vmm,
    cmdline: &mut LoaderKernelCmdline,
    net_devices: I,
    event_manager: &mut EventManager,
) -> Result<(), StartMicrovmError> {
    for net_device in net_devices {
        let id = net_device.lock().expect("Poisoned lock").id().clone();
        // The device mutex mustn't be locked here otherwise it will deadlock.
        attach_virtio_device(event_manager, vmm, id, net_device.clone(), cmdline, false)?;
    }
    Ok(())
}

fn attach_unixsock_vsock_device(
    vmm: &mut Vmm,
    cmdline: &mut LoaderKernelCmdline,
    unix_vsock: &Arc<Mutex<Vsock<VsockUnixBackend>>>,
    event_manager: &mut EventManager,
) -> Result<(), MmioError> {
    let id = String::from(unix_vsock.lock().expect("Poisoned lock").id());
    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_virtio_device(event_manager, vmm, id, unix_vsock.clone(), cmdline, false)
}

fn attach_balloon_device(
    vmm: &mut Vmm,
    cmdline: &mut LoaderKernelCmdline,
    balloon: &Arc<Mutex<Balloon>>,
    event_manager: &mut EventManager,
) -> Result<(), MmioError> {
    let id = String::from(balloon.lock().expect("Poisoned lock").id());
    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_virtio_device(event_manager, vmm, id, balloon.clone(), cmdline, false)
}

// Adds `O_NONBLOCK` to the stdout flags.
pub(crate) fn set_stdout_nonblocking() {
    // SAFETY: Call is safe since parameters are valid.
    let flags = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL, 0) };
    if flags < 0 {
        error!("Could not get Firecracker stdout flags.");
    }
    // SAFETY: Call is safe since parameters are valid.
    let rc = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        error!("Could not set Firecracker stdout to non-blocking.");
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use linux_loader::cmdline::Cmdline;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::arch::DeviceType;
    use crate::device_manager::resources::ResourceAllocator;
    use crate::devices::virtio::block::CacheType;
    use crate::devices::virtio::rng::device::ENTROPY_DEV_ID;
    use crate::devices::virtio::vsock::{TYPE_VSOCK, VSOCK_DEV_ID};
    use crate::devices::virtio::{TYPE_BALLOON, TYPE_BLOCK, TYPE_RNG};
    use crate::mmds::data_store::{Mmds, MmdsVersion};
    use crate::mmds::ns::MmdsNetworkStack;
    use crate::utils::mib_to_bytes;
    use crate::vmm_config::balloon::{BALLOON_DEV_ID, BalloonBuilder, BalloonDeviceConfig};
    use crate::vmm_config::boot_source::DEFAULT_KERNEL_CMDLINE;
    use crate::vmm_config::drive::{BlockBuilder, BlockDeviceConfig};
    use crate::vmm_config::entropy::{EntropyDeviceBuilder, EntropyDeviceConfig};
    use crate::vmm_config::net::{NetBuilder, NetworkInterfaceConfig};
    use crate::vmm_config::vsock::tests::default_config;
    use crate::vmm_config::vsock::{VsockBuilder, VsockDeviceConfig};
    use crate::vstate::vm::tests::setup_vm_with_memory;

    #[derive(Debug)]
    pub(crate) struct CustomBlockConfig {
        drive_id: String,
        is_root_device: bool,
        partuuid: Option<String>,
        is_read_only: bool,
        cache_type: CacheType,
    }

    impl CustomBlockConfig {
        pub(crate) fn new(
            drive_id: String,
            is_root_device: bool,
            partuuid: Option<String>,
            is_read_only: bool,
            cache_type: CacheType,
        ) -> Self {
            CustomBlockConfig {
                drive_id,
                is_root_device,
                partuuid,
                is_read_only,
                cache_type,
            }
        }
    }

    fn cmdline_contains(cmdline: &Cmdline, slug: &str) -> bool {
        // The following unwraps can never fail; the only way any of these methods
        // would return an `Err` is if one of the following conditions is met:
        //    1. The command line is empty: We just added things to it, and if insertion of an
        //       argument goes wrong, then `Cmdline::insert` would have already returned `Err`.
        //    2. There's a spurious null character somewhere in the command line: The
        //       `Cmdline::insert` methods verify that this is not the case.
        //    3. The `CString` is not valid UTF8: It just got created from a `String`, which was
        //       valid UTF8.

        cmdline
            .as_cstring()
            .unwrap()
            .into_string()
            .unwrap()
            .contains(slug)
    }

    pub(crate) fn default_kernel_cmdline() -> Cmdline {
        linux_loader::cmdline::Cmdline::try_from(
            DEFAULT_KERNEL_CMDLINE,
            crate::arch::CMDLINE_MAX_SIZE,
        )
        .unwrap()
    }

    pub(crate) fn default_vmm() -> Vmm {
        let (kvm, mut vm) = setup_vm_with_memory(mib_to_bytes(128));

        let mmio_device_manager = MMIODeviceManager::new();
        let acpi_device_manager = ACPIDeviceManager::new();
        #[cfg(target_arch = "x86_64")]
        let pio_device_manager = PortIODeviceManager::new(
            Arc::new(Mutex::new(BusDevice::Serial(SerialWrapper {
                serial: Serial::with_events(
                    EventFdTrigger::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                    SerialEventsWrapper {
                        buffer_ready_event_fd: None,
                    },
                    SerialOut::Sink(std::io::sink()),
                ),
                input: None,
            }))),
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();

        let (_, vcpus_exit_evt) = vm.create_vcpus(1).unwrap();

        Vmm {
            events_observer: Some(std::io::stdin()),
            instance_info: InstanceInfo::default(),
            shutdown_exit_code: None,
            kvm,
            vm,
            uffd: None,
            vcpus_handles: Vec::new(),
            vcpus_exit_evt,
            resource_allocator: ResourceAllocator::new().unwrap(),
            mmio_device_manager,
            #[cfg(target_arch = "x86_64")]
            pio_device_manager,
            acpi_device_manager,
        }
    }

    pub(crate) fn insert_block_devices(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        custom_block_cfgs: Vec<CustomBlockConfig>,
    ) -> Vec<TempFile> {
        let mut block_dev_configs = BlockBuilder::new();
        let mut block_files = Vec::new();
        for custom_block_cfg in custom_block_cfgs {
            block_files.push(TempFile::new().unwrap());

            let block_device_config = BlockDeviceConfig {
                drive_id: String::from(&custom_block_cfg.drive_id),
                partuuid: custom_block_cfg.partuuid,
                is_root_device: custom_block_cfg.is_root_device,
                cache_type: custom_block_cfg.cache_type,

                is_read_only: Some(custom_block_cfg.is_read_only),
                path_on_host: Some(
                    block_files
                        .last()
                        .unwrap()
                        .as_path()
                        .to_str()
                        .unwrap()
                        .to_string(),
                ),
                rate_limiter: None,
                file_engine_type: None,

                socket: None,
            };

            block_dev_configs.insert(block_device_config).unwrap();
        }

        attach_block_devices(
            vmm,
            cmdline,
            block_dev_configs.devices.iter(),
            event_manager,
        )
        .unwrap();
        block_files
    }

    pub(crate) fn insert_net_device(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        net_config: NetworkInterfaceConfig,
    ) {
        let mut net_builder = NetBuilder::new();
        net_builder.build(net_config).unwrap();

        let res = attach_net_devices(vmm, cmdline, net_builder.iter(), event_manager);
        res.unwrap();
    }

    pub(crate) fn insert_net_device_with_mmds(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        net_config: NetworkInterfaceConfig,
        mmds_version: MmdsVersion,
    ) {
        let mut net_builder = NetBuilder::new();
        net_builder.build(net_config).unwrap();
        let net = net_builder.iter().next().unwrap();
        let mut mmds = Mmds::default();
        mmds.set_version(mmds_version).unwrap();
        net.lock().unwrap().configure_mmds_network_stack(
            MmdsNetworkStack::default_ipv4_addr(),
            Arc::new(Mutex::new(mmds)),
        );

        attach_net_devices(vmm, cmdline, net_builder.iter(), event_manager).unwrap();
    }

    pub(crate) fn insert_vsock_device(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        vsock_config: VsockDeviceConfig,
    ) {
        let vsock_dev_id = VSOCK_DEV_ID.to_owned();
        let vsock = VsockBuilder::create_unixsock_vsock(vsock_config).unwrap();
        let vsock = Arc::new(Mutex::new(vsock));

        attach_unixsock_vsock_device(vmm, cmdline, &vsock, event_manager).unwrap();

        assert!(
            vmm.mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_VSOCK), &vsock_dev_id)
                .is_some()
        );
    }

    pub(crate) fn insert_entropy_device(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        entropy_config: EntropyDeviceConfig,
    ) {
        let mut builder = EntropyDeviceBuilder::new();
        let entropy = builder.build(entropy_config).unwrap();

        attach_entropy_device(vmm, cmdline, &entropy, event_manager).unwrap();

        assert!(
            vmm.mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_RNG), ENTROPY_DEV_ID)
                .is_some()
        );
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn insert_vmgenid_device(vmm: &mut Vmm) {
        attach_vmgenid_device(vmm).unwrap();
        assert!(vmm.acpi_device_manager.vmgenid.is_some());
    }

    pub(crate) fn insert_balloon_device(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        balloon_config: BalloonDeviceConfig,
    ) {
        let mut builder = BalloonBuilder::new();
        builder.set(balloon_config).unwrap();
        let balloon = builder.get().unwrap();

        attach_balloon_device(vmm, cmdline, balloon, event_manager).unwrap();

        assert!(
            vmm.mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_BALLOON), BALLOON_DEV_ID)
                .is_some()
        );
    }

    #[test]
    fn test_attach_net_devices() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let mut vmm = default_vmm();

        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        };

        let mut cmdline = default_kernel_cmdline();
        insert_net_device(
            &mut vmm,
            &mut cmdline,
            &mut event_manager,
            network_interface.clone(),
        );

        // We can not attach it once more.
        let mut net_builder = NetBuilder::new();
        net_builder.build(network_interface).unwrap_err();
    }

    #[test]
    fn test_attach_block_devices() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");

        // Use case 1: root block device is not specified through PARTUUID.
        {
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(
                drive_id.clone(),
                true,
                None,
                true,
                CacheType::Unsafe,
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline_contains(&cmdline, "root=/dev/vda ro"));
            assert!(
                vmm.mmio_device_manager
                    .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                    .is_some()
            );
        }

        // Use case 2: root block device is specified through PARTUUID.
        {
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(
                drive_id.clone(),
                true,
                Some("0eaa91a0-01".to_string()),
                false,
                CacheType::Unsafe,
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline_contains(&cmdline, "root=PARTUUID=0eaa91a0-01 rw"));
            assert!(
                vmm.mmio_device_manager
                    .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                    .is_some()
            );
        }

        // Use case 3: root block device is not added at all.
        {
            let drive_id = String::from("non_root");
            let block_configs = vec![CustomBlockConfig::new(
                drive_id.clone(),
                false,
                Some("0eaa91a0-01".to_string()),
                false,
                CacheType::Unsafe,
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(!cmdline_contains(&cmdline, "root=PARTUUID="));
            assert!(!cmdline_contains(&cmdline, "root=/dev/vda"));
            assert!(
                vmm.mmio_device_manager
                    .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                    .is_some()
            );
        }

        // Use case 4: rw root block device and other rw and ro drives.
        {
            let block_configs = vec![
                CustomBlockConfig::new(
                    String::from("root"),
                    true,
                    Some("0eaa91a0-01".to_string()),
                    false,
                    CacheType::Unsafe,
                ),
                CustomBlockConfig::new(
                    String::from("secondary"),
                    false,
                    None,
                    true,
                    CacheType::Unsafe,
                ),
                CustomBlockConfig::new(
                    String::from("third"),
                    false,
                    None,
                    false,
                    CacheType::Unsafe,
                ),
            ];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);

            assert!(cmdline_contains(&cmdline, "root=PARTUUID=0eaa91a0-01 rw"));
            assert!(
                vmm.mmio_device_manager
                    .get_device(DeviceType::Virtio(TYPE_BLOCK), "root")
                    .is_some()
            );
            assert!(
                vmm.mmio_device_manager
                    .get_device(DeviceType::Virtio(TYPE_BLOCK), "secondary")
                    .is_some()
            );
            assert!(
                vmm.mmio_device_manager
                    .get_device(DeviceType::Virtio(TYPE_BLOCK), "third")
                    .is_some()
            );

            // Check if these three block devices are inserted in kernel_cmdline.
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            assert!(cmdline_contains(
                &cmdline,
                "virtio_mmio.device=4K@0xd0000000:5 virtio_mmio.device=4K@0xd0001000:6 \
                 virtio_mmio.device=4K@0xd0002000:7"
            ));
        }

        // Use case 5: root block device is rw.
        {
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(
                drive_id.clone(),
                true,
                None,
                false,
                CacheType::Unsafe,
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline_contains(&cmdline, "root=/dev/vda rw"));
            assert!(
                vmm.mmio_device_manager
                    .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                    .is_some()
            );
        }

        // Use case 6: root block device is ro, with PARTUUID.
        {
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(
                drive_id.clone(),
                true,
                Some("0eaa91a0-01".to_string()),
                true,
                CacheType::Unsafe,
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline_contains(&cmdline, "root=PARTUUID=0eaa91a0-01 ro"));
            assert!(
                vmm.mmio_device_manager
                    .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                    .is_some()
            );
        }

        // Use case 7: root block device is rw with flush enabled
        {
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(
                drive_id.clone(),
                true,
                None,
                false,
                CacheType::Writeback,
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline_contains(&cmdline, "root=/dev/vda rw"));
            assert!(
                vmm.mmio_device_manager
                    .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                    .is_some()
            );
        }
    }

    #[test]
    fn test_attach_boot_timer_device() {
        let mut vmm = default_vmm();
        let request_ts = TimestampUs::default();

        let res = attach_boot_timer_device(&mut vmm, request_ts);
        res.unwrap();
        assert!(
            vmm.mmio_device_manager
                .get_device(DeviceType::BootTimer, &DeviceType::BootTimer.to_string())
                .is_some()
        );
    }

    #[test]
    fn test_attach_balloon_device() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let mut vmm = default_vmm();

        let balloon_config = BalloonDeviceConfig {
            amount_mib: 0,
            deflate_on_oom: false,
            stats_polling_interval_s: 0,
        };

        let mut cmdline = default_kernel_cmdline();
        insert_balloon_device(&mut vmm, &mut cmdline, &mut event_manager, balloon_config);
        // Check if the vsock device is described in kernel_cmdline.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        assert!(cmdline_contains(
            &cmdline,
            "virtio_mmio.device=4K@0xd0000000:5"
        ));
    }

    #[test]
    fn test_attach_entropy_device() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let mut vmm = default_vmm();

        let entropy_config = EntropyDeviceConfig::default();

        let mut cmdline = default_kernel_cmdline();
        insert_entropy_device(&mut vmm, &mut cmdline, &mut event_manager, entropy_config);
        // Check if the vsock device is described in kernel_cmdline.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        assert!(cmdline_contains(
            &cmdline,
            "virtio_mmio.device=4K@0xd0000000:5"
        ));
    }

    #[test]
    fn test_attach_vsock_device() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let mut vmm = default_vmm();

        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        let vsock_config = default_config(&tmp_sock_file);

        let mut cmdline = default_kernel_cmdline();
        insert_vsock_device(&mut vmm, &mut cmdline, &mut event_manager, vsock_config);
        // Check if the vsock device is described in kernel_cmdline.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        assert!(cmdline_contains(
            &cmdline,
            "virtio_mmio.device=4K@0xd0000000:5"
        ));
    }
}
