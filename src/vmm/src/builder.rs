// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enables pre-boot setup, instantiation and booting of a Firecracker VMM.

use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use userfaultfd::{FeatureFlags, Uffd, UffdBuilder};
use utils::sock_ctrl_msg::ScmSocket;
use vm_memory::{FileOffset, GuestMemory};

use arch::InitrdConfig;
#[cfg(target_arch = "x86_64")]
use cpuid::common::is_same_model;
#[cfg(target_arch = "aarch64")]
use devices::legacy::RTCDevice;
use devices::legacy::{
    EventFdTrigger, ReadableFd, SerialDevice, SerialEventsWrapper, SerialWrapper,
};
use devices::virtio::{Balloon, Block, MmioTransport, Net, VirtioDevice, Vsock, VsockUnixBackend};
use event_manager::{MutEventSubscriber, SubscriberOps};
use libc::EFD_NONBLOCK;
use linux_loader::cmdline::Cmdline as LoaderKernelCmdline;
#[cfg(target_arch = "x86_64")]
use linux_loader::loader::elf::Elf as Loader;
#[cfg(target_arch = "aarch64")]
use linux_loader::loader::pe::PE as Loader;
use linux_loader::loader::KernelLoader;
use logger::{error, warn, METRICS};
use seccompiler::BpfThreadMap;
use snapshot::Persist;
use utils::eventfd::EventFd;
use utils::terminal::Terminal;
use utils::time::TimestampUs;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
#[cfg(target_arch = "aarch64")]
use vm_superio::Rtc;
use vm_superio::Serial;

#[cfg(target_arch = "aarch64")]
use crate::construct_kvm_mpidrs;
#[cfg(target_arch = "x86_64")]
use crate::device_manager::legacy::PortIODeviceManager;
use crate::device_manager::mmio::MMIODeviceManager;
use crate::device_manager::persist::MMIODevManagerConstructorArgs;
use crate::persist::{GuestRegionUffdMapping, MemoryDescriptor, MicrovmState, MicrovmStateError};
use crate::resources::VmResources;
use crate::vmm_config::boot_source::BootConfig;
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::{VmConfigError, VmUpdateConfig};
use crate::vstate::system::KvmContext;
use crate::vstate::vcpu::{Vcpu, VcpuConfig};
use crate::vstate::vm::Vm;
use crate::{device_manager, Error, EventManager, Vmm, VmmEventsObserver};

/// Errors associated with starting the instance.
#[derive(Debug)]
pub enum StartMicrovmError {
    /// Unable to attach block device to Vmm.
    AttachBlockDevice(io::Error),
    /// Unable to create/open the memory backing file.
    BackingMemoryFile(io::Error),
    /// This error is thrown by the minimal boot loader implementation.
    ConfigureSystem(arch::Error),
    /// Internal errors are due to resource exhaustion.
    CreateNetDevice(devices::virtio::net::Error),
    /// Failed to create a `RateLimiter` object.
    CreateRateLimiter(io::Error),
    /// Memory regions are overlapping or mmap fails.
    GuestMemoryMmap(vm_memory::Error),
    /// Cannot load initrd due to an invalid memory configuration.
    InitrdLoad,
    /// Cannot load initrd due to an invalid image.
    InitrdRead(io::Error),
    /// Internal error encountered while starting a microVM.
    Internal(Error),
    /// The kernel command line is invalid.
    KernelCmdline(String),
    /// Cannot load kernel due to invalid memory configuration or invalid kernel image.
    KernelLoader(linux_loader::loader::Error),
    /// Cannot load command line string.
    LoadCommandline(linux_loader::loader::Error),
    /// Cannot start the VM because the kernel builder was not configured.
    MissingKernelConfig,
    /// Cannot start the VM because the size of the guest memory  was not specified.
    MissingMemSizeConfig,
    /// The seccomp filter map is missing a key.
    MissingSeccompFilters(String),
    /// The net device configuration is missing the tap device.
    NetDeviceNotConfigured,
    /// Cannot open the block device backing file.
    OpenBlockDevice(io::Error),
    /// Cannot initialize a MMIO Device or add a device to the MMIO Bus or cmdline.
    RegisterMmioDevice(device_manager::mmio::Error),
    /// Cannot restore microvm state.
    RestoreMicrovmState(MicrovmStateError),
    /// Unable to set VmResources.
    SetVmResources(VmConfigError),
    /// Failed to create an UFFD Builder.
    CreateUffdBuilder(userfaultfd::Error),
    /// Unable to connect to UDS in order to send information regarding
    /// handling guest memory page-fault events.
    UdsConnection(io::Error),
    /// Failed to register guest memory regions to UFFD.
    UffdMemoryRegionsRegister(userfaultfd::Error),
    /// Failed to send guest memory layout and path to user fault FD used to handle
    /// guest memory page faults. This information is sent to a UDS where a custom
    /// page-fault handler process is listening.
    UffdSend(kvm_ioctls::Error),

    /// Failed to get the memfd from the uffd socket
    NoMemFdReceived,
}
impl std::error::Error for StartMicrovmError {}
/// It's convenient to automatically convert `linux_loader::cmdline::Error`s
/// to `StartMicrovmError`s.
impl std::convert::From<linux_loader::cmdline::Error> for StartMicrovmError {
    fn from(err: linux_loader::cmdline::Error) -> StartMicrovmError {
        StartMicrovmError::KernelCmdline(err.to_string())
    }
}

impl Display for StartMicrovmError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::StartMicrovmError::*;
        match self {
            AttachBlockDevice(err) => {
                write!(f, "Unable to attach block device to Vmm: {}", err)
            }
            ConfigureSystem(err) => write!(f, "System configuration error: {:?}", err),
            BackingMemoryFile(err) => {
                write!(f, "Unable to create the memory backing file: {}", err)
            }
            CreateRateLimiter(err) => write!(f, "Cannot create RateLimiter: {}", err),
            CreateNetDevice(err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace('\"', "");

                write!(f, "Cannot create network device. {}", err_msg)
            }
            GuestMemoryMmap(err) => {
                // Remove imbricated quotes from error message.
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace('\"', "");
                write!(f, "Invalid Memory Configuration: {}", err_msg)
            }
            InitrdLoad => write!(
                f,
                "Cannot load initrd due to an invalid memory configuration."
            ),
            InitrdRead(err) => write!(f, "Cannot load initrd due to an invalid image: {}", err),
            Internal(err) => write!(f, "Internal error while starting microVM: {}", err),
            KernelCmdline(err) => write!(f, "Invalid kernel command line: {}", err),
            KernelLoader(err) => {
                let mut err_msg = format!("{}", err);
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot load kernel due to invalid memory configuration or invalid kernel \
                     image. {}",
                    err_msg
                )
            }
            LoadCommandline(err) => {
                let mut err_msg = format!("{}", err);
                err_msg = err_msg.replace('\"', "");
                write!(f, "Cannot load command line string. {}", err_msg)
            }
            MissingKernelConfig => write!(f, "Cannot start microvm without kernel configuration."),
            MissingMemSizeConfig => {
                write!(f, "Cannot start microvm without guest mem_size config.")
            }
            MissingSeccompFilters(thread_category) => write!(
                f,
                "No seccomp filter for thread category: {}",
                thread_category
            ),
            NetDeviceNotConfigured => {
                write!(f, "The net device configuration is missing the tap device.")
            }
            OpenBlockDevice(err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace('\"', "");

                write!(f, "Cannot open the block device backing file. {}", err_msg)
            }
            RegisterMmioDevice(err) => {
                let mut err_msg = format!("{}", err);
                err_msg = err_msg.replace('\"', "");
                write!(
                    f,
                    "Cannot initialize a MMIO Device or add a device to the MMIO Bus or cmdline. \
                     {}",
                    err_msg
                )
            }
            RestoreMicrovmState(err) => write!(f, "Cannot restore microvm state. Error: {}", err),
            SetVmResources(err) => write!(f, "Cannot set vm resources. Error: {}", err),
            CreateUffdBuilder(err) => write!(f, "Cannot create uffd socket. Error: {}", err),
            UdsConnection(err) => write!(f, "Cannot connect to uffd socket. Error: {}", err),
            UffdMemoryRegionsRegister(err) => {
                write!(f, "Cannot uffd memory region register. Error: {}", err)
            }
            UffdSend(err) => write!(f, "Cannot send to uffd. Error: {}", err),
            NoMemFdReceived => write!(f, "No memfd received from uffd."),
        }
    }
}

// Wrapper over io::Stdin that implements `Serial::ReadableFd` and `vmm::VmmEventsObserver`.
pub(crate) struct SerialStdin(io::Stdin);
impl SerialStdin {
    /// Returns a `SerialStdin` wrapper over `io::stdin`.
    pub fn get() -> Self {
        SerialStdin(io::stdin())
    }
}

impl io::Read for SerialStdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl AsRawFd for SerialStdin {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl ReadableFd for SerialStdin {}

impl VmmEventsObserver for SerialStdin {
    fn on_vmm_boot(&mut self) -> std::result::Result<(), utils::errno::Error> {
        // Set raw mode for stdin.
        self.0.lock().set_raw_mode().map_err(|err| {
            warn!("Cannot set raw mode for the terminal. {:?}", err);
            err
        })?;

        // Set non blocking stdin.
        self.0.lock().set_non_block(true).map_err(|err| {
            warn!("Cannot set non block for the terminal. {:?}", err);
            err
        })
    }
    fn on_vmm_stop(&mut self) -> std::result::Result<(), utils::errno::Error> {
        self.0.lock().set_canon_mode().map_err(|err| {
            warn!("Cannot set canonical mode for the terminal. {:?}", err);
            err
        })
    }
}

#[cfg_attr(target_arch = "aarch64", allow(unused))]
fn create_vmm_and_vcpus(
    instance_info: &InstanceInfo,
    event_manager: &mut EventManager,
    guest_memory: GuestMemoryMmap,
    memory_descriptor: Option<MemoryDescriptor>,
    track_dirty_pages: bool,
    vcpu_count: u8,
) -> std::result::Result<(Vmm, Vec<Vcpu>), StartMicrovmError> {
    use self::StartMicrovmError::*;

    // Set up Kvm Vm and register memory regions.
    let mut vm = setup_kvm_vm(&guest_memory, track_dirty_pages)?;

    let vcpus_exit_evt = EventFd::new(libc::EFD_NONBLOCK)
        .map_err(Error::EventFd)
        .map_err(Internal)?;

    // Instantiate the MMIO device manager.
    // 'mmio_base' address has to be an address which is protected by the kernel
    // and is architectural specific.
    let mmio_device_manager = MMIODeviceManager::new(
        arch::MMIO_MEM_START,
        arch::MMIO_MEM_SIZE,
        (arch::IRQ_BASE, arch::IRQ_MAX),
    )
    .map_err(StartMicrovmError::RegisterMmioDevice)?;

    let vcpus;
    // For x86_64 we need to create the interrupt controller before calling `KVM_CREATE_VCPUS`
    // while on aarch64 we need to do it the other way around.
    #[cfg(target_arch = "x86_64")]
    let pio_device_manager = {
        setup_interrupt_controller(&mut vm)?;
        vcpus = create_vcpus(&vm, vcpu_count, &vcpus_exit_evt).map_err(Internal)?;

        // Make stdout non blocking.
        set_stdout_nonblocking();

        // Serial device setup.
        let serial_device = setup_serial_device(
            event_manager,
            Box::new(SerialStdin::get()),
            Box::new(io::stdout()),
        )
        .map_err(Internal)?;
        // x86_64 uses the i8042 reset event as the Vmm exit event.
        let reset_evt = vcpus_exit_evt
            .try_clone()
            .map_err(Error::EventFd)
            .map_err(Internal)?;
        create_pio_dev_manager_with_legacy_devices(&vm, serial_device, reset_evt)
            .map_err(Internal)?
    };

    // On aarch64, the vCPUs need to be created (i.e call KVM_CREATE_VCPU) before setting up the
    // IRQ chip because the `KVM_CREATE_VCPU` ioctl will return error if the IRQCHIP
    // was already initialized.
    // Search for `kvm_arch_vcpu_create` in arch/arm/kvm/arm.c.
    #[cfg(target_arch = "aarch64")]
    {
        vcpus = create_vcpus(&vm, vcpu_count, &vcpus_exit_evt).map_err(Internal)?;
        setup_interrupt_controller(&mut vm, vcpu_count)?;
    }

    let vmm = Vmm {
        events_observer: Some(Box::new(SerialStdin::get())),
        instance_info: instance_info.clone(),
        shutdown_exit_code: None,
        vm,
        guest_memory,
        memory_descriptor,
        vcpus_handles: Vec::new(),
        vcpus_exit_evt,
        mmio_device_manager,
        #[cfg(target_arch = "x86_64")]
        pio_device_manager,
    };

    Ok((vmm, vcpus))
}

/// Builds and starts a microVM based on the current Firecracker VmResources configuration.
///
/// This is the default build recipe, one could build other microVM flavors by using the
/// independent functions in this module instead of calling this recipe.
///
/// An `Arc` reference of the built `Vmm` is also plugged in the `EventManager`, while another
/// is returned.
pub fn build_microvm_for_boot(
    instance_info: &InstanceInfo,
    vm_resources: &super::resources::VmResources,
    event_manager: &mut EventManager,
    seccomp_filters: &BpfThreadMap,
) -> std::result::Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    use self::StartMicrovmError::*;

    // Timestamp for measuring microVM boot duration.
    let request_ts = TimestampUs::default();

    let boot_config = vm_resources
        .boot_source_builder()
        .ok_or(MissingKernelConfig)?;

    let track_dirty_pages = vm_resources.track_dirty_pages();

    let (guest_memory, memory_descriptor, _file) =
        if let Some(ref backend_config) = vm_resources.memory_backend {
            match backend_config.backend_type {
                crate::vmm_config::snapshot::MemBackendType::File => {
                    let file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .open(&backend_config.backend_path)
                        .map_err(BackingMemoryFile)?;
                    file.set_len((vm_resources.vm_config().mem_size_mib * 1024 * 1024) as u64)
                        .map_err(|e| {
                            error!("Failed to set backing memory file size: {}", e);
                            StartMicrovmError::BackingMemoryFile(e)
                        })?;

                    let file = Arc::new(file);

                    (
                        create_guest_memory(
                            vm_resources.vm_config().mem_size_mib,
                            Some(file.clone()),
                            track_dirty_pages,
                        )?,
                        Some(MemoryDescriptor::File(file)),
                        None,
                    )
                }
                crate::vmm_config::snapshot::MemBackendType::Uffd => {
                    let (mem, uffd, file) = create_uffd_guest_memory(
                        vm_resources.vm_config().mem_size_mib,
                        backend_config.backend_path.as_path(),
                        track_dirty_pages,
                    )?;

                    (mem, Some(MemoryDescriptor::Uffd(uffd)), Some(file))
                }
            }
        } else {
            (
                create_guest_memory(
                    vm_resources.vm_config().mem_size_mib,
                    None,
                    track_dirty_pages,
                )?,
                None,
                None,
            )
        };

    let vcpu_config = vm_resources.vcpu_config();
    let entry_addr = load_kernel(boot_config, &guest_memory)?;
    let initrd = load_initrd_from_config(boot_config, &guest_memory)?;
    // Clone the command-line so that a failed boot doesn't pollute the original.
    #[allow(unused_mut)]
    let mut boot_cmdline = boot_config.cmdline.clone();

    let (mut vmm, mut vcpus) = create_vmm_and_vcpus(
        instance_info,
        event_manager,
        guest_memory,
        memory_descriptor,
        track_dirty_pages,
        vcpu_config.vcpu_count,
    )?;

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
        vm_resources.block.list.iter(),
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

    #[cfg(target_arch = "aarch64")]
    attach_legacy_devices_aarch64(event_manager, &mut vmm, &mut boot_cmdline).map_err(Internal)?;

    configure_system_for_boot(
        &vmm,
        vcpus.as_mut(),
        vcpu_config,
        entry_addr,
        &initrd,
        boot_cmdline,
    )?;

    // Move vcpus to their own threads and start their state machine in the 'Paused' state.
    vmm.start_vcpus(
        vcpus,
        seccomp_filters
            .get("vcpu")
            .ok_or_else(|| MissingSeccompFilters("vcpu".to_string()))?
            .clone(),
    )
    .map_err(Error::VcpuStart)
    .map_err(StartMicrovmError::Internal)?;

    // Load seccomp filters for the VMM thread.
    // Execution panics if filters cannot be loaded, use --no-seccomp if skipping filters
    // altogether is the desired behaviour.
    // Keep this as the last step before resuming vcpus.
    seccompiler::apply_filter(
        seccomp_filters
            .get("vmm")
            .ok_or_else(|| MissingSeccompFilters("vmm".to_string()))?,
    )
    .map_err(Error::SeccompFilters)
    .map_err(StartMicrovmError::Internal)?;

    // The vcpus start off in the `Paused` state, let them run.
    vmm.resume_vm().map_err(Internal)?;

    let vmm = Arc::new(Mutex::new(vmm));
    event_manager.add_subscriber(vmm.clone());

    Ok(vmm)
}

/// Error type for [`build_microvm_from_snapshot`].
#[derive(Debug, thiserror::Error)]
pub enum BuildMicrovmFromSnapshotError {
    /// Failed to create microVM and vCPUs.
    #[error("Failed to create microVM and vCPUs: {0}")]
    CreateMicrovmAndVcpus(#[from] StartMicrovmError),
    /// Only 255 vCPU state are supported, but {0} states where given.
    #[error("Only 255 vCPU state are supported, but {0} states where given.")]
    TooManyVCPUs(usize),
    /// Could not access KVM.
    #[error("Could not access KVM: {0}")]
    KvmAccess(#[from] utils::errno::Error),
    /// The CPUID specification from the snapshot contains features unsupported by and/or fields
    /// outside the supported range, of the KVM.
    #[error(
        "The CPUID specification from the snapshot contains features unsupported by and/or fields \
         outside the supported range, of the KVM"
    )]
    UnsupportedCPUID,
    /// Error configuring the TSC, frequency not present in the given snapshot.
    #[error("Error configuring the TSC, frequency not present in the given snapshot.")]
    TscFrequencyNotPresent,
    /// Could not get TSC to check if TSC scaling was required with the snapshot.
    #[cfg(target_arch = "x86_64")]
    #[error("Could not get TSC to check if TSC scaling was required with the snapshot: {0}")]
    GetTsc(#[from] crate::vstate::vcpu::GetTscError),
    /// Could not set TSC scaling within the snapshot.
    #[cfg(target_arch = "x86_64")]
    #[error("Could not set TSC scaling within the snapshot: {0}")]
    SetTsc(#[from] crate::vstate::vcpu::SetTscError),
    /// Failed to restore microVM state.
    #[error("Failed to restore microVM state: {0}")]
    RestoreState(#[from] crate::vstate::vm::RestoreStateError),
    /// Failed to update microVM configuration.
    #[error("Failed to update microVM configuration: {0}")]
    VmUpdateConfig(#[from] VmConfigError),
    /// Failed to restore MMIO device.
    #[error("Failed to restore MMIO device: {0}")]
    RestoreMmioDevice(#[from] MicrovmStateError),
    /// Failed to emulate MMIO serial.
    #[error("Failed to emulate MMIO serial: {0}")]
    EmulateSerialInit(#[from] crate::EmulateSerialInitError),
    /// Failed to start vCPUs as no vCPU seccomp filter found.
    #[error("Failed to start vCPUs as no vCPU seccomp filter found.")]
    MissingVcpuSeccompFilters,
    /// Failed to start vCPUs.
    #[error("Failed to start vCPUs: {0}")]
    StartVcpus(#[from] crate::StartVcpusError),
    /// Failed to restore vCPUs.
    #[error("Failed to restore vCPUs: {0}")]
    RestoreVcpus(#[from] crate::RestoreVcpusError),
    /// Failed to apply VMM secccomp filter as none found.
    #[error("Failed to apply VMM secccomp filter as none found.")]
    MissingVmmSeccompFilters,
    /// Failed to apply VMM secccomp filter.
    #[error("Failed to apply VMM secccomp filter: {0}")]
    SeccompFiltersInternal(#[from] seccompiler::InstallationError),
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
    guest_memory: GuestMemoryMmap,
    memory_descriptor: Option<MemoryDescriptor>,
    track_dirty_pages: bool,
    seccomp_filters: &BpfThreadMap,
    vm_resources: &mut VmResources,
) -> std::result::Result<Arc<Mutex<Vmm>>, BuildMicrovmFromSnapshotError> {
    let vcpu_count = u8::try_from(microvm_state.vcpu_states.len()).map_err(|_| {
        BuildMicrovmFromSnapshotError::TooManyVCPUs(microvm_state.vcpu_states.len())
    })?;

    // Build Vmm.
    let (mut vmm, vcpus) = create_vmm_and_vcpus(
        instance_info,
        event_manager,
        guest_memory.clone(),
        memory_descriptor,
        track_dirty_pages,
        vcpu_count,
    )?;

    #[cfg(target_arch = "x86_64")]
    // Check if we need to scale the TSC.
    // We start by checking if the CPU model in the snapshot is
    // the same as this host's. If they are the same, we don't
    // need to do anything else.
    if !is_same_model(&microvm_state.vcpu_states[0].cpuid) {
        // Extract the TSC freq from the state.
        // No TSC freq in snapshot means we have to fail-fast.
        let state_tsc = microvm_state.vcpu_states[0]
            .tsc_khz
            .ok_or(BuildMicrovmFromSnapshotError::TscFrequencyNotPresent)?;

        // Scale the TSC frequency for all VCPUs, if needed.
        if vcpus[0].kvm_vcpu.is_tsc_scaling_required(state_tsc)? {
            for vcpu in &vcpus {
                vcpu.kvm_vcpu.set_tsc_khz(state_tsc)?;
            }
        }
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

    vm_resources.update_vm_config(&VmUpdateConfig {
        vcpu_count: Some(vcpu_count),
        mem_size_mib: Some(microvm_state.vm_info.mem_size_mib as usize),
        smt: Some(microvm_state.vm_info.smt),
        cpu_template: Some(microvm_state.vm_info.cpu_template),
        track_dirty_pages: Some(track_dirty_pages),
    })?;

    // Restore the boot source config paths.
    vm_resources.set_boot_source_config(microvm_state.vm_info.boot_source);

    // Restore devices states.
    let mmio_ctor_args = MMIODevManagerConstructorArgs {
        mem: guest_memory,
        vm: vmm.vm.fd(),
        event_manager,
        for_each_restored_device: VmResources::update_from_restored_device,
        vm_resources,
        instance_id: &instance_info.id,
    };

    vmm.mmio_device_manager =
        MMIODeviceManager::restore(mmio_ctor_args, &microvm_state.device_states)
            .map_err(MicrovmStateError::RestoreDevices)?;
    vmm.emulate_serial_init()?;

    // Move vcpus to their own threads and start their state machine in the 'Paused' state.
    vmm.start_vcpus(
        vcpus,
        seccomp_filters
            .get("vcpu")
            .ok_or(BuildMicrovmFromSnapshotError::MissingVcpuSeccompFilters)?
            .clone(),
    )?;

    // Restore vcpus kvm state.
    vmm.restore_vcpu_states(microvm_state.vcpu_states)?;

    let vmm = Arc::new(Mutex::new(vmm));
    event_manager.add_subscriber(vmm.clone());

    // Load seccomp filters for the VMM thread.
    // Keep this as the last step of the building process.
    seccompiler::apply_filter(
        seccomp_filters
            .get("vmm")
            .ok_or(BuildMicrovmFromSnapshotError::MissingVmmSeccompFilters)?,
    )?;

    Ok(vmm)
}

/// Creates GuestMemory of `mem_size_mib` MiB in size.
pub fn create_guest_memory(
    mem_size_mib: usize,
    backing_memory_file: Option<Arc<File>>,
    track_dirty_pages: bool,
) -> std::result::Result<GuestMemoryMmap, StartMicrovmError> {
    let mem_size = mem_size_mib << 20;
    let arch_mem_regions = arch::arch_memory_regions(mem_size);

    let mut offset = 0_u64;
    vm_memory::create_guest_memory(
        &arch_mem_regions
            .iter()
            .map(|(addr, size)| {
                let file_offset = backing_memory_file
                    .clone()
                    .map(|file| FileOffset::from_arc(file, offset));
                offset += *size as u64;

                (file_offset, *addr, *size)
            })
            .collect::<Vec<_>>()[..],
        track_dirty_pages,
    )
    .map_err(StartMicrovmError::GuestMemoryMmap)
}

/// Creates GuestMemory of `mem_size_mib` MiB in size.
pub fn create_uffd_guest_memory(
    mem_size_mib: usize,
    uds_socket_path: &Path,
    track_dirty_pages: bool,
) -> std::result::Result<(GuestMemoryMmap, Uffd, Arc<File>), StartMicrovmError> {
    use StartMicrovmError::{CreateUffdBuilder, NoMemFdReceived, UdsConnection, UffdSend};

    let mut socket = UnixStream::connect(uds_socket_path).map_err(UdsConnection)?;

    let mut buf = [0u8; 8];
    let (_, memfd) = socket.recv_with_fd(&mut buf).map_err(UffdSend)?;

    if memfd.is_none() {
        return Err(NoMemFdReceived);
    }

    let mem_size = mem_size_mib << 20;
    let arch_mem_regions = arch::arch_memory_regions(mem_size);
    let backing_memory_file = Arc::new(memfd.unwrap());

    let mut offset = 0_u64;
    let guest_memory = vm_memory::create_guest_memory(
        &arch_mem_regions
            .iter()
            .map(|(addr, size)| {
                let file_offset = Some(FileOffset::from_arc(backing_memory_file.clone(), offset));
                offset += *size as u64;

                (file_offset, *addr, *size)
            })
            .collect::<Vec<_>>()[..],
        track_dirty_pages,
    )
    .map_err(StartMicrovmError::GuestMemoryMmap)?;

    let uffd = UffdBuilder::new()
        .require_features(
            FeatureFlags::EVENT_REMOVE
                | FeatureFlags::EVENT_REMAP
                | FeatureFlags::EVENT_FORK
                | FeatureFlags::EVENT_UNMAP
                | FeatureFlags::MISSING_SHMEM
                | FeatureFlags::MINOR_SHMEM
                | FeatureFlags::PAGEFAULT_FLAG_WP,
        )
        .user_mode_only(false)
        .create()
        .map_err(CreateUffdBuilder)?;

    let mut backend_mappings = Vec::with_capacity(guest_memory.num_regions());
    let mut offset = 0;
    for mem_region in guest_memory.iter() {
        let host_base_addr = mem_region.as_ptr();
        let size = mem_region.size();

        backend_mappings.push(GuestRegionUffdMapping {
            base_host_virt_addr: host_base_addr as u64,
            size,
            offset,
        });
        offset += size as u64;
    }

    // This is safe to unwrap() because we control the contents of the vector
    // (i.e GuestRegionUffdMapping entries).
    let backend_mappings = serde_json::to_string(&backend_mappings).unwrap();

    socket
        .send_with_fd(
            backend_mappings.as_bytes(),
            // In the happy case we can close the fd since the other process has it open and is
            // using it to serve us pages.
            //
            // The problem is that if other process crashes/exits, firecracker guest memory
            // will simply revert to anon-mem behavior which would lead to silent errors and
            // undefined behavior.
            //
            // To tackle this scenario, the page fault handler can notify Firecracker of any
            // crashes/exits. There is no need for Firecracker to explicitly send its process ID.
            // The external process can obtain Firecracker's PID by calling `getsockopt` with
            // `libc::SO_PEERCRED` option like so:
            //
            // let mut val = libc::ucred { pid: 0, gid: 0, uid: 0 };
            // let mut ucred_size: u32 = mem::size_of::<libc::ucred>() as u32;
            // libc::getsockopt(
            //      socket.as_raw_fd(),
            //      libc::SOL_SOCKET,
            //      libc::SO_PEERCRED,
            //      &mut val as *mut _ as *mut _,
            //      &mut ucred_size as *mut libc::socklen_t,
            // );
            //
            // Per this linux man page: https://man7.org/linux/man-pages/man7/unix.7.html,
            // `SO_PEERCRED` returns the credentials (PID, UID and GID) of the peer process
            // connected to this socket. The returned credentials are those that were in effect
            // at the time of the `connect` call.
            //
            // Moreover, Firecracker holds a copy of the UFFD fd as well, so that even if the
            // page fault handler process does not tear down Firecracker when necessary, the
            // uffd will still be alive but with no one to serve faults, leading to guest freeze.
            uffd.as_raw_fd(),
        )
        .map_err(UffdSend)?;

    // Wait for UFFD to be ready.
    // TODO: maybe add a timeout?
    let mut buf = [0; 2];
    socket.read_exact(&mut buf).map_err(UdsConnection)?;

    Ok((guest_memory, uffd, backing_memory_file))
}

fn load_kernel(
    boot_config: &BootConfig,
    guest_memory: &GuestMemoryMmap,
) -> std::result::Result<GuestAddress, StartMicrovmError> {
    let mut kernel_file = boot_config
        .kernel_file
        .try_clone()
        .map_err(|err| StartMicrovmError::Internal(Error::KernelFile(err)))?;

    #[cfg(target_arch = "x86_64")]
    let entry_addr = Loader::load::<std::fs::File, GuestMemoryMmap>(
        guest_memory,
        None,
        &mut kernel_file,
        Some(GuestAddress(arch::get_kernel_start())),
    )
    .map_err(StartMicrovmError::KernelLoader)?;

    #[cfg(target_arch = "aarch64")]
    let entry_addr = Loader::load::<std::fs::File, GuestMemoryMmap>(
        guest_memory,
        Some(GuestAddress(arch::get_kernel_start())),
        &mut kernel_file,
        None,
    )
    .map_err(StartMicrovmError::KernelLoader)?;

    Ok(entry_addr.kernel_load)
}

fn load_initrd_from_config(
    boot_cfg: &BootConfig,
    vm_memory: &GuestMemoryMmap,
) -> std::result::Result<Option<InitrdConfig>, StartMicrovmError> {
    use self::StartMicrovmError::InitrdRead;

    Ok(match &boot_cfg.initrd_file {
        Some(f) => Some(load_initrd(
            vm_memory,
            &mut f.try_clone().map_err(InitrdRead)?,
        )?),
        None => None,
    })
}

/// Loads the initrd from a file into the given memory slice.
///
/// * `vm_memory` - The guest memory the initrd is written to.
/// * `image` - The initrd image.
///
/// Returns the result of initrd loading
fn load_initrd<F>(
    vm_memory: &GuestMemoryMmap,
    image: &mut F,
) -> std::result::Result<InitrdConfig, StartMicrovmError>
where
    F: Read + Seek,
{
    use self::StartMicrovmError::{InitrdLoad, InitrdRead};

    let size: usize;
    // Get the image size
    match image.seek(SeekFrom::End(0)) {
        Err(err) => return Err(InitrdRead(err)),
        Ok(0) => {
            return Err(InitrdRead(io::Error::new(
                io::ErrorKind::InvalidData,
                "Initrd image seek returned a size of zero",
            )))
        }
        Ok(s) => size = s as usize,
    };
    // Go back to the image start
    image.seek(SeekFrom::Start(0)).map_err(InitrdRead)?;

    // Get the target address
    let address = arch::initrd_load_addr(vm_memory, size).map_err(|_| InitrdLoad)?;

    // Load the image into memory
    vm_memory
        .read_from(GuestAddress(address), image, size)
        .map_err(|_| InitrdLoad)?;

    Ok(InitrdConfig {
        address: GuestAddress(address),
        size,
    })
}

pub(crate) fn setup_kvm_vm(
    guest_memory: &GuestMemoryMmap,
    track_dirty_pages: bool,
) -> std::result::Result<Vm, StartMicrovmError> {
    use self::StartMicrovmError::Internal;
    let kvm = KvmContext::new()
        .map_err(Error::KvmContext)
        .map_err(Internal)?;
    let mut vm = Vm::new(kvm.fd()).map_err(Error::Vm).map_err(Internal)?;
    vm.memory_init(guest_memory, kvm.max_memslots(), track_dirty_pages)
        .map_err(Error::Vm)
        .map_err(Internal)?;
    Ok(vm)
}

/// Sets up the irqchip for a x86_64 microVM.
#[cfg(target_arch = "x86_64")]
pub fn setup_interrupt_controller(vm: &mut Vm) -> std::result::Result<(), StartMicrovmError> {
    vm.setup_irqchip()
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)
}

/// Sets up the irqchip for a aarch64 microVM.
#[cfg(target_arch = "aarch64")]
pub fn setup_interrupt_controller(
    vm: &mut Vm,
    vcpu_count: u8,
) -> std::result::Result<(), StartMicrovmError> {
    vm.setup_irqchip(vcpu_count)
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)
}

/// Sets up the serial device.
pub fn setup_serial_device(
    event_manager: &mut EventManager,
    input: Box<dyn ReadableFd + Send>,
    out: Box<dyn io::Write + Send>,
) -> super::Result<Arc<Mutex<SerialDevice>>> {
    let interrupt_evt = EventFdTrigger::new(EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?);
    let kick_stdin_read_evt =
        EventFdTrigger::new(EventFd::new(EFD_NONBLOCK).map_err(Error::EventFd)?);
    let serial = Arc::new(Mutex::new(SerialWrapper {
        serial: Serial::with_events(
            interrupt_evt,
            SerialEventsWrapper {
                metrics: METRICS.uart.clone(),
                buffer_ready_event_fd: Some(kick_stdin_read_evt),
            },
            out,
        ),
        input: Some(input),
    }));
    event_manager.add_subscriber(serial.clone());
    Ok(serial)
}

#[cfg(target_arch = "aarch64")]
/// Sets up the RTC device.
pub fn setup_rtc_device() -> Arc<Mutex<RTCDevice>> {
    let rtc = Rtc::with_events(METRICS.rtc.clone());
    Arc::new(Mutex::new(rtc))
}

#[cfg(target_arch = "x86_64")]
fn create_pio_dev_manager_with_legacy_devices(
    vm: &Vm,
    serial: Arc<Mutex<SerialDevice>>,
    i8042_reset_evfd: EventFd,
) -> std::result::Result<PortIODeviceManager, super::Error> {
    let mut pio_dev_mgr =
        PortIODeviceManager::new(serial, i8042_reset_evfd).map_err(Error::CreateLegacyDevice)?;
    pio_dev_mgr
        .register_devices(vm.fd())
        .map_err(Error::LegacyIOBus)?;
    Ok(pio_dev_mgr)
}

#[cfg(target_arch = "aarch64")]
fn attach_legacy_devices_aarch64(
    event_manager: &mut EventManager,
    vmm: &mut Vmm,
    cmdline: &mut LoaderKernelCmdline,
) -> super::Result<()> {
    // Serial device setup.
    let cmdline_contains_console = cmdline
        .as_cstring()
        .map_err(|_| Error::Cmdline)?
        .into_string()
        .map_err(|_| Error::Cmdline)?
        .contains("console=");

    if cmdline_contains_console {
        // Make stdout non-blocking.
        set_stdout_nonblocking();
        let serial = setup_serial_device(
            event_manager,
            Box::new(SerialStdin::get()),
            Box::new(io::stdout()),
        )?;
        vmm.mmio_device_manager
            .register_mmio_serial(vmm.vm.fd(), serial, None)
            .map_err(Error::RegisterMMIODevice)?;
        vmm.mmio_device_manager
            .add_mmio_serial_to_cmdline(cmdline)
            .map_err(Error::RegisterMMIODevice)?;
    }

    let rtc = setup_rtc_device();
    vmm.mmio_device_manager
        .register_mmio_rtc(rtc, None)
        .map_err(Error::RegisterMMIODevice)
}

fn create_vcpus(vm: &Vm, vcpu_count: u8, exit_evt: &EventFd) -> super::Result<Vec<Vcpu>> {
    let mut vcpus = Vec::with_capacity(vcpu_count as usize);
    for cpu_idx in 0..vcpu_count {
        let exit_evt = exit_evt.try_clone().map_err(Error::EventFd)?;

        let vcpu = Vcpu::new(cpu_idx, vm, exit_evt).map_err(Error::VcpuCreate)?;
        #[cfg(target_arch = "aarch64")]
        vcpu.kvm_vcpu.init(vm.fd()).map_err(Error::VcpuInit)?;

        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

/// Configures the system for booting Linux.
#[cfg_attr(target_arch = "aarch64", allow(unused))]
pub fn configure_system_for_boot(
    vmm: &Vmm,
    vcpus: &mut [Vcpu],
    vcpu_config: VcpuConfig,
    entry_addr: GuestAddress,
    initrd: &Option<InitrdConfig>,
    boot_cmdline: LoaderKernelCmdline,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;
    #[cfg(target_arch = "x86_64")]
    {
        for vcpu in vcpus.iter_mut() {
            vcpu.kvm_vcpu
                .configure(
                    vmm.guest_memory(),
                    entry_addr,
                    &vcpu_config,
                    vmm.vm.supported_cpuid().clone(),
                )
                .map_err(Error::VcpuConfigure)
                .map_err(Internal)?;
        }

        // Write the kernel command line to guest memory. This is x86_64 specific, since on
        // aarch64 the command line will be specified through the FDT.
        let cmdline_size = boot_cmdline
            .as_cstring()
            .map(|cmdline_cstring| cmdline_cstring.as_bytes_with_nul().len())?;

        linux_loader::loader::load_cmdline::<vm_memory::GuestMemoryMmap>(
            vmm.guest_memory(),
            GuestAddress(arch::x86_64::layout::CMDLINE_START),
            &boot_cmdline,
        )
        .map_err(LoadCommandline)?;
        arch::x86_64::configure_system(
            &vmm.guest_memory,
            vm_memory::GuestAddress(arch::x86_64::layout::CMDLINE_START),
            cmdline_size,
            initrd,
            vcpus.len() as u8,
        )
        .map_err(ConfigureSystem)?;
    }
    #[cfg(target_arch = "aarch64")]
    {
        for vcpu in vcpus.iter_mut() {
            vcpu.kvm_vcpu
                .configure(vmm.guest_memory(), entry_addr)
                .map_err(Error::VcpuConfigure)
                .map_err(Internal)?;
        }

        let vcpu_mpidr = vcpus
            .iter_mut()
            .map(|cpu| cpu.kvm_vcpu.get_mpidr())
            .collect();
        let cmdline = boot_cmdline.as_cstring()?;
        arch::aarch64::configure_system(
            &vmm.guest_memory,
            cmdline,
            vcpu_mpidr,
            vmm.mmio_device_manager.get_device_info(),
            vmm.vm.get_irqchip(),
            initrd,
        )
        .map_err(ConfigureSystem)?;
    }
    Ok(())
}

/// Attaches a VirtioDevice device to the device manager and event manager.
fn attach_virtio_device<T: 'static + VirtioDevice + MutEventSubscriber>(
    event_manager: &mut EventManager,
    vmm: &mut Vmm,
    id: String,
    device: Arc<Mutex<T>>,
    cmdline: &mut LoaderKernelCmdline,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    event_manager.add_subscriber(device.clone());

    // The device mutex mustn't be locked here otherwise it will deadlock.
    let device = MmioTransport::new(vmm.guest_memory().clone(), device);
    vmm.mmio_device_manager
        .register_mmio_virtio_for_boot(vmm.vm.fd(), id, device, cmdline)
        .map_err(RegisterMmioDevice)
        .map(|_| ())
}

pub(crate) fn attach_boot_timer_device(
    vmm: &mut Vmm,
    request_ts: TimestampUs,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    let boot_timer = devices::pseudo::BootTimer::new(request_ts);

    vmm.mmio_device_manager
        .register_mmio_boot_timer(boot_timer)
        .map_err(RegisterMmioDevice)?;

    Ok(())
}

fn attach_block_devices<'a>(
    vmm: &mut Vmm,
    cmdline: &mut LoaderKernelCmdline,
    blocks: impl Iterator<Item = &'a Arc<Mutex<Block>>>,
    event_manager: &mut EventManager,
) -> std::result::Result<(), StartMicrovmError> {
    for block in blocks {
        let id = {
            let locked = block.lock().expect("Poisoned lock");
            if locked.is_root_device() {
                cmdline.insert_str(if let Some(partuuid) = locked.partuuid() {
                    format!("root=PARTUUID={}", partuuid)
                } else {
                    // If no PARTUUID was specified for the root device, try with the /dev/vda.
                    "root=/dev/vda".to_string()
                })?;

                let flags = if locked.is_read_only() { "ro" } else { "rw" };
                cmdline.insert_str(flags)?;
            }
            locked.id().clone()
        };
        // The device mutex mustn't be locked here otherwise it will deadlock.
        attach_virtio_device(event_manager, vmm, id, block.clone(), cmdline)?;
    }
    Ok(())
}

fn attach_net_devices<'a>(
    vmm: &mut Vmm,
    cmdline: &mut LoaderKernelCmdline,
    net_devices: impl Iterator<Item = &'a Arc<Mutex<Net>>>,
    event_manager: &mut EventManager,
) -> std::result::Result<(), StartMicrovmError> {
    for net_device in net_devices {
        let id = net_device.lock().expect("Poisoned lock").id().clone();
        // The device mutex mustn't be locked here otherwise it will deadlock.
        attach_virtio_device(event_manager, vmm, id, net_device.clone(), cmdline)?;
    }
    Ok(())
}

fn attach_unixsock_vsock_device(
    vmm: &mut Vmm,
    cmdline: &mut LoaderKernelCmdline,
    unix_vsock: &Arc<Mutex<Vsock<VsockUnixBackend>>>,
    event_manager: &mut EventManager,
) -> std::result::Result<(), StartMicrovmError> {
    let id = String::from(unix_vsock.lock().expect("Poisoned lock").id());
    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_virtio_device(event_manager, vmm, id, unix_vsock.clone(), cmdline)
}

fn attach_balloon_device(
    vmm: &mut Vmm,
    cmdline: &mut LoaderKernelCmdline,
    balloon: &Arc<Mutex<Balloon>>,
    event_manager: &mut EventManager,
) -> std::result::Result<(), StartMicrovmError> {
    let id = String::from(balloon.lock().expect("Poisoned lock").id());
    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_virtio_device(event_manager, vmm, id, balloon.clone(), cmdline)
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
pub mod tests {
    use std::io::Cursor;

    use arch::DeviceType;
    use devices::virtio::vsock::VSOCK_DEV_ID;
    use devices::virtio::{TYPE_BALLOON, TYPE_BLOCK, TYPE_VSOCK};
    use linux_loader::cmdline::Cmdline;
    use mmds::data_store::{Mmds, MmdsVersion};
    use mmds::ns::MmdsNetworkStack;
    use utils::tempfile::TempFile;
    use vm_memory::GuestMemory;

    use super::*;
    use crate::vmm_config::balloon::{BalloonBuilder, BalloonDeviceConfig, BALLOON_DEV_ID};
    use crate::vmm_config::boot_source::DEFAULT_KERNEL_CMDLINE;
    use crate::vmm_config::drive::{BlockBuilder, BlockDeviceConfig, CacheType, FileEngineType};
    use crate::vmm_config::net::{NetBuilder, NetworkInterfaceConfig};
    use crate::vmm_config::vsock::tests::default_config;
    use crate::vmm_config::vsock::{VsockBuilder, VsockDeviceConfig};

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

    fn default_mmio_device_manager() -> MMIODeviceManager {
        MMIODeviceManager::new(
            arch::MMIO_MEM_START,
            arch::MMIO_MEM_SIZE,
            (arch::IRQ_BASE, arch::IRQ_MAX),
        )
        .unwrap()
    }

    #[cfg(target_arch = "x86_64")]
    fn default_portio_device_manager() -> PortIODeviceManager {
        PortIODeviceManager::new(
            Arc::new(Mutex::new(SerialWrapper {
                serial: Serial::with_events(
                    EventFdTrigger::new(EventFd::new(EFD_NONBLOCK).unwrap()),
                    SerialEventsWrapper {
                        metrics: METRICS.uart.clone(),
                        buffer_ready_event_fd: None,
                    },
                    Box::new(std::io::sink()),
                ),
                input: None,
            })),
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        )
        .unwrap()
    }

    fn cmdline_contains(cmdline: &Cmdline, slug: &str) -> bool {
        // The following unwraps can never fail; the only way any of these methods
        // would return an `Err` is if one of the following conditions is met:
        //    1. The command line is empty: We just added things to it, and if insertion
        //       of an argument goes wrong, then `Cmdline::insert` would have already
        //       returned `Err`.
        //    2. There's a spurious null character somewhere in the command line: The
        //       `Cmdline::insert` methods verify that this is not the case.
        //    3. The `CString` is not valid UTF8: It just got created from a `String`,
        //       which was valid UTF8.

        cmdline
            .as_cstring()
            .unwrap()
            .into_string()
            .unwrap()
            .contains(slug)
    }

    pub(crate) fn default_kernel_cmdline() -> Cmdline {
        linux_loader::cmdline::Cmdline::try_from(DEFAULT_KERNEL_CMDLINE, arch::CMDLINE_MAX_SIZE)
            .unwrap()
    }

    pub(crate) fn default_vmm() -> Vmm {
        let guest_memory = create_guest_memory(128, None, false).unwrap();

        let vcpus_exit_evt = EventFd::new(libc::EFD_NONBLOCK)
            .map_err(Error::EventFd)
            .map_err(StartMicrovmError::Internal)
            .unwrap();

        let mut vm = setup_kvm_vm(&guest_memory, false).unwrap();
        let mmio_device_manager = default_mmio_device_manager();
        #[cfg(target_arch = "x86_64")]
        let pio_device_manager = default_portio_device_manager();

        #[cfg(target_arch = "x86_64")]
        setup_interrupt_controller(&mut vm).unwrap();

        #[cfg(target_arch = "aarch64")]
        {
            let exit_evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
            let _vcpu = Vcpu::new(1, &vm, exit_evt).unwrap();
            setup_interrupt_controller(&mut vm, 1).unwrap();
        }

        Vmm {
            events_observer: Some(Box::new(SerialStdin::get())),
            instance_info: InstanceInfo::default(),
            shutdown_exit_code: None,
            vm,
            guest_memory,
            vcpus_handles: Vec::new(),
            vcpus_exit_evt,
            mmio_device_manager,
            #[cfg(target_arch = "x86_64")]
            pio_device_manager,
            memory_descriptor: None,
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
        for custom_block_cfg in &custom_block_cfgs {
            block_files.push(TempFile::new().unwrap());
            let block_device_config = BlockDeviceConfig {
                drive_id: String::from(&custom_block_cfg.drive_id),
                path_on_host: block_files
                    .last()
                    .unwrap()
                    .as_path()
                    .to_str()
                    .unwrap()
                    .to_string(),
                is_root_device: custom_block_cfg.is_root_device,
                partuuid: custom_block_cfg.partuuid.clone(),
                is_read_only: custom_block_cfg.is_read_only,
                cache_type: custom_block_cfg.cache_type,
                rate_limiter: None,
                file_engine_type: FileEngineType::default(),
            };
            block_dev_configs.insert(block_device_config).unwrap();
        }

        attach_block_devices(vmm, cmdline, block_dev_configs.list.iter(), event_manager).unwrap();
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
        assert!(res.is_ok());
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

        assert!(attach_unixsock_vsock_device(vmm, cmdline, &vsock, event_manager).is_ok());

        assert!(vmm
            .mmio_device_manager
            .get_device(DeviceType::Virtio(TYPE_VSOCK), &vsock_dev_id)
            .is_some());
    }

    pub(crate) fn insert_balloon_device(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        balloon_config: BalloonDeviceConfig,
    ) {
        let mut builder = BalloonBuilder::new();
        assert!(builder.set(balloon_config).is_ok());
        let balloon = builder.get().unwrap();

        assert!(attach_balloon_device(vmm, cmdline, balloon, event_manager).is_ok());

        assert!(vmm
            .mmio_device_manager
            .get_device(DeviceType::Virtio(TYPE_BALLOON), BALLOON_DEV_ID)
            .is_some());
    }

    fn make_test_bin() -> Vec<u8> {
        let mut fake_bin = Vec::new();
        fake_bin.resize(1_000_000, 0xAA);
        fake_bin
    }

    fn create_guest_mem_at(at: GuestAddress, size: usize) -> GuestMemoryMmap {
        vm_memory::test_utils::create_guest_memory_unguarded(&[(at, size)], false).unwrap()
    }

    pub(crate) fn create_guest_mem_with_size(size: usize) -> GuestMemoryMmap {
        create_guest_mem_at(GuestAddress(0x0), size)
    }

    fn is_dirty_tracking_enabled(mem: &GuestMemoryMmap) -> bool {
        mem.iter().all(|r| r.bitmap().is_some())
    }

    #[test]
    // Test that loading the initrd is successful on different archs.
    fn test_load_initrd() {
        use vm_memory::GuestMemory;
        let image = make_test_bin();

        let mem_size: usize = image.len() * 2 + arch::PAGE_SIZE;

        #[cfg(target_arch = "x86_64")]
        let gm = create_guest_mem_with_size(mem_size);

        #[cfg(target_arch = "aarch64")]
        let gm = create_guest_mem_with_size(mem_size + arch::aarch64::layout::FDT_MAX_SIZE);

        let res = load_initrd(&gm, &mut Cursor::new(&image));
        assert!(res.is_ok());
        let initrd = res.unwrap();
        assert!(gm.address_in_range(initrd.address));
        assert_eq!(initrd.size, image.len());
    }

    #[test]
    fn test_load_initrd_no_memory() {
        let gm = create_guest_mem_with_size(79);
        let image = make_test_bin();
        let res = load_initrd(&gm, &mut Cursor::new(&image));
        assert!(res.is_err());
        assert_eq!(
            StartMicrovmError::InitrdLoad.to_string(),
            res.err().unwrap().to_string()
        );
    }

    #[test]
    fn test_load_initrd_unaligned() {
        let image = vec![1, 2, 3, 4];
        let gm = create_guest_mem_at(GuestAddress(arch::PAGE_SIZE as u64 + 1), image.len() * 2);

        let res = load_initrd(&gm, &mut Cursor::new(&image));
        assert!(res.is_err());
        assert_eq!(
            StartMicrovmError::InitrdLoad.to_string(),
            res.err().unwrap().to_string()
        );
    }

    #[test]
    fn test_stdin_wrapper() {
        let wrapper = SerialStdin::get();
        assert_eq!(wrapper.as_raw_fd(), io::stdin().as_raw_fd())
    }

    #[test]
    fn test_create_guest_memory() {
        let mem_size = 4096 * 2;

        // Case 1: create guest memory without dirty page tracking
        {
            let guest_memory = create_guest_memory(mem_size, None, false).unwrap();
            assert!(!is_dirty_tracking_enabled(&guest_memory));
        }

        // Case 2: create guest memory with dirty page tracking
        {
            let guest_memory = create_guest_memory(mem_size, None, true).unwrap();
            assert!(is_dirty_tracking_enabled(&guest_memory));
        }
    }

    #[test]
    fn test_create_vcpus() {
        let vcpu_count = 2;
        let guest_memory = create_guest_memory(128, None, false).unwrap();

        #[allow(unused_mut)]
        let mut vm = setup_kvm_vm(&guest_memory, false).unwrap();
        let evfd = EventFd::new(libc::EFD_NONBLOCK).unwrap();

        #[cfg(target_arch = "x86_64")]
        setup_interrupt_controller(&mut vm).unwrap();

        let vcpu_vec = create_vcpus(&vm, vcpu_count, &evfd).unwrap();
        assert_eq!(vcpu_vec.len(), vcpu_count as usize);
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
        assert!(net_builder.build(network_interface).is_err());
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
            assert!(vmm
                .mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                .is_some());
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
            assert!(vmm
                .mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                .is_some());
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
            assert!(vmm
                .mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                .is_some());
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
            assert!(vmm
                .mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_BLOCK), "root")
                .is_some());
            assert!(vmm
                .mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_BLOCK), "secondary")
                .is_some());
            assert!(vmm
                .mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_BLOCK), "third")
                .is_some());

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
            assert!(vmm
                .mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                .is_some());
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
            assert!(vmm
                .mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                .is_some());
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
            assert!(vmm
                .mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                .is_some());
        }
    }

    #[test]
    fn test_attach_boot_timer_device() {
        let mut vmm = default_vmm();
        let request_ts = TimestampUs::default();

        let res = attach_boot_timer_device(&mut vmm, request_ts);
        assert!(res.is_ok());
        assert!(vmm
            .mmio_device_manager
            .get_device(DeviceType::BootTimer, &DeviceType::BootTimer.to_string())
            .is_some());
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

    #[test]
    fn test_error_messages() {
        use crate::builder::StartMicrovmError::*;
        let err = AttachBlockDevice(io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);

        let err = CreateNetDevice(devices::virtio::net::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{}{:?}", err, err);

        let err = CreateRateLimiter(io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);

        let err = Internal(Error::Serial(io::Error::from_raw_os_error(0)));
        let _ = format!("{}{:?}", err, err);

        let err = KernelCmdline(String::from("dummy --cmdline"));
        let _ = format!("{}{:?}", err, err);

        let err = KernelLoader(linux_loader::loader::Error::InvalidKernelStartAddress);
        let _ = format!("{}{:?}", err, err);
        let err = LoadCommandline(linux_loader::loader::Error::CommandLineOverflow);
        let _ = format!("{}{:?}", err, err);

        let err = MissingKernelConfig;
        let _ = format!("{}{:?}", err, err);

        let err = MissingMemSizeConfig;
        let _ = format!("{}{:?}", err, err);

        let err = NetDeviceNotConfigured;
        let _ = format!("{}{:?}", err, err);

        let err = OpenBlockDevice(io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);
    }

    #[test]
    fn test_kernel_cmdline_err_to_startuvm_err() {
        let err = StartMicrovmError::from(linux_loader::cmdline::Error::HasSpace);
        let _ = format!("{}{:?}", err, err);
    }
}
