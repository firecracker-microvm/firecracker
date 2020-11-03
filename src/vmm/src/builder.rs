// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enables pre-boot setup, instantiation and booting of a Firecracker VMM.

#[cfg(target_arch = "x86_64")]
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use crate::device_manager::mmio::MMIODeviceManager;
#[cfg(target_arch = "x86_64")]
use crate::device_manager::{legacy::PortIODeviceManager, persist::MMIODevManagerConstructorArgs};
#[cfg(target_arch = "x86_64")]
use crate::persist::{MicrovmState, MicrovmStateError};
use crate::vmm_config::boot_source::BootConfig;
use crate::vstate::{
    system::KvmContext,
    vcpu::{Vcpu, VcpuConfig},
    vm::Vm,
};
use crate::{device_manager, Error, Vmm, VmmEventsObserver};

use arch::InitrdConfig;
use devices::legacy::Serial;
use devices::virtio::{Balloon, Block, MmioTransport, Net, VirtioDevice, Vsock, VsockUnixBackend};
use kernel::cmdline::Cmdline as KernelCmdline;
use logger::warn;
use polly::event_manager::{Error as EventManagerError, EventManager, Subscriber};
use seccomp::{BpfProgramRef, SeccompFilter};
#[cfg(target_arch = "x86_64")]
use snapshot::Persist;
use utils::eventfd::EventFd;
use utils::terminal::Terminal;
use utils::time::TimestampUs;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

/// Errors associated with starting the instance.
#[derive(Debug)]
pub enum StartMicrovmError {
    /// Unable to attach block device to Vmm.
    AttachBlockDevice(io::Error),
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
    KernelLoader(kernel::loader::Error),
    /// Cannot load command line string.
    LoadCommandline(kernel::cmdline::Error),
    /// Cannot start the VM because the kernel was not configured.
    MissingKernelConfig,
    /// Cannot start the VM because the size of the guest memory  was not specified.
    MissingMemSizeConfig,
    /// The net device configuration is missing the tap device.
    NetDeviceNotConfigured,
    /// Cannot open the block device backing file.
    OpenBlockDevice(io::Error),
    /// Cannot register an EventHandler.
    RegisterEvent(EventManagerError),
    /// Cannot initialize a MMIO Device or add a device to the MMIO Bus or cmdline.
    RegisterMmioDevice(device_manager::mmio::Error),
    #[cfg(target_arch = "x86_64")]
    /// Cannot restore microvm state.
    RestoreMicrovmState(MicrovmStateError),
}

/// It's convenient to automatically convert `kernel::cmdline::Error`s
/// to `StartMicrovmError`s.
impl std::convert::From<kernel::cmdline::Error> for StartMicrovmError {
    fn from(e: kernel::cmdline::Error) -> StartMicrovmError {
        StartMicrovmError::KernelCmdline(e.to_string())
    }
}

impl Display for StartMicrovmError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::StartMicrovmError::*;
        match self {
            AttachBlockDevice(err) => {
                write!(f, "Unable to attach block device to Vmm. Error: {}", err)
            }
            ConfigureSystem(e) => write!(f, "System configuration error: {:?}", e),
            CreateRateLimiter(err) => write!(f, "Cannot create RateLimiter: {}", err),
            CreateNetDevice(err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Cannot create network device. {}", err_msg)
            }
            GuestMemoryMmap(err) => {
                // Remove imbricated quotes from error message.
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");
                write!(f, "Invalid Memory Configuration: {}", err_msg)
            }
            InitrdLoad => write!(
                f,
                "Cannot load initrd due to an invalid memory configuration."
            ),
            InitrdRead(err) => write!(f, "Cannot load initrd due to an invalid image: {}", err),
            Internal(err) => write!(f, "Internal error while starting microVM: {:?}", err),
            KernelCmdline(err) => write!(f, "Invalid kernel command line: {}", err),
            KernelLoader(err) => {
                let mut err_msg = format!("{}", err);
                err_msg = err_msg.replace("\"", "");
                write!(
                    f,
                    "Cannot load kernel due to invalid memory configuration or invalid kernel \
                     image. {}",
                    err_msg
                )
            }
            LoadCommandline(err) => {
                let mut err_msg = format!("{}", err);
                err_msg = err_msg.replace("\"", "");
                write!(f, "Cannot load command line string. {}", err_msg)
            }
            MissingKernelConfig => write!(f, "Cannot start microvm without kernel configuration."),
            MissingMemSizeConfig => {
                write!(f, "Cannot start microvm without guest mem_size config.")
            }
            NetDeviceNotConfigured => {
                write!(f, "The net device configuration is missing the tap device.")
            }
            OpenBlockDevice(err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Cannot open the block device backing file. {}", err_msg)
            }
            RegisterEvent(err) => write!(f, "Cannot register EventHandler. {:?}", err),
            RegisterMmioDevice(err) => {
                let mut err_msg = format!("{}", err);
                err_msg = err_msg.replace("\"", "");
                write!(
                    f,
                    "Cannot initialize a MMIO Device or add a device to the MMIO Bus or cmdline. {}",
                    err_msg
                )
            }
            #[cfg(target_arch = "x86_64")]
            RestoreMicrovmState(err) => write!(f, "Cannot restore microvm state. Error: {}", err),
        }
    }
}

// Wrapper over io::Stdin that implements `Serial::ReadableFd` and `vmm::VmmEventsObserver`.
struct SerialStdin(io::Stdin);
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

impl devices::legacy::ReadableFd for SerialStdin {}

impl VmmEventsObserver for SerialStdin {
    fn on_vmm_boot(&mut self) -> std::result::Result<(), utils::errno::Error> {
        // Set raw mode for stdin.
        self.0.lock().set_raw_mode().map_err(|e| {
            warn!("Cannot set raw mode for the terminal. {:?}", e);
            e
        })?;

        // Set non blocking stdin.
        self.0.lock().set_non_block(true).map_err(|e| {
            warn!("Cannot set non block for the terminal. {:?}", e);
            e
        })
    }
    fn on_vmm_stop(&mut self) -> std::result::Result<(), utils::errno::Error> {
        self.0.lock().set_canon_mode().map_err(|e| {
            warn!("Cannot set canonical mode for the terminal. {:?}", e);
            e
        })
    }
}

#[cfg_attr(target_arch = "aarch64", allow(unused))]
fn create_vmm_and_vcpus(
    event_manager: &mut EventManager,
    guest_memory: GuestMemoryMmap,
    track_dirty_pages: bool,
    vcpu_count: u8,
) -> std::result::Result<(Vmm, Vec<Vcpu>), StartMicrovmError> {
    use self::StartMicrovmError::*;

    // Set up Kvm Vm and register memory regions.
    let mut vm = setup_kvm_vm(&guest_memory, track_dirty_pages)?;

    // Vmm exit event.
    let exit_evt = EventFd::new(libc::EFD_NONBLOCK)
        .map_err(Error::EventFd)
        .map_err(Internal)?;

    // Instantiate the MMIO device manager.
    // 'mmio_base' address has to be an address which is protected by the kernel
    // and is architectural specific.
    let mmio_device_manager =
        MMIODeviceManager::new(arch::MMIO_MEM_START, (arch::IRQ_BASE, arch::IRQ_MAX));

    let vcpus;
    // For x86_64 we need to create the interrupt controller before calling `KVM_CREATE_VCPUS`
    // while on aarch64 we need to do it the other way around.
    #[cfg(target_arch = "x86_64")]
    let pio_device_manager = {
        setup_interrupt_controller(&mut vm)?;
        vcpus = create_vcpus(&vm, vcpu_count, &exit_evt).map_err(Internal)?;

        // Serial device setup.
        let serial_device = setup_serial_device(
            event_manager,
            Box::new(SerialStdin::get()),
            Box::new(io::stdout()),
        )
        .map_err(Internal)?;
        // x86_64 uses the i8042 reset event as the Vmm exit event.
        let reset_evt = exit_evt
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
        vcpus = create_vcpus(&vm, vcpu_count, &exit_evt).map_err(Internal)?;
        setup_interrupt_controller(&mut vm, vcpu_count)?;
    }

    let vmm = Vmm {
        events_observer: Some(Box::new(SerialStdin::get())),
        guest_memory,
        vcpus_handles: Vec::new(),
        exit_evt,
        vm,
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
    vm_resources: &super::resources::VmResources,
    event_manager: &mut EventManager,
    seccomp_filter: BpfProgramRef,
) -> std::result::Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    use self::StartMicrovmError::*;
    let boot_config = vm_resources.boot_source().ok_or(MissingKernelConfig)?;

    let guest_memory = create_guest_memory(
        vm_resources
            .vm_config()
            .mem_size_mib
            .ok_or(MissingMemSizeConfig)?,
    )?;
    let vcpu_config = vm_resources.vcpu_config();
    let track_dirty_pages = vm_resources.track_dirty_pages();
    let entry_addr = load_kernel(boot_config, &guest_memory)?;
    let initrd = load_initrd_from_config(boot_config, &guest_memory)?;
    // Clone the command-line so that a failed boot doesn't pollute the original.
    #[allow(unused_mut)]
    let mut boot_cmdline = boot_config.cmdline.clone();

    // Timestamp for measuring microVM boot duration.
    let request_ts = TimestampUs::default();

    let (mut vmm, mut vcpus) = create_vmm_and_vcpus(
        event_manager,
        guest_memory,
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
    vmm.start_vcpus(vcpus, seccomp_filter).map_err(Internal)?;

    // Load seccomp filters for the VMM thread.
    // Execution panics if filters cannot be loaded, use --seccomp-level=0 if skipping filters
    // altogether is the desired behaviour.
    // Keep this as the last step before resuming vcpus.
    SeccompFilter::apply(seccomp_filter.to_vec())
        .map_err(Error::SeccompFilters)
        .map_err(Internal)?;

    // The vcpus start off in the `Paused` state, let them run.
    vmm.resume_vcpus().map_err(Internal)?;

    let vmm = Arc::new(Mutex::new(vmm));
    event_manager
        .add_subscriber(vmm.clone())
        .map_err(RegisterEvent)?;

    Ok(vmm)
}

/// Builds and starts a microVM based on the provided MicrovmState.
///
/// An `Arc` reference of the built `Vmm` is also plugged in the `EventManager`, while another
/// is returned.
#[cfg(target_arch = "x86_64")]
pub fn build_microvm_from_snapshot(
    event_manager: &mut EventManager,
    microvm_state: MicrovmState,
    guest_memory: GuestMemoryMmap,
    track_dirty_pages: bool,
    seccomp_filter: BpfProgramRef,
) -> std::result::Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    use self::StartMicrovmError::*;
    let vcpu_count = u8::try_from(microvm_state.vcpu_states.len())
        .map_err(|_| MicrovmStateError::InvalidInput)
        .map_err(RestoreMicrovmState)?;

    // Build Vmm.
    let (mut vmm, vcpus) = create_vmm_and_vcpus(
        event_manager,
        guest_memory.clone(),
        track_dirty_pages,
        vcpu_count,
    )?;

    // Restore kvm vm state.
    vmm.vm
        .restore_state(&microvm_state.vm_state)
        .map_err(MicrovmStateError::RestoreVmState)
        .map_err(RestoreMicrovmState)?;

    // Restore devices states.
    let mmio_ctor_args = MMIODevManagerConstructorArgs {
        mem: guest_memory,
        vm: vmm.vm.fd(),
        event_manager,
    };
    vmm.mmio_device_manager =
        MMIODeviceManager::restore(mmio_ctor_args, &microvm_state.device_states)
            .map_err(MicrovmStateError::RestoreDevices)
            .map_err(RestoreMicrovmState)?;

    // Move vcpus to their own threads and start their state machine in the 'Paused' state.
    vmm.start_vcpus(vcpus, seccomp_filter)
        .map_err(StartMicrovmError::Internal)?;

    // Restore vcpus kvm state.
    vmm.restore_vcpu_states(microvm_state.vcpu_states)
        .map_err(RestoreMicrovmState)?;

    let vmm = Arc::new(Mutex::new(vmm));
    event_manager
        .add_subscriber(vmm.clone())
        .map_err(StartMicrovmError::RegisterEvent)?;

    // Load seccomp filters for the VMM thread.
    // Keep this as the last step of the building process.
    SeccompFilter::apply(seccomp_filter.to_vec())
        .map_err(Error::SeccompFilters)
        .map_err(StartMicrovmError::Internal)?;

    Ok(vmm)
}

/// Creates GuestMemory of `mem_size_mib` MiB in size.
pub fn create_guest_memory(
    mem_size_mib: usize,
) -> std::result::Result<GuestMemoryMmap, StartMicrovmError> {
    let mem_size = mem_size_mib << 20;
    let arch_mem_regions = arch::arch_memory_regions(mem_size);

    Ok(GuestMemoryMmap::from_ranges(&arch_mem_regions)
        .map_err(StartMicrovmError::GuestMemoryMmap)?)
}

fn load_kernel(
    boot_config: &BootConfig,
    guest_memory: &GuestMemoryMmap,
) -> std::result::Result<GuestAddress, StartMicrovmError> {
    let mut kernel_file = boot_config
        .kernel_file
        .try_clone()
        .map_err(|e| StartMicrovmError::Internal(Error::KernelFile(e)))?;

    let entry_addr =
        kernel::loader::load_kernel(guest_memory, &mut kernel_file, arch::get_kernel_start())
            .map_err(StartMicrovmError::KernelLoader)?;

    Ok(entry_addr)
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
        Err(e) => return Err(InitrdRead(e)),
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
    vm.memory_init(&guest_memory, kvm.max_memslots(), track_dirty_pages)
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
    input: Box<dyn devices::legacy::ReadableFd + Send>,
    out: Box<dyn io::Write + Send>,
) -> super::Result<Arc<Mutex<Serial>>> {
    let interrupt_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?;
    let kick_stdin_read_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?;
    let serial = Arc::new(Mutex::new(Serial::new_in_out(
        interrupt_evt,
        input,
        out,
        Some(kick_stdin_read_evt),
    )));
    if let Err(e) = event_manager.add_subscriber(serial.clone()) {
        // TODO: We just log this message, and immediately return Ok, instead of returning the
        // actual error because this operation always fails with EPERM when adding a fd which
        // has been redirected to /dev/null via dup2 (this may happen inside the jailer).
        // Find a better solution to this (and think about the state of the serial device
        // while we're at it).
        warn!("Could not add serial input event to epoll: {:?}", e);
    }
    Ok(serial)
}

#[cfg(target_arch = "x86_64")]
fn create_pio_dev_manager_with_legacy_devices(
    vm: &Vm,
    serial: Arc<Mutex<devices::legacy::Serial>>,
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
    cmdline: &mut KernelCmdline,
) -> super::Result<()> {
    // Serial device setup.
    if cmdline.as_str().contains("console=") {
        let serial = setup_serial_device(
            event_manager,
            Box::new(SerialStdin::get()),
            Box::new(io::stdout()),
        )?;
        vmm.mmio_device_manager
            .register_mmio_serial(vmm.vm.fd(), serial)
            .map_err(Error::RegisterMMIODevice)?;
        vmm.mmio_device_manager
            .add_mmio_serial_to_cmdline(cmdline)
            .map_err(Error::RegisterMMIODevice)?;
    }

    vmm.mmio_device_manager
        .register_new_mmio_rtc(vmm.vm.fd())
        .map_err(Error::RegisterMMIODevice)
}

fn create_vcpus(vm: &Vm, vcpu_count: u8, exit_evt: &EventFd) -> super::Result<Vec<Vcpu>> {
    let mut vcpus = Vec::with_capacity(vcpu_count as usize);
    for cpu_idx in 0..vcpu_count {
        let exit_evt = exit_evt.try_clone().map_err(Error::EventFd)?;

        let vcpu = Vcpu::new(cpu_idx, vm, exit_evt).map_err(Error::VcpuCreate)?;

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
    boot_cmdline: KernelCmdline,
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
        kernel::loader::load_cmdline(
            vmm.guest_memory(),
            GuestAddress(arch::x86_64::layout::CMDLINE_START),
            &boot_cmdline.as_cstring().map_err(LoadCommandline)?,
        )
        .map_err(LoadCommandline)?;
        arch::x86_64::configure_system(
            &vmm.guest_memory,
            vm_memory::GuestAddress(arch::x86_64::layout::CMDLINE_START),
            boot_cmdline.len() + 1,
            initrd,
            vcpus.len() as u8,
        )
        .map_err(ConfigureSystem)?;
    }
    #[cfg(target_arch = "aarch64")]
    {
        for vcpu in vcpus.iter_mut() {
            vcpu.kvm_vcpu
                .configure(vmm.vm.fd(), vmm.guest_memory(), entry_addr)
                .map_err(Error::VcpuConfigure)
                .map_err(Internal)?;
        }

        let vcpu_mpidr = vcpus
            .iter_mut()
            .map(|cpu| cpu.kvm_vcpu.get_mpidr())
            .collect();
        arch::aarch64::configure_system(
            &vmm.guest_memory,
            &boot_cmdline.as_cstring().map_err(LoadCommandline)?,
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
fn attach_virtio_device<T: 'static + VirtioDevice + Subscriber>(
    event_manager: &mut EventManager,
    vmm: &mut Vmm,
    id: String,
    device: Arc<Mutex<T>>,
    cmdline: &mut KernelCmdline,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    event_manager
        .add_subscriber(device.clone())
        .map_err(RegisterEvent)?;

    // The device mutex mustn't be locked here otherwise it will deadlock.
    let device = MmioTransport::new(vmm.guest_memory().clone(), device);
    vmm.mmio_device_manager
        .register_new_virtio_mmio_device(vmm.vm.fd(), id, device, cmdline)
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
        .register_new_mmio_boot_timer(boot_timer)
        .map_err(RegisterMmioDevice)?;

    Ok(())
}

fn attach_block_devices<'a>(
    vmm: &mut Vmm,
    cmdline: &mut KernelCmdline,
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
    cmdline: &mut KernelCmdline,
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
    cmdline: &mut KernelCmdline,
    unix_vsock: &Arc<Mutex<Vsock<VsockUnixBackend>>>,
    event_manager: &mut EventManager,
) -> std::result::Result<(), StartMicrovmError> {
    let id = String::from(unix_vsock.lock().expect("Poisoned lock").id());
    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_virtio_device(event_manager, vmm, id, unix_vsock.clone(), cmdline)
}

fn attach_balloon_device(
    vmm: &mut Vmm,
    cmdline: &mut KernelCmdline,
    balloon: &Arc<Mutex<Balloon>>,
    event_manager: &mut EventManager,
) -> std::result::Result<(), StartMicrovmError> {
    let id = String::from(balloon.lock().expect("Poisoned lock").id());
    // The device mutex mustn't be locked here otherwise it will deadlock.
    attach_virtio_device(event_manager, vmm, id, balloon.clone(), cmdline)
}

#[cfg(test)]
pub mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::vmm_config::balloon::{BalloonBuilder, BalloonDeviceConfig, BALLOON_DEV_ID};
    use crate::vmm_config::boot_source::DEFAULT_KERNEL_CMDLINE;
    use crate::vmm_config::drive::{BlockBuilder, BlockDeviceConfig};
    use crate::vmm_config::net::{NetBuilder, NetworkInterfaceConfig};
    use crate::vmm_config::vsock::tests::default_config;
    use crate::vmm_config::vsock::{VsockBuilder, VsockDeviceConfig};
    use arch::DeviceType;
    use devices::virtio::{TYPE_BALLOON, TYPE_BLOCK, TYPE_VSOCK};
    use kernel::cmdline::Cmdline;
    use polly::event_manager::EventManager;
    use utils::tempfile::TempFile;

    pub(crate) struct CustomBlockConfig {
        drive_id: String,
        is_root_device: bool,
        partuuid: Option<String>,
        is_read_only: bool,
    }

    impl CustomBlockConfig {
        pub(crate) fn new(
            drive_id: String,
            is_root_device: bool,
            partuuid: Option<String>,
            is_read_only: bool,
        ) -> Self {
            CustomBlockConfig {
                drive_id,
                is_root_device,
                partuuid,
                is_read_only,
            }
        }
    }

    fn default_mmio_device_manager() -> MMIODeviceManager {
        MMIODeviceManager::new(arch::MMIO_MEM_START, (arch::IRQ_BASE, arch::IRQ_MAX))
    }

    #[cfg(target_arch = "x86_64")]
    fn default_portio_device_manager() -> PortIODeviceManager {
        PortIODeviceManager::new(
            Arc::new(Mutex::new(Serial::new_sink(
                EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            ))),
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        )
        .unwrap()
    }

    pub(crate) fn default_kernel_cmdline() -> Cmdline {
        let mut kernel_cmdline = kernel::cmdline::Cmdline::new(4096);
        kernel_cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).unwrap();
        kernel_cmdline
    }

    pub(crate) fn default_vmm() -> Vmm {
        let guest_memory = create_guest_memory(128).unwrap();

        let exit_evt = EventFd::new(libc::EFD_NONBLOCK)
            .map_err(Error::EventFd)
            .map_err(StartMicrovmError::Internal)
            .unwrap();

        let vm = setup_kvm_vm(&guest_memory, false).unwrap();
        let mmio_device_manager = default_mmio_device_manager();
        #[cfg(target_arch = "x86_64")]
        let pio_device_manager = default_portio_device_manager();

        let mut vmm = Vmm {
            events_observer: Some(Box::new(SerialStdin::get())),
            guest_memory,
            vcpus_handles: Vec::new(),
            exit_evt,
            vm,
            mmio_device_manager,
            #[cfg(target_arch = "x86_64")]
            pio_device_manager,
        };

        #[cfg(target_arch = "x86_64")]
        setup_interrupt_controller(&mut vmm.vm).unwrap();

        #[cfg(target_arch = "aarch64")]
        setup_interrupt_controller(&mut vmm.vm, 1).unwrap();

        vmm
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
                rate_limiter: None,
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

    pub(crate) fn insert_vsock_device(
        vmm: &mut Vmm,
        cmdline: &mut Cmdline,
        event_manager: &mut EventManager,
        vsock_config: VsockDeviceConfig,
    ) {
        let vsock_dev_id = vsock_config.vsock_id.clone();
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
        GuestMemoryMmap::from_ranges(&[(at, size)]).unwrap()
    }

    pub(crate) fn create_guest_mem_with_size(size: usize) -> GuestMemoryMmap {
        create_guest_mem_at(GuestAddress(0x0), size)
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
    fn test_create_vcpus() {
        let vcpu_count = 2;
        let guest_memory = create_guest_memory(128).unwrap();

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
            allow_mmds_requests: true,
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
            let block_configs = vec![CustomBlockConfig::new(drive_id.clone(), true, None, true)];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline.as_str().contains("root=/dev/vda ro"));
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
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline.as_str().contains("root=PARTUUID=0eaa91a0-01 rw"));
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
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(!cmdline.as_str().contains("root=PARTUUID="));
            assert!(!cmdline.as_str().contains("root=/dev/vda"));
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
                ),
                CustomBlockConfig::new(String::from("secondary"), false, None, true),
                CustomBlockConfig::new(String::from("third"), false, None, false),
            ];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);

            assert!(cmdline.as_str().contains("root=PARTUUID=0eaa91a0-01 rw"));
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
            assert!(cmdline
                .as_str()
                .contains("virtio_mmio.device=4K@0xd0000000:5 virtio_mmio.device=4K@0xd0001000:6 virtio_mmio.device=4K@0xd0002000:7"));
        }

        // Use case 5: root block device is rw.
        {
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(drive_id.clone(), true, None, false)];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline.as_str().contains("root=/dev/vda rw"));
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
            )];
            let mut vmm = default_vmm();
            let mut cmdline = default_kernel_cmdline();
            insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);
            assert!(cmdline.as_str().contains("root=PARTUUID=0eaa91a0-01 ro"));
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
            amount_mb: 0,
            must_tell_host: false,
            deflate_on_oom: false,
            stats_polling_interval_s: 0,
        };

        let mut cmdline = default_kernel_cmdline();
        insert_balloon_device(&mut vmm, &mut cmdline, &mut event_manager, balloon_config);
        // Check if the vsock device is described in kernel_cmdline.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        assert!(cmdline
            .as_str()
            .contains("virtio_mmio.device=4K@0xd0000000:5"));
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
        assert!(cmdline
            .as_str()
            .contains("virtio_mmio.device=4K@0xd0000000:5"));
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

        let err = KernelLoader(kernel::loader::Error::InvalidElfMagicNumber);
        let _ = format!("{}{:?}", err, err);

        let err = LoadCommandline(kernel::cmdline::Error::TooLarge);
        let _ = format!("{}{:?}", err, err);

        let err = MissingKernelConfig;
        let _ = format!("{}{:?}", err, err);

        let err = MissingMemSizeConfig;
        let _ = format!("{}{:?}", err, err);

        let err = NetDeviceNotConfigured;
        let _ = format!("{}{:?}", err, err);

        let err = OpenBlockDevice(io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);

        let err = RegisterEvent(EventManagerError::EpollCreate(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{}{:?}", err, err);
    }

    #[test]
    fn test_kernel_cmdline_err_to_startuvm_err() {
        let err = StartMicrovmError::from(kernel::cmdline::Error::HasSpace);
        let _ = format!("{}{:?}", err, err);
    }
}
