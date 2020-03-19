// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enables pre-boot setup, instantiation and booting of a Firecracker VMM.

use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};

use super::{Error, Vmm};

use arch::InitrdConfig;
#[cfg(target_arch = "x86_64")]
use device_manager::legacy::PortIODeviceManager;
use device_manager::mmio::MMIODeviceManager;
use devices::legacy::Serial;
use devices::virtio::MmioTransport;
use polly::event_manager::{Error as EventManagerError, EventManager};
use seccomp::BpfProgramRef;
use utils::eventfd::EventFd;
use utils::terminal::Terminal;
use utils::time::TimestampUs;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vmm_config;
use vmm_config::boot_source::BootConfig;
use vmm_config::drive::BlockDeviceConfigs;
use vmm_config::net::NetworkInterfaceConfigs;
use vmm_config::vsock::VsockDeviceConfig;
use vstate::{KvmContext, Vcpu, VcpuConfig, Vm};
use {device_manager, VmmEventsObserver};

/// Errors associated with starting the instance.
#[derive(Debug)]
pub enum StartMicrovmError {
    /// Unable to seek the block device backing file due to invalid permissions or
    /// the file was deleted/corrupted.
    CreateBlockDevice(io::Error),
    /// Internal errors are due to resource exhaustion.
    CreateNetDevice(devices::virtio::net::Error),
    /// Failed to create a `RateLimiter` object.
    CreateRateLimiter(io::Error),
    /// Failed to create the backend for the vsock device.
    CreateVsockBackend(devices::virtio::vsock::VsockUnixBackendError),
    /// Failed to create the vsock device.
    CreateVsockDevice(devices::virtio::vsock::VsockError),
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
    /// The start command was issued more than once.
    MicroVMAlreadyRunning,
    /// Cannot start the VM because the kernel was not configured.
    MissingKernelConfig,
    /// Cannot start the VM because the size of the guest memory  was not specified.
    MissingMemSizeConfig,
    /// The net device configuration is missing the tap device.
    NetDeviceNotConfigured,
    /// Cannot open the block device backing file.
    OpenBlockDevice(io::Error),
    /// Cannot initialize a MMIO Block Device or add a device to the MMIO Bus.
    RegisterBlockDevice(device_manager::mmio::Error),
    /// Cannot register an EventHandler.
    RegisterEvent(EventManagerError),
    /// Cannot initialize a MMIO Network Device or add a device to the MMIO Bus.
    RegisterNetDevice(device_manager::mmio::Error),
    /// Cannot initialize a MMIO Vsock Device or add a device to the MMIO Bus.
    RegisterVsockDevice(device_manager::mmio::Error),
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
        match *self {
            CreateBlockDevice(ref err) => write!(
                f,
                "Unable to seek the block device backing file due to invalid permissions or \
                 the file was deleted/corrupted. Error number: {}",
                err
            ),
            CreateRateLimiter(ref err) => write!(f, "Cannot create RateLimiter: {}", err),
            CreateVsockBackend(ref err) => {
                write!(f, "Cannot create backend for vsock device: {:?}", err)
            }
            CreateVsockDevice(ref err) => write!(f, "Cannot create vsock device: {:?}", err),
            CreateNetDevice(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Cannot create network device. {}", err_msg)
            }
            GuestMemoryMmap(ref err) => {
                // Remove imbricated quotes from error message.
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");
                write!(f, "Invalid Memory Configuration: {}", err_msg)
            }
            InitrdLoad => write!(
                f,
                "Cannot load initrd due to an invalid memory configuration."
            ),
            InitrdRead(ref err) => write!(f, "Cannot load initrd due to an invalid image: {}", err),
            Internal(ref err) => write!(f, "Internal error while starting microVM: {:?}", err),
            KernelCmdline(ref err) => write!(f, "Invalid kernel command line: {}", err),
            KernelLoader(ref err) => {
                let mut err_msg = format!("{}", err);
                err_msg = err_msg.replace("\"", "");
                write!(
                    f,
                    "Cannot load kernel due to invalid memory configuration or invalid kernel \
                     image. {}",
                    err_msg
                )
            }
            LoadCommandline(ref err) => {
                let mut err_msg = format!("{}", err);
                err_msg = err_msg.replace("\"", "");
                write!(f, "Cannot load command line string. {}", err_msg)
            }
            MicroVMAlreadyRunning => write!(f, "Microvm already running."),
            MissingKernelConfig => write!(f, "Cannot start microvm without kernel configuration."),
            MissingMemSizeConfig => {
                write!(f, "Cannot start microvm without guest mem_size config.")
            }
            NetDeviceNotConfigured => {
                write!(f, "The net device configuration is missing the tap device.")
            }
            OpenBlockDevice(ref err) => {
                let mut err_msg = format!("{:?}", err);
                err_msg = err_msg.replace("\"", "");

                write!(f, "Cannot open the block device backing file. {}", err_msg)
            }
            RegisterBlockDevice(ref err) => {
                let mut err_msg = format!("{}", err);
                err_msg = err_msg.replace("\"", "");
                write!(
                    f,
                    "Cannot initialize a MMIO Block Device or add a device to the MMIO Bus. {}",
                    err_msg
                )
            }
            RegisterEvent(ref err) => write!(f, "Cannot register EventHandler. {:?}", err),
            RegisterNetDevice(ref err) => {
                let mut err_msg = format!("{}", err);
                err_msg = err_msg.replace("\"", "");

                write!(
                    f,
                    "Cannot initialize a MMIO Network Device or add a device to the MMIO Bus. {}",
                    err_msg
                )
            }
            RegisterVsockDevice(ref err) => {
                let mut err_msg = format!("{}", err);
                err_msg = err_msg.replace("\"", "");

                write!(
                    f,
                    "Cannot initialize a MMIO Vsock Device or add a device to the MMIO Bus. {}",
                    err_msg
                )
            }
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
        })
    }
    fn on_vmm_stop(&mut self) -> std::result::Result<(), utils::errno::Error> {
        self.0.lock().set_canon_mode().map_err(|e| {
            warn!("Cannot set canonical mode for the terminal. {:?}", e);
            e
        })
    }
}

/// Builds and starts a microVM based on the current Firecracker VmResources configuration.
///
/// This is the default build recipe, one could build other microVM flavors by using the
/// independent functions in this module instead of calling this recipe.
///
/// An `Arc` reference of the built `Vmm` is also plugged in the `EventManager`, while another
/// is returned.
pub fn build_microvm(
    vm_resources: &super::resources::VmResources,
    event_manager: &mut EventManager,
    seccomp_filter: BpfProgramRef,
) -> std::result::Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
    let boot_config = vm_resources
        .boot_source()
        .ok_or(StartMicrovmError::MissingKernelConfig)?;

    // Timestamp for measuring microVM boot duration.
    let request_ts = TimestampUs::default();

    let guest_memory = create_guest_memory(
        vm_resources
            .vm_config()
            .mem_size_mib
            .ok_or(StartMicrovmError::MissingMemSizeConfig)?,
    )?;
    let vcpu_config = vm_resources.vcpu_config();
    let entry_addr = load_kernel(boot_config, &guest_memory)?;
    let initrd = load_initrd_from_config(boot_config, &guest_memory)?;
    // Clone the command-line so that a failed boot doesn't pollute the original.
    #[allow(unused_mut)]
    let mut kernel_cmdline = boot_config.cmdline.clone();
    let mut vm = setup_kvm_vm(&guest_memory)?;

    // On x86_64 always create a serial device,
    // while on aarch64 only create it if 'console=' is specified in the boot args.
    let serial_device = if cfg!(target_arch = "x86_64")
        || (cfg!(target_arch = "aarch64") && kernel_cmdline.as_str().contains("console="))
    {
        Some(setup_serial_device(
            event_manager,
            Box::new(SerialStdin::get()),
            Box::new(io::stdout()),
        )?)
    } else {
        None
    };

    let exit_evt = EventFd::new(libc::EFD_NONBLOCK)
        .map_err(Error::EventFd)
        .map_err(StartMicrovmError::Internal)?;

    #[cfg(target_arch = "x86_64")]
    // Safe to unwrap 'serial_device' as it's always 'Some' on x86_64.
    // x86_64 uses the i8042 reset event as the Vmm exit event.
    let mut pio_device_manager = PortIODeviceManager::new(
        serial_device.unwrap(),
        exit_evt
            .try_clone()
            .map_err(Error::EventFd)
            .map_err(StartMicrovmError::Internal)?,
    )
    .map_err(Error::CreateLegacyDevice)
    .map_err(StartMicrovmError::Internal)?;

    // Instantiate the MMIO device manager.
    // 'mmio_base' address has to be an address which is protected by the kernel
    // and is architectural specific.
    #[allow(unused_mut)]
    let mut mmio_device_manager = MMIODeviceManager::new(
        &mut (arch::MMIO_MEM_START as u64),
        (arch::IRQ_BASE, arch::IRQ_MAX),
    );

    let vcpus;
    // For x86_64 we need to create the interrupt controller before calling `KVM_CREATE_VCPUS`
    // while on aarch64 we need to do it the other way around.
    #[cfg(target_arch = "x86_64")]
    {
        setup_interrupt_controller(&mut vm)?;
        attach_legacy_devices(&vm, &mut pio_device_manager)?;

        vcpus = create_vcpus_x86_64(
            &vm,
            &vcpu_config,
            &guest_memory,
            entry_addr,
            request_ts,
            &pio_device_manager.io_bus,
            &exit_evt,
        )
        .map_err(StartMicrovmError::Internal)?;
    }

    // On aarch64, the vCPUs need to be created (i.e call KVM_CREATE_VCPU) and configured before
    // setting up the IRQ chip because the `KVM_CREATE_VCPU` ioctl will return error if the IRQCHIP
    // was already initialized.
    // Search for `kvm_arch_vcpu_create` in arch/arm/kvm/arm.c.
    #[cfg(target_arch = "aarch64")]
    {
        vcpus = create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &guest_memory,
            entry_addr,
            request_ts,
            &exit_evt,
        )
        .map_err(StartMicrovmError::Internal)?;

        setup_interrupt_controller(&mut vm, vcpu_config.vcpu_count)?;
        attach_legacy_devices(
            &vm,
            &mut mmio_device_manager,
            &mut kernel_cmdline,
            serial_device,
        )?;
    }

    let mut vmm = Vmm {
        events_observer: Some(Box::new(SerialStdin::get())),
        guest_memory,
        kernel_cmdline,
        vcpus_handles: Vec::new(),
        exit_evt,
        vm,
        mmio_device_manager,
        #[cfg(target_arch = "x86_64")]
        pio_device_manager,
    };

    attach_block_devices(&mut vmm, &vm_resources.block, event_manager)?;
    attach_net_devices(&mut vmm, &vm_resources.network_interface, event_manager)?;
    if let Some(vsock) = vm_resources.vsock.as_ref() {
        attach_vsock_device(&mut vmm, vsock, event_manager)?;
    }

    // Write the kernel command line to guest memory. This is x86_64 specific, since on
    // aarch64 the command line will be specified through the FDT.
    #[cfg(target_arch = "x86_64")]
    load_cmdline(&vmm)?;

    vmm.configure_system(vcpus.as_slice(), &initrd)
        .map_err(StartMicrovmError::Internal)?;
    // Firecracker uses the same seccomp filter for all threads.
    vmm.start_vcpus(vcpus, seccomp_filter.to_vec(), seccomp_filter)
        .map_err(StartMicrovmError::Internal)?;

    let vmm = Arc::new(Mutex::new(vmm));
    event_manager
        .add_subscriber(vmm.clone())
        .map_err(StartMicrovmError::RegisterEvent)?;

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

#[cfg(target_arch = "x86_64")]
fn load_cmdline(vmm: &Vmm) -> std::result::Result<(), StartMicrovmError> {
    kernel::loader::load_cmdline(
        vmm.guest_memory(),
        GuestAddress(arch::x86_64::layout::CMDLINE_START),
        &vmm.kernel_cmdline
            .as_cstring()
            .map_err(StartMicrovmError::LoadCommandline)?,
    )
    .map_err(StartMicrovmError::LoadCommandline)
}

pub(crate) fn setup_kvm_vm(
    guest_memory: &GuestMemoryMmap,
) -> std::result::Result<Vm, StartMicrovmError> {
    let kvm = KvmContext::new()
        .map_err(Error::KvmContext)
        .map_err(StartMicrovmError::Internal)?;
    let mut vm = Vm::new(kvm.fd())
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
    vm.memory_init(&guest_memory, kvm.max_memslots())
        .map_err(Error::Vm)
        .map_err(StartMicrovmError::Internal)?;
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
) -> std::result::Result<Arc<Mutex<Serial>>, StartMicrovmError> {
    let interrupt_evt = EventFd::new(libc::EFD_NONBLOCK)
        .map_err(Error::EventFd)
        .map_err(StartMicrovmError::Internal)?;
    let serial = Arc::new(Mutex::new(Serial::new_in_out(interrupt_evt, input, out)));
    if let Err(e) = event_manager.add_subscriber(serial.clone()) {
        // TODO: We just log this message, and immediately return Ok, instead of returning the
        // actual error because this operation always fails with EPERM when adding a fd which
        // has been redirected to /dev/null via dup2 (this may happen inside the jailer).
        // Find a better solution to this (and think about the state of the serial device
        // while we're at it). This also led to commenting out parts of the
        // enable_disable_stdin_test() unit test function.
        warn!("Could not add serial input event to epoll: {:?}", e);
    }
    Ok(serial)
}

#[cfg(target_arch = "x86_64")]
fn attach_legacy_devices(
    vm: &Vm,
    pio_device_manager: &mut PortIODeviceManager,
) -> std::result::Result<(), StartMicrovmError> {
    pio_device_manager
        .register_devices()
        .map_err(Error::LegacyIOBus)
        .map_err(StartMicrovmError::Internal)?;

    macro_rules! register_irqfd_evt {
        ($evt: ident, $index: expr) => {{
            vm.fd()
                .register_irqfd(&pio_device_manager.$evt, $index)
                .map_err(|e| {
                    Error::LegacyIOBus(device_manager::legacy::Error::EventFd(
                        io::Error::from_raw_os_error(e.errno()),
                    ))
                })
                .map_err(StartMicrovmError::Internal)?;
        }};
    }

    register_irqfd_evt!(com_evt_1_3, 4);
    register_irqfd_evt!(com_evt_2_4, 3);
    register_irqfd_evt!(kbd_evt, 1);
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn attach_legacy_devices(
    vm: &Vm,
    mmio_device_manager: &mut MMIODeviceManager,
    kernel_cmdline: &mut kernel::cmdline::Cmdline,
    serial: Option<Arc<Mutex<Serial>>>,
) -> std::result::Result<(), StartMicrovmError> {
    if let Some(serial) = serial {
        mmio_device_manager
            .register_mmio_serial(vm.fd(), kernel_cmdline, serial)
            .map_err(Error::RegisterMMIODevice)
            .map_err(StartMicrovmError::Internal)?;
    }

    mmio_device_manager
        .register_mmio_rtc(vm.fd())
        .map_err(Error::RegisterMMIODevice)
        .map_err(StartMicrovmError::Internal)?;

    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn create_vcpus_x86_64(
    vm: &Vm,
    vcpu_config: &VcpuConfig,
    guest_mem: &GuestMemoryMmap,
    entry_addr: GuestAddress,
    request_ts: TimestampUs,
    io_bus: &devices::Bus,
    exit_evt: &EventFd,
) -> super::Result<Vec<Vcpu>> {
    let mut vcpus = Vec::with_capacity(vcpu_config.vcpu_count as usize);
    for cpu_index in 0..vcpu_config.vcpu_count {
        let mut vcpu = Vcpu::new_x86_64(
            cpu_index,
            vm.fd(),
            vm.supported_cpuid().clone(),
            vm.supported_msrs().clone(),
            io_bus.clone(),
            exit_evt.try_clone().map_err(Error::EventFd)?,
            request_ts.clone(),
        )
        .map_err(Error::Vcpu)?;

        vcpu.configure_x86_64(guest_mem, entry_addr, vcpu_config)
            .map_err(Error::Vcpu)?;

        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

#[cfg(target_arch = "aarch64")]
fn create_vcpus_aarch64(
    vm: &Vm,
    vcpu_config: &VcpuConfig,
    guest_mem: &GuestMemoryMmap,
    entry_addr: GuestAddress,
    request_ts: TimestampUs,
    exit_evt: &EventFd,
) -> super::Result<Vec<Vcpu>> {
    let mut vcpus = Vec::with_capacity(vcpu_config.vcpu_count as usize);
    for cpu_index in 0..vcpu_config.vcpu_count {
        let mut vcpu = Vcpu::new_aarch64(
            cpu_index,
            vm.fd(),
            exit_evt.try_clone().map_err(Error::EventFd)?,
            request_ts.clone(),
        )
        .map_err(Error::Vcpu)?;

        vcpu.configure_aarch64(vm.fd(), guest_mem, entry_addr)
            .map_err(Error::Vcpu)?;

        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

/// Attaches an MmioTransport device to the device manager.
fn attach_mmio_device(
    vmm: &mut Vmm,
    id: String,
    device: MmioTransport,
) -> std::result::Result<(), device_manager::mmio::Error> {
    let type_id = device
        .device()
        .lock()
        .expect("Poisoned device lock")
        .device_type();
    let cmdline = &mut vmm.kernel_cmdline;

    vmm.mmio_device_manager.register_mmio_device(
        vmm.vm.fd(),
        device,
        cmdline,
        type_id,
        id.as_str(),
    )?;

    Ok(())
}

fn attach_block_devices(
    vmm: &mut Vmm,
    blocks: &BlockDeviceConfigs,
    event_manager: &mut EventManager,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    for drive_config in blocks.config_list.iter() {
        // Add the block device from file.
        let block_file = OpenOptions::new()
            .read(true)
            .write(!drive_config.is_read_only)
            .open(&drive_config.path_on_host)
            .map_err(OpenBlockDevice)?;

        if drive_config.is_root_device {
            let kernel_cmdline = &mut vmm.kernel_cmdline;

            kernel_cmdline.insert_str(if let Some(partuuid) = &drive_config.partuuid {
                format!("root=PARTUUID={}", partuuid)
            } else {
                // If no PARTUUID was specified for the root device, try with the /dev/vda.
                "root=/dev/vda".to_string()
            })?;

            let flags = if drive_config.is_read_only {
                "ro"
            } else {
                "rw"
            };

            kernel_cmdline.insert_str(flags)?;
        }

        let rate_limiter = drive_config
            .rate_limiter
            .map(vmm_config::RateLimiterConfig::try_into)
            .transpose()
            .map_err(CreateRateLimiter)?;

        let block_device = Arc::new(Mutex::new(
            devices::virtio::Block::new(
                vmm.guest_memory.clone(),
                block_file,
                drive_config.is_read_only,
                rate_limiter.unwrap_or_default(),
            )
            .map_err(CreateBlockDevice)?,
        ));

        event_manager
            .add_subscriber(block_device.clone())
            .map_err(StartMicrovmError::RegisterEvent)?;

        attach_mmio_device(
            vmm,
            drive_config.drive_id.clone(),
            MmioTransport::new(vmm.guest_memory().clone(), block_device.clone())
                .map_err(CreateBlockDevice)?,
        )
        .map_err(RegisterBlockDevice)?;
    }

    Ok(())
}

fn attach_net_devices(
    vmm: &mut Vmm,
    network_ifaces: &NetworkInterfaceConfigs,
    event_manager: &mut EventManager,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;

    for cfg in network_ifaces.iter() {
        let allow_mmds_requests = cfg.allow_mmds_requests();

        let rx_rate_limiter = cfg
            .rx_rate_limiter
            .map(vmm_config::RateLimiterConfig::try_into)
            .transpose()
            .map_err(CreateRateLimiter)?;

        let tx_rate_limiter = cfg
            .tx_rate_limiter
            .map(vmm_config::RateLimiterConfig::try_into)
            .transpose()
            .map_err(CreateRateLimiter)?;

        let tap = cfg.open_tap().map_err(|_| NetDeviceNotConfigured)?;
        let net_device = Arc::new(Mutex::new(
            devices::virtio::net::Net::new_with_tap(
                tap,
                cfg.guest_mac(),
                vmm.guest_memory().clone(),
                rx_rate_limiter.unwrap_or_default(),
                tx_rate_limiter.unwrap_or_default(),
                allow_mmds_requests,
            )
            .map_err(CreateNetDevice)?,
        ));
        event_manager
            .add_subscriber(net_device.clone())
            .map_err(StartMicrovmError::RegisterEvent)?;

        attach_mmio_device(
            vmm,
            cfg.iface_id.clone(),
            MmioTransport::new(vmm.guest_memory().clone(), net_device).map_err(|e| {
                RegisterNetDevice(super::device_manager::mmio::Error::CreateMmioDevice(e))
            })?,
        )
        .map_err(RegisterNetDevice)?;
    }

    Ok(())
}

fn attach_vsock_device(
    vmm: &mut Vmm,
    vsock: &VsockDeviceConfig,
    event_manager: &mut EventManager,
) -> std::result::Result<(), StartMicrovmError> {
    use self::StartMicrovmError::*;
    let backend = devices::virtio::vsock::VsockUnixBackend::new(
        u64::from(vsock.guest_cid),
        vsock.uds_path.clone(),
    )
    .map_err(CreateVsockBackend)?;

    let vsock_device = Arc::new(Mutex::new(
        devices::virtio::Vsock::new(
            u64::from(vsock.guest_cid),
            vmm.guest_memory().clone(),
            backend,
        )
        .map_err(CreateVsockDevice)?,
    ));

    event_manager
        .add_subscriber(vsock_device.clone())
        .map_err(StartMicrovmError::RegisterEvent)?;

    attach_mmio_device(
        vmm,
        vsock.vsock_id.clone(),
        MmioTransport::new(vmm.guest_memory().clone(), vsock_device)
            .map_err(device_manager::mmio::Error::CreateMmioDevice)
            .map_err(RegisterVsockDevice)?,
    )
    .map_err(RegisterVsockDevice)?;

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use std::fs::{remove_file, File};
    use std::io::Cursor;

    use super::*;
    use arch::DeviceType;
    use devices::virtio::{TYPE_BLOCK, TYPE_VSOCK};
    use kernel::cmdline::Cmdline;
    use polly::event_manager::EventManager;
    use utils::tempfile::TempFile;
    use vmm_config::boot_source::DEFAULT_KERNEL_CMDLINE;
    use vmm_config::drive::BlockDeviceConfig;
    use vmm_config::net::NetworkInterfaceConfig;

    struct SerialInput(File);
    impl io::Read for SerialInput {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl AsRawFd for SerialInput {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
    }
    impl devices::legacy::ReadableFd for SerialInput {}

    struct CustomBlockConfig {
        drive_id: String,
        is_root_device: bool,
        partuuid: Option<String>,
        is_read_only: bool,
    }

    impl CustomBlockConfig {
        fn new(
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
        MMIODeviceManager::new(
            &mut (arch::MMIO_MEM_START as u64),
            (arch::IRQ_BASE, arch::IRQ_MAX),
        )
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

    fn default_kernel_cmdline() -> Cmdline {
        let mut kernel_cmdline = kernel::cmdline::Cmdline::new(4096);
        kernel_cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).unwrap();
        kernel_cmdline
    }

    fn default_vmm() -> Vmm {
        let guest_memory = create_guest_memory(128).unwrap();
        let kernel_cmdline = default_kernel_cmdline();

        let exit_evt = EventFd::new(libc::EFD_NONBLOCK)
            .map_err(Error::EventFd)
            .map_err(StartMicrovmError::Internal)
            .unwrap();

        let vm = setup_kvm_vm(&guest_memory).unwrap();
        let mmio_device_manager = default_mmio_device_manager();
        #[cfg(target_arch = "x86_64")]
        let pio_device_manager = default_portio_device_manager();

        Vmm {
            events_observer: Some(Box::new(SerialStdin::get())),
            guest_memory,
            kernel_cmdline,
            vcpus_handles: Vec::new(),
            exit_evt,
            vm,
            mmio_device_manager,
            #[cfg(target_arch = "x86_64")]
            pio_device_manager,
        }
    }

    fn vmm_with_block_devices(
        event_manager: &mut EventManager,
        custom_block_cfgs: Vec<CustomBlockConfig>,
    ) -> Vmm {
        let mut vmm = default_vmm();

        #[cfg(target_arch = "x86_64")]
        setup_interrupt_controller(&mut vmm.vm).unwrap();

        #[cfg(target_arch = "aarch64")]
        setup_interrupt_controller(&mut vmm.vm, 1).unwrap();

        let mut block_dev_configs = BlockDeviceConfigs::new();
        let mut block_files = Vec::new();
        for custom_block_cfg in &custom_block_cfgs {
            block_files.push(TempFile::new().unwrap());
            let block_device_config = BlockDeviceConfig {
                drive_id: String::from(&custom_block_cfg.drive_id),
                path_on_host: block_files.last().unwrap().as_path().to_path_buf(),
                is_root_device: custom_block_cfg.is_root_device,
                partuuid: custom_block_cfg.partuuid.clone(),
                is_read_only: custom_block_cfg.is_read_only,
                rate_limiter: None,
            };
            block_dev_configs.insert(block_device_config).unwrap();
        }

        let res = attach_block_devices(&mut vmm, &block_dev_configs, event_manager);
        assert!(res.is_ok());
        vmm
    }

    fn make_test_bin() -> Vec<u8> {
        let mut fake_bin = Vec::new();
        fake_bin.resize(1_000_000, 0xAA);
        fake_bin
    }

    fn create_guest_mem_at(at: GuestAddress, size: usize) -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(at, size)]).unwrap()
    }

    fn create_guest_mem_with_size(size: usize) -> GuestMemoryMmap {
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
    fn test_setup_serial_device() {
        let read_tempfile = TempFile::new().unwrap();
        let read_handle = SerialInput(read_tempfile.into_file());
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");

        assert!(setup_serial_device(
            &mut event_manager,
            Box::new(read_handle),
            Box::new(io::stdout()),
        )
        .is_ok());
    }

    #[test]
    fn test_stdin_wrapper() {
        let wrapper = SerialStdin::get();
        assert_eq!(wrapper.as_raw_fd(), io::stdin().as_raw_fd())
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_create_vcpus_x86_64() {
        let vcpu_count = 2;

        let guest_memory = create_guest_memory(128).unwrap();
        let mut vm = setup_kvm_vm(&guest_memory).unwrap();
        setup_interrupt_controller(&mut vm).unwrap();
        let vcpu_config = VcpuConfig {
            vcpu_count,
            ht_enabled: false,
            cpu_template: None,
        };

        // Dummy entry_addr, vcpus will not boot.
        let entry_addr = GuestAddress(0);
        let bus = devices::Bus::new();
        let vcpu_vec = create_vcpus_x86_64(
            &vm,
            &vcpu_config,
            &guest_memory,
            entry_addr,
            TimestampUs::default(),
            &bus,
            &EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();
        assert_eq!(vcpu_vec.len(), vcpu_count as usize);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_create_vcpus_aarch64() {
        let guest_memory = create_guest_memory(128).unwrap();
        let vm = setup_kvm_vm(&guest_memory).unwrap();
        let vcpu_count = 2;

        let vcpu_config = VcpuConfig {
            vcpu_count,
            ht_enabled: false,
            cpu_template: None,
        };

        // Dummy entry_addr, vcpus will not boot.
        let entry_addr = GuestAddress(0);
        let vcpu_vec = create_vcpus_aarch64(
            &vm,
            &vcpu_config,
            &guest_memory,
            entry_addr,
            TimestampUs::default(),
            &EventFd::new(libc::EFD_NONBLOCK).unwrap(),
        )
        .unwrap();
        assert_eq!(vcpu_vec.len(), vcpu_count as usize);
    }

    #[test]
    fn test_attach_net_devices() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let mut vmm = default_vmm();

        #[cfg(target_arch = "x86_64")]
        setup_interrupt_controller(&mut vmm.vm).unwrap();

        #[cfg(target_arch = "aarch64")]
        setup_interrupt_controller(&mut vmm.vm, 1).unwrap();

        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
        };

        let mut network_interface_configs = NetworkInterfaceConfigs::new();
        network_interface_configs.insert(network_interface).unwrap();

        assert!(
            attach_net_devices(&mut vmm, &network_interface_configs, &mut event_manager).is_ok()
        );

        // We can not attach it once more.
        assert!(
            attach_net_devices(&mut vmm, &network_interface_configs, &mut event_manager).is_err()
        );
    }

    #[test]
    fn test_attach_block_devices() {
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");

        // Use case 1: root block device is not specified through PARTUUID.
        {
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(drive_id.clone(), true, None, true)];
            let vmm = vmm_with_block_devices(&mut event_manager, block_configs);
            assert!(vmm.kernel_cmdline.as_str().contains("root=/dev/vda ro"));
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
            let vmm = vmm_with_block_devices(&mut event_manager, block_configs);
            assert!(vmm
                .kernel_cmdline
                .as_str()
                .contains("root=PARTUUID=0eaa91a0-01 rw"));
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
            let vmm = vmm_with_block_devices(&mut event_manager, block_configs);
            assert!(!vmm.kernel_cmdline.as_str().contains("root=PARTUUID="));
            assert!(!vmm.kernel_cmdline.as_str().contains("root=/dev/vda"));
            assert!(vmm
                .mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                .is_some());
        }

        // Use case 4: rw root block device and other rw and ro drives.
        {
            let drive_configs = vec![
                CustomBlockConfig::new(
                    String::from("root"),
                    true,
                    Some("0eaa91a0-01".to_string()),
                    false,
                ),
                CustomBlockConfig::new(String::from("secondary"), false, None, true),
                CustomBlockConfig::new(String::from("third"), false, None, false),
            ];
            let vmm = vmm_with_block_devices(&mut event_manager, drive_configs);

            assert!(vmm
                .kernel_cmdline
                .as_str()
                .contains("root=PARTUUID=0eaa91a0-01 rw"));
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
            assert!(vmm
                .kernel_cmdline
                .as_str()
                .contains("virtio_mmio.device=4K@0xd0000000:5 virtio_mmio.device=4K@0xd0001000:6 virtio_mmio.device=4K@0xd0002000:7"));
        }

        // Use case 5: root block device is rw.
        {
            let drive_id = String::from("root");
            let block_configs = vec![CustomBlockConfig::new(drive_id.clone(), true, None, false)];
            let vmm = vmm_with_block_devices(&mut event_manager, block_configs);
            assert!(vmm.kernel_cmdline.as_str().contains("root=/dev/vda rw"));
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
            let vmm = vmm_with_block_devices(&mut event_manager, block_configs);
            assert!(vmm
                .kernel_cmdline
                .as_str()
                .contains("root=PARTUUID=0eaa91a0-01 ro"));
            assert!(vmm
                .mmio_device_manager
                .get_device(DeviceType::Virtio(TYPE_BLOCK), drive_id.as_str())
                .is_some());
        }
    }

    #[test]
    fn test_attach_vsock_device() {
        // Placeholder for the path where a socket file will be created.
        // The socket file will be removed when the scope ends.
        struct TempSockFile {
            path: String,
        }

        impl TempSockFile {
            fn new(tmp_file: TempFile) -> Self {
                TempSockFile {
                    path: String::from(tmp_file.as_path().to_str().unwrap()),
                }
            }
        }

        impl Drop for TempSockFile {
            fn drop(&mut self) {
                let _ = remove_file(&self.path);
            }
        }

        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        let mut vmm = default_vmm();

        #[cfg(target_arch = "x86_64")]
        setup_interrupt_controller(&mut vmm.vm).unwrap();

        #[cfg(target_arch = "aarch64")]
        setup_interrupt_controller(&mut vmm.vm, 1).unwrap();

        let tmp_sock_file = TempSockFile::new(TempFile::new().unwrap());
        let vsock_dev_id = "vsock_1";
        let vsock_config = VsockDeviceConfig {
            vsock_id: vsock_dev_id.to_string(),
            guest_cid: 3,
            uds_path: tmp_sock_file.path.clone(),
        };

        assert!(attach_vsock_device(&mut vmm, &vsock_config, &mut event_manager).is_ok());

        assert!(vmm
            .mmio_device_manager
            .get_device(DeviceType::Virtio(TYPE_VSOCK), vsock_dev_id)
            .is_some());
    }

    #[test]
    fn test_error_messages() {
        use builder::StartMicrovmError::*;
        let err = CreateBlockDevice(io::Error::from_raw_os_error(0));
        assert_eq!(
            format!("{}", err),
            format!(
                "Unable to seek the block device backing file due to invalid permissions or \
                 the file was deleted/corrupted. Error number: {}",
                io::Error::from_raw_os_error(0)
            )
        );

        let err = CreateNetDevice(devices::virtio::net::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let mut inner_err_msg = format!(
            "{:?}",
            devices::virtio::net::Error::EventFd(io::Error::from_raw_os_error(0))
        );
        inner_err_msg = inner_err_msg.replace("\"", "");
        assert_eq!(
            format!("{}", err),
            format!("Cannot create network device. {}", inner_err_msg)
        );

        let err = CreateRateLimiter(io::Error::from_raw_os_error(0));
        assert_eq!(
            format!("{}", err),
            format!(
                "Cannot create RateLimiter: {}",
                io::Error::from_raw_os_error(0)
            )
        );

        let err = CreateVsockBackend(devices::virtio::vsock::VsockUnixBackendError::EpollAdd(
            io::Error::from_raw_os_error(0),
        ));
        assert_eq!(
            format!("{}", err),
            format!(
                "Cannot create backend for vsock device: {:?}",
                devices::virtio::vsock::VsockUnixBackendError::EpollAdd(
                    io::Error::from_raw_os_error(0)
                )
            )
        );

        let err = CreateVsockDevice(devices::virtio::vsock::VsockError::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        assert_eq!(
            format!("{}", err),
            format!(
                "Cannot create vsock device: {:?}",
                devices::virtio::vsock::VsockError::EventFd(io::Error::from_raw_os_error(0))
            )
        );

        let err = Internal(Error::Serial(io::Error::from_raw_os_error(0)));
        assert_eq!(
            format!("{}", err),
            format!(
                "Internal error while starting microVM: {:?}",
                Error::Serial(io::Error::from_raw_os_error(0))
            )
        );

        let err = KernelCmdline(String::from("dummy --cmdline"));
        assert_eq!(
            format!("{}", err),
            "Invalid kernel command line: dummy --cmdline"
        );

        let err = KernelLoader(kernel::loader::Error::InvalidElfMagicNumber);
        assert_eq!(
            format!("{}", err),
            format!(
                "Cannot load kernel due to invalid memory configuration or invalid kernel \
                 image. {}",
                kernel::loader::Error::InvalidElfMagicNumber
            )
        );

        let err = LoadCommandline(kernel::cmdline::Error::TooLarge);
        assert_eq!(
            format!("{}", err),
            format!(
                "Cannot load command line string. {}",
                kernel::cmdline::Error::TooLarge
            )
        );

        let err = MicroVMAlreadyRunning;
        assert_eq!(format!("{}", err), "Microvm already running.");

        let err = MissingKernelConfig;
        assert_eq!(
            format!("{}", err),
            "Cannot start microvm without kernel configuration."
        );

        let err = MissingMemSizeConfig;
        assert_eq!(
            format!("{}", err),
            "Cannot start microvm without guest mem_size config."
        );

        let err = NetDeviceNotConfigured;
        assert_eq!(
            format!("{}", err),
            "The net device configuration is missing the tap device."
        );

        let err = OpenBlockDevice(io::Error::from_raw_os_error(0));
        let mut inner_err_msg = format!("{:?}", io::Error::from_raw_os_error(0));
        inner_err_msg = inner_err_msg.replace("\"", "");
        assert_eq!(
            format!("{}", err),
            format!(
                "Cannot open the block device backing file. {}",
                inner_err_msg
            )
        );

        let err = RegisterBlockDevice(device_manager::mmio::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        assert_eq!(
            format!("{}", err),
            format!(
                "Cannot initialize a MMIO Block Device or add a device to the MMIO Bus. {}",
                device_manager::mmio::Error::EventFd(io::Error::from_raw_os_error(0))
            )
        );

        let err = RegisterEvent(EventManagerError::EpollCreate(
            io::Error::from_raw_os_error(0),
        ));
        assert_eq!(
            format!("{}", err),
            format!(
                "Cannot register EventHandler. {:?}",
                EventManagerError::EpollCreate(io::Error::from_raw_os_error(0))
            )
        );

        let err = RegisterNetDevice(device_manager::mmio::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        assert_eq!(
            format!("{}", err),
            format!(
                "Cannot initialize a MMIO Network Device or add a device to the MMIO Bus. {}",
                device_manager::mmio::Error::EventFd(io::Error::from_raw_os_error(0))
            )
        );

        let err = RegisterVsockDevice(device_manager::mmio::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        assert_eq!(
            format!("{}", err),
            format!(
                "Cannot initialize a MMIO Vsock Device or add a device to the MMIO Bus. {}",
                device_manager::mmio::Error::EventFd(io::Error::from_raw_os_error(0))
            )
        );
    }

    #[test]
    fn test_kernel_cmdline_err_to_startuvm_err() {
        let err = StartMicrovmError::from(kernel::cmdline::Error::HasSpace);
        assert_eq!(
            format!("{}", err),
            format!(
                "Invalid kernel command line: {}",
                kernel::cmdline::Error::HasSpace.to_string()
            )
        );
    }
}
