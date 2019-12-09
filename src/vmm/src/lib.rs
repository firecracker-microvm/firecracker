// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Virtual Machine Monitor that leverages the Linux Kernel-based Virtual Machine (KVM),
//! and other virtualization features to run a single lightweight micro-virtual
//! machine (microVM).
#![deny(missing_docs)]
extern crate epoll;
extern crate kvm_bindings;
extern crate kvm_ioctls;
extern crate libc;
extern crate polly;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate timerfd;

extern crate arch;
#[cfg(target_arch = "x86_64")]
extern crate cpuid;
extern crate devices;
extern crate kernel;
#[macro_use]
extern crate logger;
extern crate dumbo;
extern crate rate_limiter;
extern crate seccomp;
extern crate utils;
extern crate vm_memory;

/// Handles setup, initialization, and runtime configuration of a `Vmm` object.
pub mod controller;
/// Syscalls allowed through the seccomp filter.
pub mod default_syscalls;
pub(crate) mod device_manager;
pub mod error;
/// Signal handling utilities.
pub mod signal_handler;
/// Wrappers over structures used to configure the VMM.
pub mod vmm_config;
mod vstate;

use std::collections::HashMap;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::result;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};

use arch::DeviceType;
use arch::InitrdConfig;
#[cfg(target_arch = "x86_64")]
use device_manager::legacy::PortIODeviceManager;
#[cfg(target_arch = "aarch64")]
use device_manager::mmio::MMIODeviceInfo;
use device_manager::mmio::MMIODeviceManager;
use devices::virtio::EpollConfigConstructor;
use devices::virtio::MmioDevice;
use devices::{BusDevice, DeviceEventT, EpollHandler, RawIOHandler};
use error::{Error, Result, UserResult};
use kernel::cmdline::Cmdline as KernelCmdline;
#[cfg(target_arch = "x86_64")]
use kernel::loader as kernel_loader;
use logger::error::LoggerError;
use logger::{Metric, LOGGER, METRICS};
use polly::event_manager::EventManager;
use seccomp::{BpfProgram, SeccompFilter};
use utils::eventfd::EventFd;
use utils::net::TapError;
use utils::terminal::Terminal;
use utils::time::TimestampUs;
use vm_memory::{GuestAddress, GuestMemoryMmap};
use vmm_config::boot_source::{BootSourceConfig, BootSourceConfigError};
use vmm_config::drive::{BlockDeviceConfig, DriveError};
use vmm_config::logger::{LoggerConfig, LoggerConfigError};
use vmm_config::machine_config::{CpuFeaturesTemplate, VmConfig, VmConfigError};
use vmm_config::net::{NetworkInterfaceConfig, NetworkInterfaceError};
use vmm_config::vsock::VsockDeviceConfig;
use vstate::{KvmContext, Vcpu, VcpuEvent, VcpuHandle, VcpuResponse, Vm};

pub use error::{ErrorKind, LoadInitrdError, StartMicrovmError, VmmActionError};

const WRITE_METRICS_PERIOD_SECONDS: u64 = 60;

/// Success exit code.
pub const FC_EXIT_CODE_OK: u8 = 0;
/// Generic error exit code.
pub const FC_EXIT_CODE_GENERIC_ERROR: u8 = 1;
/// Generic exit code for an error considered not possible to occur if the program logic is sound.
pub const FC_EXIT_CODE_UNEXPECTED_ERROR: u8 = 2;
/// Firecracker was shut down after intercepting a restricted system call.
pub const FC_EXIT_CODE_BAD_SYSCALL: u8 = 148;
/// Firecracker was shut down after intercepting `SIGBUS`.
pub const FC_EXIT_CODE_SIGBUS: u8 = 149;
/// Firecracker was shut down after intercepting `SIGSEGV`.
pub const FC_EXIT_CODE_SIGSEGV: u8 = 150;
/// Invalid json passed to the Firecracker process for configuring microvm.
pub const FC_EXIT_CODE_INVALID_JSON: u8 = 151;
/// Bad configuration for microvm's resources, when using a single json.
pub const FC_EXIT_CODE_BAD_CONFIGURATION: u8 = 152;
/// Command line arguments parsing error.
pub const FC_EXIT_CODE_ARG_PARSING: u8 = 153;

/// Describes all possible reasons which may cause the event loop to return to the caller in
/// the absence of errors.
#[derive(Debug)]
pub enum EventLoopExitReason {
    /// A break statement interrupted the event loop during normal execution. This is the
    /// default exit reason.
    Break,
    /// The control action file descriptor has data available for reading.
    ControlAction,
}

/// Dispatch categories for epoll events.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EpollDispatch {
    /// This dispatch type is now obsolete.
    Exit,
    /// Stdin event.
    Stdin,
    /// Cascaded polly event.
    PollyEvent,
    /// Event has to be dispatch to an EpollHandler.
    DeviceHandler(usize, DeviceEventT),
    /// The event loop has to be temporarily suspended for an external action request.
    VmmActionRequest,
    /// Periodically generated to write Vmm metrics.
    WriteMetrics,
}

struct MaybeHandler {
    handler: Option<Box<dyn EpollHandler>>,
    receiver: Receiver<Box<dyn EpollHandler>>,
}

impl MaybeHandler {
    fn new(receiver: Receiver<Box<dyn EpollHandler>>) -> Self {
        MaybeHandler {
            handler: None,
            receiver,
        }
    }
}

/// Handles epoll related business.
// A glaring shortcoming of the current design is the liberal passing around of raw_fds,
// and duping of file descriptors. This issue will be solved when we also implement device removal.
pub struct EpollContext {
    epoll_raw_fd: RawFd,
    stdin_index: u64,
    // FIXME: find a different design as this does not scale. This Vec can only grow.
    dispatch_table: Vec<Option<EpollDispatch>>,
    device_handlers: Vec<MaybeHandler>,
    device_id_to_handler_id: HashMap<(u32, String), usize>,

    // This part of the class relates to incoming epoll events. The incoming events are held in
    // `events[event_index..num_events)`, followed by the events not yet read from `epoll_raw_fd`.
    events: Vec<epoll::Event>,
    num_events: usize,
    event_index: usize,
}

impl EpollContext {
    /// Creates a new `EpollContext` object.
    pub fn new() -> Result<Self> {
        const EPOLL_EVENTS_LEN: usize = 100;

        let epoll_raw_fd = epoll::create(true).map_err(Error::EpollFd)?;

        // Initial capacity needs to be large enough to hold:
        // * 1 exit event
        // * 1 stdin event
        // * 2 queue events for virtio block
        // * 4 for virtio net
        // The total is 8 elements; allowing spare capacity to avoid reallocations.
        let mut dispatch_table = Vec::with_capacity(20);
        let stdin_index = dispatch_table.len() as u64;
        dispatch_table.push(None);
        Ok(EpollContext {
            epoll_raw_fd,
            stdin_index,
            dispatch_table,
            device_handlers: Vec::with_capacity(6),
            device_id_to_handler_id: HashMap::new(),
            events: vec![epoll::Event::new(epoll::Events::empty(), 0); EPOLL_EVENTS_LEN],
            num_events: 0,
            event_index: 0,
        })
    }

    /// Registers an EPOLLIN event associated with the stdin file descriptor.
    pub fn enable_stdin_event(&mut self) {
        if let Err(e) = epoll::ctl(
            self.epoll_raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::Events::EPOLLIN, self.stdin_index),
        ) {
            // TODO: We just log this message, and immediately return Ok, instead of returning the
            // actual error because this operation always fails with EPERM when adding a fd which
            // has been redirected to /dev/null via dup2 (this may happen inside the jailer).
            // Find a better solution to this (and think about the state of the serial device
            // while we're at it). This also led to commenting out parts of the
            // enable_disable_stdin_test() unit test function.
            warn!("Could not add stdin event to epoll. {}", e);
        } else {
            self.dispatch_table[self.stdin_index as usize] = Some(EpollDispatch::Stdin);
        }
    }

    /// Removes the stdin event from the event set.
    pub fn disable_stdin_event(&mut self) {
        // Ignore failure to remove from epoll. The only reason for failure is
        // that stdin has closed or changed in which case we won't get
        // any more events on the original event_fd anyway.
        let _ = epoll::ctl(
            self.epoll_raw_fd,
            epoll::ControlOptions::EPOLL_CTL_DEL,
            libc::STDIN_FILENO,
            epoll::Event::new(epoll::Events::EPOLLIN, self.stdin_index),
        );
        self.dispatch_table[self.stdin_index as usize] = None;
    }

    /// Given a file descriptor `fd`, and an EpollDispatch token `token`,
    /// associate `token` with an `EPOLLIN` event for `fd`, through the
    /// `dispatch_table`.
    pub fn add_epollin_event<T: AsRawFd + ?Sized>(
        &mut self,
        fd: &T,
        token: EpollDispatch,
    ) -> Result<()> {
        // The index in the dispatch where the new token will be added.
        let dispatch_index = self.dispatch_table.len() as u64;

        // Add a new epoll event on `fd`, associated with index
        // `dispatch_index`.
        epoll::ctl(
            self.epoll_raw_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            fd.as_raw_fd(),
            epoll::Event::new(epoll::Events::EPOLLIN, dispatch_index),
        )
        .map_err(Error::EpollFd)?;

        // Add the associated token at index `dispatch_index`
        self.dispatch_table.push(Some(token));

        Ok(())
    }

    /// Allocates `count` dispatch tokens, simultaneously registering them in
    /// `dispatch_table`. The tokens will be associated with a device.
    /// This device's handler will be added to the end of `device_handlers`.
    /// This returns the index of the first token, and a channel on which to
    /// send an epoll handler for the relevant device.
    pub fn allocate_tokens_for_device(
        &mut self,
        count: usize,
    ) -> (u64, Sender<Box<dyn EpollHandler>>) {
        let dispatch_base = self.dispatch_table.len() as u64;
        let device_idx = self.device_handlers.len();
        let (sender, receiver) = channel();

        self.dispatch_table.extend((0..count).map(|index| {
            Some(EpollDispatch::DeviceHandler(
                device_idx,
                index as DeviceEventT,
            ))
        }));
        self.device_handlers.push(MaybeHandler::new(receiver));

        (dispatch_base, sender)
    }

    /// Allocate tokens for a virtio device, as with `allocate_tokens_for_device`,
    /// but also call T::new to create a device handler for the device. This handler
    /// will then be associated to a given `device_id` through the `device_id_to_handler_id`
    /// table. Finally, return the handler.
    pub fn allocate_tokens_for_virtio_device<T: EpollConfigConstructor>(
        &mut self,
        type_id: u32,
        device_id: &str,
        count: usize,
    ) -> T {
        let (dispatch_base, sender) = self.allocate_tokens_for_device(count);

        self.device_id_to_handler_id.insert(
            (type_id, device_id.to_string()),
            self.device_handlers.len() - 1,
        );

        T::new(dispatch_base, self.epoll_raw_fd, sender)
    }

    /// Obtains the `EpollHandler` trait object associated with the provided handler id.
    pub fn get_device_handler_by_handler_id(&mut self, id: usize) -> Result<&mut dyn EpollHandler> {
        let maybe = &mut self.device_handlers[id];
        match maybe.handler {
            Some(ref mut v) => Ok(v.as_mut()),
            None => {
                // This should only be called in response to an epoll trigger.
                // Moreover, this branch of the match should only be active on the first call
                // (the first epoll event for this device), therefore the channel is guaranteed
                // to contain a message for the first epoll event since both epoll event
                // registration and channel send() happen in the device activate() function.
                let received = maybe
                    .receiver
                    .try_recv()
                    .map_err(|_| Error::DeviceEventHandlerNotFound)?;
                Ok(maybe.handler.get_or_insert(received).as_mut())
            }
        }
    }

    /// Obtains a mut reference to an object implementing `EpollHandler` for the given device
    /// type and identifier.
    pub fn get_device_handler_by_device_id<T: EpollHandler + 'static>(
        &mut self,
        type_id: u32,
        device_id: &str,
    ) -> Result<&mut T> {
        let handler_id = *self
            .device_id_to_handler_id
            .get(&(type_id, device_id.to_string()))
            .ok_or(Error::DeviceEventHandlerNotFound)?;
        let device_handler = self.get_device_handler_by_handler_id(handler_id)?;
        device_handler
            .as_mut_any()
            .downcast_mut::<T>()
            .ok_or(Error::DeviceEventHandlerInvalidDowncast)
    }

    /// Gets the next event from `epoll_raw_fd`.
    pub fn get_event(&mut self) -> Result<epoll::Event> {
        // Check if no events are left in `events`:
        while self.num_events == self.event_index {
            // If so, get more events.
            // Note that if there is an error, we propagate it.
            self.num_events =
                epoll::wait(self.epoll_raw_fd, -1, &mut self.events[..]).map_err(Error::Poll)?;
            // And reset the event_index.
            self.event_index = 0;
        }

        // Now, move our position in the stream.
        self.event_index += 1;

        // And return the appropriate event.
        Ok(self.events[self.event_index - 1])
    }
}

impl Drop for EpollContext {
    fn drop(&mut self) {
        let rc = unsafe { libc::close(self.epoll_raw_fd) };
        if rc != 0 {
            warn!("Cannot close epoll.");
        }
    }
}

/// Used for configuring a vmm from one single json passed to the Firecracker process.
#[derive(Deserialize)]
pub struct VmmConfig {
    #[serde(rename = "boot-source")]
    boot_source: BootSourceConfig,
    #[serde(rename = "drives")]
    block_devices: Vec<BlockDeviceConfig>,
    #[serde(rename = "network-interfaces", default)]
    net_devices: Vec<NetworkInterfaceConfig>,
    #[serde(rename = "logger")]
    logger: Option<LoggerConfig>,
    #[serde(rename = "machine-config")]
    machine_config: Option<VmConfig>,
    #[serde(rename = "vsock")]
    vsock_device: Option<VsockDeviceConfig>,
}

// /// Contains the state and associated methods required for the Firecracker VMM.
//pub struct Vmm {
//    kvm: KvmContext,
//
//    vm_config: VmConfig,
//    shared_info: Arc<RwLock<InstanceInfo>>,
//
//    stdin_handle: io::Stdin,
//
//    // Guest VM core resources.
//    kernel_config: Option<KernelConfig>,
//    vcpus_handles: Vec<VcpuHandle>,
//    exit_evt: EventFd,
//    vm: Vm,
//
//    // Guest VM devices.
//    mmio_device_manager: Option<MMIODeviceManager>,
//    #[cfg(target_arch = "x86_64")]
//    pio_device_manager: PortIODeviceManager,
//
//    // Device configurations.
//    device_configs: DeviceConfigs,
//
//    epoll_context: EpollContext,
//
//    write_metrics_event_fd: TimerFd,
//}
//
//impl Vmm {
//    /// Creates a new VMM object.
//    pub fn new(shared_info: Arc<RwLock<InstanceInfo>>, control_fd: &dyn AsRawFd) -> Result<Self> {
//        let mut epoll_context = EpollContext::new()?;
//        // If this fails, it's fatal; using expect() to crash.
//        epoll_context
//            .add_epollin_event(control_fd, EpollDispatch::VmmActionRequest)
//            .expect("Cannot add vmm control_fd to epoll.");
//
//        let write_metrics_event_fd =
//            TimerFd::new_custom(ClockId::Monotonic, true, true).map_err(Error::TimerFd)?;

/// Encapsulates configuration parameters for the guest vCPUS.
pub struct VcpuConfig {
    /// Number of guest VCPUs.
    pub vcpu_count: u8,
    /// Enable hyperthreading in the CPUID configuration.
    pub ht_enabled: bool,
    /// CPUID template to use.
    pub cpu_template: Option<CpuFeaturesTemplate>,
}

/// Encapsulates configuration parameters for a `VmmBuilder`.
pub struct VmmBuilderConfig {
    /// The guest memory object for this VM.
    pub guest_memory: GuestMemoryMmap,
    /// The guest physical address of the execution entry point.
    pub entry_addr: GuestAddress,
    /// Base kernel command line contents.
    pub kernel_cmdline: KernelCmdline,
    /// Initrd configuration.
    pub initrd: Option<InitrdConfig>,
    /// vCPU configuration paramters.
    pub vcpu_config: VcpuConfig,
    vmm_seccomp_filter: BpfProgram,
    vcpu_seccomp_filter: BpfProgram,
}

/// Helps build a Vmm.
pub struct VmmBuilder {
    vmm: Vmm,
    vcpus: Vec<Vcpu>,
    initrd: Option<InitrdConfig>,
    vmm_seccomp_filter: BpfProgram,
    vcpu_seccomp_filter: BpfProgram,
}

impl VmmBuilder {
    /// Create a new VmmBuilder.
    pub fn new(
        epoll_context: &mut EpollContext,
        config: VmmBuilderConfig,
    ) -> std::result::Result<Self, VmmActionError> {
        let write_metrics_event_fd = TimerFd::new_custom(ClockId::Monotonic, true, true)
            .map_err(Error::TimerFd)
            .map_err(StartMicrovmError::Internal)?;

        let event_manager = EventManager::new()
            .map_err(Error::EventManager)
            .map_err(StartMicrovmError::Internal)?;

        epoll_context
            .add_epollin_event(&event_manager, EpollDispatch::PollyEvent)
            .expect("Cannot cascade EventManager from epoll_context");

        epoll_context
            .add_epollin_event(
                // non-blocking & close on exec
                &write_metrics_event_fd,
                EpollDispatch::WriteMetrics,
            )
            .expect("Cannot add write metrics TimerFd to epoll.");

        let kvm = KvmContext::new()
            .map_err(Error::KvmContext)
            .map_err(StartMicrovmError::Internal)?;

        let mut vm = Vm::new(kvm.fd())
            .map_err(Error::Vm)
            .map_err(StartMicrovmError::Internal)?;

        vm.memory_init(config.guest_memory.clone(), &kvm)
            .map_err(StartMicrovmError::ConfigureVm)?;

        // Instantiate the MMIO device manager.
        // 'mmio_base' address has to be an address which is protected by the kernel
        // and is architectural specific.
        let mmio_device_manager = MMIODeviceManager::new(
            config.guest_memory.clone(),
            &mut (arch::MMIO_MEM_START as u64),
            (arch::IRQ_BASE, arch::IRQ_MAX),
        );

        #[cfg(target_arch = "x86_64")]
        let pio_device_manager = PortIODeviceManager::new()
            .map_err(Error::CreateLegacyDevice)
            .map_err(StartMicrovmError::Internal)?;
        #[cfg(target_arch = "x86_64")]
        let exit_evt = pio_device_manager
            .i8042
            .lock()
            .expect("Failed to start VCPUs due to poisoned i8042 lock")
            .get_reset_evt_clone()
            .map_err(|_| StartMicrovmError::EventFd)?;
        #[cfg(target_arch = "aarch64")]
        let exit_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?;

        let mut vmm = Vmm {
            stdin_handle: io::stdin(),
            guest_memory: config.guest_memory,
            vcpu_config: config.vcpu_config,
            kernel_cmdline: config.kernel_cmdline,
            vcpus_handles: Vec::new(),
            exit_evt,
            vm,
            mmio_device_manager,
            #[cfg(target_arch = "x86_64")]
            pio_device_manager,
            write_metrics_event_fd,
            event_manager,
        };

        // For x86_64 we need to create the interrupt controller before calling `KVM_CREATE_VCPUS`
        // while on aarch64 we need to do it the other way around.
        #[cfg(target_arch = "x86_64")]
        {
            vmm.setup_interrupt_controller()?;
            // This call has to be here after setting up the irqchip, because
            // we set up some irqfd inside for some reason.
            vmm.attach_legacy_devices()?;
        }

        let initrd = config.initrd.clone();
        let vmm_seccomp_filter = config.vmm_seccomp_filter.clone();
        let vcpu_seccomp_filter = config.vcpu_seccomp_filter.clone();
        // This was supposed to be the timestamp when the start command is recevied. Having this
        // here just to create the vcpu; going forward the req timestamp will prob be somehow
        // decoupled from the creation. At this point it's still fine because we create the
        // builder and run the Vmm when the StartMicrovm request is received by the controller.
        let request_ts = TimestampUs::default();
        let vcpus = vmm.create_vcpus(config.entry_addr, request_ts)?;

        #[cfg(target_arch = "aarch64")]
        {
            vmm.setup_interrupt_controller()?;
            vmm.attach_legacy_devices()?;
        }

        Ok(VmmBuilder {
            vmm,
            vcpus,
            initrd,
            vmm_seccomp_filter,
            vcpu_seccomp_filter,
        })
    }

    /// Return a reference to the guest memory object used by the builder.
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        self.vmm.guest_memory()
    }

    /// Returns a mutable reference to the guest kernel cmdline.
    pub fn kernel_cmdline_mut(&mut self) -> &mut KernelCmdline {
        &mut self.vmm.kernel_cmdline
    }

    /// Adds a MmioDevice.
    pub fn attach_device(
        &mut self,
        id: String,
        device: MmioDevice,
    ) -> result::Result<(), StartMicrovmError> {
        // TODO: we currently map into StartMicrovmError::RegisterBlockDevice for all
        // devices at the end of device_manager.register_mmio_device.
        let type_id = device.device().device_type();
        let cmdline = &mut self.vmm.kernel_cmdline;

        self.vmm
            .mmio_device_manager
            .register_mmio_device(self.vmm.vm.fd(), device, cmdline, type_id, id.as_str())
            .map_err(StartMicrovmError::RegisterBlockDevice)?;

        Ok(())
    }

    /// Start running and return the Vmm.
    pub fn run(mut self, epoll_context: &mut EpollContext) -> result::Result<Vmm, VmmActionError> {
        // Write the kernel command line to guest memory. This is x86_64 specific, since on
        // aarch64 the command line will be specified through the FDT.
        #[cfg(target_arch = "x86_64")]
        kernel_loader::load_cmdline(
            self.vmm.guest_memory(),
            GuestAddress(arch::x86_64::layout::CMDLINE_START),
            &self
                .vmm
                .kernel_cmdline
                .as_cstring()
                .map_err(StartMicrovmError::LoadCommandline)?,
        )
        .map_err(StartMicrovmError::LoadCommandline)?;

        self.vmm
            .configure_system(self.vcpus.as_slice(), &self.initrd)?;

        self.vmm.register_events(epoll_context)?;

        self.vmm.start_vcpus(
            self.vcpus,
            self.vmm_seccomp_filter,
            self.vcpu_seccomp_filter,
        )?;

        // Arm the log write timer.
        // TODO: the timer does not stop on InstanceStop.
        let timer_state = TimerState::Periodic {
            current: Duration::from_secs(WRITE_METRICS_PERIOD_SECONDS),
            interval: Duration::from_secs(WRITE_METRICS_PERIOD_SECONDS),
        };
        self.vmm
            .write_metrics_event_fd
            .set_state(timer_state, SetTimeFlags::Default);

        // Log the metrics straight away to check the process startup time.
        if LOGGER.log_metrics().is_err() {
            METRICS.logger.missed_metrics_count.inc();
        }

        Ok(self.vmm)
    }
}

/// Contains the state and associated methods required for the Firecracker VMM.
pub struct Vmm {
    stdin_handle: io::Stdin,

    // Guest VM core resources.
    guest_memory: GuestMemoryMmap,
    vcpu_config: VcpuConfig,

    kernel_cmdline: KernelCmdline,

    vcpus_handles: Vec<VcpuHandle>,
    exit_evt: EventFd,
    vm: Vm,

    // Guest VM devices.
    mmio_device_manager: MMIODeviceManager,
    #[cfg(target_arch = "x86_64")]
    pio_device_manager: PortIODeviceManager,

    write_metrics_event_fd: TimerFd,
    event_manager: EventManager,
}

impl Vmm {
    /// Gets the the specified bus device.
    pub fn get_bus_device(
        &self,
        device_type: DeviceType,
        device_id: &str,
    ) -> Option<&Mutex<dyn BusDevice>> {
        self.mmio_device_manager.get_device(device_type, device_id)
    }

    /// Force writes metrics.
    pub fn flush_metrics(&mut self) -> UserResult {
        self.write_metrics().map_err(|e| {
            let (kind, error_contents) = match e {
                LoggerError::NeverInitialized(s) => (ErrorKind::User, s),
                _ => (ErrorKind::Internal, e.to_string()),
            };
            VmmActionError::Logger(kind, LoggerConfigError::FlushMetrics(error_contents))
        })
    }

    fn write_metrics(&mut self) -> result::Result<(), LoggerError> {
        LOGGER.log_metrics().map(|_| ())
    }

    #[cfg(target_arch = "x86_64")]
    fn get_serial_device(&self) -> Option<Arc<Mutex<dyn RawIOHandler>>> {
        Some(self.pio_device_manager.stdio_serial.clone())
    }

    #[cfg(target_arch = "aarch64")]
    fn get_serial_device(&self) -> Option<&Arc<Mutex<dyn RawIOHandler>>> {
        self.mmio_device_manager
            .get_raw_io_device(DeviceType::Serial)
    }

    #[cfg(target_arch = "aarch64")]
    fn get_mmio_device_info(&self) -> Option<&HashMap<(DeviceType, String), MMIODeviceInfo>> {
        Some(self.mmio_device_manager.get_device_info())
    }

    #[cfg(target_arch = "x86_64")]
    fn setup_interrupt_controller(&mut self) -> std::result::Result<(), StartMicrovmError> {
        self.vm
            .setup_irqchip()
            .map_err(StartMicrovmError::ConfigureVm)
    }

    #[cfg(target_arch = "aarch64")]
    fn setup_interrupt_controller(&mut self) -> std::result::Result<(), StartMicrovmError> {
        self.vm
            .setup_irqchip(self.vcpu_config.vcpu_count)
            .map_err(StartMicrovmError::ConfigureVm)
    }

    #[cfg(target_arch = "x86_64")]
    fn attach_legacy_devices(&mut self) -> std::result::Result<(), StartMicrovmError> {
        self.pio_device_manager
            .register_devices()
            .map_err(StartMicrovmError::LegacyIOBus)?;

        macro_rules! register_irqfd_evt {
            ($evt: ident, $index: expr) => {{
                self.vm
                    .fd()
                    .register_irqfd(&self.pio_device_manager.$evt, $index)
                    .map_err(|e| {
                        StartMicrovmError::LegacyIOBus(device_manager::legacy::Error::EventFd(
                            io::Error::from_raw_os_error(e.errno()),
                        ))
                    })?;
            }};
        }

        register_irqfd_evt!(com_evt_1_3, 4);
        register_irqfd_evt!(com_evt_2_4, 3);
        register_irqfd_evt!(kbd_evt, 1);
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn attach_legacy_devices(&mut self) -> std::result::Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        if self.kernel_cmdline.as_str().contains("console=") {
            self.mmio_device_manager
                .register_mmio_serial(self.vm.fd(), &mut self.kernel_cmdline)
                .map_err(RegisterMMIODevice)?;
        }

        self.mmio_device_manager
            .register_mmio_rtc(self.vm.fd())
            .map_err(RegisterMMIODevice)?;

        Ok(())
    }

    // On aarch64, the vCPUs need to be created (i.e call KVM_CREATE_VCPU) and configured before
    // setting up the IRQ chip because the `KVM_CREATE_VCPU` ioctl will return error if the IRQCHIP
    // was already initialized.
    // Search for `kvm_arch_vcpu_create` in arch/arm/kvm/arm.c.
    fn create_vcpus(
        &mut self,
        entry_addr: GuestAddress,
        request_ts: TimestampUs,
    ) -> std::result::Result<Vec<Vcpu>, StartMicrovmError> {
        let vcpu_count = self.vcpu_config.vcpu_count;

        let vm_memory = self
            .vm
            .memory()
            .expect("Cannot create vCPUs before guest memory initialization!");

        let mut vcpus = Vec::with_capacity(vcpu_count as usize);

        for cpu_index in 0..vcpu_count {
            let mut vcpu;
            #[cfg(target_arch = "x86_64")]
            {
                let vcpu_exit_evt = self
                    .pio_device_manager
                    .i8042
                    .lock()
                    .expect("Failed to start VCPUs due to poisoned i8042 lock")
                    .get_reset_evt_clone()
                    .map_err(|_| StartMicrovmError::EventFd)?;
                vcpu = Vcpu::new_x86_64(
                    cpu_index,
                    self.vm.fd(),
                    self.vm.supported_cpuid().clone(),
                    self.vm.supported_msrs().clone(),
                    self.pio_device_manager.io_bus.clone(),
                    vcpu_exit_evt,
                    request_ts.clone(),
                )
                .map_err(StartMicrovmError::Vcpu)?;

                vcpu.configure_x86_64(vm_memory, entry_addr, &self.vcpu_config)
                    .map_err(StartMicrovmError::VcpuConfigure)?;
            }
            #[cfg(target_arch = "aarch64")]
            {
                let exit_evt = self
                    .exit_evt
                    .try_clone()
                    .map_err(|_| StartMicrovmError::EventFd)?;
                vcpu = Vcpu::new_aarch64(cpu_index, self.vm.fd(), exit_evt, request_ts.clone())
                    .map_err(StartMicrovmError::Vcpu)?;

                vcpu.configure_aarch64(self.vm.fd(), vm_memory, entry_addr)
                    .map_err(StartMicrovmError::VcpuConfigure)?;
            }

            vcpus.push(vcpu);
        }
        Ok(vcpus)
    }

    fn start_vcpus(
        &mut self,
        mut vcpus: Vec<Vcpu>,
        vmm_seccomp_filter: BpfProgram,
        vcpu_seccomp_filter: BpfProgram,
    ) -> std::result::Result<(), StartMicrovmError> {
        let vcpu_count = vcpus.len();

        Vcpu::register_kick_signal_handler();

        self.vcpus_handles.reserve(vcpu_count as usize);

        for mut vcpu in vcpus.drain(..) {
            vcpu.set_mmio_bus(self.mmio_device_manager.bus.clone());

            self.vcpus_handles.push(
                vcpu.start_threaded(vcpu_seccomp_filter.clone())
                    .map_err(StartMicrovmError::VcpuHandle)?,
            );
        }

        // Load seccomp filters for the VMM thread.
        // Execution panics if filters cannot be loaded, use --seccomp-level=0 if skipping filters
        // altogether is the desired behaviour.
        SeccompFilter::apply(vmm_seccomp_filter).map_err(StartMicrovmError::SeccompFilters)?;

        // The vcpus start off in the `Paused` state, let them run.
        self.resume_vcpus()?;

        Ok(())
    }

    fn resume_vcpus(&mut self) -> std::result::Result<(), StartMicrovmError> {
        for handle in self.vcpus_handles.iter() {
            handle
                .send_event(VcpuEvent::Resume)
                .map_err(StartMicrovmError::VcpuEvent)?;
        }
        for handle in self.vcpus_handles.iter() {
            match handle
                .response_receiver()
                .recv_timeout(Duration::from_millis(1000))
            {
                Ok(VcpuResponse::Resumed) => (),
                _ => return Err(StartMicrovmError::VcpuResume),
            }
        }
        Ok(())
    }

    fn configure_system(
        &self,
        vcpus: &[Vcpu],
        initrd: &Option<InitrdConfig>,
    ) -> std::result::Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        let vm_memory = self
            .vm
            .memory()
            .expect("Cannot configure registers prior to allocating memory!");

        let vcpu_count = vcpus.len() as u8;

        #[cfg(target_arch = "x86_64")]
        arch::x86_64::configure_system(
            vm_memory,
            GuestAddress(arch::x86_64::layout::CMDLINE_START),
            self.kernel_cmdline.len() + 1,
            initrd,
            vcpu_count,
        )
        .map_err(ConfigureSystem)?;

        #[cfg(target_arch = "aarch64")]
        {
            let vcpu_mpidr = vcpus.into_iter().map(|cpu| cpu.get_mpidr()).collect();
            arch::aarch64::configure_system(
                vm_memory,
                &self.kernel_cmdline.as_cstring().map_err(LoadCommandline)?,
                vcpu_mpidr,
                self.get_mmio_device_info(),
                self.vm.get_irqchip(),
                initrd,
            )
            .map_err(ConfigureSystem)?;
        }

        self.configure_stdin()
    }

    fn register_events(
        &mut self,
        epoll_context: &mut EpollContext,
    ) -> std::result::Result<(), StartMicrovmError> {
        epoll_context
            .add_epollin_event(&self.exit_evt, EpollDispatch::Exit)
            .map_err(|_| StartMicrovmError::RegisterEvent)?;

        epoll_context.enable_stdin_event();

        Ok(())
    }

    fn configure_stdin(&self) -> std::result::Result<(), StartMicrovmError> {
        // Set raw mode for stdin.
        self.stdin_handle
            .lock()
            .set_raw_mode()
            .map_err(StartMicrovmError::StdinHandle)?;

        Ok(())
    }

    /// Returns a reference to the inner `GuestMemoryMmap` object if present, or `None` otherwise.
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.guest_memory
    }

    /// Injects CTRL+ALT+DEL keystroke combo in the i8042 device.
    #[cfg(target_arch = "x86_64")]
    pub fn send_ctrl_alt_del(&mut self) -> UserResult {
        self.pio_device_manager
            .i8042
            .lock()
            .expect("i8042 lock was poisoned")
            .trigger_ctrl_alt_del()
            .map_err(|e| VmmActionError::SendCtrlAltDel(ErrorKind::Internal, e))
    }

    /// Waits for all vCPUs to exit and terminates the Firecracker process.
    pub fn stop(&mut self, exit_code: i32) {
        info!("Vmm is stopping.");

        if let Err(e) = self.stdin_handle.lock().set_canon_mode() {
            warn!("Cannot set canonical mode for the terminal. {:?}", e);
        }

        // Log the metrics before exiting.
        if let Err(e) = LOGGER.log_metrics() {
            error!("Failed to log metrics while stopping: {}", e);
        }

        // Exit from Firecracker using the provided exit code. Safe because we're terminating
        // the process anyway.
        unsafe {
            libc::_exit(exit_code);
        }
    }

    fn handle_stdin_event(&self, buffer: &[u8]) -> Result<()> {
        match self.get_serial_device() {
            Some(serial) => {
                // Use expect() to panic if another thread panicked
                // while holding the lock.
                serial
                    .lock()
                    .expect("Failed to process stdin event due to poisoned lock")
                    .raw_input(buffer)
                    .map_err(Error::Serial)?;
            }
            None => warn!("Unable to handle stdin event: no serial device available"),
        }

        Ok(())
    }

    /// Wait on VMM events and dispatch them to the appropriate handler. Returns to the caller
    /// when a control action occurs.
    pub fn run_event_loop(
        &mut self,
        epoll_context: &mut EpollContext,
    ) -> Result<EventLoopExitReason> {
        // TODO: try handling of errors/failures without breaking this main loop.
        loop {
            let event = epoll_context.get_event()?;
            let evset = match epoll::Events::from_bits(event.events) {
                Some(evset) => evset,
                None => {
                    let evbits = event.events;
                    warn!("epoll: ignoring unknown event set: 0x{:x}", evbits);
                    continue;
                }
            };

            match epoll_context.dispatch_table[event.data as usize] {
                Some(EpollDispatch::Exit) => {
                    self.exit_evt.read().map_err(Error::EventFd)?;

                    // Query each vcpu for the exit_code.
                    // If the exit_code can't be found on any vcpu, it means that the exit signal
                    // has been issued by the i8042 controller in which case we exit with
                    // FC_EXIT_CODE_OK.
                    let exit_code = self
                        .vcpus_handles
                        .iter()
                        .find_map(|handle| match handle.response_receiver().try_recv() {
                            Ok(VcpuResponse::Exited(exit_code)) => Some(exit_code),
                            _ => None,
                        })
                        .unwrap_or(FC_EXIT_CODE_OK);

                    self.stop(i32::from(exit_code));
                }
                Some(EpollDispatch::Stdin) => {
                    let mut out = [0u8; 64];
                    let stdin_lock = self.stdin_handle.lock();
                    match stdin_lock.read_raw(&mut out[..]) {
                        Ok(0) => {
                            // Zero-length read indicates EOF. Remove from pollables.
                            epoll_context.disable_stdin_event();
                        }
                        Err(e) => {
                            warn!("error while reading stdin: {:?}", e);
                            epoll_context.disable_stdin_event();
                        }
                        Ok(count) => {
                            self.handle_stdin_event(&out[..count])?;
                        }
                    }
                }
                Some(EpollDispatch::DeviceHandler(device_idx, device_token)) => {
                    METRICS.vmm.device_events.inc();
                    match epoll_context.get_device_handler_by_handler_id(device_idx) {
                        Ok(handler) => match handler.handle_event(device_token, evset) {
                            Err(devices::Error::PayloadExpected) => {
                                panic!("Received update disk image event with empty payload.")
                            }
                            Err(devices::Error::UnknownEvent { device, event }) => {
                                panic!("Unknown event: {:?} {:?}", device, event)
                            }
                            _ => (),
                        },
                        Err(e) => warn!("invalid handler for device {}: {:?}", device_idx, e),
                    }
                }
                Some(EpollDispatch::VmmActionRequest) => {
                    return Ok(EventLoopExitReason::ControlAction);
                }
                Some(EpollDispatch::WriteMetrics) => {
                    self.write_metrics_event_fd.read();
                    // Please note that, since LOGGER has no output file configured yet, it will write to
                    // stdout, so logging will interfere with console output.
                    if let Err(e) = self.write_metrics() {
                        error!("Failed to log metrics: {}", e);
                    }
                }
                // Cascaded polly: We are doing this until all devices have been ported away
                // from epoll_context to polly.
                Some(EpollDispatch::PollyEvent) => {
                    self.event_manager.run().map_err(Error::EventManager)?;
                }
                None => {
                    // Do nothing.
                }
            }
        }
        // Currently, we never get to return with Ok(EventLoopExitReason::Break) because
        // we just invoke stop() whenever that would happen.
    }

    fn log_boot_time(t0_ts: &TimestampUs) {
        let now_tm_us = TimestampUs::default();

        let boot_time_us = now_tm_us.time_us - t0_ts.time_us;
        let boot_time_cpu_us = now_tm_us.cputime_us - t0_ts.cputime_us;
        info!(
            "Guest-boot-time = {:>6} us {} ms, {:>6} CPU us {} CPU ms",
            boot_time_us,
            boot_time_us / 1000,
            boot_time_cpu_us,
            boot_time_cpu_us / 1000
        );
    }

    /// Returns a reference to the inner KVM Vm object.
    pub fn kvm_vm(&self) -> &Vm {
        &self.vm
    }
}

#[cfg(test)]
mod tests {
    use vm_memory::GuestMemoryMmap;

    use super::*;

    impl Vmm {
        // Left around here because it's called by tests::create_vmm_object in the device_manager
        // mmio module.
        /// Creates a new VMM object.
        pub fn new(control_fd: &dyn AsRawFd) -> Result<Self> {
            let mut epoll_context = EpollContext::new()?;
            // If this fails, it's fatal; using expect() to crash.
            epoll_context
                .add_epollin_event(control_fd, EpollDispatch::VmmActionRequest)
                .expect("Cannot add vmm control_fd to epoll.");

            let event_manager = EventManager::new().map_err(Error::EventManager)?;

            let write_metrics_event_fd =
                TimerFd::new_custom(ClockId::Monotonic, true, true).map_err(Error::TimerFd)?;

            epoll_context
                .add_epollin_event(
                    // non-blocking & close on exec
                    &write_metrics_event_fd,
                    EpollDispatch::WriteMetrics,
                )
                .expect("Cannot add write metrics TimerFd to epoll.");

            let kvm = KvmContext::new().map_err(Error::KvmContext)?;
            let vm = Vm::new(kvm.fd()).map_err(Error::Vm)?;

            let guest_memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)])
                .expect("Could not create guest memory object");

            let vcpu_config = VcpuConfig {
                vcpu_count: 1,
                ht_enabled: false,
                cpu_template: None,
            };

            // Instantiate the MMIO device manager.
            // 'mmio_base' address has to be an address which is protected by the kernel
            // and is architectural specific.
            let mmio_device_manager = MMIODeviceManager::new(
                guest_memory.clone(),
                &mut (arch::MMIO_MEM_START as u64),
                (arch::IRQ_BASE, arch::IRQ_MAX),
            );

            Ok(Vmm {
                stdin_handle: io::stdin(),
                guest_memory,
                vcpu_config,
                kernel_cmdline: KernelCmdline::new(1000),
                vcpus_handles: vec![],
                exit_evt: EventFd::new(libc::EFD_NONBLOCK).expect("Cannot create eventFD"),
                vm,
                mmio_device_manager,
                #[cfg(target_arch = "x86_64")]
                pio_device_manager: PortIODeviceManager::new()
                    .map_err(Error::CreateLegacyDevice)?,
                write_metrics_event_fd,
                event_manager,
            })
        }
    }
}
