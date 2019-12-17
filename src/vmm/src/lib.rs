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
extern crate memory_model;
extern crate rate_limiter;
extern crate seccomp;
extern crate utils;

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
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

use timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};

use arch::DeviceType;
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
#[cfg(target_arch = "x86_64")]
use logger::LogOption;
use logger::{Metric, LOGGER, METRICS};
use memory_model::{GuestAddress, GuestMemory};
use polly::event_manager::EventManager;
use utils::eventfd::EventFd;
use utils::net::TapError;
use utils::terminal::Terminal;
use utils::time::TimestampUs;
use vmm_config::boot_source::{BootSourceConfig, BootSourceConfigError};
use vmm_config::drive::{BlockDeviceConfig, DriveError};
use vmm_config::logger::{LoggerConfig, LoggerConfigError};
use vmm_config::machine_config::{CpuFeaturesTemplate, VmConfig, VmConfigError};
use vmm_config::net::{NetworkInterfaceConfig, NetworkInterfaceError};
use vmm_config::vsock::VsockDeviceConfig;
use vstate::{KvmContext, Vcpu, Vm};

pub use error::{ErrorKind, StartMicrovmError, VmmActionError};

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

/// Encapsulates configuration parameters for the guest vCPUS.
pub struct VcpuConfig {
    /// Number of guest VCPUs.
    pub vcpu_count: u8,
    /// Enable hyperthreading in the CPUID configuration.
    pub ht_enabled: bool,
    /// CPUID template to use.
    pub cpu_template: Option<CpuFeaturesTemplate>,
}

/// Encapsulates configuration parameters for a `VmmBuilderz`.
pub struct VmmBuilderzConfig {
    /// The guest memory object for this VM.
    pub guest_memory: GuestMemory,
    /// The guest physical address of the execution entry point.
    pub entry_addr: GuestAddress,
    /// Base kernel command line contents.
    pub kernel_cmdline: KernelCmdline,
    /// vCPU configuration paramters.
    pub vcpu_config: VcpuConfig,
    /// Seccomp filtering level.
    pub seccomp_level: u32,
}

/// Helps build a Vmm.
pub struct VmmBuilderz {
    vmm: Vmm,
    vcpus: Vec<Vcpu>,
}

impl VmmBuilderz {
    /// Create a new VmmBuilderz.
    pub fn new(
        epoll_context: &mut EpollContext,
        config: VmmBuilderzConfig,
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

        let mut vmm = Vmm {
            stdin_handle: io::stdin(),
            guest_memory: config.guest_memory,
            vcpu_config: config.vcpu_config,
            kernel_cmdline: config.kernel_cmdline,
            vcpus_handles: Vec::new(),
            exit_evt: None,
            vm,
            mmio_device_manager,
            #[cfg(target_arch = "x86_64")]
            pio_device_manager: PortIODeviceManager::new()
                .map_err(Error::CreateLegacyDevice)
                .map_err(StartMicrovmError::Internal)?,
            write_metrics_event_fd,
            seccomp_level: config.seccomp_level,
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

        Ok(VmmBuilderz { vmm, vcpus })
    }

    /// Return a reference to the guest memory object used by the builder.
    pub fn guest_memory(&self) -> &GuestMemory {
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

        self.vmm.configure_system(self.vcpus.as_slice())?;

        self.vmm.register_events(epoll_context)?;

        self.vmm.start_vcpus(self.vcpus)?;

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
    guest_memory: GuestMemory,
    vcpu_config: VcpuConfig,

    kernel_cmdline: KernelCmdline,

    vcpus_handles: Vec<thread::JoinHandle<()>>,
    exit_evt: Option<EventFd>,
    vm: Vm,

    // Guest VM devices.
    mmio_device_manager: MMIODeviceManager,
    #[cfg(target_arch = "x86_64")]
    pio_device_manager: PortIODeviceManager,

    write_metrics_event_fd: TimerFd,
    // The level of seccomp filtering used. Seccomp filters are loaded before executing guest code.
    seccomp_level: u32,
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

    #[cfg(target_arch = "x86_64")]
    fn log_dirty_pages(&mut self) {
        // If we're logging dirty pages, post the metrics on how many dirty pages there are.
        if LOGGER.flags() | LogOption::LogDirtyPages as usize > 0 {
            METRICS.memory.dirty_pages.add(self.get_dirty_page_count());
        }
    }

    fn write_metrics(&mut self) -> result::Result<(), LoggerError> {
        // The dirty pages are only available on x86_64.
        #[cfg(target_arch = "x86_64")]
        self.log_dirty_pages();
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
                vcpu = Vcpu::new_x86_64(
                    cpu_index,
                    self.vm.fd(),
                    self.vm.supported_cpuid().clone(),
                    self.pio_device_manager.io_bus.clone(),
                    request_ts.clone(),
                )
                .map_err(StartMicrovmError::Vcpu)?;

                vcpu.configure_x86_64(vm_memory, entry_addr, &self.vcpu_config)
                    .map_err(StartMicrovmError::VcpuConfigure)?;
            }
            #[cfg(target_arch = "aarch64")]
            {
                vcpu = Vcpu::new_aarch64(cpu_index, self.vm.fd(), request_ts.clone())
                    .map_err(StartMicrovmError::Vcpu)?;

                vcpu.configure_aarch64(self.vm.fd(), vm_memory, entry_addr)
                    .map_err(StartMicrovmError::VcpuConfigure)?;
            }

            vcpus.push(vcpu);
        }
        Ok(vcpus)
    }

    fn start_vcpus(&mut self, mut vcpus: Vec<Vcpu>) -> std::result::Result<(), StartMicrovmError> {
        let vcpu_count = vcpus.len();

        Vcpu::register_kick_signal_handler();

        self.vcpus_handles.reserve(vcpu_count as usize);

        let vcpus_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));

        // We're going in reverse so we can `.pop()` on the vec and still maintain order.
        for cpu_id in (0..vcpu_count).rev() {
            let vcpu_thread_barrier = vcpus_thread_barrier.clone();

            // On x86_64 we support i8042. Get a clone of its reset event.
            // If the lock is poisoned, it's OK to panic.
            #[cfg(target_arch = "x86_64")]
            let vcpu_exit_evt = self
                .pio_device_manager
                .i8042
                .lock()
                .expect("Failed to start VCPUs due to poisoned i8042 lock")
                .get_reset_evt_clone()
                .map_err(|_| StartMicrovmError::EventFd)?;

            // On aarch64 we don't support i8042. Use a dummy event nobody touches until
            // we get i8042 support.
            #[cfg(target_arch = "aarch64")]
            let vcpu_exit_evt =
                EventFd::new(libc::EFD_NONBLOCK).map_err(|_| StartMicrovmError::EventFd)?;

            // `unwrap` is safe since we are asserting that the `vcpu_count` is equal to the number
            // of items of `vcpus` vector.
            let mut vcpu = vcpus.pop().unwrap();

            vcpu.set_mmio_bus(self.mmio_device_manager.bus.clone());

            let seccomp_level = self.seccomp_level;
            self.vcpus_handles.push(
                thread::Builder::new()
                    .name(format!("fc_vcpu{}", cpu_id))
                    .spawn(move || {
                        vcpu.run(vcpu_thread_barrier, seccomp_level, vcpu_exit_evt);
                    })
                    .map_err(StartMicrovmError::VcpuSpawn)?,
            );
        }

        // Load seccomp filters for the VMM thread.
        // Execution panics if filters cannot be loaded, use --seccomp-level=0 if skipping filters
        // altogether is the desired behaviour.
        default_syscalls::set_seccomp_level(self.seccomp_level)
            .map_err(StartMicrovmError::SeccompFilters)?;

        vcpus_thread_barrier.wait();

        Ok(())
    }

    #[allow(unused_variables)]
    fn configure_system(&self, vcpus: &[Vcpu]) -> std::result::Result<(), StartMicrovmError> {
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
            )
            .map_err(ConfigureSystem)?;
        }

        self.configure_stdin()
    }

    fn register_events(
        &mut self,
        epoll_context: &mut EpollContext,
    ) -> std::result::Result<(), StartMicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            use StartMicrovmError::*;
            // If the lock is poisoned, it's OK to panic.
            let exit_poll_evt_fd = self
                .pio_device_manager
                .i8042
                .lock()
                .expect("Failed to register events on the event fd due to poisoned lock")
                .get_reset_evt_clone()
                .map_err(|_| EventFd)?;

            epoll_context
                .add_epollin_event(&exit_poll_evt_fd, EpollDispatch::Exit)
                .map_err(|_| RegisterEvent)?;

            self.exit_evt = Some(exit_poll_evt_fd);
        }

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

    /// Returns a reference to the inner `GuestMemory` object if present, or `None` otherwise.
    pub fn guest_memory(&self) -> &GuestMemory {
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
                    match self.exit_evt {
                        Some(ref ev) => {
                            ev.read().map_err(Error::EventFd)?;
                        }
                        None => warn!("leftover exit-evt in epollcontext!"),
                    }
                    self.stop(i32::from(FC_EXIT_CODE_OK));
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

    // Count the number of pages dirtied since the last call to this function.
    // Because this is used for metrics, it swallows most errors and simply doesn't count dirty
    // pages if the KVM operation fails.
    #[cfg(target_arch = "x86_64")]
    fn get_dirty_page_count(&mut self) -> usize {
        let dirty_pages_in_region =
            |(slot, memory_region): (usize, &memory_model::MemoryRegion)| {
                self.vm
                    .fd()
                    .get_dirty_log(slot as u32, memory_region.size())
                    .map(|v| v.iter().map(|page| page.count_ones() as usize).sum())
                    .unwrap_or(0 as usize)
            };

        self.guest_memory()
            .map_and_fold(0, dirty_pages_in_region, std::ops::Add::add)
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
    use super::*;

    impl Vmm {
        // Left around here because it's called by tests::create_vmm_object in the device_manager
        // mmio module.
        /// Creates a new VMM object.
        pub fn new(control_fd: &dyn AsRawFd, seccomp_level: u32) -> Result<Self> {
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

            let guest_memory = GuestMemory::new(&[(GuestAddress(0), 0x10000)])
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
                exit_evt: None,
                vm,
                mmio_device_manager,
                #[cfg(target_arch = "x86_64")]
                pio_device_manager: PortIODeviceManager::new()
                    .map_err(Error::CreateLegacyDevice)?,
                write_metrics_event_fd,
                seccomp_level,
                event_manager,
            })
        }
    }
}

/*
    macro_rules! assert_match {
        ($x:expr, $y:pat) => {{
            if let $y = $x {
                ()
            } else {
                panic!()
            }
        }};
    }

    use super::*;

    use std::fs::File;
    use std::io::BufRead;
    use std::io::BufReader;
    use std::sync::atomic::AtomicUsize;

    use arch::DeviceType;
    use devices::virtio::{ActivateResult, MmioDevice, Queue};
    use dumbo::MacAddr;
    use vmm_config::drive::DriveError;
    use vmm_config::machine_config::CpuFeaturesTemplate;
    use vmm_config::{RateLimiterConfig, TokenBucketConfig};

    fn good_kernel_file() -> PathBuf {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let parent = path.parent().unwrap();

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return [parent.to_str().unwrap(), "kernel/src/loader/test_elf.bin"]
            .iter()
            .collect();
        #[cfg(target_arch = "aarch64")]
        return [parent.to_str().unwrap(), "kernel/src/loader/test_pe.bin"]
            .iter()
            .collect();
    }

    impl Vmm {
        fn get_kernel_cmdline_str(&self) -> &str {
            if let Some(ref k) = self.kernel_config {
                k.cmdline.as_str()
            } else {
                ""
            }
        }

        fn remove_device_info(&mut self, type_id: u32, id: &str) {
            self.mmio_device_manager
                .as_mut()
                .unwrap()
                .remove_device_info(type_id, id);
        }

        fn default_kernel_config(&mut self, cust_kernel_path: Option<PathBuf>) {
            let kernel_temp_file =
                NamedTempFile::new().expect("Failed to create temporary kernel file.");
            let kernel_path = match cust_kernel_path {
                Some(kernel_path) => kernel_path,
                None => kernel_temp_file.path().to_path_buf(),
            };
            let kernel_file = File::open(kernel_path).expect("Cannot open kernel file");
            let mut cmdline = kernel_cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
            assert!(cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).is_ok());
            let kernel_cfg = KernelConfig {
                cmdline,
                kernel_file,
            };
            self.set_kernel_config(kernel_cfg);
        }

        fn set_instance_state(&mut self, instance_state: InstanceState) {
            self.shared_info.write().unwrap().state = instance_state;
        }

        fn update_block_device_path(&mut self, block_device_id: &str, new_path: PathBuf) {
            for config in self.device_configs.block.config_list.iter_mut() {
                if config.drive_id == block_device_id {
                    config.path_on_host = new_path;
                    break;
                }
            }
        }

        fn change_id(&mut self, prev_id: &str, new_id: &str) {
            for config in self.device_configs.block.config_list.iter_mut() {
                if config.drive_id == prev_id {
                    config.drive_id = new_id.to_string();
                    break;
                }
            }
        }
    }

    struct DummyEpollHandler {
        evt: Option<DeviceEventT>,
    }

    impl EpollHandler for DummyEpollHandler {
        fn handle_event(
            &mut self,
            device_event: DeviceEventT,
            _evset: epoll::Events,
        ) -> std::result::Result<(), devices::Error> {
            self.evt = Some(device_event);
            Ok(())
        }
    }

    #[allow(dead_code)]
    #[derive(Clone)]
    struct DummyDevice {
        dummy: u32,
    }

    impl devices::virtio::VirtioDevice for DummyDevice {
        fn device_type(&self) -> u32 {
            0
        }

        fn queue_max_sizes(&self) -> &[u16] {
            &[10]
        }

        fn ack_features_by_page(&mut self, _: u32, _: u32) {}

        fn avail_features(&self) -> u64 {
            0
        }

        fn acked_features(&self) -> u64 {
            0
        }

        fn set_acked_features(&mut self, _: u64) {}

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            let _ = offset;
            let _ = data;
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            let _ = offset;
            let _ = data;
        }

        #[allow(unused_variables)]
        #[allow(unused_mut)]
        fn activate(
            &mut self,
            mem: GuestMemory,
            interrupt_evt: EventFd,
            status: Arc<AtomicUsize>,
            queues: Vec<devices::virtio::Queue>,
            mut queue_evts: Vec<EventFd>,
        ) -> ActivateResult {
            Ok(())
        }
    }

    fn create_vmm_object(state: InstanceState) -> Vmm {
        let shared_info = Arc::new(RwLock::new(InstanceInfo {
            state,
            id: "TEST_ID".to_string(),
            vmm_version: "1.0".to_string(),
        }));

        Vmm::new(
            shared_info,
            &EventFd::new(libc::EFD_NONBLOCK).expect("Cannot create eventFD"),
            seccomp::SECCOMP_LEVEL_NONE,
        )
        .expect("Cannot Create VMM")
    }

    #[test]
    fn test_device_handler() {
        let mut ep = EpollContext::new().unwrap();
        let (base, sender) = ep.allocate_tokens_for_device(1);
        assert_eq!(ep.device_handlers.len(), 1);
        assert_eq!(base, 1);

        let handler = DummyEpollHandler { evt: None };
        assert!(sender.send(Box::new(handler)).is_ok());
        assert!(ep.get_device_handler_by_handler_id(0).is_ok());
    }



    #[test]
    fn test_insert_net_device() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

        // test create network interface
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname1"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
        };
        assert!(vmm.insert_net_device(network_interface).is_ok());

        let mac = MacAddr::parse_str("01:23:45:67:89:0A").unwrap();
        // test update network interface
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname2"),
            guest_mac: Some(mac),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
        };
        assert!(vmm.insert_net_device(network_interface).is_ok());

        // Test insert new net device with same mac fails.
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif2"),
            host_dev_name: String::from("hostname3"),
            guest_mac: Some(mac),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
        };
        assert!(vmm.insert_net_device(network_interface).is_err());

        // Test that update post-boot fails.
        vmm.set_instance_state(InstanceState::Running);
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname2"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
        };
        assert!(vmm.insert_net_device(network_interface).is_err());
    }

    #[test]
    fn test_update_net_device() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

        let tbc_1mtps = TokenBucketConfig {
            size: 1024 * 1024,
            one_time_burst: None,
            refill_time: 1000,
        };
        let tbc_2mtps = TokenBucketConfig {
            size: 2 * 1024 * 1024,
            one_time_burst: None,
            refill_time: 1000,
        };

        vmm.insert_net_device(NetworkInterfaceConfig {
            iface_id: String::from("1"),
            host_dev_name: String::from("hostname4"),
            guest_mac: None,
            rx_rate_limiter: Some(RateLimiterConfig {
                bandwidth: Some(tbc_1mtps),
                ops: None,
            }),
            tx_rate_limiter: None,
            allow_mmds_requests: false,
        })
        .unwrap();

        vmm.update_net_device(NetworkInterfaceUpdateConfig {
            iface_id: "1".to_string(),
            rx_rate_limiter: Some(RateLimiterConfig {
                bandwidth: None,
                ops: Some(tbc_2mtps),
            }),
            tx_rate_limiter: Some(RateLimiterConfig {
                bandwidth: None,
                ops: Some(tbc_2mtps),
            }),
        })
        .unwrap();

        {
            let nic_1: &mut NetworkInterfaceConfig = vmm
                .device_configs
                .network_interface
                .iter_mut()
                .next()
                .unwrap();
            // The RX bandwidth should be unaffected.
            assert_eq!(nic_1.rx_rate_limiter.unwrap().bandwidth.unwrap(), tbc_1mtps);
            // The RX ops should be set to 2mtps.
            assert_eq!(nic_1.rx_rate_limiter.unwrap().ops.unwrap(), tbc_2mtps);
            // The TX bandwith should be unlimited (unaffected).
            assert_eq!(nic_1.tx_rate_limiter.unwrap().bandwidth, None);
            // The TX ops should be set to 2mtps.
            assert_eq!(nic_1.tx_rate_limiter.unwrap().ops.unwrap(), tbc_2mtps);
        }

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.setup_interrupt_controller().is_ok());
        vmm.default_kernel_config(None);
        vmm.init_mmio_device_manager();

        vmm.attach_net_devices().unwrap();
        vmm.set_instance_state(InstanceState::Running);

        // The update should fail before device activation.
        assert!(vmm
            .update_net_device(NetworkInterfaceUpdateConfig {
                iface_id: "1".to_string(),
                rx_rate_limiter: None,
                tx_rate_limiter: None,
            })
            .is_err());

        // Activate the device
        {
            let device_manager = vmm.mmio_device_manager.as_ref().unwrap();
            let bus_device_mutex = device_manager
                .get_device(DeviceType::Virtio(TYPE_NET), "1")
                .unwrap();
            let bus_device = &mut *bus_device_mutex.lock().unwrap();
            let mmio_device: &mut MmioDevice = bus_device
                .as_mut_any()
                .downcast_mut::<MmioDevice>()
                .unwrap();

            assert!(mmio_device
                .device_mut()
                .activate(
                    vmm.vm.memory().unwrap().clone(),
                    EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                    Arc::new(AtomicUsize::new(0)),
                    vec![Queue::new(0), Queue::new(0)],
                    vec![
                        EventFd::new(libc::EFD_NONBLOCK).unwrap(),
                        EventFd::new(libc::EFD_NONBLOCK).unwrap()
                    ],
                )
                .is_ok());
        }

        // the update should succeed after the device activation
        vmm.update_net_device(NetworkInterfaceUpdateConfig {
            iface_id: "1".to_string(),
            rx_rate_limiter: Some(RateLimiterConfig {
                bandwidth: Some(tbc_2mtps),
                ops: None,
            }),
            tx_rate_limiter: Some(RateLimiterConfig {
                bandwidth: Some(tbc_1mtps),
                ops: None,
            }),
        })
        .unwrap();
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_machine_configuration() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

        // test the default values of machine config
        // vcpu_count = 1
        assert_eq!(vmm.vm_config.vcpu_count, Some(1));
        // mem_size = 128
        assert_eq!(vmm.vm_config.mem_size_mib, Some(128));
        // ht_enabled = false
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));
        // no cpu template
        assert!(vmm.vm_config.cpu_template.is_none());

        // 1. Tests with no hyperthreading
        // test put machine configuration for vcpu count with valid value
        let machine_config = VmConfig {
            vcpu_count: Some(3),
            mem_size_mib: None,
            ht_enabled: None,
            cpu_template: None,
        };
        assert!(vmm.set_vm_configuration(machine_config).is_ok());
        assert_eq!(vmm.vm_config.vcpu_count, Some(3));
        assert_eq!(vmm.vm_config.mem_size_mib, Some(128));
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));

        // test put machine configuration for mem size with valid value
        let machine_config = VmConfig {
            vcpu_count: None,
            mem_size_mib: Some(256),
            ht_enabled: None,
            cpu_template: None,
        };
        assert!(vmm.set_vm_configuration(machine_config).is_ok());
        assert_eq!(vmm.vm_config.vcpu_count, Some(3));
        assert_eq!(vmm.vm_config.mem_size_mib, Some(256));
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));

        // Test Error cases for put_machine_configuration with invalid value for vcpu_count
        // Test that the put method return error & that the vcpu value is not changed
        let machine_config = VmConfig {
            vcpu_count: Some(0),
            mem_size_mib: None,
            ht_enabled: None,
            cpu_template: None,
        };
        assert!(vmm.set_vm_configuration(machine_config).is_err());
        assert_eq!(vmm.vm_config.vcpu_count, Some(3));

        // Test Error cases for put_machine_configuration with invalid value for the mem_size_mib
        // Test that the put method return error & that the mem_size_mib value is not changed
        let machine_config = VmConfig {
            vcpu_count: Some(1),
            mem_size_mib: Some(0),
            ht_enabled: Some(false),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };
        assert!(vmm.set_vm_configuration(machine_config).is_err());
        assert_eq!(vmm.vm_config.vcpu_count, Some(3));
        assert_eq!(vmm.vm_config.mem_size_mib, Some(256));
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));
        assert!(vmm.vm_config.cpu_template.is_none());

        // 2. Test with hyperthreading enabled
        // Test that you can't change the hyperthreading value to false when the vcpu count
        // is odd
        let machine_config = VmConfig {
            vcpu_count: None,
            mem_size_mib: None,
            ht_enabled: Some(true),
            cpu_template: None,
        };
        assert!(vmm.set_vm_configuration(machine_config).is_err());
        assert_eq!(vmm.vm_config.ht_enabled, Some(false));
        // Test that you can change the ht flag when you have a valid vcpu count
        // Also set the CPU Template since we are here
        let machine_config = VmConfig {
            vcpu_count: Some(2),
            mem_size_mib: None,
            ht_enabled: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };
        assert!(vmm.set_vm_configuration(machine_config).is_ok());
        assert_eq!(vmm.vm_config.vcpu_count, Some(2));
        assert_eq!(vmm.vm_config.ht_enabled, Some(true));
        assert_eq!(vmm.vm_config.cpu_template, Some(CpuFeaturesTemplate::T2));

        // 3. Test update vm configuration after boot.
        vmm.set_instance_state(InstanceState::Running);
        let machine_config = VmConfig {
            vcpu_count: Some(2),
            mem_size_mib: None,
            ht_enabled: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };
        assert!(vmm.set_vm_configuration(machine_config).is_err());
    }

    #[test]
    fn new_epoll_context_test() {
        assert!(EpollContext::new().is_ok());
    }

    #[test]
    fn add_epollin_event_test() {
        let mut ep = EpollContext::new().unwrap();
        let evfd = EventFd::new(libc::EFD_NONBLOCK).unwrap();

        // adding new event should work
        assert!(ep.add_epollin_event(&evfd, EpollDispatch::Exit).is_ok());
    }

    #[test]
    fn epoll_event_test() {
        let mut ep = EpollContext::new().unwrap();
        let evfd = EventFd::new(libc::EFD_NONBLOCK).unwrap();

        // adding new event should work
        assert!(ep.add_epollin_event(&evfd, EpollDispatch::Exit).is_ok());

        let evpoll_events_len = 10;
        let mut events = vec![epoll::Event::new(epoll::Events::empty(), 0); evpoll_events_len];

        // epoll should have no pending events
        let epollret = epoll::wait(ep.epoll_raw_fd, 0, &mut events[..]);
        let num_events = epollret.unwrap();
        assert_eq!(num_events, 0);

        // raise the event
        assert!(evfd.write(1).is_ok());

        // epoll should report one event
        let epollret = epoll::wait(ep.epoll_raw_fd, 0, &mut events[..]);
        let num_events = epollret.unwrap();
        assert_eq!(num_events, 1);

        // reported event should be the one we raised
        let idx = events[0].data as usize;
        assert!(ep.dispatch_table[idx].is_some());
        assert_eq!(
            *ep.dispatch_table[idx].as_ref().unwrap(),
            EpollDispatch::Exit
        );
    }

    #[test]
    fn test_check_health() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert!(vmm.check_health().is_err());

        vmm.set_kernel_config(KernelConfig {
            cmdline: kernel_cmdline::Cmdline::new(10),
            kernel_file: tempfile::tempfile().unwrap(),
        });
        assert!(vmm.check_health().is_ok());
    }

    #[test]
    fn test_is_instance_initialized() {
        let vmm = create_vmm_object(InstanceState::Uninitialized);
        assert_eq!(vmm.is_instance_initialized(), false);

        let vmm = create_vmm_object(InstanceState::Starting);
        assert_eq!(vmm.is_instance_initialized(), true);

        let vmm = create_vmm_object(InstanceState::Running);
        assert_eq!(vmm.is_instance_initialized(), true);
    }

    #[test]
    fn test_epoll_stdin_event() {
        let mut epoll_context = EpollContext::new().unwrap();

        // If this unit test is run without a terminal attached (i.e ssh without pseudo terminal,
        // request, jailer with `--daemonize` flag on) EPOLL_CTL_ADD would return EPERM
        // on STDIN_FILENO. So, we are using `isatty` to check whether STDIN_FILENO refers
        // to a terminal. If it does not, we are no longer asserting against
        // `epoll_context.dispatch_table[epoll_context.stdin_index as usize]` holding any value.
        if unsafe { libc::isatty(libc::STDIN_FILENO as i32) } == 1 {
            epoll_context.enable_stdin_event();
            assert_eq!(
                epoll_context.dispatch_table[epoll_context.stdin_index as usize].unwrap(),
                EpollDispatch::Stdin
            );
        }

        epoll_context.enable_stdin_event();
        epoll_context.disable_stdin_event();
        assert!(epoll_context.dispatch_table[epoll_context.stdin_index as usize].is_none());
    }

    #[test]
    fn test_attach_net_devices() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.memory().is_some());

        vmm.default_kernel_config(None);
        vmm.setup_interrupt_controller()
            .expect("Failed to setup interrupt controller");
        vmm.init_mmio_device_manager();

        // test create network interface
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname5"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
        };

        assert!(vmm.insert_net_device(network_interface).is_ok());

        assert!(vmm.attach_net_devices().is_ok());
        // a second call to attach_net_devices should fail because when
        // we are creating the virtio::Net object, we are taking the tap.
        assert!(vmm.attach_net_devices().is_err());
    }

    #[test]
    fn test_init_devices() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.default_kernel_config(None);
        assert!(vmm.init_guest_memory().is_ok());
        vmm.setup_interrupt_controller()
            .expect("Failed to setup interrupt controller");

        vmm.init_mmio_device_manager();
        assert!(vmm.attach_virtio_devices().is_ok());
    }

    #[test]
    fn test_configure_boot_source() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

        // Test invalid kernel path.
        assert!(vmm
            .configure_boot_source(BootSourceConfig {
                kernel_image_path: String::from("dummy-path"),
                boot_args: None
            })
            .is_err());

        // Test valid kernel path and invalid cmdline.
        let kernel_file = NamedTempFile::new().expect("Failed to create temporary kernel file.");
        let kernel_path = String::from(kernel_file.path().to_path_buf().to_str().unwrap());
        let invalid_cmdline = String::from_utf8(vec![b'X'; arch::CMDLINE_MAX_SIZE + 1]).unwrap();
        assert!(vmm
            .configure_boot_source(BootSourceConfig {
                kernel_image_path: kernel_path.clone(),
                boot_args: Some(invalid_cmdline)
            })
            .is_err());

        // Test valid configuration.
        assert!(vmm
            .configure_boot_source(BootSourceConfig {
                kernel_image_path: kernel_path.clone(),
                boot_args: None
            })
            .is_ok());
        assert!(vmm
            .configure_boot_source(BootSourceConfig {
                kernel_image_path: kernel_path.clone(),
                boot_args: Some(String::from("reboot=k"))
            })
            .is_ok());

        // Test valid configuration after boot (should fail).
        vmm.set_instance_state(InstanceState::Running);
        assert!(vmm
            .configure_boot_source(BootSourceConfig {
                kernel_image_path: kernel_path.clone(),
                boot_args: None
            })
            .is_err());
    }

    #[test]
    fn test_block_device_rescan() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.default_kernel_config(None);

        let root_file = NamedTempFile::new().unwrap();
        let scratch_file = NamedTempFile::new().unwrap();
        let scratch_id = "not_root".to_string();

        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: root_file.path().to_path_buf(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            rate_limiter: None,
        };
        let non_root_block_device = BlockDeviceConfig {
            drive_id: scratch_id.clone(),
            path_on_host: scratch_file.path().to_path_buf(),
            is_root_device: false,
            partuuid: None,
            is_read_only: true,
            rate_limiter: None,
        };

        assert!(vmm.insert_block_device(root_block_device.clone()).is_ok());
        assert!(vmm
            .insert_block_device(non_root_block_device.clone())
            .is_ok());

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.memory().is_some());
        assert!(vmm.setup_interrupt_controller().is_ok());

        vmm.init_mmio_device_manager();

        {
            let dummy_box = Box::new(DummyDevice { dummy: 0 });
            let device_manager = vmm.mmio_device_manager.as_mut().unwrap();

            // Use a dummy command line as it is not used in this test.
            let _addr = device_manager
                .register_virtio_device(
                    vmm.vm.fd(),
                    dummy_box,
                    &mut kernel_cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE),
                    TYPE_BLOCK,
                    &scratch_id,
                )
                .unwrap();
        }

        vmm.set_instance_state(InstanceState::Running);

        // Test valid rescan_block_device.
        assert!(vmm.rescan_block_device(&scratch_id).is_ok());

        // Test rescan block device with size not a multiple of sector size.
        let new_size = 10 * virtio::block::SECTOR_SIZE + 1;
        scratch_file.as_file().set_len(new_size).unwrap();
        assert!(vmm.rescan_block_device(&scratch_id).is_ok());

        // Test rescan block device with invalid path.
        let prev_path = non_root_block_device.path_on_host().clone();
        vmm.update_block_device_path(&scratch_id, PathBuf::from("foo"));
        assert_match!(
            vmm.rescan_block_device(&scratch_id),
            Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::BlockDeviceUpdateFailed,
            ))
        );
        vmm.update_block_device_path(&scratch_id, prev_path);

        // Test rescan_block_device with invalid ID.
        assert_match!(
            vmm.rescan_block_device(&"foo".to_string()),
            Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::InvalidBlockDeviceID
            ))
        );

        vmm.change_id(&scratch_id, "scratch");
        assert_match!(
            vmm.rescan_block_device(&scratch_id),
            Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::InvalidBlockDeviceID
            ))
        );

        // Test rescan_block_device with invalid device address.
        vmm.remove_device_info(TYPE_BLOCK, &scratch_id);

        assert_match!(
            vmm.rescan_block_device(&scratch_id),
            Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::InvalidBlockDeviceID
            ))
        );

        // Test rescan not allowed.
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert!(vmm
            .insert_block_device(non_root_block_device.clone())
            .is_ok());

        assert_match!(
            vmm.rescan_block_device(&scratch_id),
            Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::OperationNotAllowedPreBoot,
            ))
        );
    }

    #[test]
    fn test_init_logger() {
        // Error case: update after instance is running
        let log_file = NamedTempFile::new().unwrap();
        let metrics_file = NamedTempFile::new().unwrap();
        let desc = LoggerConfig {
            log_fifo: log_file.path().to_str().unwrap().to_string(),
            metrics_fifo: metrics_file.path().to_str().unwrap().to_string(),
            level: LoggerLevel::Warning,
            show_level: true,
            show_log_origin: true,
            #[cfg(target_arch = "x86_64")]
            options: vec![],
        };

        let mut vmm = create_vmm_object(InstanceState::Running);
        assert!(vmm.init_logger(desc).is_err());

        // Reset vmm state to test the other scenarios.
        vmm.set_instance_state(InstanceState::Uninitialized);

        // Error case: initializing logger with invalid log pipe returns error.
        let desc = LoggerConfig {
            log_fifo: String::from("not_found_file_log"),
            metrics_fifo: metrics_file.path().to_str().unwrap().to_string(),
            level: LoggerLevel::Debug,
            show_level: false,
            show_log_origin: false,
            #[cfg(target_arch = "x86_64")]
            options: vec![],
        };
        assert!(vmm.init_logger(desc).is_err());

        // Error case: initializing logger with invalid metrics pipe returns error.
        let desc = LoggerConfig {
            log_fifo: log_file.path().to_str().unwrap().to_string(),
            metrics_fifo: String::from("not_found_file_metrics"),
            level: LoggerLevel::Debug,
            show_level: false,
            show_log_origin: false,
            #[cfg(target_arch = "x86_64")]
            options: vec![],
        };
        assert!(vmm.init_logger(desc).is_err());

        // Error case: initializing logger with invalid metrics and log pipe returns error.
        let desc = LoggerConfig {
            log_fifo: String::from("not_found_file_log"),
            metrics_fifo: String::from("not_found_file_metrics"),
            level: LoggerLevel::Warning,
            show_level: false,
            show_log_origin: false,
            #[cfg(target_arch = "x86_64")]
            options: vec![],
        };
        assert!(vmm.init_logger(desc).is_err());

        // Initializing logger with valid pipes is ok.
        let log_file = NamedTempFile::new().unwrap();
        let metrics_file = NamedTempFile::new().unwrap();
        let desc = LoggerConfig {
            log_fifo: log_file.path().to_str().unwrap().to_string(),
            metrics_fifo: metrics_file.path().to_str().unwrap().to_string(),
            level: LoggerLevel::Info,
            show_level: true,
            show_log_origin: true,
            #[cfg(target_arch = "x86_64")]
            options: vec![LogOption::LogDirtyPages],
        };
        // Flushing metrics before initializing logger is not erroneous.
        assert!(vmm.flush_metrics().is_ok());

        assert!(vmm.init_logger(desc.clone()).is_ok());
        assert!(vmm.init_logger(desc).is_err());

        assert!(vmm.flush_metrics().is_ok());

        let f = File::open(metrics_file).unwrap();
        let mut reader = BufReader::new(f);

        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("utc_timestamp_ms"));

        // It is safe to do that because the tests are run sequentially (so no other test may be
        // writing to the same file.
        assert!(vmm.flush_metrics().is_ok());
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("utc_timestamp_ms"));

        // Validate logfile works.
        warn!("this is a test");

        let f = File::open(log_file).unwrap();
        let mut reader = BufReader::new(f);

        let mut line = String::new();
        loop {
            if line.contains("this is a test") {
                break;
            }
            if reader.read_line(&mut line).unwrap() == 0 {
                // If it ever gets here, this assert will fail.
                assert!(line.contains("this is a test"));
            }
        }

        // Validate logging the boot time works.
        Vmm::log_boot_time(&TimestampUs::default());
        let mut line = String::new();
        loop {
            if line.contains("Guest-boot-time =") {
                break;
            }
            if reader.read_line(&mut line).unwrap() == 0 {
                // If it ever gets here, this assert will fail.
                assert!(line.contains("Guest-boot-time ="));
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_dirty_page_count() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert_eq!(vmm.get_dirty_page_count(), 0);
        // Booting an actual guest and getting real data is covered by `kvm::tests::run_code_test`.
    }

    #[test]
    fn test_create_vcpus() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.default_kernel_config(None);

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.memory().is_some());

        #[cfg(target_arch = "x86_64")]
        // `KVM_CREATE_VCPU` fails if the irqchip is not created beforehand. This is x86_64 speciifc.
        vmm.vm
            .setup_irqchip()
            .expect("Cannot create IRQCHIP or PIT");

        assert!(vmm
            .create_vcpus(GuestAddress(0x0), TimestampUs::default())
            .is_ok());
    }

    #[test]
    #[should_panic(expected = "Cannot load kernel prior allocating memory!")]
    fn test_load_kernel_no_mem() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.load_kernel().unwrap();
    }

    #[test]
    fn test_load_kernel() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.memory().is_some());

        assert_eq!(
            vmm.load_kernel().unwrap_err().to_string(),
            "Cannot start microvm without kernel configuration."
        );

        vmm.default_kernel_config(None);

        #[cfg(target_arch = "aarch64")]
        assert_eq!(
            vmm.load_kernel().unwrap_err().to_string(),
            "Cannot load kernel due to invalid memory configuration or invalid kernel image. Failed to read magic number"
        );

        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            vmm.load_kernel().unwrap_err().to_string(),
            "Cannot load kernel due to invalid memory configuration or invalid kernel image. Failed to read ELF header"
        );

        vmm.default_kernel_config(Some(good_kernel_file()));
        assert!(vmm.load_kernel().is_ok());
    }

    #[test]
    #[should_panic(expected = "Cannot configure registers prior to allocating memory!")]
    fn test_configure_system_no_mem() {
        let vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.configure_system(&Vec::new()).unwrap();
    }

    #[test]
    fn test_configure_system() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

        assert!(vmm.init_guest_memory().is_ok());

        // test that we can do this any number of times we want.
        assert!(vmm.init_guest_memory().is_ok());

        assert!(vmm.vm.memory().is_some());

        assert_eq!(
            vmm.configure_system(&Vec::new()).unwrap_err().to_string(),
            "Cannot start microvm without kernel configuration."
        );

        vmm.default_kernel_config(None);

        // We need this so that configure_system finds a properly setup GIC device
        #[cfg(target_arch = "aarch64")]
        assert!(vmm.vm.setup_irqchip(1).is_ok());
        assert!(vmm.configure_system(&Vec::new()).is_ok());

        vmm.stdin_handle.lock().set_canon_mode().unwrap();
    }

    #[test]
    fn test_attach_virtio_devices() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.default_kernel_config(None);

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.memory().is_some());
        vmm.setup_interrupt_controller()
            .expect("Failed to setup interrupt controller");

        // Create test network interface.
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname6"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
        };

        assert!(vmm.insert_net_device(network_interface).is_ok());
        assert!(vmm.attach_virtio_devices().is_ok());
        assert!(vmm.mmio_device_manager.is_some());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_attach_legacy_devices() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.setup_interrupt_controller()
            .expect("Failed to setup interrupt controller");

        assert!(vmm.attach_legacy_devices().is_ok());
        assert!(vmm.pio_device_manager.io_bus.get_device(0x3f8).is_some());
        assert!(vmm.pio_device_manager.io_bus.get_device(0x2f8).is_some());
        assert!(vmm.pio_device_manager.io_bus.get_device(0x3e8).is_some());
        assert!(vmm.pio_device_manager.io_bus.get_device(0x2e8).is_some());
        assert!(vmm.pio_device_manager.io_bus.get_device(0x060).is_some());
        assert!(vmm.configure_stdin().is_ok());
        assert!(vmm.handle_stdin_event(&[b'a', b'b', b'c']).is_ok());
        vmm.stdin_handle.lock().set_canon_mode().unwrap();
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_attach_legacy_devices_without_uart() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.memory().is_some());

        let guest_mem = vmm.vm.memory().unwrap().clone();
        let device_manager = MMIODeviceManager::new(
            guest_mem,
            &mut (arch::MMIO_MEM_START),
            (arch::IRQ_BASE, arch::IRQ_MAX),
        );
        vmm.mmio_device_manager = Some(device_manager);

        vmm.default_kernel_config(None);
        vmm.setup_interrupt_controller()
            .expect("Failed to setup interrupt controller");
        assert!(vmm.attach_legacy_devices().is_ok());

        let dev_man = vmm.mmio_device_manager.as_ref().unwrap();
        // On aarch64, we are using first region of the memory
        // reserved for attaching MMIO devices for measuring boot time.
        assert!(dev_man.bus.get_device(arch::MMIO_MEM_START).is_none());
        assert!(dev_man
            .get_device_info()
            .get(&(DeviceType::Serial, DeviceType::Serial.to_string()))
            .is_none());
        assert!(dev_man
            .get_device_info()
            .get(&(DeviceType::RTC, "rtc".to_string()))
            .is_some());
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_attach_legacy_devices_with_uart() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.memory().is_some());

        let guest_mem = vmm.vm.memory().unwrap().clone();
        let device_manager = MMIODeviceManager::new(
            guest_mem,
            &mut (arch::MMIO_MEM_START),
            (arch::IRQ_BASE, arch::IRQ_MAX),
        );
        vmm.mmio_device_manager = Some(device_manager);

        vmm.default_kernel_config(None);
        vmm.setup_interrupt_controller()
            .expect("Failed to setup interrupt controller");
        {
            let kernel_config = vmm.kernel_config.as_mut().unwrap();
            kernel_config.cmdline.insert("console", "tty1").unwrap();
        }
        assert!(vmm.attach_legacy_devices().is_ok());
        let dev_man = vmm.mmio_device_manager.as_ref().unwrap();
        assert!(dev_man
            .get_device_info()
            .get(&(DeviceType::Serial, DeviceType::Serial.to_string()))
            .is_some());

        let serial_device = vmm.get_serial_device();
        assert!(serial_device.is_some());

        assert!(vmm.configure_stdin().is_ok());
        vmm.stdin_handle.lock().set_canon_mode().unwrap();
        assert!(vmm.handle_stdin_event(&[b'a', b'b', b'c']).is_ok());
    }

    #[test]
    fn test_configure_vmm_from_json() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

        let kernel_file = NamedTempFile::new().unwrap();
        let rootfs_file = NamedTempFile::new().unwrap();

        // We will test different scenarios with invalid resources configuration and
        // check the expected errors. We include configuration for the kernel and rootfs
        // in every json because they are mandatory fields. If we don't configure
        // these resources, it is considered an invalid json and the test will crash.

        // Invalid kernel path.
        let mut json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "/invalid/path",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ]
            }}"#,
            rootfs_file.path().to_str().unwrap()
        );

        match vmm.configure_from_json(json) {
            Err(VmmActionError::BootSource(
                ErrorKind::User,
                BootSourceConfigError::InvalidKernelPath(_),
            )) => (),
            _ => unreachable!(),
        }

        // Invalid rootfs path.
        json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "/invalid/path",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ]
            }}"#,
            kernel_file.path().to_str().unwrap()
        );

        match vmm.configure_from_json(json) {
            Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::InvalidBlockDevicePath,
            )) => (),
            _ => unreachable!(),
        }

        // Invalid vCPU number.
        json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ],
                    "machine-config": {{
                        "vcpu_count": 0,
                        "mem_size_mib": 1024,
                        "ht_enabled": false
                    }}
            }}"#,
            kernel_file.path().to_str().unwrap(),
            rootfs_file.path().to_str().unwrap()
        );

        match vmm.configure_from_json(json) {
            Err(VmmActionError::MachineConfig(
                ErrorKind::User,
                VmConfigError::InvalidVcpuCount,
            )) => (),
            _ => unreachable!(),
        }

        // Invalid memory size.
        json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ],
                    "machine-config": {{
                        "vcpu_count": 2,
                        "mem_size_mib": 0,
                        "ht_enabled": false
                    }}
            }}"#,
            kernel_file.path().to_str().unwrap(),
            rootfs_file.path().to_str().unwrap()
        );

        match vmm.configure_from_json(json) {
            Err(VmmActionError::MachineConfig(
                ErrorKind::User,
                VmConfigError::InvalidMemorySize,
            )) => (),
            _ => unreachable!(),
        }

        // Invalid path for logger pipe.
        json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ],
                    "logger": {{
                        "log_fifo": "/invalid/path",
                        "metrics_fifo": "metrics.fifo"
                    }}
            }}"#,
            kernel_file.path().to_str().unwrap(),
            rootfs_file.path().to_str().unwrap()
        );

        match vmm.configure_from_json(json) {
            Err(VmmActionError::Logger(
                ErrorKind::User,
                LoggerConfigError::InitializationFailure { .. },
            )) => (),
            _ => unreachable!(),
        }

        // Reuse of a host name.
        json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ],
                    "network-interfaces": [
                        {{
                            "iface_id": "netif1",
                            "host_dev_name": "hostname7"
                        }},
                        {{
                            "iface_id": "netif2",
                            "host_dev_name": "hostname7"
                        }}
                    ]
            }}"#,
            kernel_file.path().to_str().unwrap(),
            rootfs_file.path().to_str().unwrap()
        );

        match vmm.configure_from_json(json) {
            Err(VmmActionError::NetworkConfig(
                ErrorKind::User,
                NetworkInterfaceError::HostDeviceNameInUse { .. },
            )) => (),
            _ => unreachable!(),
        }

        // Let's try now passing a valid configuration. We won't include any logger
        // configuration because the logger was already initialized in another test
        // of this module and the reinitialization of it will cause crashing.
        json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ],
                    "network-interfaces": [
                        {{
                            "iface_id": "netif",
                            "host_dev_name": "hostname8"
                        }}
                    ],
                     "machine-config": {{
                            "vcpu_count": 2,
                            "mem_size_mib": 1024,
                            "ht_enabled": false
                     }}
            }}"#,
            kernel_file.path().to_str().unwrap(),
            rootfs_file.path().to_str().unwrap()
        );

        assert!(vmm.configure_from_json(json).is_ok());
    }
}
*/
