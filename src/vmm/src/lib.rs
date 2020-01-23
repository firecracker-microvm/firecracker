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

/// Syscalls allowed through the seccomp filter.
pub mod default_syscalls;
mod device_manager;
pub mod error;
/// Signal handling utilities.
pub mod signal_handler;
/// Wrappers over structures used to configure the VMM.
pub mod vmm_config;
mod vstate;

use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::process;
use std::result;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};

#[cfg(target_arch = "aarch64")]
use arch::DeviceType;
use arch::InitrdConfig;
#[cfg(target_arch = "x86_64")]
use device_manager::legacy::PortIODeviceManager;
#[cfg(target_arch = "aarch64")]
use device_manager::mmio::MMIODeviceInfo;
use device_manager::mmio::MMIODeviceManager;
use devices::virtio;
use devices::virtio::vsock::{TYPE_VSOCK, VSOCK_EVENTS_COUNT};
use devices::virtio::EpollConfigConstructor;
use devices::virtio::{BLOCK_EVENTS_COUNT, TYPE_BLOCK};
use devices::virtio::{NET_EVENTS_COUNT, TYPE_NET};
use devices::RawIOHandler;
use devices::{DeviceEventT, EpollHandler};
use error::{Error, Result, UserResult};
use kernel::cmdline as kernel_cmdline;
use kernel::loader as kernel_loader;
use logger::error::LoggerError;
use logger::{AppInfo, Level, Metric, LOGGER, METRICS};
use seccomp::{BpfProgram, SeccompFilter};
use utils::eventfd::EventFd;
use utils::net::TapError;
use utils::terminal::Terminal;
use utils::time::TimestampUs;
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vmm_config::boot_source::{
    BootSourceConfig, BootSourceConfigError, KernelConfig, DEFAULT_KERNEL_CMDLINE,
};
use vmm_config::device_config::DeviceConfigs;
use vmm_config::drive::{BlockDeviceConfig, BlockDeviceConfigs, DriveError};
use vmm_config::instance_info::{InstanceInfo, InstanceState};
use vmm_config::logger::{LoggerConfig, LoggerConfigError, LoggerLevel, LoggerWriter};
use vmm_config::machine_config::{VmConfig, VmConfigError};
use vmm_config::net::{
    NetworkInterfaceConfig, NetworkInterfaceConfigs, NetworkInterfaceError,
    NetworkInterfaceUpdateConfig,
};
use vmm_config::vsock::{VsockDeviceConfig, VsockError};
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

#[derive(Debug, Clone, Copy, PartialEq)]
enum EpollDispatch {
    Exit,
    Stdin,
    DeviceHandler(usize, DeviceEventT),
    VmmActionRequest,
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

// Handles epoll related business.
// A glaring shortcoming of the current design is the liberal passing around of raw_fds,
// and duping of file descriptors. This issue will be solved when we also implement device removal.
struct EpollContext {
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
    fn new() -> Result<Self> {
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

    fn enable_stdin_event(&mut self) {
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

    fn disable_stdin_event(&mut self) {
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
    fn add_epollin_event<T: AsRawFd + ?Sized>(
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
    fn allocate_tokens_for_device(&mut self, count: usize) -> (u64, Sender<Box<dyn EpollHandler>>) {
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
    fn allocate_tokens_for_virtio_device<T: EpollConfigConstructor>(
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

    fn get_device_handler_by_handler_id(&mut self, id: usize) -> Result<&mut dyn EpollHandler> {
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

    fn get_device_handler_by_device_id<T: EpollHandler + 'static>(
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
    fn get_event(&mut self) -> Result<epoll::Event> {
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

/// Contains the state and associated methods required for the Firecracker VMM.
pub struct Vmm {
    kvm: KvmContext,

    vm_config: VmConfig,
    shared_info: Arc<RwLock<InstanceInfo>>,

    stdin_handle: io::Stdin,

    // Guest VM core resources.
    kernel_config: Option<KernelConfig>,
    vcpus_handles: Vec<VcpuHandle>,
    exit_evt: Option<EventFd>,
    vm: Vm,

    // Guest VM devices.
    mmio_device_manager: Option<MMIODeviceManager>,
    #[cfg(target_arch = "x86_64")]
    pio_device_manager: PortIODeviceManager,

    // Device configurations.
    device_configs: DeviceConfigs,

    epoll_context: EpollContext,

    write_metrics_event_fd: TimerFd,
}

impl Vmm {
    /// Creates a new VMM object.
    pub fn new(shared_info: Arc<RwLock<InstanceInfo>>, control_fd: &dyn AsRawFd) -> Result<Self> {
        let mut epoll_context = EpollContext::new()?;
        // If this fails, it's fatal; using expect() to crash.
        epoll_context
            .add_epollin_event(control_fd, EpollDispatch::VmmActionRequest)
            .expect("Cannot add vmm control_fd to epoll.");

        let write_metrics_event_fd =
            TimerFd::new_custom(ClockId::Monotonic, true, true).map_err(Error::TimerFd)?;

        epoll_context
            .add_epollin_event(
                // non-blocking & close on exec
                &write_metrics_event_fd,
                EpollDispatch::WriteMetrics,
            )
            .expect("Cannot add write metrics TimerFd to epoll.");

        let device_configs = DeviceConfigs::new(
            BlockDeviceConfigs::new(),
            NetworkInterfaceConfigs::new(),
            None,
        );

        let kvm = KvmContext::new().map_err(Error::KvmContext)?;
        let vm = Vm::new(kvm.fd()).map_err(Error::Vm)?;

        Ok(Vmm {
            kvm,
            vm_config: VmConfig::default(),
            shared_info,
            stdin_handle: io::stdin(),
            kernel_config: None,
            vcpus_handles: vec![],
            exit_evt: None,
            vm,
            mmio_device_manager: None,
            #[cfg(target_arch = "x86_64")]
            pio_device_manager: PortIODeviceManager::new().map_err(Error::CreateLegacyDevice)?,
            device_configs,
            epoll_context,
            write_metrics_event_fd,
        })
    }

    /// Returns the VmConfig of this Vmm.
    pub fn vm_config(&self) -> &VmConfig {
        &self.vm_config
    }

    fn update_drive_handler(
        &mut self,
        drive_id: &str,
        disk_image: File,
    ) -> result::Result<(), DriveError> {
        let handler = self
            .epoll_context
            .get_device_handler_by_device_id::<virtio::BlockEpollHandler>(TYPE_BLOCK, drive_id)
            .map_err(|_| DriveError::EpollHandlerNotFound)?;

        handler
            .update_disk_image(disk_image)
            .map_err(|_| DriveError::BlockDeviceUpdateFailed)
    }

    // Attaches all block devices from the BlockDevicesConfig.
    fn attach_block_devices(&mut self) -> std::result::Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        // We rely on check_health function for making sure kernel_config is not None.
        let kernel_config = self.kernel_config.as_mut().ok_or(MissingKernelConfig)?;

        // If no PARTUUID was specified for the root device, try with the /dev/vda.
        if self.device_configs.block.has_root_block_device()
            && !self.device_configs.block.has_partuuid_root()
        {
            kernel_config.cmdline.insert_str("root=/dev/vda")?;

            let flags = if self.device_configs.block.has_read_only_root() {
                "ro"
            } else {
                "rw"
            };

            kernel_config.cmdline.insert_str(flags)?;
        }

        let epoll_context = &mut self.epoll_context;
        // `unwrap` is suitable for this context since this should be called only after the
        // device manager has been initialized.
        let device_manager = self.mmio_device_manager.as_mut().unwrap();

        for drive_config in self.device_configs.block.config_list.iter_mut() {
            // Add the block device from file.
            let block_file = OpenOptions::new()
                .read(true)
                .write(!drive_config.is_read_only)
                .open(&drive_config.path_on_host)
                .map_err(OpenBlockDevice)?;

            if drive_config.is_root_device && drive_config.get_partuuid().is_some() {
                kernel_config.cmdline.insert_str(format!(
                    "root=PARTUUID={}",
                    //The unwrap is safe as we are firstly checking that partuuid is_some().
                    drive_config.get_partuuid().unwrap()
                ))?;

                let flags = if drive_config.is_read_only() {
                    "ro"
                } else {
                    "rw"
                };

                kernel_config.cmdline.insert_str(flags)?;
            }

            let epoll_config = epoll_context.allocate_tokens_for_virtio_device(
                TYPE_BLOCK,
                &drive_config.drive_id,
                BLOCK_EVENTS_COUNT,
            );
            let rate_limiter = drive_config
                .rate_limiter
                .map(vmm_config::RateLimiterConfig::try_into)
                .transpose()
                .map_err(CreateRateLimiter)?;

            let block_box = Box::new(
                devices::virtio::Block::new(
                    block_file,
                    drive_config.is_read_only,
                    epoll_config,
                    rate_limiter,
                )
                .map_err(CreateBlockDevice)?,
            );
            device_manager
                .register_virtio_device(
                    self.vm.fd(),
                    block_box,
                    &mut kernel_config.cmdline,
                    TYPE_BLOCK,
                    &drive_config.drive_id,
                )
                .map_err(RegisterBlockDevice)?;
        }

        Ok(())
    }

    fn attach_net_devices(&mut self) -> std::result::Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        // We rely on check_health function for making sure kernel_config is not None.
        let kernel_config = self.kernel_config.as_mut().ok_or(MissingKernelConfig)?;

        // `unwrap` is suitable for this context since this should be called only after the
        // device manager has been initialized.
        let device_manager = self.mmio_device_manager.as_mut().unwrap();

        for cfg in self.device_configs.network_interface.iter_mut() {
            let epoll_config = self.epoll_context.allocate_tokens_for_virtio_device(
                TYPE_NET,
                &cfg.iface_id,
                NET_EVENTS_COUNT,
            );

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

            let vm_fd = self.vm.fd();
            cfg.open_tap()
                .map_err(|_| NetDeviceNotConfigured)
                .and_then(|tap| {
                    let net_box = Box::new(
                        devices::virtio::Net::new_with_tap(
                            tap,
                            cfg.guest_mac(),
                            epoll_config,
                            rx_rate_limiter,
                            tx_rate_limiter,
                            allow_mmds_requests,
                        )
                        .map_err(CreateNetDevice)?,
                    );

                    device_manager
                        .register_virtio_device(
                            vm_fd,
                            net_box,
                            &mut kernel_config.cmdline,
                            TYPE_NET,
                            &cfg.iface_id,
                        )
                        .map_err(RegisterNetDevice)
                })?;
        }
        Ok(())
    }

    fn attach_vsock_devices(&mut self) -> std::result::Result<(), StartMicrovmError> {
        let kernel_config = self
            .kernel_config
            .as_mut()
            .ok_or(StartMicrovmError::MissingKernelConfig)?;

        // `unwrap` is suitable for this context since this should be called only after the
        // device manager has been initialized.
        let device_manager = self.mmio_device_manager.as_mut().unwrap();

        if let Some(cfg) = &self.device_configs.vsock {
            let backend = devices::virtio::vsock::VsockUnixBackend::new(
                u64::from(cfg.guest_cid),
                cfg.uds_path.clone(),
            )
            .map_err(StartMicrovmError::CreateVsockBackend)?;

            let epoll_config = self.epoll_context.allocate_tokens_for_virtio_device(
                TYPE_VSOCK,
                &cfg.vsock_id,
                VSOCK_EVENTS_COUNT,
            );
            let vsock_box = Box::new(
                devices::virtio::Vsock::new(u64::from(cfg.guest_cid), epoll_config, backend)
                    .map_err(StartMicrovmError::CreateVsockDevice)?,
            );
            device_manager
                .register_virtio_device(
                    self.vm.fd(),
                    vsock_box,
                    &mut kernel_config.cmdline,
                    TYPE_VSOCK,
                    &cfg.vsock_id,
                )
                .map_err(StartMicrovmError::RegisterVsockDevice)?;
        }

        Ok(())
    }

    fn set_kernel_config(&mut self, kernel_config: KernelConfig) {
        self.kernel_config = Some(kernel_config);
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

    fn init_guest_memory(&mut self) -> std::result::Result<(), StartMicrovmError> {
        // We are not allowing reinitialization of vm guest memory.
        if self.vm.memory().is_some() {
            return Ok(());
        }

        // We are defaulting the mem_size_mib to 128 (search for `impl Default for VmConfig`) so
        // we should panic when `None` (since it denotes programming error).
        let mem_size = self
            .vm_config
            .mem_size_mib
            .expect("The size of guest memory is not specified!")
            << 20;
        let arch_mem_regions = arch::arch_memory_regions(mem_size);

        self.vm
            .memory_init(
                GuestMemoryMmap::new(&arch_mem_regions)
                    .map_err(StartMicrovmError::GuestMemoryMmap)?,
                &self.kvm,
            )
            .map_err(StartMicrovmError::ConfigureVm)
    }

    fn check_health(&self) -> std::result::Result<(), StartMicrovmError> {
        self.kernel_config
            .as_ref()
            .ok_or(StartMicrovmError::MissingKernelConfig)
            .map(|_| ())
    }

    fn init_mmio_device_manager(&mut self) {
        if self.mmio_device_manager.is_some() {
            return;
        }

        let guest_mem = self
            .vm
            .memory()
            .expect("Cannot initialize device manager prior to guest memory!")
            .clone();

        // Instantiate the MMIO device manager.
        // 'mmio_base' address has to be an address which is protected by the kernel
        // and is architectural specific.
        let device_manager = MMIODeviceManager::new(
            guest_mem,
            &mut (arch::MMIO_MEM_START as u64),
            (arch::IRQ_BASE, arch::IRQ_MAX),
        );
        self.mmio_device_manager = Some(device_manager);
    }

    fn attach_virtio_devices(&mut self) -> std::result::Result<(), StartMicrovmError> {
        self.init_mmio_device_manager();

        self.attach_block_devices()?;
        self.attach_net_devices()?;
        self.attach_vsock_devices()?;

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn get_serial_device(&self) -> Option<Arc<Mutex<dyn RawIOHandler>>> {
        Some(self.pio_device_manager.stdio_serial.clone())
    }

    #[cfg(target_arch = "aarch64")]
    fn get_serial_device(&self) -> Option<&Arc<Mutex<dyn RawIOHandler>>> {
        self.mmio_device_manager
            .as_ref()
            .unwrap()
            .get_raw_io_device(DeviceType::Serial)
    }

    #[cfg(target_arch = "aarch64")]
    fn get_mmio_device_info(&self) -> Option<&HashMap<(DeviceType, String), MMIODeviceInfo>> {
        if let Some(ref device_manager) = self.mmio_device_manager {
            Some(device_manager.get_device_info())
        } else {
            None
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn setup_interrupt_controller(&mut self) -> std::result::Result<(), StartMicrovmError> {
        self.vm
            .setup_irqchip()
            .map_err(StartMicrovmError::ConfigureVm)
    }

    #[cfg(target_arch = "aarch64")]
    fn setup_interrupt_controller(&mut self) -> std::result::Result<(), StartMicrovmError> {
        let vcpu_count = self
            .vm_config
            .vcpu_count
            .ok_or(StartMicrovmError::VcpusNotConfigured)?;

        self.vm
            .setup_irqchip(vcpu_count)
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

        self.init_mmio_device_manager();
        // `unwrap` is suitable for this context since this should be called only after the
        // device manager has been initialized.
        let device_manager = self.mmio_device_manager.as_mut().unwrap();

        // We rely on check_health function for making sure kernel_config is not None.
        let kernel_config = self.kernel_config.as_mut().ok_or(MissingKernelConfig)?;

        if kernel_config.cmdline.as_str().contains("console=") {
            device_manager
                .register_mmio_serial(self.vm.fd(), &mut kernel_config.cmdline)
                .map_err(RegisterMMIODevice)?;
        }

        device_manager
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
        let vcpu_count = self
            .vm_config
            .vcpu_count
            .ok_or(StartMicrovmError::VcpusNotConfigured)?;

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
                    self.pio_device_manager.io_bus.clone(),
                    vcpu_exit_evt,
                    request_ts.clone(),
                )
                .map_err(StartMicrovmError::Vcpu)?;

                vcpu.configure_x86_64(&self.vm_config, vm_memory, entry_addr)
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

    fn start_vcpus(
        &mut self,
        mut vcpus: Vec<Vcpu>,
        vmm_seccomp_filter: BpfProgram,
        vcpu_seccomp_filter: BpfProgram,
    ) -> std::result::Result<(), StartMicrovmError> {
        // vm_config has a default value for vcpu_count.
        let vcpu_count = self
            .vm_config
            .vcpu_count
            .ok_or(StartMicrovmError::VcpusNotConfigured)?;

        assert_eq!(
            vcpus.len(),
            vcpu_count as usize,
            "The number of vCPU fds is corrupted!"
        );

        Vcpu::register_kick_signal_handler();

        self.vcpus_handles.reserve(vcpu_count as usize);

        for mut vcpu in vcpus.drain(..) {
            if let Some(ref mmio_device_manager) = self.mmio_device_manager {
                vcpu.set_mmio_bus(mmio_device_manager.bus.clone());
            }

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
                .recv_timeout(Duration::from_millis(100))
            {
                Ok(VcpuResponse::Resumed) => (),
                _ => return Err(StartMicrovmError::VcpuResume),
            }
        }
        Ok(())
    }

    fn load_kernel(&mut self) -> std::result::Result<GuestAddress, StartMicrovmError> {
        use StartMicrovmError::*;

        // Trying to load kernel before initialzing guest memory is a programming error.
        let vm_memory = self
            .vm
            .memory()
            .expect("Cannot load kernel prior allocating memory!");

        // This is the easy way out of consuming the value of the kernel_cmdline.
        let kernel_config = self.kernel_config.as_mut().ok_or(MissingKernelConfig)?;

        let entry_addr = kernel_loader::load_kernel(
            vm_memory,
            &mut kernel_config.kernel_file,
            arch::get_kernel_start(),
        )
        .map_err(KernelLoader)?;

        // This is x86_64 specific since on aarch64 the commandline will be specified through the FDT.
        #[cfg(target_arch = "x86_64")]
        kernel_loader::load_cmdline(
            vm_memory,
            GuestAddress(arch::x86_64::layout::CMDLINE_START),
            &kernel_config
                .cmdline
                .as_cstring()
                .map_err(LoadCommandline)?,
        )
        .map_err(LoadCommandline)?;

        Ok(entry_addr)
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
    ) -> std::result::Result<InitrdConfig, LoadInitrdError>
    where
        F: Read + Seek,
    {
        use LoadInitrdError::*;

        let size: usize;
        // Get the image size
        match image.seek(SeekFrom::End(0)) {
            Err(e) => return Err(ReadInitrd(e)),
            Ok(0) => {
                return Err(ReadInitrd(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Initrd image seek returned a size of zero",
                )))
            }
            Ok(s) => size = s as usize,
        };
        // Go back to the image start
        image.seek(SeekFrom::Start(0)).map_err(ReadInitrd)?;

        // Get the target address
        let address = arch::initrd_load_addr(vm_memory, size).map_err(|_| LoadInitrd)?;

        // Load the image into memory
        vm_memory
            .read_from(GuestAddress(address), image, size)
            .map_err(|_| LoadInitrd)?;

        Ok(InitrdConfig {
            address: GuestAddress(address),
            size,
        })
    }

    fn configure_system(&self, vcpus: &[Vcpu]) -> std::result::Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        let vm_memory = self
            .vm
            .memory()
            .expect("Cannot configure registers prior to allocating memory!");

        let kernel_config = self.kernel_config.as_ref().ok_or(MissingKernelConfig)?;

        let initrd: Option<InitrdConfig> = match &kernel_config.initrd_file {
            Some(f) => {
                let initrd_file = f.try_clone();
                if initrd_file.is_err() {
                    return Err(InitrdLoader(LoadInitrdError::ReadInitrd(io::Error::from(
                        io::ErrorKind::InvalidData,
                    ))));
                }
                let res = Vmm::load_initrd(vm_memory, &mut initrd_file.unwrap())?;
                Some(res)
            }
            None => None,
        };

        #[cfg(target_arch = "x86_64")]
        arch::x86_64::configure_system(
            vm_memory,
            GuestAddress(arch::x86_64::layout::CMDLINE_START),
            kernel_config.cmdline.len() + 1,
            &initrd,
            vcpus.len() as u8,
        )
        .map_err(ConfigureSystem)?;

        #[cfg(target_arch = "aarch64")]
        {
            let vcpu_mpidr = vcpus.into_iter().map(|cpu| cpu.get_mpidr()).collect();
            arch::aarch64::configure_system(
                vm_memory,
                &kernel_config
                    .cmdline
                    .as_cstring()
                    .map_err(LoadCommandline)?,
                vcpu_mpidr,
                self.get_mmio_device_info(),
                self.vm.get_irqchip(),
                &initrd,
            )
            .map_err(ConfigureSystem)?;
        }

        self.configure_stdin()
    }

    fn register_events(&mut self) -> std::result::Result<(), StartMicrovmError> {
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

            self.epoll_context
                .add_epollin_event(&exit_poll_evt_fd, EpollDispatch::Exit)
                .map_err(|_| RegisterEvent)?;

            self.exit_evt = Some(exit_poll_evt_fd);
        }

        self.epoll_context.enable_stdin_event();

        Ok(())
    }

    fn configure_stdin(&self) -> std::result::Result<(), StartMicrovmError> {
        // Set raw mode for stdin.
        self.stdin_handle
            .lock()
            .set_raw_mode()
            .map_err(StartMicrovmError::StdinHandle)
    }

    /// Set up the initial microVM state and start the vCPU threads.
    pub fn start_microvm(
        &mut self,
        vmm_seccomp_filter: BpfProgram,
        vcpu_seccomp_filter: BpfProgram,
    ) -> UserResult {
        info!("VMM received instance start command");
        if self.is_instance_initialized() {
            return Err(StartMicrovmError::MicroVMAlreadyRunning.into());
        }

        let request_ts = TimestampUs::default();

        self.check_health()?;
        // Use expect() to crash if the other thread poisoned this lock.
        self.shared_info
            .write()
            .expect("Failed to start microVM because shared info couldn't be written due to poisoned lock")
            .state = InstanceState::Starting;

        self.init_guest_memory()?;

        let vcpus;

        // For x86_64 we need to create the interrupt controller before calling `KVM_CREATE_VCPUS`
        // while on aarch64 we need to do it the other way around.
        #[cfg(target_arch = "x86_64")]
        {
            self.setup_interrupt_controller()?;
            self.attach_virtio_devices()?;
            self.attach_legacy_devices()?;

            let entry_addr = self.load_kernel()?;
            vcpus = self.create_vcpus(entry_addr, request_ts)?;
        }

        #[cfg(target_arch = "aarch64")]
        {
            let entry_addr = self.load_kernel()?;
            vcpus = self.create_vcpus(entry_addr, request_ts)?;

            self.setup_interrupt_controller()?;
            self.attach_virtio_devices()?;
            self.attach_legacy_devices()?;
        }

        self.configure_system(&vcpus)?;

        self.register_events()?;

        self.start_vcpus(vcpus, vmm_seccomp_filter, vcpu_seccomp_filter)?;

        // Use expect() to crash if the other thread poisoned this lock.
        self.shared_info
            .write()
            .expect("Failed to start microVM because shared info couldn't be written due to poisoned lock")
            .state = InstanceState::Running;

        // Arm the log write timer.
        // TODO: the timer does not stop on InstanceStop.
        let timer_state = TimerState::Periodic {
            current: Duration::from_secs(WRITE_METRICS_PERIOD_SECONDS),
            interval: Duration::from_secs(WRITE_METRICS_PERIOD_SECONDS),
        };
        self.write_metrics_event_fd
            .set_state(timer_state, SetTimeFlags::Default);

        // Log the metrics straight away to check the process startup time.
        if LOGGER.log_metrics().is_err() {
            METRICS.logger.missed_metrics_count.inc();
        }

        Ok(())
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

    fn is_instance_initialized(&self) -> bool {
        let error_string = "Cannot check instance initialization as shared info lock is poisoned";
        self.shared_info.read().expect(error_string).state != InstanceState::Uninitialized
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
    pub fn run_event_loop(&mut self) -> Result<EventLoopExitReason> {
        // TODO: try handling of errors/failures without breaking this main loop.
        loop {
            let event = self.epoll_context.get_event()?;
            let evset = match epoll::Events::from_bits(event.events) {
                Some(evset) => evset,
                None => {
                    let evbits = event.events;
                    warn!("epoll: ignoring unknown event set: 0x{:x}", evbits);
                    continue;
                }
            };

            match self.epoll_context.dispatch_table[event.data as usize] {
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
                            self.epoll_context.disable_stdin_event();
                        }
                        Err(e) => {
                            warn!("error while reading stdin: {:?}", e);
                            self.epoll_context.disable_stdin_event();
                        }
                        Ok(count) => {
                            self.handle_stdin_event(&out[..count])?;
                        }
                    }
                }
                Some(EpollDispatch::DeviceHandler(device_idx, device_token)) => {
                    METRICS.vmm.device_events.inc();
                    match self
                        .epoll_context
                        .get_device_handler_by_handler_id(device_idx)
                    {
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
                None => {
                    // Do nothing.
                }
            }
        }
        // Currently, we never get to return with Ok(EventLoopExitReason::Break) because
        // we just invoke stop() whenever that would happen.
    }

    /// Set the guest boot source configuration.
    pub fn configure_boot_source(&mut self, boot_source_cfg: BootSourceConfig) -> UserResult {
        use BootSourceConfigError::{
            InvalidKernelCommandLine, InvalidKernelPath, UpdateNotAllowedPostBoot,
        };
        use ErrorKind::User;
        use VmmActionError::BootSource;

        if self.is_instance_initialized() {
            return Err(BootSource(User, UpdateNotAllowedPostBoot));
        }

        let kernel_file = File::open(boot_source_cfg.kernel_image_path)
            .map_err(|e| BootSource(User, InvalidKernelPath(e)))?;

        let initrd_file = match boot_source_cfg.initrd_path {
            None => None,
            Some(path) => Some({
                File::open(path).map_err(|_| {
                    VmmActionError::BootSource(
                        ErrorKind::User,
                        BootSourceConfigError::InvalidInitrdPath,
                    )
                })?
            }),
        };

        let mut cmdline = kernel_cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
        cmdline
            .insert_str(
                boot_source_cfg
                    .boot_args
                    .unwrap_or_else(|| String::from(DEFAULT_KERNEL_CMDLINE)),
            )
            .map_err(|e| BootSource(User, InvalidKernelCommandLine(e.to_string())))?;

        let kernel_config = KernelConfig {
            kernel_file,
            initrd_file,
            cmdline,
        };
        self.set_kernel_config(kernel_config);

        Ok(())
    }

    /// Set the machine configuration of the microVM.
    pub fn set_vm_configuration(&mut self, machine_config: VmConfig) -> UserResult {
        if self.is_instance_initialized() {
            return Err(VmConfigError::UpdateNotAllowedPostBoot.into());
        }

        if machine_config.vcpu_count == Some(0) {
            return Err(VmConfigError::InvalidVcpuCount.into());
        }

        if machine_config.mem_size_mib == Some(0) {
            return Err(VmConfigError::InvalidMemorySize.into());
        }

        let ht_enabled = machine_config
            .ht_enabled
            .unwrap_or_else(|| self.vm_config.ht_enabled.unwrap());

        let vcpu_count_value = machine_config
            .vcpu_count
            .unwrap_or_else(|| self.vm_config.vcpu_count.unwrap());

        // If hyperthreading is enabled or is to be enabled in this call
        // only allow vcpu count to be 1 or even.
        if ht_enabled && vcpu_count_value > 1 && vcpu_count_value % 2 == 1 {
            return Err(VmConfigError::InvalidVcpuCount.into());
        }

        // Update all the fields that have a new value.
        self.vm_config.vcpu_count = Some(vcpu_count_value);
        self.vm_config.ht_enabled = Some(ht_enabled);

        if machine_config.mem_size_mib.is_some() {
            self.vm_config.mem_size_mib = machine_config.mem_size_mib;
        }

        if machine_config.cpu_template.is_some() {
            self.vm_config.cpu_template = machine_config.cpu_template;
        }

        Ok(())
    }

    /// Inserts a network device to be attached when the VM starts.
    pub fn insert_net_device(&mut self, body: NetworkInterfaceConfig) -> UserResult {
        if self.is_instance_initialized() {
            return Err(NetworkInterfaceError::UpdateNotAllowedPostBoot.into());
        }
        self.device_configs
            .network_interface
            .insert(body)
            .map_err(|e| VmmActionError::NetworkConfig(ErrorKind::User, e))
    }

    /// Updates configuration for an emulated net device as described in `new_cfg`.
    pub fn update_net_device(&mut self, new_cfg: NetworkInterfaceUpdateConfig) -> UserResult {
        if !self.is_instance_initialized() {
            // VM not started yet, so we only need to update the device configs, not the actual
            // live device.
            let old_cfg = self
                .device_configs
                .network_interface
                .iter_mut()
                .find(|&&mut ref c| c.iface_id == new_cfg.iface_id)
                .ok_or(NetworkInterfaceError::DeviceIdNotFound)?;

            macro_rules! update_rate_limiter {
                ($rate_limiter: ident) => {{
                    if let Some(new_rlim_cfg) = new_cfg.$rate_limiter {
                        if let Some(ref mut old_rlim_cfg) = old_cfg.$rate_limiter {
                            // We already have an RX rate limiter set, so we'll update it.
                            old_rlim_cfg.update(&new_rlim_cfg);
                        } else {
                            // No old RX rate limiter; create one now.
                            old_cfg.$rate_limiter = Some(new_rlim_cfg);
                        }
                    }
                }};
            }

            update_rate_limiter!(rx_rate_limiter);
            update_rate_limiter!(tx_rate_limiter);
        } else {
            // If we got to here, the VM is running. We need to update the live device.

            let handler = self
                .epoll_context
                .get_device_handler_by_device_id::<virtio::NetEpollHandler>(
                    TYPE_NET,
                    &new_cfg.iface_id,
                )
                .map_err(NetworkInterfaceError::EpollHandlerNotFound)?;

            macro_rules! get_handler_arg {
                ($rate_limiter: ident, $metric: ident) => {{
                    new_cfg
                        .$rate_limiter
                        .map(|rl| rl.$metric.map(vmm_config::TokenBucketConfig::into))
                        .unwrap_or(None)
                }};
            }

            handler.patch_rate_limiters(
                get_handler_arg!(rx_rate_limiter, bandwidth),
                get_handler_arg!(rx_rate_limiter, ops),
                get_handler_arg!(tx_rate_limiter, bandwidth),
                get_handler_arg!(tx_rate_limiter, ops),
            );
        }

        Ok(())
    }

    /// Sets a vsock device to be attached when the VM starts.
    pub fn set_vsock_device(&mut self, config: VsockDeviceConfig) -> UserResult {
        if self.is_instance_initialized() {
            Err(VmmActionError::VsockConfig(
                ErrorKind::User,
                VsockError::UpdateNotAllowedPostBoot,
            ))
        } else {
            self.device_configs.vsock = Some(config);
            Ok(())
        }
    }

    /// Updates the path of the host file backing the emulated block device with id `drive_id`.
    pub fn set_block_device_path(&mut self, drive_id: String, path_on_host: String) -> UserResult {
        // Get the block device configuration specified by drive_id.
        let block_device_index = self
            .device_configs
            .block
            .get_index_of_drive_id(&drive_id)
            .ok_or(DriveError::InvalidBlockDeviceID)?;

        let file_path = PathBuf::from(path_on_host);
        // Try to open the file specified by path_on_host using the permissions of the block_device.
        let disk_file = OpenOptions::new()
            .read(true)
            .write(!self.device_configs.block.config_list[block_device_index].is_read_only())
            .open(&file_path)
            .map_err(|_| DriveError::CannotOpenBlockDevice)?;

        // Update the path of the block device with the specified path_on_host.
        self.device_configs.block.config_list[block_device_index].path_on_host = file_path;

        // When the microvm is running, we also need to update the drive handler and send a
        // rescan command to the drive.
        if self.is_instance_initialized() {
            self.update_drive_handler(&drive_id, disk_file)?;
            self.rescan_block_device(&drive_id)?;
        }
        Ok(())
    }

    /// Triggers a rescan of the host file backing the emulated block device with id `drive_id`.
    fn rescan_block_device(&mut self, drive_id: &str) -> UserResult {
        // Rescan can only happen after the guest is booted.
        if !self.is_instance_initialized() {
            return Err(DriveError::OperationNotAllowedPreBoot.into());
        }

        // Safe to unwrap() because mmio_device_manager is initialized in init_devices(), which is
        // called before the guest boots, and this function is called after boot.
        let device_manager = self.mmio_device_manager.as_ref().unwrap();
        for drive_config in self.device_configs.block.config_list.iter() {
            if drive_config.drive_id == *drive_id {
                // Use seek() instead of stat() (std::fs::Metadata) to support block devices.
                let new_size = File::open(&drive_config.path_on_host)
                    .and_then(|mut f| f.seek(SeekFrom::End(0)))
                    .map_err(|_| DriveError::BlockDeviceUpdateFailed)?;
                return device_manager
                    .update_drive(drive_id, new_size)
                    .map_err(|_| VmmActionError::from(DriveError::BlockDeviceUpdateFailed));
            }
        }
        Err(VmmActionError::from(DriveError::InvalidBlockDeviceID))
    }

    /// Inserts a block to be attached when the VM starts.
    // Only call this function as part of user configuration.
    // If the drive_id does not exist, a new Block Device Config is added to the list.
    pub fn insert_block_device(&mut self, block_device_config: BlockDeviceConfig) -> UserResult {
        if self.is_instance_initialized() {
            return Err(DriveError::UpdateNotAllowedPostBoot.into());
        }
        self.device_configs
            .block
            .insert(block_device_config)
            .map_err(VmmActionError::from)
    }

    /// Configures the logger as described in `logger_cfg`.
    pub fn init_logger(&self, logger_cfg: LoggerConfig) -> UserResult {
        if self.is_instance_initialized() {
            return Err(VmmActionError::Logger(
                ErrorKind::User,
                LoggerConfigError::InitializationFailure(
                    "Cannot initialize logger after boot.".to_string(),
                ),
            ));
        }

        let firecracker_version;
        {
            let guard = self.shared_info.read().unwrap();
            LOGGER.set_instance_id(guard.id.clone());
            firecracker_version = guard.vmm_version.clone();
        }

        LOGGER.set_level(match logger_cfg.level {
            LoggerLevel::Error => Level::Error,
            LoggerLevel::Warning => Level::Warn,
            LoggerLevel::Info => Level::Info,
            LoggerLevel::Debug => Level::Debug,
        });

        LOGGER.set_include_origin(logger_cfg.show_log_origin, logger_cfg.show_log_origin);
        LOGGER.set_include_level(logger_cfg.show_level);

        LOGGER
            .init(
                &AppInfo::new("Firecracker", &firecracker_version),
                Box::new(LoggerWriter::new(&logger_cfg.log_fifo).map_err(|e| {
                    VmmActionError::Logger(
                        ErrorKind::User,
                        LoggerConfigError::InitializationFailure(e.to_string()),
                    )
                })?),
                Box::new(LoggerWriter::new(&logger_cfg.metrics_fifo).map_err(|e| {
                    VmmActionError::Logger(
                        ErrorKind::User,
                        LoggerConfigError::InitializationFailure(e.to_string()),
                    )
                })?),
            )
            .map_err(|e| {
                VmmActionError::Logger(
                    ErrorKind::User,
                    LoggerConfigError::InitializationFailure(e.to_string()),
                )
            })
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

    /// Configures Vmm resources as described by the `config_json` param.
    pub fn configure_from_json(
        &mut self,
        config_json: String,
    ) -> std::result::Result<(), VmmActionError> {
        let vmm_config = serde_json::from_slice::<VmmConfig>(config_json.as_bytes())
            .unwrap_or_else(|e| {
                error!("Invalid json: {}", e);
                process::exit(i32::from(FC_EXIT_CODE_INVALID_JSON));
            });

        if let Some(logger) = vmm_config.logger {
            self.init_logger(logger)?;
        }
        self.configure_boot_source(vmm_config.boot_source)?;
        for drive_config in vmm_config.block_devices.into_iter() {
            self.insert_block_device(drive_config)?;
        }
        for net_config in vmm_config.net_devices.into_iter() {
            self.insert_net_device(net_config)?;
        }
        if let Some(machine_config) = vmm_config.machine_config {
            self.set_vm_configuration(machine_config)?;
        }
        if let Some(vsock_config) = vmm_config.vsock_device {
            self.set_vsock_device(vsock_config)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    macro_rules! assert_match {
        ($x:expr, $y:pat) => {{
            if let $y = $x {
                ()
            } else {
                panic!()
            }
        }};
    }

    use std::fs::File;
    use std::io::BufRead;
    use std::io::BufReader;
    use std::io::Cursor;
    use std::io::Write;
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use arch::DeviceType;
    use devices::virtio::{ActivateResult, MmioDevice, Queue};
    use dumbo::MacAddr;
    use utils::tempfile::TempFile;
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
                TempFile::new().expect("Failed to create temporary kernel file.");
            let kernel_path = match cust_kernel_path {
                Some(kernel_path) => kernel_path,
                None => kernel_temp_file.as_path().to_path_buf(),
            };
            let kernel_file = File::open(kernel_path).expect("Cannot open kernel file");
            let mut cmdline = kernel_cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
            assert!(cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).is_ok());
            let kernel_cfg = KernelConfig {
                cmdline,
                kernel_file,
                initrd_file: None,
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
            mem: GuestMemoryMmap,
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
    fn test_insert_block_device() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        let f = TempFile::new().unwrap();
        // Test that creating a new block device returns the correct output.
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: f.as_path().to_path_buf(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            rate_limiter: None,
        };
        assert!(vmm.insert_block_device(root_block_device.clone()).is_ok());
        assert!(vmm
            .device_configs
            .block
            .config_list
            .contains(&root_block_device));

        // Test that updating a block device returns the correct output.
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: f.as_path().to_path_buf(),
            is_root_device: true,
            partuuid: None,
            is_read_only: true,
            rate_limiter: None,
        };
        assert!(vmm.insert_block_device(root_block_device.clone()).is_ok());
        assert!(vmm
            .device_configs
            .block
            .config_list
            .contains(&root_block_device));

        // Test insert second drive with the same path fails.
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("dummy_dev"),
            path_on_host: f.as_path().to_path_buf(),
            is_root_device: false,
            partuuid: None,
            is_read_only: true,
            rate_limiter: None,
        };
        assert!(vmm.insert_block_device(root_block_device.clone()).is_err());

        // Test inserting a second drive is ok.
        let f = TempFile::new().unwrap();
        // Test that creating a new block device returns the correct output.
        let non_root = BlockDeviceConfig {
            drive_id: String::from("non_root"),
            path_on_host: f.as_path().to_path_buf(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            rate_limiter: None,
        };
        assert!(vmm.insert_block_device(non_root).is_ok());

        // Test that making the second device root fails (it would result in 2 root block
        // devices.
        let non_root = BlockDeviceConfig {
            drive_id: String::from("non_root"),
            path_on_host: f.as_path().to_path_buf(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            rate_limiter: None,
        };
        assert!(vmm.insert_block_device(non_root).is_err());

        // Test update after boot.
        vmm.set_instance_state(InstanceState::Running);
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: f.as_path().to_path_buf(),
            is_root_device: false,
            partuuid: None,
            is_read_only: true,
            rate_limiter: None,
        };
        assert!(vmm.insert_block_device(root_block_device).is_err())
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

        let kernel_file_temp = TempFile::new().unwrap();
        vmm.set_kernel_config(KernelConfig {
            cmdline: kernel_cmdline::Cmdline::new(10),
            kernel_file: File::open(kernel_file_temp.as_path()).unwrap(),
            initrd_file: None,
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
    fn test_attach_block_devices() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        let block_file = TempFile::new().unwrap();

        // Use Case 1: Root Block Device is not specified through PARTUUID.
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: block_file.as_path().to_path_buf(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            rate_limiter: None,
        };
        // Test that creating a new block device returns the correct output.
        assert!(vmm.insert_block_device(root_block_device.clone()).is_ok());
        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.memory().is_some());
        assert!(vmm.setup_interrupt_controller().is_ok());

        vmm.default_kernel_config(None);
        vmm.init_mmio_device_manager();

        assert!(vmm.attach_block_devices().is_ok());
        assert!(vmm.get_kernel_cmdline_str().contains("root=/dev/vda rw"));

        // Use Case 2: Root Block Device is specified through PARTUUID.
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: block_file.as_path().to_path_buf(),
            is_root_device: true,
            partuuid: Some("0eaa91a0-01".to_string()),
            is_read_only: false,
            rate_limiter: None,
        };

        // Test that creating a new block device returns the correct output.
        assert!(vmm.insert_block_device(root_block_device.clone()).is_ok());
        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.memory().is_some());
        assert!(vmm.setup_interrupt_controller().is_ok());

        vmm.default_kernel_config(None);
        vmm.init_mmio_device_manager();

        assert!(vmm.attach_block_devices().is_ok());
        assert!(vmm
            .get_kernel_cmdline_str()
            .contains("root=PARTUUID=0eaa91a0-01 rw"));

        // Use Case 3: Root Block Device is not added at all.
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        let non_root_block_device = BlockDeviceConfig {
            drive_id: String::from("not_root"),
            path_on_host: block_file.as_path().to_path_buf(),
            is_root_device: false,
            partuuid: Some("0eaa91a0-01".to_string()),
            is_read_only: false,
            rate_limiter: None,
        };

        // Test that creating a new block device returns the correct output.
        assert!(vmm
            .insert_block_device(non_root_block_device.clone())
            .is_ok());
        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.memory().is_some());
        assert!(vmm.setup_interrupt_controller().is_ok());

        vmm.default_kernel_config(None);
        vmm.init_mmio_device_manager();

        assert!(vmm.attach_block_devices().is_ok());
        // Test that kernel commandline does not contain either /dev/vda or PARTUUID.
        assert!(!vmm.get_kernel_cmdline_str().contains("root=PARTUUID="));
        assert!(!vmm.get_kernel_cmdline_str().contains("root=/dev/vda"));

        // Test that the non root device is attached.
        {
            let device_manager = vmm.mmio_device_manager.as_ref().unwrap();
            assert!(device_manager
                .get_device(
                    DeviceType::Virtio(TYPE_BLOCK),
                    &non_root_block_device.drive_id
                )
                .is_some());
        }

        // Test partial update of block devices.
        let new_block = TempFile::new().unwrap();
        let path = String::from(new_block.as_path().to_path_buf().to_str().unwrap());
        assert!(vmm
            .set_block_device_path("not_root".to_string(), path)
            .is_ok());

        // Test partial update of block device fails due to invalid file.
        assert!(vmm
            .set_block_device_path("not_root".to_string(), String::from("dummy_path"))
            .is_err());

        vmm.set_instance_state(InstanceState::Running);

        // Test updating the block device path, after instance start.
        let path = String::from(new_block.as_path().to_path_buf().to_str().unwrap());
        match vmm.set_block_device_path("not_root".to_string(), path) {
            Err(VmmActionError::DriveConfig(ErrorKind::User, DriveError::EpollHandlerNotFound)) => {
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
            Ok(_) => {
                panic!("Updating block device path shouldn't be possible without an epoll handler.")
            }
        }
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
                initrd_path: None,
                boot_args: None
            })
            .is_err());

        // Test valid kernel path and invalid cmdline.
        let kernel_file = TempFile::new().expect("Failed to create temporary kernel file.");
        let kernel_path = String::from(kernel_file.as_path().to_path_buf().to_str().unwrap());
        let initrd_file = TempFile::new().expect("Failed to create temporary initrd file.");
        let initrd_path = String::from(initrd_file.as_path().to_path_buf().to_str().unwrap());
        let invalid_cmdline = String::from_utf8(vec![b'X'; arch::CMDLINE_MAX_SIZE + 1]).unwrap();
        assert!(vmm
            .configure_boot_source(BootSourceConfig {
                kernel_image_path: kernel_path.clone(),
                initrd_path: None,
                boot_args: Some(invalid_cmdline)
            })
            .is_err());

        // Test valid configuration.
        assert!(vmm
            .configure_boot_source(BootSourceConfig {
                kernel_image_path: kernel_path.clone(),
                initrd_path: None,
                boot_args: None
            })
            .is_ok());
        assert!(vmm
            .configure_boot_source(BootSourceConfig {
                kernel_image_path: kernel_path.clone(),
                initrd_path: None,
                boot_args: Some(String::from("reboot=k"))
            })
            .is_ok());

        // Test invalid initrd path
        assert!(vmm
            .configure_boot_source(BootSourceConfig {
                kernel_image_path: kernel_path.clone(),
                initrd_path: Some(String::from("dummy-path")),
                boot_args: None
            })
            .is_err());

        // Test valid configuration + initrd.
        assert!(vmm
            .configure_boot_source(BootSourceConfig {
                kernel_image_path: kernel_path.clone(),
                initrd_path: Some(initrd_path.clone()),
                boot_args: None
            })
            .is_ok());
        assert!(vmm
            .configure_boot_source(BootSourceConfig {
                kernel_image_path: kernel_path.clone(),
                initrd_path: Some(initrd_path.clone()),
                boot_args: Some(String::from("reboot=k"))
            })
            .is_ok());

        // Test valid configuration after boot (should fail).
        vmm.set_instance_state(InstanceState::Running);
        assert!(vmm
            .configure_boot_source(BootSourceConfig {
                kernel_image_path: kernel_path.clone(),
                initrd_path: None,
                boot_args: None
            })
            .is_err());
    }

    #[test]
    fn test_block_device_rescan() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.default_kernel_config(None);

        let root_file = TempFile::new().unwrap();
        let scratch_file = TempFile::new().unwrap();
        let scratch_id = "not_root".to_string();

        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: root_file.as_path().to_path_buf(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            rate_limiter: None,
        };
        let non_root_block_device = BlockDeviceConfig {
            drive_id: scratch_id.clone(),
            path_on_host: scratch_file.as_path().to_path_buf(),
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
        let log_file = TempFile::new().unwrap();
        let metrics_file = TempFile::new().unwrap();
        let desc = LoggerConfig {
            log_fifo: log_file.as_path().to_str().unwrap().to_string(),
            metrics_fifo: metrics_file.as_path().to_str().unwrap().to_string(),
            level: LoggerLevel::Warning,
            show_level: true,
            show_log_origin: true,
        };

        let mut vmm = create_vmm_object(InstanceState::Running);
        assert!(vmm.init_logger(desc).is_err());

        // Reset vmm state to test the other scenarios.
        vmm.set_instance_state(InstanceState::Uninitialized);

        // Error case: initializing logger with invalid log pipe returns error.
        let desc = LoggerConfig {
            log_fifo: String::from("not_found_file_log"),
            metrics_fifo: metrics_file.as_path().to_str().unwrap().to_string(),
            level: LoggerLevel::Debug,
            show_level: false,
            show_log_origin: false,
        };
        assert!(vmm.init_logger(desc).is_err());

        // Error case: initializing logger with invalid metrics pipe returns error.
        let desc = LoggerConfig {
            log_fifo: log_file.as_path().to_str().unwrap().to_string(),
            metrics_fifo: String::from("not_found_file_metrics"),
            level: LoggerLevel::Debug,
            show_level: false,
            show_log_origin: false,
        };
        assert!(vmm.init_logger(desc).is_err());

        // Error case: initializing logger with invalid metrics and log pipe returns error.
        let desc = LoggerConfig {
            log_fifo: String::from("not_found_file_log"),
            metrics_fifo: String::from("not_found_file_metrics"),
            level: LoggerLevel::Warning,
            show_level: false,
            show_log_origin: false,
        };
        assert!(vmm.init_logger(desc).is_err());

        // Initializing logger with valid pipes is ok.
        let log_file = TempFile::new().unwrap();
        let metrics_file = TempFile::new().unwrap();
        let desc = LoggerConfig {
            log_fifo: log_file.as_path().to_str().unwrap().to_string(),
            metrics_fifo: metrics_file.as_path().to_str().unwrap().to_string(),
            level: LoggerLevel::Info,
            show_level: true,
            show_log_origin: true,
        };
        // Flushing metrics before initializing logger is not erroneous.
        assert!(vmm.flush_metrics().is_ok());

        assert!(vmm.init_logger(desc.clone()).is_ok());
        assert!(vmm.init_logger(desc).is_err());

        assert!(vmm.flush_metrics().is_ok());

        let f = File::open(metrics_file.as_path()).unwrap();
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

        let f = File::open(log_file.as_path()).unwrap();
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

    #[test]
    fn test_create_vcpus() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.default_kernel_config(None);

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.memory().is_some());

        #[cfg(target_arch = "x86_64")]
        // `KVM_CREATE_VCPU` fails if the irqchip is not created beforehand. This is x86_64 specific.
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

    fn create_guest_mem_at(at: GuestAddress, size: usize) -> GuestMemoryMmap {
        GuestMemoryMmap::new(&[(at, size)]).unwrap()
    }

    fn create_guest_mem_with_size(size: usize) -> GuestMemoryMmap {
        const MEM_START: GuestAddress = GuestAddress(0x0);

        GuestMemoryMmap::new(&[(MEM_START, size)]).unwrap()
    }

    fn make_test_bin() -> Vec<u8> {
        let mut fake_bin = Vec::new();
        fake_bin.resize(1_000_000, 0xAA);
        fake_bin
    }

    #[test]
    // Test that loading the initrd is successful on different archs.
    fn test_load_initrd() {
        let image = make_test_bin();

        let mem_size: usize = image.len() * 2 + arch::PAGE_SIZE;

        #[cfg(target_arch = "x86_64")]
        let gm = create_guest_mem_with_size(mem_size);

        #[cfg(target_arch = "aarch64")]
        let gm = create_guest_mem_with_size(mem_size + arch::aarch64::layout::FDT_MAX_SIZE);

        let res = Vmm::load_initrd(&gm, &mut Cursor::new(&image));
        assert!(res.is_ok());
        let initrd = res.unwrap();
        assert!(gm.address_in_range(initrd.address));
        assert_eq!(initrd.size, image.len());
    }

    #[test]
    fn test_load_initrd_no_memory() {
        let gm = create_guest_mem_with_size(79);
        let image = make_test_bin();
        let res = Vmm::load_initrd(&gm, &mut Cursor::new(&image));
        assert!(res.is_err());
        assert_eq!(
            LoadInitrdError::LoadInitrd.to_string(),
            res.err().unwrap().to_string()
        );
    }

    #[test]
    fn test_load_initrd_unaligned() {
        let image = vec![1, 2, 3, 4];
        let gm = create_guest_mem_at(GuestAddress(arch::PAGE_SIZE as u64 + 1), image.len() * 2);

        let res = Vmm::load_initrd(&gm, &mut Cursor::new(&image));
        assert!(res.is_err());
        assert_eq!(
            LoadInitrdError::LoadInitrd.to_string(),
            res.err().unwrap().to_string()
        );
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
    fn test_configure_system_with_initrd() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.default_kernel_config(None);

        let initrd_temp_file = TempFile::new().expect("Failed to create temporary initrd file.");
        initrd_temp_file
            .as_file()
            .write_all(b"This is a nice initrd")
            .expect("Cannot write temporary initrd file");
        let initrd_path = String::from(initrd_temp_file.as_path().to_path_buf().to_str().unwrap());
        let initrd_file = File::open(initrd_path).expect("Cannot open initrd file");

        vmm.kernel_config = {
            let cfg = vmm.kernel_config.unwrap();
            Some(KernelConfig {
                kernel_file: cfg.kernel_file,
                initrd_file: Some(initrd_file),
                cmdline: cfg.cmdline,
            })
        };

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.memory().is_some());

        // We need this so that configure_system finds a properly setup GIC device
        #[cfg(target_arch = "aarch64")]
        assert!(vmm.vm.setup_irqchip(1).is_ok());

        assert!(vmm.configure_system(&Vec::new()).is_ok());
        vmm.stdin_handle.lock().set_canon_mode().unwrap();
    }

    #[test]
    fn test_configure_system_with_empty_initrd() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.default_kernel_config(None);

        let initrd_temp_file = TempFile::new().expect("Failed to create temporary initrd file.");
        let initrd_path = String::from(initrd_temp_file.as_path().to_path_buf().to_str().unwrap());
        let initrd_file = File::open(initrd_path).expect("Cannot open initrd file");

        vmm.kernel_config = {
            let cfg = vmm.kernel_config.unwrap();
            Some(KernelConfig {
                kernel_file: cfg.kernel_file,
                initrd_file: Some(initrd_file),
                cmdline: cfg.cmdline,
            })
        };

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.memory().is_some());

        // We need this so that configure_system finds a properly setup GIC device
        #[cfg(target_arch = "aarch64")]
        assert!(vmm.vm.setup_irqchip(1).is_ok());

        assert!(vmm.configure_system(&Vec::new()).is_err());
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

        let kernel_file = TempFile::new().unwrap();
        let rootfs_file = TempFile::new().unwrap();

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
            rootfs_file.as_path().to_str().unwrap()
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
            kernel_file.as_path().to_str().unwrap()
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
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
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
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
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
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
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
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
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
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        assert!(vmm.configure_from_json(json).is_ok());
    }
}
