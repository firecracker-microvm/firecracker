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
extern crate futures;
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
extern crate fc_util;
extern crate kernel;
#[macro_use]
extern crate logger;
extern crate memory_model;
extern crate net_util;
extern crate rate_limiter;
extern crate seccomp;
extern crate sys_util;

/// Syscalls allowed through the seccomp filter.
pub mod default_syscalls;
mod device_manager;
/// Signal handling utilities.
pub mod signal_handler;
/// Wrappers over structures used to configure the VMM.
pub mod vmm_config;
mod vstate;

use futures::sync::oneshot;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::fs::{metadata, File, OpenOptions};
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::process;
use std::result;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Barrier, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use kvm_bindings::KVM_API_VERSION;
use kvm_ioctls::{Cap, Kvm};
use timerfd::{ClockId, SetTimeFlags, TimerFd, TimerState};

#[cfg(target_arch = "aarch64")]
use arch::DeviceType;
use device_manager::legacy::PortIODeviceManager;
#[cfg(target_arch = "aarch64")]
use device_manager::mmio::MMIODeviceInfo;
use device_manager::mmio::MMIODeviceManager;
use devices::legacy::I8042DeviceError;
use devices::virtio;
use devices::virtio::vsock::{TYPE_VSOCK, VSOCK_EVENTS_COUNT};
use devices::virtio::EpollConfigConstructor;
use devices::virtio::{BLOCK_EVENTS_COUNT, TYPE_BLOCK};
use devices::virtio::{NET_EVENTS_COUNT, TYPE_NET};
use devices::RawIOHandler;
use devices::{DeviceEventT, EpollHandler};
use fc_util::{get_time, ClockType};
use kernel::cmdline as kernel_cmdline;
use kernel::loader as kernel_loader;
use logger::error::LoggerError;
#[cfg(target_arch = "x86_64")]
use logger::LogOption;
use logger::{AppInfo, Level, Metric, LOGGER, METRICS};
use memory_model::{GuestAddress, GuestMemory};
use net_util::TapError;
#[cfg(target_arch = "aarch64")]
use serde_json::Value;
use sys_util::{EventFd, Terminal};
use vmm_config::boot_source::{BootSourceConfig, BootSourceConfigError};
use vmm_config::device_config::DeviceConfigs;
use vmm_config::drive::{BlockDeviceConfig, BlockDeviceConfigs, DriveError};
use vmm_config::instance_info::{InstanceInfo, InstanceState, StartMicrovmError};
use vmm_config::logger::{LoggerConfig, LoggerConfigError, LoggerLevel};
use vmm_config::machine_config::{VmConfig, VmConfigError};
use vmm_config::net::{
    NetworkInterfaceConfig, NetworkInterfaceConfigs, NetworkInterfaceError,
    NetworkInterfaceUpdateConfig,
};
use vmm_config::vsock::{VsockDeviceConfig, VsockError};
use vstate::{Vcpu, Vm};

/// Default guest kernel command line:
/// - `reboot=k` shut down the guest on reboot, instead of well... rebooting;
/// - `panic=1` on panic, reboot after 1 second;
/// - `pci=off` do not scan for PCI devices (save boot time);
/// - `nomodules` disable loadable kernel module support;
/// - `8250.nr_uarts=0` disable 8250 serial interface;
/// - `i8042.noaux` do not probe the i8042 controller for an attached mouse (save boot time);
/// - `i8042.nomux` do not probe i8042 for a multiplexing controller (save boot time);
/// - `i8042.nopnp` do not use ACPIPnP to discover KBD/AUX controllers (save boot time);
/// - `i8042.dumbkbd` do not attempt to control kbd state via the i8042 (save boot time).
const DEFAULT_KERNEL_CMDLINE: &str = "reboot=k panic=1 pci=off nomodules 8250.nr_uarts=0 \
                                      i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd";
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

/// Errors associated with the VMM internal logic. These errors cannot be generated by direct user
/// input, but can result from bad configuration of the host (for example if Firecracker doesn't
/// have permissions to open the KVM fd).
pub enum Error {
    /// Cannot receive message from the API.
    ApiChannel,
    /// Legacy devices work with Event file descriptors and the creation can fail because
    /// of resource exhaustion.
    CreateLegacyDevice(device_manager::legacy::Error),
    /// An operation on the epoll instance failed due to resource exhaustion or bad configuration.
    EpollFd(io::Error),
    /// Cannot read from an Event file descriptor.
    EventFd(io::Error),
    /// An event arrived for a device, but the dispatcher can't find the event (epoll) handler.
    DeviceEventHandlerNotFound,
    /// An epoll handler can't be downcasted to the desired type.
    DeviceEventHandlerInvalidDowncast,
    /// Cannot open /dev/kvm. Either the host does not have KVM or Firecracker does not have
    /// permission to open the file descriptor.
    Kvm(io::Error),
    /// The host kernel reports an invalid KVM API version.
    KvmApiVersion(i32),
    /// Cannot initialize the KVM context due to missing capabilities.
    KvmCap(kvm_ioctls::Cap),
    /// Epoll wait failed.
    Poll(io::Error),
    /// Write to the serial console failed.
    Serial(io::Error),
    /// Cannot create Timer file descriptor.
    TimerFd(io::Error),
    /// Cannot open the VM file descriptor.
    Vm(vstate::Error),
}

// Implementing Debug as these errors are mostly used in panics & expects.
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            ApiChannel => write!(f, "ApiChannel: error receiving data from the API server"),
            CreateLegacyDevice(e) => write!(f, "Error creating legacy device: {:?}", e),
            EpollFd(e) => write!(f, "Epoll fd error: {}", e.to_string()),
            EventFd(e) => write!(f, "Event fd error: {}", e.to_string()),
            DeviceEventHandlerNotFound => write!(
                f,
                "Device event handler not found. This might point to a guest device driver issue."
            ),
            DeviceEventHandlerInvalidDowncast => write!(
                f,
                "Device event handler couldn't be downcasted to expected type."
            ),
            Kvm(os_err) => write!(f, "Cannot open /dev/kvm. Error: {}", os_err.to_string()),
            KvmApiVersion(ver) => write!(f, "Bad KVM API version: {}", ver),
            KvmCap(cap) => write!(f, "Missing KVM capability: {:?}", cap),
            Poll(e) => write!(f, "Epoll wait failed: {}", e.to_string()),
            Serial(e) => write!(f, "Error writing to the serial console: {:?}", e),
            TimerFd(e) => write!(f, "Error creating timer fd: {}", e.to_string()),
            Vm(e) => write!(f, "Error opening VM fd: {:?}", e),
        }
    }
}

/// Types of errors associated with vmm actions.
#[derive(Clone, Debug, PartialEq)]
pub enum ErrorKind {
    /// User Errors describe bad configuration (user input).
    User,
    /// Internal Errors are unrelated to the user and usually refer to logical errors
    /// or bad management of resources (memory, file descriptors & others).
    Internal,
}

/// Wrapper for all errors associated with VMM actions.
#[derive(Debug)]
pub enum VmmActionError {
    /// The action `ConfigureBootSource` failed either because of bad user input (`ErrorKind::User`)
    /// or an internal error (`ErrorKind::Internal`).
    BootSource(ErrorKind, BootSourceConfigError),
    /// One of the actions `InsertBlockDevice`, `RescanBlockDevice` or `UpdateBlockDevicePath`
    /// failed either because of bad user input (`ErrorKind::User`) or an
    /// internal error (`ErrorKind::Internal`).
    DriveConfig(ErrorKind, DriveError),
    /// The action `ConfigureLogger` failed either because of bad user input (`ErrorKind::User`) or
    /// an internal error (`ErrorKind::Internal`).
    Logger(ErrorKind, LoggerConfigError),
    /// One of the actions `GetVmConfiguration` or `SetVmConfiguration` failed either because of bad
    /// input (`ErrorKind::User`) or an internal error (`ErrorKind::Internal`).
    MachineConfig(ErrorKind, VmConfigError),
    /// The action `InsertNetworkDevice` failed either because of bad user input (`ErrorKind::User`)
    /// or an internal error (`ErrorKind::Internal`).
    NetworkConfig(ErrorKind, NetworkInterfaceError),
    /// The action `StartMicroVm` failed either because of bad user input (`ErrorKind::User`) or
    /// an internal error (`ErrorKind::Internal`).
    StartMicrovm(ErrorKind, StartMicrovmError),
    /// The action `SendCtrlAltDel` failed. Details are provided by the device-specific error
    /// `I8042DeviceError`.
    SendCtrlAltDel(ErrorKind, I8042DeviceError),
    /// The action `set_vsock_device` failed either because of bad user input (`ErrorKind::User`)
    /// or an internal error (`ErrorKind::Internal`).
    VsockConfig(ErrorKind, VsockError),
}

// It's convenient to turn DriveErrors into VmmActionErrors directly.
impl std::convert::From<DriveError> for VmmActionError {
    fn from(e: DriveError) -> Self {
        use DriveError::*;

        // This match is used to force developers who add new types of
        // `DriveError`s to explicitly consider what kind they should
        // have. Remove this comment when a match arm that yields
        // something other than `ErrorKind::User` is added.
        let kind = match e {
            // User errors.
            CannotOpenBlockDevice
            | InvalidBlockDeviceID
            | InvalidBlockDevicePath
            | BlockDevicePathAlreadyExists
            | EpollHandlerNotFound
            | BlockDeviceUpdateFailed
            | OperationNotAllowedPreBoot
            | UpdateNotAllowedPostBoot
            | RootBlockDeviceAlreadyAdded => ErrorKind::User,
        };

        VmmActionError::DriveConfig(kind, e)
    }
}

// It's convenient to turn VmConfigErrors into VmmActionErrors directly.
impl std::convert::From<VmConfigError> for VmmActionError {
    fn from(e: VmConfigError) -> Self {
        use VmConfigError::*;

        // This match is used to force developers who add new types of
        // `VmConfigError`s to explicitly consider what kind they should
        // have. Remove this comment when a match arm that yields
        // something other than `ErrorKind::User` is added.
        let kind = match e {
            // User errors.
            InvalidVcpuCount | InvalidMemorySize | UpdateNotAllowedPostBoot => ErrorKind::User,
        };

        VmmActionError::MachineConfig(kind, e)
    }
}

// It's convenient to turn NetworkInterfaceErrors into VmmActionErrors directly.
impl std::convert::From<NetworkInterfaceError> for VmmActionError {
    fn from(e: NetworkInterfaceError) -> Self {
        use NetworkInterfaceError::*;
        use TapError::*;

        let kind = match e {
            // User errors.
            GuestMacAddressInUse(_)
            | HostDeviceNameInUse(_)
            | DeviceIdNotFound
            | UpdateNotAllowedPostBoot => ErrorKind::User,
            // Internal errors.
            EpollHandlerNotFound(_) | RateLimiterUpdateFailed(_) => ErrorKind::Internal,
            OpenTap(ref te) => match te {
                // User errors.
                OpenTun(_) | CreateTap(_) | InvalidIfname => ErrorKind::User,
                // Internal errors.
                IoctlError(_) | NetUtil(_) => ErrorKind::Internal,
            },
        };

        VmmActionError::NetworkConfig(kind, e)
    }
}

// It's convenient to turn StartMicrovmErrors into VmmActionErrors directly.
impl std::convert::From<StartMicrovmError> for VmmActionError {
    fn from(e: StartMicrovmError) -> Self {
        use StartMicrovmError::*;

        let kind = match e {
            // User errors.
            CreateBlockDevice(_)
            | CreateNetDevice(_)
            | CreateVsockDevice
            | KernelCmdline(_)
            | KernelLoader(_)
            | MicroVMAlreadyRunning
            | MissingKernelConfig
            | NetDeviceNotConfigured
            | OpenBlockDevice(_)
            | VcpusNotConfigured => ErrorKind::User,
            // Internal errors.
            ConfigureSystem(_)
            | ConfigureVm(_)
            | CreateRateLimiter(_)
            | DeviceManager
            | EventFd
            | GuestMemory(_)
            | LegacyIOBus(_)
            | RegisterBlockDevice(_)
            | RegisterEvent
            | RegisterMMIODevice(_)
            | RegisterNetDevice(_)
            | RegisterVsockDevice(_)
            | SeccompFilters(_)
            | Vcpu(_)
            | VcpuConfigure(_)
            | VcpuSpawn(_) => ErrorKind::Internal,
            // The only user `LoadCommandline` error is `CommandLineOverflow`.
            LoadCommandline(ref cle) => match cle {
                kernel::cmdline::Error::CommandLineOverflow => ErrorKind::User,
                _ => ErrorKind::Internal,
            },
            StdinHandle(_) => ErrorKind::Internal,
        };
        VmmActionError::StartMicrovm(kind, e)
    }
}

impl VmmActionError {
    /// Returns the error type.
    pub fn kind(&self) -> &ErrorKind {
        use self::VmmActionError::*;

        match *self {
            BootSource(ref kind, _) => kind,
            DriveConfig(ref kind, _) => kind,
            Logger(ref kind, _) => kind,
            MachineConfig(ref kind, _) => kind,
            NetworkConfig(ref kind, _) => kind,
            StartMicrovm(ref kind, _) => kind,
            SendCtrlAltDel(ref kind, _) => kind,
            VsockConfig(ref kind, _) => kind,
        }
    }
}

impl Display for VmmActionError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::VmmActionError::*;

        let error = match *self {
            BootSource(_, ref err) => err as &ToString,
            DriveConfig(_, ref err) => err,
            Logger(_, ref err) => err,
            MachineConfig(_, ref err) => err,
            NetworkConfig(_, ref err) => err,
            StartMicrovm(_, ref err) => err,
            SendCtrlAltDel(_, ref err) => err,
            VsockConfig(_, ref err) => err,
        };

        write!(f, "{}", error.to_string())
    }
}

/// This enum represents the public interface of the VMM. Each action contains various
/// bits of information (ids, paths, etc.), together with an OutcomeSender, which is always present.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum VmmAction {
    /// Configure the boot source of the microVM using as input the `ConfigureBootSource`. This
    /// action can only be called before the microVM has booted. The response is sent using the
    /// `OutcomeSender`.
    ConfigureBootSource(BootSourceConfig, OutcomeSender),
    /// Configure the logger using as input the `LoggerConfig`. This action can only be called
    /// before the microVM has booted. The response is sent using the `OutcomeSender`.
    ConfigureLogger(LoggerConfig, OutcomeSender),
    /// Get the configuration of the microVM. The action response is sent using the `OutcomeSender`.
    GetVmConfiguration(OutcomeSender),
    /// Flush the metrics. This action can only be called after the logger has been configured.
    /// The response is sent using the `OutcomeSender`.
    FlushMetrics(OutcomeSender),
    /// Add a new block device or update one that already exists using the `BlockDeviceConfig` as
    /// input. This action can only be called before the microVM has booted. The response
    /// is sent using the `OutcomeSender`.
    InsertBlockDevice(BlockDeviceConfig, OutcomeSender),
    /// Add a new network interface config or update one that already exists using the
    /// `NetworkInterfaceConfig` as input. This action can only be called before the microVM has
    /// booted. The response is sent using the `OutcomeSender`.
    InsertNetworkDevice(NetworkInterfaceConfig, OutcomeSender),
    /// Set the vsock device or update the one that already exists using the
    /// `VsockDeviceConfig` as input. This action can only be called before the microVM has
    /// booted. The response is sent using the `OutcomeSender`.
    SetVsockDevice(VsockDeviceConfig, OutcomeSender),
    /// Update the size of an existing block device specified by an ID. The ID is the first data
    /// associated with this enum variant. This action can only be called after the microVM is
    /// started. The response is sent using the `OutcomeSender`.
    RescanBlockDevice(String, OutcomeSender),
    /// Set the microVM configuration (memory & vcpu) using `VmConfig` as input. This
    /// action can only be called before the microVM has booted. The action
    /// response is sent using the `OutcomeSender`.
    SetVmConfiguration(VmConfig, OutcomeSender),
    /// Launch the microVM. This action can only be called before the microVM has booted.
    /// The response is sent using the `OutcomeSender`.
    StartMicroVm(OutcomeSender),
    /// Send CTRL+ALT+DEL to the microVM, using the i8042 keyboard function. If an AT-keyboard
    /// driver is listening on the guest end, this can be used to shut down the microVM gracefully.
    SendCtrlAltDel(OutcomeSender),
    /// Update the path of an existing block device. The data associated with this variant
    /// represents the `drive_id` and the `path_on_host`. The response is sent using
    /// the `OutcomeSender`.
    UpdateBlockDevicePath(String, String, OutcomeSender),
    /// Update a network interface, after microVM start. Currently, the only updatable properties
    /// are the RX and TX rate limiters.
    UpdateNetworkInterface(NetworkInterfaceUpdateConfig, OutcomeSender),
}

/// The enum represents the response sent by the VMM in case of success. The response is either
/// empty, when no data needs to be sent, or an internal VMM structure.
#[derive(Debug)]
pub enum VmmData {
    /// No data is sent on the channel.
    Empty,
    /// The microVM configuration represented by `VmConfig`.
    MachineConfiguration(VmConfig),
}

/// Data type used to communicate between the API and the VMM.
pub type VmmRequestOutcome = std::result::Result<VmmData, VmmActionError>;
/// One shot channel used to send a request.
pub type OutcomeSender = oneshot::Sender<VmmRequestOutcome>;
/// One shot channel used to receive a response.
pub type OutcomeReceiver = oneshot::Receiver<VmmRequestOutcome>;

type Result<T> = std::result::Result<T, Error>;

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

/// Holds a micro-second resolution timestamp with both the real time and cpu time.
#[derive(Clone, Default)]
pub struct TimestampUs {
    /// Real time in microseconds.
    pub time_us: u64,
    /// Cpu time in microseconds.
    pub cputime_us: u64,
}

#[inline]
/// Gets the wallclock timestamp as microseconds.
fn get_time_us() -> u64 {
    (get_time(ClockType::Monotonic) / 1000)
}

/// Describes a KVM context that gets attached to the micro vm instance.
/// It gives access to the functionality of the KVM wrapper as long as every required
/// KVM capability is present on the host.
pub struct KvmContext {
    kvm: Kvm,
    max_memslots: usize,
}

impl KvmContext {
    fn with_kvm(kvm: Kvm) -> Result<Self> {
        use Cap::*;

        // Check that KVM has the correct version.
        if kvm.get_api_version() != KVM_API_VERSION as i32 {
            return Err(Error::KvmApiVersion(kvm.get_api_version()));
        }

        // A list of KVM capabilities we want to check.
        #[cfg(target_arch = "x86_64")]
        let capabilities = vec![Irqchip, Ioeventfd, Irqfd, UserMemory, SetTssAddr];

        #[cfg(target_arch = "aarch64")]
        let capabilities = vec![Irqchip, Ioeventfd, Irqfd, UserMemory, ArmPsci02];

        // Check that all desired capabilities aer supported.
        for capability in capabilities.iter() {
            if !kvm.check_extension(*capability) {
                Err(Error::KvmCap(*capability))?;
            }
        }

        let max_memslots = kvm.get_nr_memslots();
        Ok(KvmContext { kvm, max_memslots })
    }

    fn fd(&self) -> &Kvm {
        &self.kvm
    }

    /// Get the maximum number of memory slots reported by this KVM context.
    pub fn max_memslots(&self) -> usize {
        self.max_memslots
    }
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
    handler: Option<Box<EpollHandler>>,
    receiver: Receiver<Box<EpollHandler>>,
}

impl MaybeHandler {
    fn new(receiver: Receiver<Box<EpollHandler>>) -> Self {
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
            warn!("Could not add stdin event to epoll. {:?}", e);
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
    fn add_event<T: AsRawFd + ?Sized>(&mut self, fd: &T, token: EpollDispatch) -> Result<()> {
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
    fn allocate_tokens_for_device(&mut self, count: usize) -> (u64, Sender<Box<EpollHandler>>) {
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

    fn get_device_handler_by_handler_id(&mut self, id: usize) -> Result<&mut EpollHandler> {
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

struct KernelConfig {
    cmdline: kernel_cmdline::Cmdline,
    kernel_file: File,
    #[cfg(target_arch = "x86_64")]
    cmdline_addr: GuestAddress,
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
    guest_memory: Option<GuestMemory>,
    kernel_config: Option<KernelConfig>,
    vcpus_handles: Vec<thread::JoinHandle<()>>,
    exit_evt: Option<EventFd>,
    vm: Vm,

    // Guest VM devices.
    mmio_device_manager: Option<MMIODeviceManager>,
    pio_device_manager: PortIODeviceManager,

    // Device configurations.
    device_configs: DeviceConfigs,

    epoll_context: EpollContext,

    // API resources.
    from_api: Receiver<Box<VmmAction>>,

    write_metrics_event_fd: TimerFd,

    // The level of seccomp filtering used. Seccomp filters are loaded before executing guest code.
    seccomp_level: u32,
}

impl Vmm {
    /// Creates a new VMM object.
    pub fn new(
        api_shared_info: Arc<RwLock<InstanceInfo>>,
        control_fd: &AsRawFd,
        from_api: Receiver<Box<VmmAction>>,
        seccomp_level: u32,
        kvm: Kvm,
    ) -> Result<Self> {
        let mut epoll_context = EpollContext::new()?;
        // If this fails, it's fatal; using expect() to crash.
        epoll_context
            .add_event(control_fd, EpollDispatch::VmmActionRequest)
            .expect("Cannot add API control_fd to epoll.");

        let write_metrics_event_fd =
            TimerFd::new_custom(ClockId::Monotonic, true, true).map_err(Error::TimerFd)?;

        epoll_context
            .add_event(
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
        let kvm = KvmContext::with_kvm(kvm)?;
        let vm = Vm::new(kvm.fd()).map_err(Error::Vm)?;

        Ok(Vmm {
            kvm,
            vm_config: VmConfig::default(),
            shared_info: api_shared_info,
            stdin_handle: io::stdin(),
            guest_memory: None,
            kernel_config: None,
            vcpus_handles: vec![],
            exit_evt: None,
            vm,
            mmio_device_manager: None,
            pio_device_manager: PortIODeviceManager::new().map_err(Error::CreateLegacyDevice)?,
            device_configs,
            epoll_context,
            from_api,
            write_metrics_event_fd,
            seccomp_level,
        })
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
                .map(vmm_config::RateLimiterConfig::into_rate_limiter)
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
                    self.vm.get_fd(),
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
                .map(vmm_config::RateLimiterConfig::into_rate_limiter)
                .transpose()
                .map_err(CreateRateLimiter)?;

            let tx_rate_limiter = cfg
                .tx_rate_limiter
                .map(vmm_config::RateLimiterConfig::into_rate_limiter)
                .transpose()
                .map_err(CreateRateLimiter)?;

            let vm_fd = self.vm.get_fd();
            cfg.take_tap()
                .ok_or(NetDeviceNotConfigured)
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
            .map_err(|_| StartMicrovmError::CreateVsockDevice)?;

            let epoll_config = self.epoll_context.allocate_tokens_for_virtio_device(
                TYPE_VSOCK,
                &cfg.vsock_id,
                VSOCK_EVENTS_COUNT,
            );
            let vsock_box = Box::new(
                devices::virtio::Vsock::new(u64::from(cfg.guest_cid), epoll_config, backend)
                    .or(Err(StartMicrovmError::CreateVsockDevice))?,
            );
            device_manager
                .register_virtio_device(
                    self.vm.get_fd(),
                    vsock_box,
                    &mut kernel_config.cmdline,
                    TYPE_VSOCK,
                    &cfg.vsock_id,
                )
                .map_err(StartMicrovmError::RegisterVsockDevice)?;
        }

        Ok(())
    }

    fn configure_kernel(&mut self, kernel_config: KernelConfig) {
        self.kernel_config = Some(kernel_config);
    }

    fn flush_metrics(&mut self) -> std::result::Result<VmmData, VmmActionError> {
        self.write_metrics().map(|_| VmmData::Empty).map_err(|e| {
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
        LOGGER.log_metrics()
    }

    fn init_guest_memory(&mut self) -> std::result::Result<(), StartMicrovmError> {
        if self.guest_memory().is_none() {
            let mem_size = self
                .vm_config
                .mem_size_mib
                .ok_or(StartMicrovmError::GuestMemory(
                    memory_model::GuestMemoryError::MemoryNotInitialized,
                ))?
                << 20;
            let arch_mem_regions = arch::arch_memory_regions(mem_size);
            self.set_guest_memory(
                GuestMemory::new(&arch_mem_regions).map_err(StartMicrovmError::GuestMemory)?,
            );
        }

        self.vm
            .memory_init(
                self.guest_memory
                    .clone()
                    .ok_or(StartMicrovmError::GuestMemory(
                        memory_model::GuestMemoryError::MemoryNotInitialized,
                    ))?,
                &self.kvm,
            )
            .map_err(StartMicrovmError::ConfigureVm)?;
        Ok(())
    }

    fn check_health(&self) -> std::result::Result<(), StartMicrovmError> {
        self.kernel_config
            .as_ref()
            .ok_or(StartMicrovmError::MissingKernelConfig)
            .map(|_| ())
    }

    fn init_mmio_device_manager(&mut self) -> std::result::Result<(), StartMicrovmError> {
        if self.mmio_device_manager.is_none() {
            let guest_mem = self
                .guest_memory
                .clone()
                .ok_or(StartMicrovmError::GuestMemory(
                    memory_model::GuestMemoryError::MemoryNotInitialized,
                ))?;

            // Instantiate the MMIO device manager.
            // 'mmio_base' address has to be an address which is protected by the kernel
            // and is architectural specific.
            let device_manager = MMIODeviceManager::new(
                guest_mem.clone(),
                &mut (arch::get_reserved_mem_addr() as u64),
                (arch::IRQ_BASE, arch::IRQ_MAX),
            );
            self.mmio_device_manager = Some(device_manager);
        }

        Ok(())
    }

    fn attach_virtio_devices(&mut self) -> std::result::Result<(), StartMicrovmError> {
        self.init_mmio_device_manager()?;

        self.attach_block_devices()?;
        self.attach_net_devices()?;
        self.attach_vsock_devices()?;

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn get_serial_device(&self) -> Option<Arc<Mutex<RawIOHandler>>> {
        Some(self.pio_device_manager.stdio_serial.clone())
    }

    #[cfg(target_arch = "aarch64")]
    fn get_serial_device(&self) -> Option<&Arc<Mutex<RawIOHandler>>> {
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
                    .get_fd()
                    .register_irqfd(self.pio_device_manager.$evt.as_raw_fd(), $index)
                    .map_err(|e| {
                        StartMicrovmError::LegacyIOBus(device_manager::legacy::Error::EventFd(e))
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

        self.init_mmio_device_manager()?;
        // `unwrap` is suitable for this context since this should be called only after the
        // device manager has been initialized.
        let device_manager = self.mmio_device_manager.as_mut().unwrap();

        // We rely on check_health function for making sure kernel_config is not None.
        let kernel_config = self.kernel_config.as_mut().ok_or(MissingKernelConfig)?;

        if kernel_config.cmdline.as_str().contains("console=") {
            device_manager
                .register_mmio_serial(self.vm.get_fd(), &mut kernel_config.cmdline)
                .map_err(RegisterMMIODevice)?;
        }

        device_manager
            .register_mmio_rtc(self.vm.get_fd())
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

        let mut vcpus = Vec::with_capacity(vcpu_count as usize);

        for cpu_id in 0..vcpu_count {
            let io_bus = self.pio_device_manager.io_bus.clone();
            let mut vcpu = Vcpu::new(cpu_id, &self.vm, io_bus, request_ts.clone())
                .map_err(StartMicrovmError::Vcpu)?;

            vcpu.configure(&self.vm_config, entry_addr, &self.vm)
                .map_err(StartMicrovmError::VcpuConfigure)?;

            vcpus.push(vcpu);
        }
        Ok(vcpus)
    }

    fn start_vcpus(&mut self, mut vcpus: Vec<Vcpu>) -> std::result::Result<(), StartMicrovmError> {
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

        self.vcpus_handles.reserve(vcpu_count as usize);

        let vcpus_thread_barrier = Arc::new(Barrier::new((vcpu_count + 1) as usize));

        // We're going in reverse so we can `.pop()` on the vec and still maintain order.
        for cpu_id in (0..vcpu_count).rev() {
            let vcpu_thread_barrier = vcpus_thread_barrier.clone();

            // If the lock is poisoned, it's OK to panic.
            let vcpu_exit_evt = self
                .pio_device_manager
                .i8042
                .lock()
                .expect("Failed to start VCPUs due to poisoned i8042 lock")
                .get_reset_evt_clone()
                .map_err(|_| StartMicrovmError::EventFd)?;

            // `unwrap` is safe since we are asserting that the `vcpu_count` is equal to the number
            // of items of `vcpus` vector.
            let mut vcpu = vcpus.pop().unwrap();

            if let Some(ref mmio_device_manager) = self.mmio_device_manager {
                vcpu.set_mmio_bus(mmio_device_manager.bus.clone());
            }

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

    fn load_kernel(&mut self) -> std::result::Result<GuestAddress, StartMicrovmError> {
        use StartMicrovmError::*;

        // This is the easy way out of consuming the value of the kernel_cmdline.
        let kernel_config = self.kernel_config.as_mut().ok_or(MissingKernelConfig)?;

        // It is safe to unwrap because the VM memory was initialized before in vm.memory_init().
        let vm_memory = self.vm.get_memory().ok_or(GuestMemory(
            memory_model::GuestMemoryError::MemoryNotInitialized,
        ))?;

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
            kernel_config.cmdline_addr,
            &kernel_config
                .cmdline
                .as_cstring()
                .map_err(LoadCommandline)?,
        )
        .map_err(LoadCommandline)?;

        Ok(entry_addr)
    }

    fn configure_system(&self) -> std::result::Result<(), StartMicrovmError> {
        use StartMicrovmError::*;

        let kernel_config = self.kernel_config.as_ref().ok_or(MissingKernelConfig)?;

        let vm_memory = self.vm.get_memory().ok_or(GuestMemory(
            memory_model::GuestMemoryError::MemoryNotInitialized,
        ))?;

        // The vcpu_count has a default value. We shouldn't have gotten to this point without
        // having set the vcpu count.
        let vcpu_count = self.vm_config.vcpu_count.ok_or(VcpusNotConfigured)?;

        #[cfg(target_arch = "x86_64")]
        arch::x86_64::configure_system(
            vm_memory,
            kernel_config.cmdline_addr,
            kernel_config.cmdline.len() + 1,
            vcpu_count,
        )
        .map_err(ConfigureSystem)?;

        #[cfg(target_arch = "aarch64")]
        {
            arch::aarch64::configure_system(
                vm_memory,
                &kernel_config
                    .cmdline
                    .as_cstring()
                    .map_err(LoadCommandline)?,
                vcpu_count,
                self.get_mmio_device_info(),
            )
            .map_err(ConfigureSystem)?;
        }

        self.configure_stdin()?;
        Ok(())
    }

    fn register_events(&mut self) -> std::result::Result<(), StartMicrovmError> {
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
            .add_event(&exit_poll_evt_fd, EpollDispatch::Exit)
            .map_err(|_| RegisterEvent)?;

        self.exit_evt = Some(exit_poll_evt_fd);

        self.epoll_context.enable_stdin_event();

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

    /// Set the guest memory based on a pre-constructed `GuestMemory` object.
    pub fn set_guest_memory(&mut self, guest_memory: GuestMemory) {
        self.guest_memory = Some(guest_memory);
    }

    /// Returns a reference to the inner `GuestMemory` object if present, or `None` otherwise.
    pub fn guest_memory(&self) -> Option<&GuestMemory> {
        self.guest_memory.as_ref()
    }

    /// Set up the initial microVM state and start the vCPU threads.
    pub fn start_microvm(&mut self) -> std::result::Result<VmmData, VmmActionError> {
        info!("VMM received instance start command");
        if self.is_instance_initialized() {
            Err(StartMicrovmError::MicroVMAlreadyRunning)?;
        }

        let request_ts = TimestampUs {
            time_us: get_time_us(),
            cputime_us: get_time(ClockType::ProcessCpu) / 1000,
        };

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

        self.configure_system()?;

        self.register_events()?;

        self.start_vcpus(vcpus)?;

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

        Ok(VmmData::Empty)
    }

    fn send_ctrl_alt_del(&mut self) -> std::result::Result<VmmData, VmmActionError> {
        self.pio_device_manager
            .i8042
            .lock()
            .expect("i8042 lock was poisoned")
            .trigger_ctrl_alt_del()
            .map_err(|e| VmmActionError::SendCtrlAltDel(ErrorKind::Internal, e))?;
        Ok(VmmData::Empty)
    }

    /// Waits for all vCPUs to exit and terminates the Firecracker process.
    fn stop(&mut self, exit_code: i32) {
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
    fn run_event_loop(&mut self) -> Result<EventLoopExitReason> {
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

    // Count the number of pages dirtied since the last call to this function.
    // Because this is used for metrics, it swallows most errors and simply doesn't count dirty
    // pages if the KVM operation fails.
    #[cfg(target_arch = "x86_64")]
    fn get_dirty_page_count(&mut self) -> usize {
        let dirty_pages_in_region =
            |(slot, memory_region): (usize, &memory_model::MemoryRegion)| {
                self.vm
                    .get_fd()
                    .get_dirty_log(slot as u32, memory_region.size())
                    .map(|v| v.iter().map(|page| page.count_ones() as usize).sum())
                    .unwrap_or(0 as usize)
            };

        self.guest_memory()
            .map(|ref mem| mem.map_and_fold(0, dirty_pages_in_region, std::ops::Add::add))
            .unwrap_or(0)
    }

    /// Set the guest boot source configuration.
    pub fn configure_boot_source(
        &mut self,
        kernel_image_path: String,
        kernel_cmdline: Option<String>,
    ) -> std::result::Result<VmmData, VmmActionError> {
        use BootSourceConfigError::{
            InvalidKernelCommandLine, InvalidKernelPath, UpdateNotAllowedPostBoot,
        };
        use ErrorKind::User;
        use VmmActionError::BootSource;

        if self.is_instance_initialized() {
            Err(BootSource(User, UpdateNotAllowedPostBoot))?;
        }

        let kernel_file =
            File::open(kernel_image_path).map_err(|_| BootSource(User, InvalidKernelPath))?;

        let mut cmdline = kernel_cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
        cmdline
            .insert_str(kernel_cmdline.unwrap_or_else(|| String::from(DEFAULT_KERNEL_CMDLINE)))
            .map_err(|_| BootSource(User, InvalidKernelCommandLine))?;

        let kernel_config = KernelConfig {
            kernel_file,
            cmdline,
            #[cfg(target_arch = "x86_64")]
            cmdline_addr: GuestAddress(arch::x86_64::layout::CMDLINE_START),
        };
        self.configure_kernel(kernel_config);

        Ok(VmmData::Empty)
    }

    /// Set the machine configuration of the microVM.
    pub fn set_vm_configuration(
        &mut self,
        machine_config: VmConfig,
    ) -> std::result::Result<VmmData, VmmActionError> {
        if self.is_instance_initialized() {
            Err(VmConfigError::UpdateNotAllowedPostBoot)?;
        }

        if machine_config.vcpu_count == Some(0) {
            Err(VmConfigError::InvalidVcpuCount)?;
        }

        if machine_config.mem_size_mib == Some(0) {
            Err(VmConfigError::InvalidMemorySize)?;
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
            Err(VmConfigError::InvalidVcpuCount)?;
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

        Ok(VmmData::Empty)
    }

    /// Inserts a network device to be attached when the VM starts.
    pub fn insert_net_device(
        &mut self,
        body: NetworkInterfaceConfig,
    ) -> std::result::Result<VmmData, VmmActionError> {
        if self.is_instance_initialized() {
            Err(NetworkInterfaceError::UpdateNotAllowedPostBoot)?;
        }
        self.device_configs
            .network_interface
            .insert(body)
            .map(|_| VmmData::Empty)
            .map_err(|e| VmmActionError::NetworkConfig(ErrorKind::User, e))
    }

    fn update_net_device(
        &mut self,
        new_cfg: NetworkInterfaceUpdateConfig,
    ) -> std::result::Result<VmmData, VmmActionError> {
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
                        .map(|rl| {
                            rl.$metric
                                .map(vmm_config::TokenBucketConfig::into_token_bucket)
                        })
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

        Ok(VmmData::Empty)
    }

    /// Sets a vsock device to be attached when the VM starts.
    pub fn set_vsock_device(
        &mut self,
        config: VsockDeviceConfig,
    ) -> std::result::Result<VmmData, VmmActionError> {
        if self.is_instance_initialized() {
            Err(VmmActionError::VsockConfig(
                ErrorKind::User,
                VsockError::UpdateNotAllowedPostBoot,
            ))
        } else {
            self.device_configs.vsock = Some(config);
            Ok(VmmData::Empty)
        }
    }

    fn set_block_device_path(
        &mut self,
        drive_id: String,
        path_on_host: String,
    ) -> std::result::Result<VmmData, VmmActionError> {
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
        Ok(VmmData::Empty)
    }

    fn rescan_block_device(
        &mut self,
        drive_id: &str,
    ) -> std::result::Result<VmmData, VmmActionError> {
        // Rescan can only happen after the guest is booted.
        if !self.is_instance_initialized() {
            Err(DriveError::OperationNotAllowedPreBoot)?;
        }

        // Safe to unwrap() because mmio_device_manager is initialized in init_devices(), which is
        // called before the guest boots, and this function is called after boot.
        let device_manager = self.mmio_device_manager.as_ref().unwrap();
        for drive_config in self.device_configs.block.config_list.iter() {
            if drive_config.drive_id == *drive_id {
                let metadata = metadata(&drive_config.path_on_host)
                    .map_err(|_| DriveError::BlockDeviceUpdateFailed)?;
                let new_size = metadata.len();
                if new_size % virtio::block::SECTOR_SIZE != 0 {
                    warn!(
                        "Disk size {} is not a multiple of sector size {}; \
                         the remainder will not be visible to the guest.",
                        new_size,
                        virtio::block::SECTOR_SIZE
                    );
                }
                return device_manager
                    .update_drive(drive_id, new_size)
                    .map(|_| VmmData::Empty)
                    .map_err(|_| VmmActionError::from(DriveError::BlockDeviceUpdateFailed));
            }
        }
        Err(VmmActionError::from(DriveError::InvalidBlockDeviceID))
    }

    /// Inserts a block to be attached when the VM starts.
    // Only call this function as part of the API.
    // If the drive_id does not exist, a new Block Device Config is added to the list.
    pub fn insert_block_device(
        &mut self,
        block_device_config: BlockDeviceConfig,
    ) -> std::result::Result<VmmData, VmmActionError> {
        if self.is_instance_initialized() {
            Err(DriveError::UpdateNotAllowedPostBoot)?;
        }
        self.device_configs
            .block
            .insert(block_device_config)
            .map(|_| VmmData::Empty)
            .map_err(VmmActionError::from)
    }

    fn init_logger(
        &self,
        api_logger: LoggerConfig,
    ) -> std::result::Result<VmmData, VmmActionError> {
        if self.is_instance_initialized() {
            return Err(VmmActionError::Logger(
                ErrorKind::User,
                LoggerConfigError::InitializationFailure(
                    "Cannot initialize logger after boot.".to_string(),
                ),
            ));
        }

        let instance_id;
        let firecracker_version;
        {
            let guard = self.shared_info.read().unwrap();
            instance_id = guard.id.clone();
            firecracker_version = guard.vmm_version.clone();
        }

        LOGGER.set_level(match api_logger.level {
            LoggerLevel::Error => Level::Error,
            LoggerLevel::Warning => Level::Warn,
            LoggerLevel::Info => Level::Info,
            LoggerLevel::Debug => Level::Debug,
        });

        LOGGER.set_include_origin(api_logger.show_log_origin, api_logger.show_log_origin);
        LOGGER.set_include_level(api_logger.show_level);

        #[cfg(target_arch = "aarch64")]
        let options: &Vec<Value> = &vec![];

        #[cfg(target_arch = "x86_64")]
        let options = api_logger.options.as_array().unwrap();

        LOGGER
            .init(
                &AppInfo::new("Firecracker", &firecracker_version),
                &instance_id,
                api_logger.log_fifo,
                api_logger.metrics_fifo,
                options,
            )
            .map(|_| VmmData::Empty)
            .map_err(|e| {
                VmmActionError::Logger(
                    ErrorKind::User,
                    LoggerConfigError::InitializationFailure(e.to_string()),
                )
            })
    }

    fn send_response(outcome: VmmRequestOutcome, sender: OutcomeSender) {
        sender
            .send(outcome)
            .map_err(|_| ())
            .expect("one-shot channel closed");
    }

    fn run_vmm_action(&mut self) -> Result<()> {
        use VmmAction::*;

        let request = match self.from_api.try_recv() {
            Ok(t) => *t,
            Err(TryRecvError::Empty) => {
                return Err(Error::ApiChannel)?;
            }
            Err(TryRecvError::Disconnected) => {
                panic!("The channel's sending half was disconnected. Cannot receive data.");
            }
        };

        match request {
            ConfigureBootSource(boot_source_body, sender) => {
                Vmm::send_response(
                    self.configure_boot_source(
                        boot_source_body.kernel_image_path,
                        boot_source_body.boot_args,
                    ),
                    sender,
                );
            }
            ConfigureLogger(logger_description, sender) => {
                Vmm::send_response(self.init_logger(logger_description), sender);
            }
            FlushMetrics(sender) => {
                Vmm::send_response(self.flush_metrics(), sender);
            }
            GetVmConfiguration(sender) => {
                Vmm::send_response(
                    Ok(VmmData::MachineConfiguration(self.vm_config.clone())),
                    sender,
                );
            }
            InsertBlockDevice(block_device_config, sender) => {
                Vmm::send_response(self.insert_block_device(block_device_config), sender);
            }
            InsertNetworkDevice(netif_body, sender) => {
                Vmm::send_response(self.insert_net_device(netif_body), sender);
            }
            SetVsockDevice(vsock_cfg, sender) => {
                Vmm::send_response(self.set_vsock_device(vsock_cfg), sender);
            }
            RescanBlockDevice(drive_id, sender) => {
                Vmm::send_response(self.rescan_block_device(&drive_id), sender);
            }
            StartMicroVm(sender) => {
                Vmm::send_response(self.start_microvm(), sender);
            }
            SendCtrlAltDel(sender) => {
                Vmm::send_response(self.send_ctrl_alt_del(), sender);
            }
            SetVmConfiguration(machine_config_body, sender) => {
                Vmm::send_response(self.set_vm_configuration(machine_config_body), sender);
            }
            UpdateBlockDevicePath(drive_id, path_on_host, sender) => {
                Vmm::send_response(self.set_block_device_path(drive_id, path_on_host), sender);
            }
            UpdateNetworkInterface(netif_update, sender) => {
                Vmm::send_response(self.update_net_device(netif_update), sender);
            }
        };
        Ok(())
    }

    fn log_boot_time(t0_ts: &TimestampUs) {
        let now_cpu_us = get_time(ClockType::ProcessCpu) / 1000;
        let now_us = get_time_us();

        let boot_time_us = now_us - t0_ts.time_us;
        let boot_time_cpu_us = now_cpu_us - t0_ts.cputime_us;
        info!(
            "Guest-boot-time = {:>6} us {} ms, {:>6} CPU us {} CPU ms",
            boot_time_us,
            boot_time_us / 1000,
            boot_time_cpu_us,
            boot_time_cpu_us / 1000
        );
    }

    fn configure_from_json(
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
        self.configure_boot_source(
            vmm_config.boot_source.kernel_image_path,
            vmm_config.boot_source.boot_args,
        )?;
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

    /// Returns a reference to the inner KVM Vm object.
    pub fn kvm_vm(&self) -> &Vm {
        &self.vm
    }
}

// Can't derive PartialEq directly because the sender members can't be compared.
// This implementation is only used in tests, but cannot be moved to mod tests,
// because it is used in tests outside of the vmm crate (api_server).
impl PartialEq for VmmAction {
    fn eq(&self, other: &VmmAction) -> bool {
        use VmmAction::*;
        match (self, other) {
            (
                &UpdateBlockDevicePath(ref drive_id, ref path_on_host, _),
                &UpdateBlockDevicePath(ref other_drive_id, ref other_path_on_host, _),
            ) => drive_id == other_drive_id && path_on_host == other_path_on_host,
            (
                &ConfigureBootSource(ref boot_source, _),
                &ConfigureBootSource(ref other_boot_source, _),
            ) => boot_source == other_boot_source,
            (
                &InsertBlockDevice(ref block_device, _),
                &InsertBlockDevice(ref other_other_block_device, _),
            ) => block_device == other_other_block_device,
            (&ConfigureLogger(ref log, _), &ConfigureLogger(ref other_log, _)) => log == other_log,
            (
                &SetVmConfiguration(ref vm_config, _),
                &SetVmConfiguration(ref other_vm_config, _),
            ) => vm_config == other_vm_config,
            (&InsertNetworkDevice(ref net_dev, _), &InsertNetworkDevice(ref other_net_dev, _)) => {
                net_dev == other_net_dev
            }
            (
                &UpdateNetworkInterface(ref net_dev, _),
                &UpdateNetworkInterface(ref other_net_dev, _),
            ) => net_dev == other_net_dev,
            (&RescanBlockDevice(ref req, _), &RescanBlockDevice(ref other_req, _)) => {
                req == other_req
            }
            (&StartMicroVm(_), &StartMicroVm(_)) => true,
            (&SendCtrlAltDel(_), &SendCtrlAltDel(_)) => true,
            (&FlushMetrics(_), &FlushMetrics(_)) => true,
            _ => false,
        }
    }
}

/// Starts a new vmm thread that can service API requests.
///
/// # Arguments
///
/// * `api_shared_info` - A parameter for storing information on the VMM (e.g the current state).
/// * `api_event_fd` - An event fd used for receiving API associated events.
/// * `from_api` - The receiver end point of the communication channel.
/// * `seccomp_level` - The level of seccomp filtering used. Filters are loaded before executing
///                     guest code. Can be one of 0 (seccomp disabled), 1 (filter by syscall
///                     number) or 2 (filter by syscall number and argument values).
/// * `kvm_fd` - Provides the option of supplying an already existing raw file descriptor
///              associated with `/dev/kvm`.
/// * `config_json` - Optional parameter that can be used to configure the guest machine without
///                   using the API socket.
pub fn start_vmm_thread(
    api_shared_info: Arc<RwLock<InstanceInfo>>,
    api_event_fd: EventFd,
    from_api: Receiver<Box<VmmAction>>,
    seccomp_level: u32,
    config_json: Option<String>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("fc_vmm".to_string())
        .spawn(move || {
            // If this fails, consider it fatal. Use expect().
            let mut vmm = Vmm::new(
                api_shared_info,
                &api_event_fd,
                from_api,
                seccomp_level,
                Kvm::new().expect("Error creating the Kvm object"),
            )
            .expect("Cannot create VMM");

            if let Some(json) = config_json {
                if let Err(e) = vmm.configure_from_json(json) {
                    error!(
                        "Setting configuration for VMM from one single json failed: {}",
                        e
                    );
                    process::exit(i32::from(FC_EXIT_CODE_BAD_CONFIGURATION));
                } else if let Err(e) = vmm.start_microvm() {
                    error!(
                        "Starting microvm that was configured from one single json failed: {}",
                        e
                    );
                    process::exit(i32::from(FC_EXIT_CODE_UNEXPECTED_ERROR));
                } else {
                    info!("Successfully started microvm that was configured from one single json");
                }
            }

            // The loop continues to run as long as there is no error. Whenever run_event_loop
            // returns due to a ControlAction, we handle it and invoke `continue`. Clippy thinks
            // this never loops and complains about it, but Clippy is wrong.
            #[allow(clippy::never_loop)]
            let exit_code = loop {
                // `break <expression>` causes the outer loop to break and return the result
                // of evaluating <expression>, which in this case is the exit code.
                break match vmm.run_event_loop() {
                    Ok(exit_reason) => match exit_reason {
                        EventLoopExitReason::Break => {
                            info!("Gracefully terminated VMM control loop");
                            FC_EXIT_CODE_OK
                        }
                        EventLoopExitReason::ControlAction => {
                            if let Err(e) = api_event_fd.read() {
                                error!("Error reading VMM API event_fd {:?}", e);
                                FC_EXIT_CODE_GENERIC_ERROR
                            } else {
                                vmm.run_vmm_action().unwrap_or_else(|_| {
                                    warn!("Got a spurious notification from api thread");
                                });
                                continue;
                            }
                        }
                    },
                    Err(e) => {
                        error!("Abruptly exited VMM control loop: {:?}", e);
                        FC_EXIT_CODE_GENERIC_ERROR
                    }
                };
            };

            vmm.stop(i32::from(exit_code));
        })
        .expect("VMM thread spawn failed.")
}

#[cfg(test)]
mod tests {
    extern crate tempfile;

    use super::*;

    use serde_json::Value;
    use std::fs::File;
    use std::io::BufRead;
    use std::io::BufReader;
    use std::sync::atomic::AtomicUsize;

    use self::tempfile::NamedTempFile;
    use arch::DeviceType;
    use devices::virtio::{ActivateResult, MmioDevice, Queue};
    use net_util::MacAddr;
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
            let kernel_path = if cust_kernel_path.is_some() {
                cust_kernel_path.unwrap()
            } else {
                kernel_temp_file.path().to_path_buf()
            };
            let kernel_file = File::open(kernel_path).expect("Cannot open kernel file");
            let mut cmdline = kernel_cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
            assert!(cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).is_ok());
            let kernel_cfg = KernelConfig {
                cmdline,
                kernel_file,
                #[cfg(target_arch = "x86_64")]
                cmdline_addr: GuestAddress(arch::x86_64::layout::CMDLINE_START),
            };
            self.configure_kernel(kernel_cfg);
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

    impl KvmContext {
        pub fn new() -> Result<Self> {
            let kvm = Kvm::new().map_err(Error::Kvm)?;
            Self::with_kvm(kvm)
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

        fn ack_features(&mut self, page: u32, value: u32) {
            let _ = page;
            let _ = value;
        }

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

        let (_to_vmm, from_api) = channel();
        Vmm::new(
            shared_info,
            &EventFd::new().expect("Cannot create eventFD"),
            from_api,
            seccomp::SECCOMP_LEVEL_NONE,
            Kvm::new().expect("Error creating Kvm object"),
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
        let f = NamedTempFile::new().unwrap();
        // Test that creating a new block device returns the correct output.
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: f.path().to_path_buf(),
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
            path_on_host: f.path().to_path_buf(),
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
            path_on_host: f.path().to_path_buf(),
            is_root_device: false,
            partuuid: None,
            is_read_only: true,
            rate_limiter: None,
        };
        assert!(vmm.insert_block_device(root_block_device.clone()).is_err());

        // Test inserting a second drive is ok.
        let f = NamedTempFile::new().unwrap();
        // Test that creating a new block device returns the correct output.
        let non_root = BlockDeviceConfig {
            drive_id: String::from("non_root"),
            path_on_host: f.path().to_path_buf(),
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
            path_on_host: f.path().to_path_buf(),
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
            path_on_host: f.path().to_path_buf(),
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
            tap: None,
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
            tap: None,
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
            tap: None,
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
            tap: None,
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
            tap: None,
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
        vmm.init_mmio_device_manager()
            .expect("Cannot initialize mmio device manager");

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
                    vmm.guest_memory().unwrap().clone(),
                    EventFd::new().unwrap(),
                    Arc::new(AtomicUsize::new(0)),
                    vec![Queue::new(0), Queue::new(0)],
                    vec![EventFd::new().unwrap(), EventFd::new().unwrap()],
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
    fn add_event_test() {
        let mut ep = EpollContext::new().unwrap();
        let evfd = EventFd::new().unwrap();

        // adding new event should work
        assert!(ep.add_event(&evfd, EpollDispatch::Exit).is_ok());
    }

    #[test]
    fn epoll_event_test() {
        let mut ep = EpollContext::new().unwrap();
        let evfd = EventFd::new().unwrap();

        // adding new event should work
        assert!(ep.add_event(&evfd, EpollDispatch::Exit).is_ok());

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
    fn test_kvm_context() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::FromRawFd;

        let c = KvmContext::new().unwrap();

        assert!(c.max_memslots >= 32);

        let kvm = Kvm::new().unwrap();
        let f = unsafe { File::from_raw_fd(kvm.as_raw_fd()) };
        let m1 = f.metadata().unwrap();
        let m2 = File::open("/dev/kvm").unwrap().metadata().unwrap();

        assert_eq!(m1.dev(), m2.dev());
        assert_eq!(m1.ino(), m2.ino());
    }

    #[test]
    fn test_check_health() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert!(vmm.check_health().is_err());

        let dummy_addr = GuestAddress(0x1000);
        vmm.configure_kernel(KernelConfig {
            #[cfg(target_arch = "x86_64")]
            cmdline_addr: dummy_addr,
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

        let vmm = create_vmm_object(InstanceState::Halting);
        assert_eq!(vmm.is_instance_initialized(), true);

        let vmm = create_vmm_object(InstanceState::Halted);
        assert_eq!(vmm.is_instance_initialized(), true);

        let vmm = create_vmm_object(InstanceState::Running);
        assert_eq!(vmm.is_instance_initialized(), true);
    }

    #[test]
    fn test_attach_block_devices() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        let block_file = NamedTempFile::new().unwrap();

        // Use Case 1: Root Block Device is not specified through PARTUUID.
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: block_file.path().to_path_buf(),
            is_root_device: true,
            partuuid: None,
            is_read_only: false,
            rate_limiter: None,
        };
        // Test that creating a new block device returns the correct output.
        assert!(vmm.insert_block_device(root_block_device.clone()).is_ok());
        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.guest_memory().is_some());
        assert!(vmm.setup_interrupt_controller().is_ok());

        vmm.default_kernel_config(None);
        vmm.init_mmio_device_manager()
            .expect("Cannot initialize mmio device manager");

        assert!(vmm.attach_block_devices().is_ok());
        assert!(vmm.get_kernel_cmdline_str().contains("root=/dev/vda rw"));

        // Use Case 2: Root Block Device is specified through PARTUUID.
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        let root_block_device = BlockDeviceConfig {
            drive_id: String::from("root"),
            path_on_host: block_file.path().to_path_buf(),
            is_root_device: true,
            partuuid: Some("0eaa91a0-01".to_string()),
            is_read_only: false,
            rate_limiter: None,
        };

        // Test that creating a new block device returns the correct output.
        assert!(vmm.insert_block_device(root_block_device.clone()).is_ok());
        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.guest_memory().is_some());
        assert!(vmm.setup_interrupt_controller().is_ok());

        vmm.default_kernel_config(None);
        vmm.init_mmio_device_manager()
            .expect("Cannot initialize mmio device manager");

        assert!(vmm.attach_block_devices().is_ok());
        assert!(vmm
            .get_kernel_cmdline_str()
            .contains("root=PARTUUID=0eaa91a0-01 rw"));

        // Use Case 3: Root Block Device is not added at all.
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        let non_root_block_device = BlockDeviceConfig {
            drive_id: String::from("not_root"),
            path_on_host: block_file.path().to_path_buf(),
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
        assert!(vmm.guest_memory().is_some());
        assert!(vmm.setup_interrupt_controller().is_ok());

        vmm.default_kernel_config(None);
        vmm.init_mmio_device_manager()
            .expect("Cannot initialize mmio device manager");

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
        let new_block = NamedTempFile::new().unwrap();
        let path = String::from(new_block.path().to_path_buf().to_str().unwrap());
        assert!(vmm
            .set_block_device_path("not_root".to_string(), path)
            .is_ok());

        // Test partial update of block device fails due to invalid file.
        assert!(vmm
            .set_block_device_path("not_root".to_string(), String::from("dummy_path"))
            .is_err());

        vmm.set_instance_state(InstanceState::Running);

        // Test updating the block device path, after instance start.
        let path = String::from(new_block.path().to_path_buf().to_str().unwrap());
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
        assert!(vmm.guest_memory().is_some());

        vmm.default_kernel_config(None);
        vmm.setup_interrupt_controller()
            .expect("Failed to setup interrupt controller");
        vmm.init_mmio_device_manager()
            .expect("Cannot initialize mmio device manager");

        // test create network interface
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname5"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: false,
            tap: None,
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

        vmm.init_mmio_device_manager()
            .expect("Cannot initialize mmio device manager");
        assert!(vmm.attach_virtio_devices().is_ok());
    }

    #[test]
    fn test_configure_boot_source() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

        // Test invalid kernel path.
        assert!(vmm
            .configure_boot_source(String::from("dummy-path"), None)
            .is_err());

        // Test valid kernel path and invalid cmdline.
        let kernel_file = NamedTempFile::new().expect("Failed to create temporary kernel file.");
        let kernel_path = String::from(kernel_file.path().to_path_buf().to_str().unwrap());
        let invalid_cmdline = String::from_utf8(vec![b'X'; arch::CMDLINE_MAX_SIZE + 1]).unwrap();
        assert!(vmm
            .configure_boot_source(kernel_path.clone(), Some(invalid_cmdline))
            .is_err());

        // Test valid configuration.
        assert!(vmm.configure_boot_source(kernel_path.clone(), None).is_ok());
        assert!(vmm
            .configure_boot_source(kernel_path.clone(), Some(String::from("reboot=k")))
            .is_ok());

        // Test valid configuration after boot (should fail).
        vmm.set_instance_state(InstanceState::Running);
        assert!(vmm
            .configure_boot_source(kernel_path.clone(), None)
            .is_err());
    }

    #[test]
    // Allow assertions on constants is necessary because we cannot implement
    // PartialEq on VmmActionError.
    #[allow(clippy::assertions_on_constants)]
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
        assert!(vmm.guest_memory().is_some());
        assert!(vmm.setup_interrupt_controller().is_ok());

        vmm.init_mmio_device_manager()
            .expect("Cannot initialize mmio device manager");

        {
            let dummy_box = Box::new(DummyDevice { dummy: 0 });
            let device_manager = vmm.mmio_device_manager.as_mut().unwrap();

            // Use a dummy command line as it is not used in this test.
            let _addr = device_manager
                .register_virtio_device(
                    vmm.vm.get_fd(),
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
        match vmm.rescan_block_device(&scratch_id) {
            Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::BlockDeviceUpdateFailed,
            )) => (),
            _ => assert!(false),
        }
        vmm.update_block_device_path(&scratch_id, prev_path);

        // Test rescan_block_device with invalid ID.
        match vmm.rescan_block_device(&"foo".to_string()) {
            Err(VmmActionError::DriveConfig(ErrorKind::User, DriveError::InvalidBlockDeviceID)) => {
            }
            _ => assert!(false),
        }
        vmm.change_id(&scratch_id, "scratch");
        match vmm.rescan_block_device(&scratch_id) {
            Err(VmmActionError::DriveConfig(ErrorKind::User, DriveError::InvalidBlockDeviceID)) => {
            }
            _ => assert!(false),
        }

        // Test rescan_block_device with invalid device address.
        vmm.remove_device_info(TYPE_BLOCK, &scratch_id);
        match vmm.rescan_block_device(&scratch_id) {
            Err(VmmActionError::DriveConfig(ErrorKind::User, DriveError::InvalidBlockDeviceID)) => {
            }
            _ => assert!(false),
        }

        // Test rescan not allowed.
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert!(vmm
            .insert_block_device(non_root_block_device.clone())
            .is_ok());
        match vmm.rescan_block_device(&scratch_id) {
            Err(VmmActionError::DriveConfig(
                ErrorKind::User,
                DriveError::OperationNotAllowedPreBoot,
            )) => (),
            _ => assert!(false),
        }
    }

    #[test]
    fn test_init_logger_from_api() {
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
            options: Value::Array(vec![]),
        };

        let mut vmm = create_vmm_object(InstanceState::Running);
        assert!(vmm.init_logger(desc).is_err());

        // Reset vmm state to test the other scenarios.
        vmm.set_instance_state(InstanceState::Uninitialized);

        // Error case: initializing logger with invalid pipes returns error.
        let desc = LoggerConfig {
            log_fifo: String::from("not_found_file_log"),
            metrics_fifo: String::from("not_found_file_metrics"),
            level: LoggerLevel::Warning,
            show_level: false,
            show_log_origin: false,
            #[cfg(target_arch = "x86_64")]
            options: Value::Array(vec![]),
        };
        assert!(vmm.init_logger(desc).is_err());

        // Error case: initializing logger with invalid option flags returns error.
        let desc = LoggerConfig {
            log_fifo: String::from("not_found_file_log"),
            metrics_fifo: String::from("not_found_file_metrics"),
            level: LoggerLevel::Warning,
            show_level: false,
            show_log_origin: false,
            #[cfg(target_arch = "x86_64")]
            options: Value::Array(vec![Value::String("foobar".to_string())]),
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
            options: Value::Array(vec![Value::String("LogDirtyPages".to_string())]),
        };
        // Flushing metrics before initializing logger is erroneous.
        let err = vmm.flush_metrics();
        assert!(err.is_err());
        assert_eq!(
            format!("{:?}", err.unwrap_err()),
            "Logger(Internal, FlushMetrics(\"Logger was not initialized.\"))"
        );

        assert!(vmm.init_logger(desc).is_ok());

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
        assert!(vmm.vm.get_memory().is_some());

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
    fn test_load_kernel() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert_eq!(
            vmm.load_kernel().unwrap_err().to_string(),
            "Cannot start microvm without kernel configuration."
        );

        vmm.default_kernel_config(None);

        assert_eq!(
            vmm.load_kernel().unwrap_err().to_string(),
            "Invalid Memory Configuration: MemoryNotInitialized"
        );

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.get_memory().is_some());

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
    fn test_configure_system() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        assert_eq!(
            vmm.configure_system().unwrap_err().to_string(),
            "Cannot start microvm without kernel configuration."
        );

        vmm.default_kernel_config(None);

        assert_eq!(
            vmm.configure_system().unwrap_err().to_string(),
            "Invalid Memory Configuration: MemoryNotInitialized"
        );

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.get_memory().is_some());

        assert!(vmm.configure_system().is_ok());
        vmm.stdin_handle.lock().set_canon_mode().unwrap();
    }

    #[test]
    fn test_attach_virtio_devices() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);
        vmm.default_kernel_config(None);

        assert!(vmm.init_guest_memory().is_ok());
        assert!(vmm.vm.get_memory().is_some());
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
            tap: None,
        };

        assert!(vmm.insert_net_device(network_interface).is_ok());
        assert!(vmm.attach_virtio_devices().is_ok());
        assert!(vmm.mmio_device_manager.is_some());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_attach_legacy_devices() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

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
        assert!(vmm.guest_memory().is_some());

        let guest_mem = vmm.guest_memory().unwrap().clone();
        let device_manager = MMIODeviceManager::new(
            guest_mem,
            &mut (arch::get_reserved_mem_addr() as u64),
            (arch::IRQ_BASE, arch::IRQ_MAX),
        );
        vmm.mmio_device_manager = Some(device_manager);

        vmm.default_kernel_config(None);
        vmm.setup_interrupt_controller()
            .expect("Failed to setup interrupt controller");
        assert!(vmm.attach_legacy_devices().is_ok());
        let kernel_config = vmm.kernel_config.as_mut();

        let dev_man = vmm.mmio_device_manager.as_ref().unwrap();
        // On aarch64, we are using first region of the memory
        // reserved for attaching MMIO devices for measuring boot time.
        assert!(dev_man
            .bus
            .get_device(arch::get_reserved_mem_addr() as u64)
            .is_none());
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
        assert!(vmm.guest_memory().is_some());

        let guest_mem = vmm.guest_memory().unwrap().clone();
        let device_manager = MMIODeviceManager::new(
            guest_mem,
            &mut (arch::get_reserved_mem_addr() as u64),
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
                BootSourceConfigError::InvalidKernelPath,
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

    // Helper function to get ErrorKind of error.
    fn error_kind<T: std::convert::Into<VmmActionError>>(err: T) -> ErrorKind {
        let err: VmmActionError = err.into();
        err.kind().clone()
    }

    #[test]
    fn test_drive_error_conversion() {
        // Test `DriveError` conversion
        assert_eq!(
            error_kind(DriveError::CannotOpenBlockDevice),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(DriveError::InvalidBlockDevicePath),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(DriveError::BlockDevicePathAlreadyExists),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(DriveError::BlockDeviceUpdateFailed),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(DriveError::OperationNotAllowedPreBoot),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(DriveError::UpdateNotAllowedPostBoot),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(DriveError::RootBlockDeviceAlreadyAdded),
            ErrorKind::User
        );
    }

    #[test]
    fn test_vmconfig_error_conversion() {
        // Test `VmConfigError` conversion
        assert_eq!(error_kind(VmConfigError::InvalidVcpuCount), ErrorKind::User);
        assert_eq!(
            error_kind(VmConfigError::InvalidMemorySize),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(VmConfigError::UpdateNotAllowedPostBoot),
            ErrorKind::User
        );
    }

    #[test]
    fn test_network_interface_error_conversion() {
        // Test `NetworkInterfaceError` conversion
        assert_eq!(
            error_kind(NetworkInterfaceError::GuestMacAddressInUse(String::new())),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(NetworkInterfaceError::EpollHandlerNotFound(
                Error::DeviceEventHandlerNotFound
            )),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(NetworkInterfaceError::HostDeviceNameInUse(String::new())),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(NetworkInterfaceError::DeviceIdNotFound),
            ErrorKind::User
        );
        // NetworkInterfaceError::OpenTap can be of multiple kinds.
        {
            assert_eq!(
                error_kind(NetworkInterfaceError::OpenTap(TapError::OpenTun(
                    io::Error::from_raw_os_error(0)
                ))),
                ErrorKind::User
            );
            assert_eq!(
                error_kind(NetworkInterfaceError::OpenTap(TapError::CreateTap(
                    io::Error::from_raw_os_error(0)
                ))),
                ErrorKind::User
            );
            assert_eq!(
                error_kind(NetworkInterfaceError::OpenTap(TapError::IoctlError(
                    io::Error::from_raw_os_error(0)
                ))),
                ErrorKind::Internal
            );
            assert_eq!(
                error_kind(NetworkInterfaceError::OpenTap(TapError::NetUtil(
                    net_util::Error::CreateSocket(io::Error::from_raw_os_error(0))
                ))),
                ErrorKind::Internal
            );
            assert_eq!(
                error_kind(NetworkInterfaceError::OpenTap(TapError::InvalidIfname)),
                ErrorKind::User
            );
        }
        assert_eq!(
            error_kind(NetworkInterfaceError::RateLimiterUpdateFailed(
                devices::Error::FailedReadTap
            )),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(NetworkInterfaceError::UpdateNotAllowedPostBoot),
            ErrorKind::User
        );
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_start_microvm_error_conversion_cl() {
        // Test `StartMicrovmError` conversion.
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            error_kind(StartMicrovmError::ConfigureSystem(
                arch::Error::ZeroPageSetup
            )),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::ConfigureVm(
                vstate::Error::NotEnoughMemorySlots
            )),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::CreateBlockDevice(
                io::Error::from_raw_os_error(0)
            )),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(StartMicrovmError::CreateNetDevice(
                devices::virtio::Error::TapOpen(TapError::CreateTap(io::Error::from_raw_os_error(
                    0
                )))
            )),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(StartMicrovmError::CreateRateLimiter(
                io::Error::from_raw_os_error(0)
            )),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::CreateVsockDevice),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(StartMicrovmError::DeviceManager),
            ErrorKind::Internal
        );
        assert_eq!(error_kind(StartMicrovmError::EventFd), ErrorKind::Internal);
        assert_eq!(
            error_kind(StartMicrovmError::GuestMemory(
                memory_model::GuestMemoryError::NoMemoryRegions
            )),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::KernelCmdline(String::new())),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(StartMicrovmError::KernelLoader(
                kernel_loader::Error::SeekKernelImage
            )),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(StartMicrovmError::LegacyIOBus(
                device_manager::legacy::Error::EventFd(io::Error::from_raw_os_error(0))
            )),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::LoadCommandline(
                kernel::cmdline::Error::CommandLineOverflow
            )),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(StartMicrovmError::LoadCommandline(
                kernel::cmdline::Error::CommandLineCopy
            )),
            ErrorKind::Internal
        );
    }

    #[test]
    fn test_start_microvm_error_conversion_mv() {
        assert_eq!(
            error_kind(StartMicrovmError::MicroVMAlreadyRunning),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(StartMicrovmError::MissingKernelConfig),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(StartMicrovmError::NetDeviceNotConfigured),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(StartMicrovmError::OpenBlockDevice(
                io::Error::from_raw_os_error(0)
            )),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(StartMicrovmError::RegisterBlockDevice(
                device_manager::mmio::Error::IrqsExhausted
            )),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::RegisterEvent),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::RegisterNetDevice(
                device_manager::mmio::Error::IrqsExhausted
            )),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::RegisterMMIODevice(
                device_manager::mmio::Error::IrqsExhausted
            )),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::RegisterVsockDevice(
                device_manager::mmio::Error::IrqsExhausted
            )),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::SeccompFilters(
                seccomp::Error::InvalidArgumentNumber
            )),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::Vcpu(vstate::Error::VcpuUnhandledKvmExit)),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::VcpuConfigure(
                vstate::Error::SetSupportedCpusFailed(io::Error::from_raw_os_error(0))
            )),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::VcpusNotConfigured),
            ErrorKind::User
        );
        assert_eq!(
            error_kind(StartMicrovmError::VcpuSpawn(io::Error::from_raw_os_error(
                0
            ))),
            ErrorKind::Internal
        );
        assert_eq!(
            error_kind(StartMicrovmError::StdinHandle(
                io::Error::from_raw_os_error(0)
            )),
            ErrorKind::Internal
        );
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_error_messages() {
        // Enum `Error`

        assert_eq!(
            format!("{:?}", Error::ApiChannel),
            "ApiChannel: error receiving data from the API server"
        );
        assert_eq!(
            format!(
                "{:?}",
                Error::CreateLegacyDevice(device_manager::legacy::Error::EventFd(
                    io::Error::from_raw_os_error(42)
                ))
            ),
            format!(
                "Error creating legacy device: EventFd({:?})",
                io::Error::from_raw_os_error(42)
            )
        );
        assert_eq!(
            format!("{:?}", Error::EpollFd(io::Error::from_raw_os_error(42))),
            "Epoll fd error: No message of desired type (os error 42)"
        );
        assert_eq!(
            format!("{:?}", Error::EventFd(io::Error::from_raw_os_error(42))),
            "Event fd error: No message of desired type (os error 42)"
        );
        assert_eq!(
            format!("{:?}", Error::DeviceEventHandlerNotFound),
            "Device event handler not found. This might point to a guest device driver issue."
        );
        assert_eq!(
            format!("{:?}", Error::Kvm(io::Error::from_raw_os_error(42))),
            "Cannot open /dev/kvm. Error: No message of desired type (os error 42)"
        );
        assert_eq!(
            format!("{:?}", Error::KvmApiVersion(42)),
            "Bad KVM API version: 42"
        );
        assert_eq!(
            format!("{:?}", Error::KvmCap(Cap::Hlt)),
            "Missing KVM capability: Hlt"
        );
        assert_eq!(
            format!("{:?}", Error::Poll(io::Error::from_raw_os_error(42))),
            "Epoll wait failed: No message of desired type (os error 42)"
        );
        assert_eq!(
            format!("{:?}", Error::Serial(io::Error::from_raw_os_error(42))),
            format!(
                "Error writing to the serial console: {:?}",
                io::Error::from_raw_os_error(42)
            )
        );
        assert_eq!(
            format!("{:?}", Error::TimerFd(io::Error::from_raw_os_error(42))),
            "Error creating timer fd: No message of desired type (os error 42)"
        );
        assert_eq!(
            format!("{:?}", Error::Vm(vstate::Error::HTNotInitialized)),
            "Error opening VM fd: HTNotInitialized"
        );

        // Enum `ErrorKind`

        assert_ne!(ErrorKind::User, ErrorKind::Internal);
        assert_eq!(format!("{:?}", ErrorKind::User), "User");
        assert_eq!(format!("{:?}", ErrorKind::Internal), "Internal");

        // Enum VmmActionError

        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::BootSource(
                    ErrorKind::User,
                    BootSourceConfigError::InvalidKernelCommandLine
                )
            ),
            "BootSource(User, InvalidKernelCommandLine)"
        );
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::DriveConfig(
                    ErrorKind::User,
                    DriveError::BlockDevicePathAlreadyExists
                )
            ),
            "DriveConfig(User, BlockDevicePathAlreadyExists)"
        );
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::Logger(
                    ErrorKind::User,
                    LoggerConfigError::InitializationFailure(String::from("foobar"))
                )
            ),
            "Logger(User, InitializationFailure(\"foobar\"))"
        );
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::MachineConfig(ErrorKind::User, VmConfigError::InvalidMemorySize)
            ),
            "MachineConfig(User, InvalidMemorySize)"
        );
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::NetworkConfig(
                    ErrorKind::User,
                    NetworkInterfaceError::DeviceIdNotFound
                )
            ),
            "NetworkConfig(User, DeviceIdNotFound)"
        );
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::StartMicrovm(ErrorKind::User, StartMicrovmError::EventFd)
            ),
            "StartMicrovm(User, EventFd)"
        );
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::SendCtrlAltDel(
                    ErrorKind::User,
                    I8042DeviceError::InternalBufferFull
                )
            ),
            "SendCtrlAltDel(User, InternalBufferFull)"
        );
        assert_eq!(
            format!(
                "{}",
                VmmActionError::SendCtrlAltDel(
                    ErrorKind::User,
                    I8042DeviceError::InternalBufferFull
                )
            ),
            I8042DeviceError::InternalBufferFull.to_string()
        );
        assert_eq!(
            VmmActionError::SendCtrlAltDel(ErrorKind::User, I8042DeviceError::InternalBufferFull)
                .kind(),
            &ErrorKind::User
        );
        assert_eq!(
            format!(
                "{:?}",
                VmmActionError::VsockConfig(ErrorKind::User, VsockError::UpdateNotAllowedPostBoot)
            ),
            "VsockConfig(User, UpdateNotAllowedPostBoot)"
        );
    }

    #[test]
    fn test_misc() {
        let mut vmm = create_vmm_object(InstanceState::Uninitialized);

        assert!(vmm.guest_memory().is_none());

        let mem = GuestMemory::new(&[(GuestAddress(0x1000), 0x100)]).unwrap();
        vmm.set_guest_memory(mem);

        let mem_ref = vmm.guest_memory().unwrap();
        assert_eq!(mem_ref.num_regions(), 1);
        assert_eq!(mem_ref.end_addr(), GuestAddress(0x1100));

        assert_eq!(
            vmm.kvm_vm().get_fd().as_raw_fd(),
            vmm.vm.get_fd().as_raw_fd()
        );
    }
}
