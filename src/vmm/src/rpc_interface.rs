// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};
use std::result;

use super::{EpollContext, EventLoopExitReason, Vmm};

use builder::StartMicrovmError;
use controller::VmmController;
use resources::VmResources;
use seccomp::BpfProgram;
use vmm_config;
use vmm_config::boot_source::{BootSourceConfig, BootSourceConfigError};
use vmm_config::drive::{BlockDeviceConfig, DriveError};
use vmm_config::logger::{LoggerConfig, LoggerConfigError};
use vmm_config::machine_config::{VmConfig, VmConfigError};
use vmm_config::net::{
    NetworkInterfaceConfig, NetworkInterfaceError, NetworkInterfaceUpdateConfig,
};
use vmm_config::vsock::{VsockDeviceConfig, VsockError};

/// This enum represents the public interface of the VMM. Each action contains various
/// bits of information (ids, paths, etc.).
#[derive(PartialEq)]
pub enum VmmAction {
    /// Configure the boot source of the microVM using as input the `ConfigureBootSource`. This
    /// action can only be called before the microVM has booted.
    ConfigureBootSource(BootSourceConfig),
    /// Configure the logger using as input the `LoggerConfig`. This action can only be called
    /// before the microVM has booted.
    ConfigureLogger(LoggerConfig),
    /// Get the configuration of the microVM.
    GetVmConfiguration,
    /// Flush the metrics. This action can only be called after the logger has been configured.
    FlushMetrics,
    /// Add a new block device or update one that already exists using the `BlockDeviceConfig` as
    /// input. This action can only be called before the microVM has booted.
    InsertBlockDevice(BlockDeviceConfig),
    /// Add a new network interface config or update one that already exists using the
    /// `NetworkInterfaceConfig` as input. This action can only be called before the microVM has
    /// booted.
    InsertNetworkDevice(NetworkInterfaceConfig),
    /// Set the vsock device or update the one that already exists using the
    /// `VsockDeviceConfig` as input. This action can only be called before the microVM has
    /// booted.
    SetVsockDevice(VsockDeviceConfig),
    /// Set the microVM configuration (memory & vcpu) using `VmConfig` as input. This
    /// action can only be called before the microVM has booted.
    SetVmConfiguration(VmConfig),
    /// Launch the microVM. This action can only be called before the microVM has booted.
    StartMicroVm,
    /// Send CTRL+ALT+DEL to the microVM, using the i8042 keyboard function. If an AT-keyboard
    /// driver is listening on the guest end, this can be used to shut down the microVM gracefully.
    #[cfg(target_arch = "x86_64")]
    SendCtrlAltDel,
    /// Update the path of an existing block device. The data associated with this variant
    /// represents the `drive_id` and the `path_on_host`.
    UpdateBlockDevicePath(String, String),
    /// Update a network interface, after microVM start. Currently, the only updatable properties
    /// are the RX and TX rate limiters.
    UpdateNetworkInterface(NetworkInterfaceUpdateConfig),
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
    /// One of the actions `InsertBlockDevice` or `UpdateBlockDevicePath`
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
    /// The requested operation is not supported after starting the microVM.
    OperationNotSupportedPostBoot,
    /// The requested operation is not supported before starting the microVM.
    OperationNotSupportedPreBoot,
    /// The action `StartMicroVm` failed either because of bad user input (`ErrorKind::User`) or
    /// an internal error (`ErrorKind::Internal`).
    StartMicrovm(ErrorKind, StartMicrovmError),
    /// The action `SendCtrlAltDel` failed. Details are provided by the device-specific error
    /// `I8042DeviceError`.
    #[cfg(target_arch = "x86_64")]
    SendCtrlAltDel(ErrorKind, super::error::Error),
    /// The action `set_vsock_device` failed either because of bad user input (`ErrorKind::User`)
    /// or an internal error (`ErrorKind::Internal`).
    VsockConfig(ErrorKind, VsockError),
}

// It's convenient to turn StartMicrovmErrors into VmmActionErrors directly.
impl std::convert::From<StartMicrovmError> for VmmActionError {
    fn from(e: StartMicrovmError) -> Self {
        use self::StartMicrovmError::*;

        let kind = match e {
            // User errors.
            CreateVsockBackend(_)
            | CreateBlockDevice(_)
            | CreateNetDevice(_)
            | InitrdLoad
            | InitrdRead(_)
            | KernelCmdline(_)
            | KernelLoader(_)
            | MicroVMAlreadyRunning
            | MissingKernelConfig
            | NetDeviceNotConfigured
            | OpenBlockDevice(_) => ErrorKind::User,
            // Internal errors.
            ConfigureVm(_)
            | CreateRateLimiter(_)
            | CreateVsockDevice(_)
            | GuestMemoryMmap(_)
            | Internal(_)
            | RegisterBlockDevice(_)
            | RegisterNetDevice(_)
            | RegisterVsockDevice(_) => ErrorKind::Internal,
            // The only user `LoadCommandline` error is `CommandLineOverflow`.
            LoadCommandline(ref cle) => match cle {
                kernel::cmdline::Error::CommandLineOverflow => ErrorKind::User,
                _ => ErrorKind::Internal,
            },
        };
        VmmActionError::StartMicrovm(kind, e)
    }
}

// It's convenient to turn DriveErrors into VmmActionErrors directly.
impl std::convert::From<DriveError> for VmmActionError {
    fn from(e: DriveError) -> Self {
        use vmm_config::drive::DriveError::*;

        // This match is used to force developers who add new types of
        // `DriveError`s to explicitly consider what kind they should
        // have. Remove this comment when a match arm that yields
        // something other than `ErrorKind::User` is added.
        let kind = match e {
            // User errors.
            CannotOpenBlockDevice(_)
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
        use vmm_config::machine_config::VmConfigError::*;

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
        use utils::net::TapError::*;
        use vmm_config::net::NetworkInterfaceError::*;

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
                IoctlError(_) | CreateSocket(_) => ErrorKind::Internal,
            },
        };

        VmmActionError::NetworkConfig(kind, e)
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
            OperationNotSupportedPostBoot | OperationNotSupportedPreBoot => &ErrorKind::User,
            StartMicrovm(ref kind, _) => kind,
            #[cfg(target_arch = "x86_64")]
            SendCtrlAltDel(ref kind, _) => kind,
            VsockConfig(ref kind, _) => kind,
        }
    }
}

impl Display for VmmActionError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::VmmActionError::*;

        write!(
            f,
            "{}",
            match self {
                BootSource(_, err) => err.to_string(),
                DriveConfig(_, err) => err.to_string(),
                Logger(_, err) => err.to_string(),
                MachineConfig(_, err) => err.to_string(),
                NetworkConfig(_, err) => err.to_string(),
                OperationNotSupportedPostBoot =>
                    "The requested operation is not supported after starting the microVM."
                        .to_string(),
                OperationNotSupportedPreBoot =>
                    "The requested operation is not supported before starting the microVM."
                        .to_string(),
                StartMicrovm(_, err) => err.to_string(),
                #[cfg(target_arch = "x86_64")]
                SendCtrlAltDel(_, err) => err.to_string(),
                VsockConfig(_, err) => err.to_string(),
            }
        )
    }
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

/// Trait to be implemented by users of the `PrebootApiController`.
pub trait PrebootApiAdapter {
    /// The external implementation of this function is responsible for injecting
    /// any pending request.
    /// The provided `PrebootApiController` handler should be called for the request.
    fn preboot_request_injector(&self, handler: &mut PrebootApiController) -> Option<Vmm>;

    /// Default implementation for the function that builds and starts a microVM.
    /// It makes use of `preboot_request_injector` to inject RPC requests that configure and
    /// boot the microVM.
    ///
    /// Returns a populated `VmResources` object and a running `Vmm` object.
    fn build_microvm_from_requests(
        &self,
        seccomp_filter: BpfProgram,
        epoll_context: &mut EpollContext,
        firecracker_version: String,
    ) -> (VmResources, Vmm) {
        let mut vm_resources = VmResources::default();
        let mut built_vmm = None;
        // Need to drop the pre-boot controller to pass ownership of vm_resources.
        {
            let mut preboot_controller = PrebootApiController::new(
                seccomp_filter,
                firecracker_version,
                &mut vm_resources,
                epoll_context,
            );
            // Configure and start microVM through successive API calls.
            // Iterate through API calls to configure microVm.
            // The loop breaks when a microVM is successfully started, and returns a running Vmm.
            while built_vmm.is_none() {
                built_vmm = self.preboot_request_injector(&mut preboot_controller);
            }
        }

        // Safe to unwrap because previous loop cannot end on None.
        (vm_resources, built_vmm.unwrap())
    }
}

/// Enables pre-boot setup and instantiation of a Firecracker VMM.
pub struct PrebootApiController<'a> {
    seccomp_filter: BpfProgram,
    firecracker_version: String,
    vm_resources: &'a mut VmResources,
    epoll_context: &'a mut EpollContext,
}

impl<'a> PrebootApiController<'a> {
    /// Constructor for the PrebootApiController.
    pub fn new(
        seccomp_filter: BpfProgram,
        firecracker_version: String,
        vm_resources: &'a mut VmResources,
        epoll_context: &'a mut EpollContext,
    ) -> PrebootApiController<'a> {
        PrebootApiController {
            seccomp_filter,
            firecracker_version,
            vm_resources,
            epoll_context,
        }
    }

    /// Handles the incoming preboot request and provides a response for it.
    /// Returns a built/running `Vmm` after handling a successful `StartMicroVm` request.
    pub fn handle_preboot_request(
        &mut self,
        request: VmmAction,
    ) -> (std::result::Result<VmmData, VmmActionError>, Option<Vmm>) {
        use self::VmmAction::*;

        let mut maybe_vmm = None;
        let response = match request {
            /////////////////////////////////////////
            // Supported operations allowed pre-boot.
            ConfigureBootSource(boot_source_body) => self
                .vm_resources
                .set_boot_source(boot_source_body)
                .map(|_| VmmData::Empty)
                .map_err(|e| VmmActionError::BootSource(ErrorKind::User, e)),
            ConfigureLogger(logger_description) => {
                vmm_config::logger::init_logger(logger_description, &self.firecracker_version)
                    .map(|_| VmmData::Empty)
                    .map_err(|e| VmmActionError::Logger(ErrorKind::User, e))
            }
            GetVmConfiguration => Ok(VmmData::MachineConfiguration(
                self.vm_resources.vm_config().clone(),
            )),
            InsertBlockDevice(block_device_config) => self
                .vm_resources
                .set_block_device(block_device_config)
                .map(|_| VmmData::Empty)
                .map_err(|e| e.into()),
            InsertNetworkDevice(netif_body) => self
                .vm_resources
                .set_net_device(netif_body)
                .map(|_| VmmData::Empty)
                .map_err(|e| e.into()),
            SetVsockDevice(vsock_cfg) => {
                self.vm_resources.set_vsock_device(vsock_cfg);
                Ok(VmmData::Empty)
            }
            SetVmConfiguration(machine_config_body) => self
                .vm_resources
                .set_vm_config(machine_config_body)
                .map(|_| VmmData::Empty)
                .map_err(|e| e.into()),
            UpdateBlockDevicePath(drive_id, path_on_host) => self
                .vm_resources
                .update_block_device_path(drive_id, path_on_host)
                .map(|_| VmmData::Empty)
                .map_err(|e| e.into()),
            UpdateNetworkInterface(netif_update) => self
                .vm_resources
                .update_net_rate_limiters(netif_update)
                .map(|_| VmmData::Empty)
                .map_err(|e| e.into()),
            StartMicroVm => super::builder::build_microvm(
                &self.vm_resources,
                &mut self.epoll_context,
                &self.seccomp_filter,
            )
            .map(|vmm| {
                maybe_vmm = Some(vmm);
                VmmData::Empty
            }),

            ///////////////////////////////////
            // Operations not allowed pre-boot.
            FlushMetrics => Err(VmmActionError::Logger(
                ErrorKind::User,
                vmm_config::logger::LoggerConfigError::FlushMetrics(
                    "Cannot flush metrics before starting microVM.".to_string(),
                ),
            )),
            #[cfg(target_arch = "x86_64")]
            SendCtrlAltDel => Err(VmmActionError::OperationNotSupportedPreBoot),
        };

        (response, maybe_vmm)
    }
}

/// Enables RPC interraction with a running Firecracker VMM.
pub struct RuntimeApiController(VmmController);
impl RuntimeApiController {
    /// Constructor for the RuntimeApiController.
    pub fn new(vmm_controller: VmmController) -> RuntimeApiController {
        RuntimeApiController(vmm_controller)
    }

    /// Handles the incoming runtime `VmmAction` request and provides a response for it.
    pub fn handle_request(
        &mut self,
        request: VmmAction,
    ) -> std::result::Result<VmmData, VmmActionError> {
        use self::VmmAction::*;
        match request {
            ///////////////////////////////////
            // Supported operations allowed post-boot.
            FlushMetrics => self.0.flush_metrics().map(|_| VmmData::Empty),
            GetVmConfiguration => Ok(VmmData::MachineConfiguration(self.0.vm_config().clone())),
            #[cfg(target_arch = "x86_64")]
            SendCtrlAltDel => self.0.send_ctrl_alt_del().map(|_| VmmData::Empty),
            UpdateBlockDevicePath(drive_id, path_on_host) => self
                .0
                .update_block_device_path(drive_id, path_on_host)
                .map(|_| VmmData::Empty),
            UpdateNetworkInterface(netif_update) => self
                .0
                .update_net_rate_limiters(netif_update)
                .map(|_| VmmData::Empty),

            ///////////////////////////////////
            // Operations not allowed post-boot.
            ConfigureBootSource(_) => Err(VmmActionError::BootSource(
                ErrorKind::User,
                vmm_config::boot_source::BootSourceConfigError::UpdateNotAllowedPostBoot,
            )),
            ConfigureLogger(_) => Err(VmmActionError::Logger(
                ErrorKind::User,
                vmm_config::logger::LoggerConfigError::InitializationFailure(
                    "Cannot initialize logger after boot.".to_string(),
                ),
            )),
            InsertBlockDevice(_) => {
                Err(vmm_config::drive::DriveError::UpdateNotAllowedPostBoot.into())
            }
            InsertNetworkDevice(_) => {
                Err(vmm_config::net::NetworkInterfaceError::UpdateNotAllowedPostBoot.into())
            }
            SetVsockDevice(_) => Err(VmmActionError::VsockConfig(
                ErrorKind::User,
                vmm_config::vsock::VsockError::UpdateNotAllowedPostBoot,
            )),
            SetVmConfiguration(_) => {
                Err(vmm_config::machine_config::VmConfigError::UpdateNotAllowedPostBoot.into())
            }

            StartMicroVm => Err(super::builder::StartMicrovmError::MicroVMAlreadyRunning.into()),
        }
    }
}

/// Simple trait to be implemented by users of the `RuntimeApiController`.
pub trait RuntimeApiAdapter {
    /// The external implementation of this function is responsible for injecting
    /// any pending request.
    /// The provided `RuntimeApiController` handler should be called for the request.
    fn runtime_request_injector(
        &self,
        handler: &mut RuntimeApiController,
    ) -> result::Result<(), u8>;

    /// Default implementation that runs the vmm to completion, while any arising
    /// control events are deferred to the `RuntimeApiController` through the use of
    /// the `runtime_request_injector`.
    fn run(&self, vmm_controller: VmmController) {
        let mut controller = RuntimeApiController(vmm_controller);
        let exit_code = loop {
            match controller.0.run_event_loop() {
                Err(e) => {
                    error!("Abruptly exited VMM control loop: {:?}", e);
                    break super::FC_EXIT_CODE_GENERIC_ERROR;
                }
                Ok(exit_reason) => match exit_reason {
                    EventLoopExitReason::Break => {
                        info!("Gracefully terminated VMM control loop");
                        break super::FC_EXIT_CODE_OK;
                    }
                    EventLoopExitReason::ControlAction => {
                        if let Err(exit_code) = self.runtime_request_injector(&mut controller) {
                            break exit_code;
                        }
                    }
                },
            };
        };
        controller.0.stop(i32::from(exit_code));
    }
}
