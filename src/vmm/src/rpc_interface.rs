// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};

use super::Vmm;

use super::Error as VmmError;
use builder::StartMicrovmError;
use controller::VmmController;
use polly::event_manager::EventManager;
use resources::VmResources;
use seccomp::BpfProgram;
use vmm_config;
use vmm_config::boot_source::{BootSourceConfig, BootSourceConfigError};
use vmm_config::drive::{BlockDeviceConfig, DriveError};
use vmm_config::logger::{LoggerConfig, LoggerConfigError};
use vmm_config::machine_config::{VmConfig, VmConfigError};
use vmm_config::metrics::{MetricsConfig, MetricsConfigError};
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
    /// Configure the metrics using as input the `MetricsConfig`. This action can only be called
    /// before the microVM has booted.
    ConfigureMetrics(MetricsConfig),
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

/// Wrapper for all errors associated with VMM actions.
#[derive(Debug)]
pub enum VmmActionError {
    /// The action `ConfigureBootSource` failed because of bad user input.
    BootSource(BootSourceConfigError),
    /// One of the actions `InsertBlockDevice` or `UpdateBlockDevicePath`
    /// failed because of bad user input.
    DriveConfig(DriveError),
    /// Internal Vmm error.
    InternalVmm(VmmError),
    /// The action `ConfigureLogger` failed because of bad user input.
    Logger(LoggerConfigError),
    /// One of the actions `GetVmConfiguration` or `SetVmConfiguration` failed because of bad input.
    MachineConfig(VmConfigError),
    /// The action `ConfigureMetrics` failed because of bad user input.
    Metrics(MetricsConfigError),
    /// The action `InsertNetworkDevice` failed because of bad user input.
    NetworkConfig(NetworkInterfaceError),
    /// The requested operation is not supported after starting the microVM.
    OperationNotSupportedPostBoot,
    /// The requested operation is not supported before starting the microVM.
    OperationNotSupportedPreBoot,
    /// The action `StartMicroVm` failed because of an internal error.
    StartMicrovm(StartMicrovmError),
    /// The action `set_vsock_device` failed because of bad user input.
    VsockConfig(VsockError),
}

impl Display for VmmActionError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::VmmActionError::*;

        write!(
            f,
            "{}",
            match self {
                BootSource(err) => err.to_string(),
                DriveConfig(err) => err.to_string(),
                InternalVmm(err) => format!("Internal Vmm error: {}", err),
                Logger(err) => err.to_string(),
                MachineConfig(err) => err.to_string(),
                Metrics(err) => err.to_string(),
                NetworkConfig(err) => err.to_string(),
                OperationNotSupportedPostBoot => {
                    "The requested operation is not supported after starting the microVM."
                        .to_string()
                }
                OperationNotSupportedPreBoot => {
                    "The requested operation is not supported before starting the microVM."
                        .to_string()
                }
                StartMicrovm(err) => err.to_string(),
                VsockConfig(err) => err.to_string(),
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

/// Enables pre-boot setup and instantiation of a Firecracker VMM.
pub struct PrebootApiController<'a> {
    seccomp_filter: BpfProgram,
    firecracker_version: String,
    vm_resources: &'a mut VmResources,
    event_manager: &'a mut EventManager,

    built_vmm: Option<Arc<Mutex<Vmm>>>,
}

impl<'a> PrebootApiController<'a> {
    /// Constructor for the PrebootApiController.
    pub fn new(
        seccomp_filter: BpfProgram,
        firecracker_version: String,
        vm_resources: &'a mut VmResources,
        event_manager: &'a mut EventManager,
    ) -> PrebootApiController<'a> {
        PrebootApiController {
            seccomp_filter,
            firecracker_version,
            vm_resources,
            event_manager,
            built_vmm: None,
        }
    }

    /// Default implementation for the function that builds and starts a microVM.
    /// It takes two closures `recv_req` and `respond` as params which abstract away
    /// the message transport.
    ///
    /// Returns a populated `VmResources` object and a running `Vmm` object.
    pub fn build_microvm_from_requests<F, G>(
        seccomp_filter: BpfProgram,
        event_manager: &mut EventManager,
        firecracker_version: String,
        recv_req: F,
        respond: G,
    ) -> (VmResources, Arc<Mutex<Vmm>>)
    where
        F: Fn() -> VmmAction,
        G: Fn(std::result::Result<VmmData, VmmActionError>),
    {
        let mut vm_resources = VmResources::default();
        let mut preboot_controller = PrebootApiController::new(
            seccomp_filter,
            firecracker_version,
            &mut vm_resources,
            event_manager,
        );
        // Configure and start microVM through successive API calls.
        // Iterate through API calls to configure microVm.
        // The loop breaks when a microVM is successfully started, and a running Vmm is built.
        while preboot_controller.built_vmm.is_none() {
            // Get request, process it, send back the response.
            respond(preboot_controller.handle_preboot_request(recv_req()));
        }

        // Safe to unwrap because previous loop cannot end on None.
        let vmm = preboot_controller.built_vmm.unwrap();
        (vm_resources, vmm)
    }

    /// Handles the incoming preboot request and provides a response for it.
    /// Returns a built/running `Vmm` after handling a successful `StartMicroVm` request.
    pub fn handle_preboot_request(
        &mut self,
        request: VmmAction,
    ) -> std::result::Result<VmmData, VmmActionError> {
        use self::VmmAction::*;

        match request {
            // Supported operations allowed pre-boot.
            ConfigureBootSource(boot_source_body) => self
                .vm_resources
                .set_boot_source(boot_source_body)
                .map(|_| VmmData::Empty)
                .map_err(VmmActionError::BootSource),
            ConfigureLogger(logger_cfg) => {
                vmm_config::logger::init_logger(logger_cfg, &self.firecracker_version)
                    .map(|_| VmmData::Empty)
                    .map_err(VmmActionError::Logger)
            }
            ConfigureMetrics(metrics_cfg) => vmm_config::metrics::init_metrics(metrics_cfg)
                .map(|_| VmmData::Empty)
                .map_err(VmmActionError::Metrics),
            GetVmConfiguration => Ok(VmmData::MachineConfiguration(
                self.vm_resources.vm_config().clone(),
            )),
            InsertBlockDevice(block_device_config) => self
                .vm_resources
                .set_block_device(block_device_config)
                .map(|_| VmmData::Empty)
                .map_err(VmmActionError::DriveConfig),
            InsertNetworkDevice(netif_body) => self
                .vm_resources
                .set_net_device(netif_body)
                .map(|_| VmmData::Empty)
                .map_err(VmmActionError::NetworkConfig),
            SetVsockDevice(vsock_cfg) => {
                self.vm_resources.set_vsock_device(vsock_cfg);
                Ok(VmmData::Empty)
            }
            SetVmConfiguration(machine_config_body) => self
                .vm_resources
                .set_vm_config(&machine_config_body)
                .map(|_| VmmData::Empty)
                .map_err(VmmActionError::MachineConfig),
            UpdateBlockDevicePath(drive_id, path_on_host) => self
                .vm_resources
                .update_block_device_path(drive_id, path_on_host)
                .map(|_| VmmData::Empty)
                .map_err(VmmActionError::DriveConfig),
            UpdateNetworkInterface(netif_update) => self
                .vm_resources
                .update_net_rate_limiters(netif_update)
                .map(|_| VmmData::Empty)
                .map_err(VmmActionError::NetworkConfig),
            StartMicroVm => super::builder::build_microvm(
                &self.vm_resources,
                &mut self.event_manager,
                &self.seccomp_filter,
            )
            .map(|vmm| {
                self.built_vmm = Some(vmm);
                VmmData::Empty
            })
            .map_err(VmmActionError::StartMicrovm),

            // Operations not allowed pre-boot.
            FlushMetrics => Err(VmmActionError::OperationNotSupportedPreBoot),
            #[cfg(target_arch = "x86_64")]
            SendCtrlAltDel => Err(VmmActionError::OperationNotSupportedPreBoot),
        }
    }
}

/// Enables RPC interraction with a running Firecracker VMM.
pub struct RuntimeApiController(pub VmmController);
impl RuntimeApiController {
    /// Handles the incoming runtime `VmmAction` request and provides a response for it.
    pub fn handle_request(
        &mut self,
        request: VmmAction,
    ) -> std::result::Result<VmmData, VmmActionError> {
        use self::VmmAction::*;
        match request {
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

            // Operations not allowed post-boot.
            ConfigureBootSource(_)
            | ConfigureLogger(_)
            | ConfigureMetrics(_)
            | InsertBlockDevice(_)
            | InsertNetworkDevice(_)
            | SetVsockDevice(_)
            | SetVmConfiguration(_) => Err(VmmActionError::OperationNotSupportedPostBoot),
            StartMicroVm => Err(VmmActionError::StartMicrovm(
                StartMicrovmError::MicroVMAlreadyRunning,
            )),
        }
    }
}
