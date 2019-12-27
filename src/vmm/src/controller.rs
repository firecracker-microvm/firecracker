// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;
use std::result;

use super::{EpollContext, EventLoopExitReason, Vmm};

use arch::DeviceType;
use builder::StartMicrovmError;
use device_manager::mmio::MMIO_CFG_SPACE_OFF;
use devices::virtio::{self, TYPE_BLOCK, TYPE_NET};
use error::{Error as VmmError, Result};
use resources::VmResources;
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
    /// The requested operation is not supported after starting the microVM.
    OperationNotSupportedPostBoot,
    /// The requested operation is not supported before starting the microVM.
    OperationNotSupportedPreBoot,
    /// The action `StartMicroVm` failed either because of bad user input (`ErrorKind::User`) or
    /// an internal error (`ErrorKind::Internal`).
    StartMicrovm(ErrorKind, StartMicrovmError),
    /// The action `SendCtrlAltDel` failed. Details are provided by the device-specific error
    /// `I8042DeviceError`.
    SendCtrlAltDel(ErrorKind, VmmError),
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

/// Shorthand result type for external VMM commands.
pub type UserResult = std::result::Result<(), VmmActionError>;

/// Simple trait to be implemented by users of the `VmmController`.
pub trait ControlEventHandler {
    /// Function called when the `vmm` in the controller has a pending control event.
    fn handle_control_event(&self, controller: &mut VmmController) -> result::Result<(), u8>;
}

/// Enables pre-boot setup, instantiation and real time configuration of a Firecracker VMM.
pub struct VmmController {
    epoll_context: EpollContext,
    vm_resources: VmResources,
    vmm: Vmm,
}

impl VmmController {
    /// Returns the VmConfig.
    pub fn vm_config(&self) -> &VmConfig {
        self.vm_resources.vm_config()
    }

    /// Flush metrics. Defer to inner Vmm. We'll move to a variant where the Vmm
    /// simply exposes functionality like getting the dirty pages, and then we'll have the
    /// metrics flushing logic entirely on the outside.
    pub fn flush_metrics(&mut self) -> UserResult {
        self.vmm.write_metrics().map_err(|e| {
            VmmActionError::Logger(
                ErrorKind::Internal,
                LoggerConfigError::FlushMetrics(e.to_string()),
            )
        })
    }

    /// Injects CTRL+ALT+DEL keystroke combo to the inner Vmm (if present).
    #[cfg(target_arch = "x86_64")]
    pub fn send_ctrl_alt_del(&mut self) -> UserResult {
        self.vmm
            .send_ctrl_alt_del()
            .map_err(|e| VmmActionError::SendCtrlAltDel(ErrorKind::Internal, e))
    }

    /// Stops the inner Vmm and exits the process with the provided exit_code.
    pub fn stop(&mut self, exit_code: i32) {
        self.vmm.stop(exit_code)
    }

    /// Creates a new `VmmController`.
    pub fn new(epoll_context: EpollContext, vm_resources: VmResources, vmm: Vmm) -> Self {
        VmmController {
            epoll_context,
            vm_resources,
            vmm,
        }
    }

    /// Wait for and dispatch events. Will defer to the inner Vmm loop after it's started.
    pub fn run_event_loop(&mut self) -> Result<EventLoopExitReason> {
        self.vmm.run_event_loop(&mut self.epoll_context)
    }

    /// Runs the vmm to completion, any control events are deferred to the `ControlActionHandler`.
    pub fn run(mut self, external_handler: &dyn ControlEventHandler) {
        let exit_code = loop {
            match self.run_event_loop() {
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
                        if let Err(exit_code) = external_handler.handle_control_event(&mut self) {
                            break exit_code;
                        }
                    }
                },
            };
        };
        self.stop(i32::from(exit_code));
    }

    /// Triggers a rescan of the host file backing the emulated block device with id `drive_id`.
    pub fn rescan_block_device(&mut self, drive_id: &str) -> UserResult {
        // Rescan can only happen after the guest is booted.
        for drive_config in self.vm_resources.block.config_list.iter() {
            if drive_config.drive_id != *drive_id {
                continue;
            }

            // Use seek() instead of stat() (std::fs::Metadata) to support block devices.
            let new_size = File::open(&drive_config.path_on_host)
                .and_then(|mut f| f.seek(SeekFrom::End(0)))
                .map_err(|_| DriveError::BlockDeviceUpdateFailed)?;
            if new_size % virtio::block::SECTOR_SIZE != 0 {
                warn!(
                    "Disk size {} is not a multiple of sector size {}; \
                     the remainder will not be visible to the guest.",
                    new_size,
                    virtio::block::SECTOR_SIZE
                );
            }

            return match self
                .vmm
                .get_bus_device(DeviceType::Virtio(TYPE_BLOCK), drive_id)
            {
                Some(device) => {
                    let data = devices::virtio::build_config_space(new_size);
                    let mut busdev = device
                        .lock()
                        .map_err(|_| VmmActionError::from(DriveError::BlockDeviceUpdateFailed))?;

                    busdev.write(MMIO_CFG_SPACE_OFF, &data[..]);
                    busdev.interrupt(devices::virtio::VIRTIO_MMIO_INT_CONFIG);

                    Ok(())
                }
                None => Err(VmmActionError::from(DriveError::BlockDeviceUpdateFailed)),
            };
        }

        Err(VmmActionError::from(DriveError::InvalidBlockDeviceID))
    }

    fn update_drive_handler(
        &mut self,
        drive_id: &str,
        disk_image: File,
    ) -> result::Result<(), DriveError> {
        // The unwrap is safe because this is only called after the inner Vmm has booted.
        let handler = self
            .epoll_context
            .get_device_handler_by_device_id::<virtio::BlockEpollHandler>(TYPE_BLOCK, drive_id)
            .map_err(|_| DriveError::EpollHandlerNotFound)?;

        handler
            .update_disk_image(disk_image)
            .map_err(|_| DriveError::BlockDeviceUpdateFailed)
    }

    /// Updates the path of the host file backing the emulated block device with id `drive_id`.
    pub fn update_block_device_path(
        &mut self,
        drive_id: String,
        path_on_host: String,
    ) -> UserResult {
        // Get the block device configuration specified by drive_id.
        let block_device_index = self
            .vm_resources
            .block
            .get_index_of_drive_id(&drive_id)
            .ok_or(DriveError::InvalidBlockDeviceID)?;

        let file_path = PathBuf::from(path_on_host);
        // Try to open the file specified by path_on_host using the permissions of the block_device.
        let disk_file = OpenOptions::new()
            .read(true)
            .write(!self.vm_resources.block.config_list[block_device_index].is_read_only())
            .open(&file_path)
            .map_err(DriveError::CannotOpenBlockDevice)?;

        // Update the path of the block device with the specified path_on_host.
        self.vm_resources.block.config_list[block_device_index].path_on_host = file_path;

        // When the microvm is running, we also need to update the drive handler and send a
        // rescan command to the drive.
        self.update_drive_handler(&drive_id, disk_file)?;
        self.rescan_block_device(&drive_id)?;
        Ok(())
    }

    /// Updates configuration for an emulated net device as described in `new_cfg`.
    pub fn update_net_rate_limiters(
        &mut self,
        new_cfg: NetworkInterfaceUpdateConfig,
    ) -> UserResult {
        let handler = self
            .epoll_context
            .get_device_handler_by_device_id::<virtio::NetEpollHandler>(TYPE_NET, &new_cfg.iface_id)
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
        Ok(())
    }
}
