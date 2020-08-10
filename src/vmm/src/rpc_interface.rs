// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};
use std::result;
use std::sync::{Arc, Mutex};

use super::Vmm;

use super::Error as VmmError;
use crate::builder::{self, StartMicrovmError};
#[cfg(target_arch = "x86_64")]
use crate::persist::{self, CreateSnapshotError, LoadSnapshotError};
use crate::resources::VmResources;
#[cfg(target_arch = "x86_64")]
use crate::version_map::VERSION_MAP;
use crate::vmm_config;
use crate::vmm_config::boot_source::{BootSourceConfig, BootSourceConfigError};
use crate::vmm_config::drive::{BlockDeviceConfig, DriveError};
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::logger::{LoggerConfig, LoggerConfigError};
use crate::vmm_config::machine_config::{VmConfig, VmConfigError};
use crate::vmm_config::metrics::{MetricsConfig, MetricsConfigError};
use crate::vmm_config::mmds::{MmdsConfig, MmdsConfigError};
use crate::vmm_config::net::{
    NetworkInterfaceConfig, NetworkInterfaceError, NetworkInterfaceUpdateConfig,
};
#[cfg(target_arch = "x86_64")]
use crate::vmm_config::snapshot::{CreateSnapshotParams, LoadSnapshotParams, SnapshotType};
use crate::vmm_config::vsock::{VsockConfigError, VsockDeviceConfig};
use arch::DeviceType;
use devices::virtio::{Block, MmioTransport, Net, TYPE_BLOCK, TYPE_NET};
use logger::{info, update_metric_with_elapsed_time, METRICS};
use polly::event_manager::EventManager;
use seccomp::BpfProgram;

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
    /// Create a snapshot using as input the `CreateSnapshotParams`. This action can only be called
    /// after the microVM has booted and only when the microVM is in `Paused` state.
    #[cfg(target_arch = "x86_64")]
    CreateSnapshot(CreateSnapshotParams),
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
    /// Load the microVM state using as input the `LoadSnapshotParams`. This action can only be
    /// called before the microVM has booted. If this action is successful, the loaded microVM will
    /// be in `Paused` state. Should change this state to `Resumed` for the microVM to run.
    #[cfg(target_arch = "x86_64")]
    LoadSnapshot(LoadSnapshotParams),
    /// Pause the guest, by pausing the microVM VCPUs.
    Pause,
    /// Resume the guest, by resuming the microVM VCPUs.
    Resume,
    /// Set the MMDS configuration.
    SetMmdsConfiguration(MmdsConfig),
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
    /// The action `CreateSnapshot` failed.
    #[cfg(target_arch = "x86_64")]
    CreateSnapshot(CreateSnapshotError),
    /// One of the actions `InsertBlockDevice` or `UpdateBlockDevicePath`
    /// failed because of bad user input.
    DriveConfig(DriveError),
    /// Internal Vmm error.
    InternalVmm(VmmError),
    /// Loading a microVM snapshot failed.
    #[cfg(target_arch = "x86_64")]
    LoadSnapshot(LoadSnapshotError),
    /// The action `ConfigureLogger` failed because of bad user input.
    Logger(LoggerConfigError),
    /// One of the actions `GetVmConfiguration` or `SetVmConfiguration` failed because of bad input.
    MachineConfig(VmConfigError),
    /// The action `ConfigureMetrics` failed because of bad user input.
    Metrics(MetricsConfigError),
    /// The action `SetMmdsConfiguration` failed because of bad user input.
    MmdsConfig(MmdsConfigError),
    /// The action `InsertNetworkDevice` failed because of bad user input.
    NetworkConfig(NetworkInterfaceError),
    /// The requested operation is not supported after starting the microVM.
    OperationNotSupportedPostBoot,
    /// The requested operation is not supported before starting the microVM.
    OperationNotSupportedPreBoot,
    /// The action `StartMicroVm` failed because of an internal error.
    StartMicrovm(StartMicrovmError),
    /// The action `SetVsockDevice` failed because of bad user input.
    VsockConfig(VsockConfigError),
}

impl Display for VmmActionError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::VmmActionError::*;

        write!(
            f,
            "{}",
            match self {
                BootSource(err) => err.to_string(),
                #[cfg(target_arch = "x86_64")]
                CreateSnapshot(err) => err.to_string(),
                DriveConfig(err) => err.to_string(),
                InternalVmm(err) => format!("Internal Vmm error: {}", err),
                #[cfg(target_arch = "x86_64")]
                LoadSnapshot(err) => format!("Load microVM snapshot error: {}", err),
                Logger(err) => err.to_string(),
                MachineConfig(err) => err.to_string(),
                Metrics(err) => err.to_string(),
                MmdsConfig(err) => err.to_string(),
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
                // The action `SetVsockDevice` failed because of bad user input.
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
    instance_info: InstanceInfo,
    vm_resources: &'a mut VmResources,
    event_manager: &'a mut EventManager,
    built_vmm: Option<Arc<Mutex<Vmm>>>,
}

impl<'a> PrebootApiController<'a> {
    /// Constructor for the PrebootApiController.
    pub fn new(
        seccomp_filter: BpfProgram,
        instance_info: InstanceInfo,
        vm_resources: &'a mut VmResources,
        event_manager: &'a mut EventManager,
    ) -> PrebootApiController<'a> {
        PrebootApiController {
            seccomp_filter,
            instance_info,
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
        instance_info: InstanceInfo,
        recv_req: F,
        respond: G,
    ) -> (VmResources, Arc<Mutex<Vmm>>)
    where
        F: Fn() -> VmmAction,
        G: Fn(result::Result<VmmData, VmmActionError>),
    {
        let mut vm_resources = VmResources::default();
        let mut preboot_controller = PrebootApiController::new(
            seccomp_filter,
            instance_info,
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
    ) -> result::Result<VmmData, VmmActionError> {
        use self::VmmAction::*;

        match request {
            // Supported operations allowed pre-boot.
            ConfigureBootSource(boot_source_body) => self
                .vm_resources
                .set_boot_source(boot_source_body)
                .map(|_| VmmData::Empty)
                .map_err(VmmActionError::BootSource),
            ConfigureLogger(logger_cfg) => {
                vmm_config::logger::init_logger(logger_cfg, &self.instance_info)
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
                .build_net_device(netif_body)
                .map(|_| VmmData::Empty)
                .map_err(VmmActionError::NetworkConfig),
            #[cfg(target_arch = "x86_64")]
            LoadSnapshot(snapshot_load_cfg) => self
                .load_snapshot(&snapshot_load_cfg)
                .map(|_| VmmData::Empty),
            SetVsockDevice(vsock_cfg) => self
                .vm_resources
                .set_vsock_device(vsock_cfg)
                .map(|_| VmmData::Empty)
                .map_err(VmmActionError::VsockConfig),
            SetVmConfiguration(machine_config_body) => self
                .vm_resources
                .set_vm_config(&machine_config_body)
                .map(|_| VmmData::Empty)
                .map_err(VmmActionError::MachineConfig),
            SetMmdsConfiguration(mmds_config) => self
                .vm_resources
                .set_mmds_config(mmds_config)
                .map(|_| VmmData::Empty)
                .map_err(VmmActionError::MmdsConfig),
            StartMicroVm => builder::build_microvm_for_boot(
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
            FlushMetrics
            | Pause
            | Resume
            | UpdateBlockDevicePath(_, _)
            | UpdateNetworkInterface(_) => Err(VmmActionError::OperationNotSupportedPreBoot),
            #[cfg(target_arch = "x86_64")]
            CreateSnapshot(_) | SendCtrlAltDel => Err(VmmActionError::OperationNotSupportedPreBoot),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn load_snapshot(&mut self, load_params: &LoadSnapshotParams) -> ActionResult {
        let load_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

        let loaded_vmm = persist::load_snapshot(
            &mut self.event_manager,
            &self.seccomp_filter,
            load_params,
            VERSION_MAP.clone(),
        );

        let elapsed_time_us =
            update_metric_with_elapsed_time(&METRICS.latencies_us.vmm_load_snapshot, load_start_us);
        info!("'load snapshot' VMM action took {} us.", elapsed_time_us);

        loaded_vmm
            .map(|vmm| self.built_vmm = Some(vmm))
            .map_err(VmmActionError::LoadSnapshot)
    }
}

/// Shorthand result type for external VMM commands.
pub type ActionResult = result::Result<(), VmmActionError>;

/// Enables RPC interaction with a running Firecracker VMM.
pub struct RuntimeApiController {
    vmm: Arc<Mutex<Vmm>>,
    vm_config: VmConfig,
}

impl RuntimeApiController {
    /// Handles the incoming runtime `VmmAction` request and provides a response for it.
    pub fn handle_request(
        &mut self,
        request: VmmAction,
    ) -> result::Result<VmmData, VmmActionError> {
        use self::VmmAction::*;
        match request {
            // Supported operations allowed post-boot.
            #[cfg(target_arch = "x86_64")]
            CreateSnapshot(snapshot_create_cfg) => self
                .create_snapshot(&snapshot_create_cfg)
                .map(|_| VmmData::Empty),
            FlushMetrics => self.flush_metrics().map(|_| VmmData::Empty),
            GetVmConfiguration => Ok(VmmData::MachineConfiguration(self.vm_config.clone())),
            Pause => self.pause().map(|_| VmmData::Empty),
            Resume => self.resume().map(|_| VmmData::Empty),
            #[cfg(target_arch = "x86_64")]
            SendCtrlAltDel => self.send_ctrl_alt_del().map(|_| VmmData::Empty),
            UpdateBlockDevicePath(drive_id, path_on_host) => self
                .update_block_device_path(&drive_id, path_on_host)
                .map(|_| VmmData::Empty)
                .map_err(VmmActionError::DriveConfig),
            UpdateNetworkInterface(netif_update) => self
                .update_net_rate_limiters(netif_update)
                .map(|_| VmmData::Empty),

            // Operations not allowed post-boot.
            ConfigureBootSource(_)
            | ConfigureLogger(_)
            | ConfigureMetrics(_)
            | InsertBlockDevice(_)
            | InsertNetworkDevice(_)
            | SetVsockDevice(_)
            | SetMmdsConfiguration(_)
            | SetVmConfiguration(_) => Err(VmmActionError::OperationNotSupportedPostBoot),
            #[cfg(target_arch = "x86_64")]
            LoadSnapshot(_) => Err(VmmActionError::OperationNotSupportedPostBoot),
            StartMicroVm => Err(VmmActionError::StartMicrovm(
                StartMicrovmError::MicroVMAlreadyRunning,
            )),
        }
    }

    /// Creates a new `RuntimeApiController`.
    pub fn new(vm_config: VmConfig, vmm: Arc<Mutex<Vmm>>) -> Self {
        Self { vm_config, vmm }
    }

    /// Pauses the microVM by pausing the vCPUs.
    pub fn pause(&mut self) -> ActionResult {
        let pause_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

        self.vmm
            .lock()
            .expect("Poisoned lock")
            .pause_vcpus()
            .map_err(VmmActionError::InternalVmm)?;

        let elapsed_time_us =
            update_metric_with_elapsed_time(&METRICS.latencies_us.vmm_pause_vm, pause_start_us);
        info!("'pause vm' VMM action took {} us.", elapsed_time_us);

        Ok(())
    }

    /// Resumes the microVM by resuming the vCPUs.
    pub fn resume(&mut self) -> ActionResult {
        let resume_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

        self.vmm
            .lock()
            .expect("Poisoned lock")
            .resume_vcpus()
            .map_err(VmmActionError::InternalVmm)?;

        let elapsed_time_us =
            update_metric_with_elapsed_time(&METRICS.latencies_us.vmm_resume_vm, resume_start_us);
        info!("'resume vm' VMM action took {} us.", elapsed_time_us);

        Ok(())
    }

    /// Write the metrics on user demand (flush). We use the word `flush` here to highlight the fact
    /// that the metrics will be written immediately.
    /// Defer to inner Vmm. We'll move to a variant where the Vmm simply exposes functionality like
    /// getting the dirty pages, and then we'll have the metrics flushing logic entirely on the outside.
    fn flush_metrics(&mut self) -> ActionResult {
        // FIXME: we're losing the bool saying whether metrics were actually written.
        METRICS
            .write()
            .map(|_| ())
            .map_err(super::Error::Metrics)
            .map_err(VmmActionError::InternalVmm)
    }

    /// Injects CTRL+ALT+DEL keystroke combo to the inner Vmm (if present).
    #[cfg(target_arch = "x86_64")]
    fn send_ctrl_alt_del(&mut self) -> ActionResult {
        self.vmm
            .lock()
            .expect("Poisoned lock")
            .send_ctrl_alt_del()
            .map_err(VmmActionError::InternalVmm)
    }

    #[cfg(target_arch = "x86_64")]
    fn create_snapshot(&mut self, create_params: &CreateSnapshotParams) -> ActionResult {
        let mut locked_vmm = self.vmm.lock().unwrap();
        let create_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

        persist::create_snapshot(&mut locked_vmm, create_params, VERSION_MAP.clone())
            .map_err(VmmActionError::CreateSnapshot)?;

        match create_params.snapshot_type {
            SnapshotType::Full => {
                let elapsed_time_us = update_metric_with_elapsed_time(
                    &METRICS.latencies_us.vmm_full_create_snapshot,
                    create_start_us,
                );
                info!(
                    "'create full snapshot' VMM action took {} us.",
                    elapsed_time_us
                );
            }
            SnapshotType::Diff => {
                let elapsed_time_us = update_metric_with_elapsed_time(
                    &METRICS.latencies_us.vmm_diff_create_snapshot,
                    create_start_us,
                );
                info!(
                    "'create diff snapshot' VMM action took {} us.",
                    elapsed_time_us
                );
            }
        }
        Ok(())
    }

    /// Updates the path of the host file backing the emulated block device with id `drive_id`.
    /// We update the disk image on the device and its virtio configuration.
    fn update_block_device_path(
        &mut self,
        drive_id: &str,
        path_on_host: String,
    ) -> result::Result<(), DriveError> {
        if let Some(busdev) = self
            .vmm
            .lock()
            .expect("Poisoned lock")
            .get_bus_device(DeviceType::Virtio(TYPE_BLOCK), drive_id)
        {
            // Call the update_disk_image() handler on Block. Release the lock when done.
            {
                let virtio_dev = busdev
                    .lock()
                    .expect("Poisoned lock")
                    .as_any()
                    // Only MmioTransport implements BusDevice at this point.
                    .downcast_ref::<MmioTransport>()
                    .expect("Unexpected BusDevice type")
                    // Here we get a *new* clone of Arc<Mutex<dyn VirtioDevice>>.
                    .device();

                // We need this bound to a variable so that it lives as long as the 'block' ref.
                let mut locked_device = virtio_dev.lock().expect("Poisoned lock");
                // Get a '&mut Block' ref from the above MutexGuard<dyn VirtioDevice>.
                let block = locked_device
                    .as_mut_any()
                    // We know this is a block device from the HashMap.
                    .downcast_mut::<Block>()
                    .expect("Unexpected VirtioDevice type");

                // Now we have a Block, so call its update handler.
                block
                    .update_disk_image(path_on_host)
                    .map_err(DriveError::BlockDeviceUpdateFailed)?;
            }

            // Kick the driver to pick up the changes.
            let locked_dev = busdev.lock().expect("Poisoned lock");
            locked_dev
                .interrupt(devices::virtio::VIRTIO_MMIO_INT_CONFIG)
                .map_err(DriveError::BlockDeviceUpdateFailed)?;

            Ok(())
        } else {
            Err(DriveError::InvalidBlockDeviceID)
        }
    }

    /// Updates configuration for an emulated net device as described in `new_cfg`.
    fn update_net_rate_limiters(&mut self, new_cfg: NetworkInterfaceUpdateConfig) -> ActionResult {
        if let Some(busdev) = self
            .vmm
            .lock()
            .expect("Poisoned lock")
            .get_bus_device(DeviceType::Virtio(TYPE_NET), &new_cfg.iface_id)
        {
            let virtio_device = busdev
                .lock()
                .expect("Poisoned lock")
                .as_any()
                .downcast_ref::<MmioTransport>()
                // Only MmioTransport implements BusDevice at this point.
                .expect("Unexpected BusDevice type")
                .device();

            virtio_device
                .lock()
                .expect("Poisoned lock")
                .as_mut_any()
                .downcast_mut::<Net>()
                .unwrap()
                .patch_rate_limiters(
                    new_cfg.rx_bytes(),
                    new_cfg.rx_ops(),
                    new_cfg.tx_bytes(),
                    new_cfg.tx_ops(),
                );
        } else {
            return Err(VmmActionError::NetworkConfig(
                NetworkInterfaceError::DeviceIdNotFound,
            ));
        }

        Ok(())
    }
}
