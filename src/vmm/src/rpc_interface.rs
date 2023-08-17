// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{self, Debug};
use std::sync::{Arc, Mutex, MutexGuard};

use logger::{error, info, warn, *};
use mmds::data_store::{self, Mmds};
use seccompiler::BpfThreadMap;
use serde_json::Value;
#[cfg(test)]
use tests::{
    build_and_boot_microvm, create_snapshot, restore_from_snapshot, MockVmRes as VmResources,
    MockVmm as Vmm,
};

use super::VmmError;
#[cfg(not(test))]
use super::{
    builder::build_and_boot_microvm, persist::create_snapshot, persist::restore_from_snapshot,
    resources::VmResources, Vmm,
};
use crate::builder::StartMicrovmError;
use crate::cpu_config::templates::{CustomCpuTemplate, GuestConfigError};
use crate::persist::{CreateSnapshotError, RestoreFromSnapshotError, VmInfo};
use crate::resources::VmmConfig;
use crate::version_map::VERSION_MAP;
use crate::vmm_config::balloon::{
    BalloonConfigError, BalloonDeviceConfig, BalloonStats, BalloonUpdateConfig,
    BalloonUpdateStatsConfig,
};
use crate::vmm_config::boot_source::{BootSourceConfig, BootSourceConfigError};
use crate::vmm_config::drive::{BlockDeviceConfig, BlockDeviceUpdateConfig, DriveError};
use crate::vmm_config::entropy::{EntropyDeviceConfig, EntropyDeviceError};
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::logger::{LoggerConfig, LoggerHandles};
use crate::vmm_config::machine_config::{MachineConfig, MachineConfigUpdate, VmConfigError};
use crate::vmm_config::metrics::{MetricsConfig, MetricsConfigError};
use crate::vmm_config::mmds::{MmdsConfig, MmdsConfigError};
use crate::vmm_config::net::{
    NetworkInterfaceConfig, NetworkInterfaceError, NetworkInterfaceUpdateConfig,
};
use crate::vmm_config::snapshot::{CreateSnapshotParams, LoadSnapshotParams, SnapshotType};
use crate::vmm_config::vsock::{VsockConfigError, VsockDeviceConfig};
use crate::vmm_config::{self, RateLimiterUpdate};
use crate::{EventManager, FcExitCode};

/// This enum represents the public interface of the VMM. Each action contains various
/// bits of information (ids, paths, etc.).
#[derive(Debug, PartialEq, Eq)]
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
    CreateSnapshot(CreateSnapshotParams),
    /// Get the balloon device configuration.
    GetBalloonConfig,
    /// Get the ballon device latest statistics.
    GetBalloonStats,
    /// Get complete microVM configuration in JSON format.
    GetFullVmConfig,
    /// Get MMDS contents.
    GetMMDS,
    /// Get the machine configuration of the microVM.
    GetVmMachineConfig,
    /// Get microVM instance information.
    GetVmInstanceInfo,
    /// Get microVM version.
    GetVmmVersion,
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
    LoadSnapshot(LoadSnapshotParams),
    /// Partial update of the MMDS contents.
    PatchMMDS(Value),
    /// Pause the guest, by pausing the microVM VCPUs.
    Pause,
    /// Repopulate the MMDS contents.
    PutMMDS(Value),
    /// Configure the guest vCPU features.
    PutCpuConfiguration(CustomCpuTemplate),
    /// Resume the guest, by resuming the microVM VCPUs.
    Resume,
    /// Set the balloon device or update the one that already exists using the
    /// `BalloonDeviceConfig` as input. This action can only be called before the microVM
    /// has booted.
    SetBalloonDevice(BalloonDeviceConfig),
    /// Set the MMDS configuration.
    SetMmdsConfiguration(MmdsConfig),
    /// Set the vsock device or update the one that already exists using the
    /// `VsockDeviceConfig` as input. This action can only be called before the microVM has
    /// booted.
    SetVsockDevice(VsockDeviceConfig),
    /// Set the entropy device using `EntropyDeviceConfig` as input. This action can only be called
    /// before the microVM has booted.
    SetEntropyDevice(EntropyDeviceConfig),
    /// Launch the microVM. This action can only be called before the microVM has booted.
    StartMicroVm,
    /// Send CTRL+ALT+DEL to the microVM, using the i8042 keyboard function. If an AT-keyboard
    /// driver is listening on the guest end, this can be used to shut down the microVM gracefully.
    #[cfg(target_arch = "x86_64")]
    SendCtrlAltDel,
    /// Update the balloon size, after microVM start.
    UpdateBalloon(BalloonUpdateConfig),
    /// Update the balloon statistics polling interval, after microVM start.
    UpdateBalloonStatistics(BalloonUpdateStatsConfig),
    /// Update existing block device properties such as `path_on_host` or `rate_limiter`.
    UpdateBlockDevice(BlockDeviceUpdateConfig),
    /// Update a network interface, after microVM start. Currently, the only updatable properties
    /// are the RX and TX rate limiters.
    UpdateNetworkInterface(NetworkInterfaceUpdateConfig),
    /// Update the microVM configuration (memory & vcpu) using `VmUpdateConfig` as input. This
    /// action can only be called before the microVM has booted.
    UpdateVmConfiguration(MachineConfigUpdate),
}

/// Wrapper for all errors associated with VMM actions.
#[derive(Debug, thiserror::Error, derive_more::From)]
pub enum VmmActionError {
    /// The action `SetBalloonDevice` failed because of bad user input.
    #[error("{0}")]
    BalloonConfig(BalloonConfigError),
    /// The action `ConfigureBootSource` failed because of bad user input.
    #[error("{0}")]
    BootSource(BootSourceConfigError),
    /// The action `CreateSnapshot` failed.
    #[error("{0}")]
    CreateSnapshot(CreateSnapshotError),
    /// The action `ConfigureCpu` failed.
    #[error("{0}")]
    ConfigureCpu(GuestConfigError),
    /// One of the actions `InsertBlockDevice` or `UpdateBlockDevicePath`
    /// failed because of bad user input.
    #[error("{0}")]
    DriveConfig(DriveError),
    /// `SetEntropyDevice` action failed because of bad user input.
    #[error("{0}")]
    EntropyDevice(EntropyDeviceError),
    /// Internal Vmm error.
    #[error("Internal Vmm error: {0}")]
    InternalVmm(VmmError),
    /// Loading a microVM snapshot failed.
    #[error("Load microVM snapshot error: {0}")]
    LoadSnapshot(LoadSnapshotError),
    /// The action `ConfigureLogger` failed because of bad user input.
    #[error("{0}")]
    Logger(crate::vmm_config::logger::UpdateLoggerError),
    /// One of the actions `GetVmConfiguration` or `UpdateVmConfiguration` failed because of bad
    /// input.
    #[error("{0}")]
    MachineConfig(VmConfigError),
    /// The action `ConfigureMetrics` failed because of bad user input.
    #[error("{0}")]
    Metrics(MetricsConfigError),
    /// One of the `GetMmds`, `PutMmds` or `PatchMmds` actions failed.
    #[from(ignore)]
    #[error("{0}")]
    Mmds(data_store::Error),
    /// The action `SetMmdsConfiguration` failed because of bad user input.
    #[error("{0}")]
    MmdsConfig(MmdsConfigError),
    /// Mmds contents update failed due to exceeding the data store limit.
    #[from(ignore)]
    #[error("{0}")]
    MmdsLimitExceeded(data_store::Error),
    /// The action `InsertNetworkDevice` failed because of bad user input.
    #[error("{0}")]
    NetworkConfig(NetworkInterfaceError),
    /// The requested operation is not supported.
    #[error("The requested operation is not supported: {0}")]
    NotSupported(String),
    /// The requested operation is not supported after starting the microVM.
    #[error("The requested operation is not supported after starting the microVM.")]
    OperationNotSupportedPostBoot,
    /// The requested operation is not supported before starting the microVM.
    #[error("The requested operation is not supported before starting the microVM.")]
    OperationNotSupportedPreBoot,
    /// The action `StartMicroVm` failed because of an internal error.
    #[error("{0}")]
    StartMicrovm(StartMicrovmError),
    /// The action `SetVsockDevice` failed because of bad user input.
    #[error("{0}")]
    VsockConfig(VsockConfigError),
}

/// The enum represents the response sent by the VMM in case of success. The response is either
/// empty, when no data needs to be sent, or an internal VMM structure.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq)]
pub enum VmmData {
    /// The balloon device configuration.
    BalloonConfig(BalloonDeviceConfig),
    /// The latest balloon device statistics.
    BalloonStats(BalloonStats),
    /// No data is sent on the channel.
    Empty,
    /// The complete microVM configuration in JSON format.
    FullVmConfig(VmmConfig),
    /// The microVM configuration represented by `VmConfig`.
    MachineConfiguration(MachineConfig),
    /// Mmds contents.
    MmdsValue(serde_json::Value),
    /// The microVM instance information.
    InstanceInformation(InstanceInfo),
    /// The microVM version.
    VmmVersion(String),
}

/// Trait used for deduplicating the MMDS request handling across the two ApiControllers.
/// The methods get a mutable reference to self because the methods should initialise the data
/// store with the defaults if it's not already initialised.
trait MmdsRequestHandler {
    fn mmds(&mut self) -> MutexGuard<'_, Mmds>;

    fn get_mmds(&mut self) -> Result<VmmData, VmmActionError> {
        Ok(VmmData::MmdsValue(self.mmds().data_store_value()))
    }

    fn patch_mmds(&mut self, value: serde_json::Value) -> Result<VmmData, VmmActionError> {
        self.mmds()
            .patch_data(value)
            .map(|()| VmmData::Empty)
            .map_err(|err| match err {
                data_store::Error::DataStoreLimitExceeded => {
                    VmmActionError::MmdsLimitExceeded(data_store::Error::DataStoreLimitExceeded)
                }
                _ => VmmActionError::Mmds(err),
            })
    }

    fn put_mmds(&mut self, value: serde_json::Value) -> Result<VmmData, VmmActionError> {
        self.mmds()
            .put_data(value)
            .map(|()| VmmData::Empty)
            .map_err(|err| match err {
                data_store::Error::DataStoreLimitExceeded => {
                    VmmActionError::MmdsLimitExceeded(data_store::Error::DataStoreLimitExceeded)
                }
                _ => VmmActionError::Mmds(err),
            })
    }
}

/// Enables pre-boot setup and instantiation of a Firecracker VMM.
pub struct PrebootApiController<'a, F, G> {
    seccomp_filters: &'a BpfThreadMap,
    instance_info: InstanceInfo,
    vm_resources: &'a mut VmResources,
    event_manager: &'a mut EventManager,
    built_vmm: Option<Arc<Mutex<Vmm>>>,
    // Configuring boot specific resources will set this to true.
    // Loading from snapshot will not be allowed once this is true.
    boot_path: bool,
    // Some PrebootApiRequest errors are irrecoverable and Firecracker
    // should cleanly teardown if they occur.
    fatal_error: Option<FcExitCode>,
    /// Handles that allow re-configuring the logger.
    logger_handles: LoggerHandles<F, G>,
}

// TODO Remove when `EventManager` implements `std::fmt::Debug`.
impl<'a, F, G> fmt::Debug for PrebootApiController<'a, F, G> {
    #[tracing::instrument(level = "trace", skip(self, f))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrebootApiController")
            .field("seccomp_filters", &self.seccomp_filters)
            .field("instance_info", &self.instance_info)
            .field("vm_resources", &self.vm_resources)
            .field("event_manager", &"?")
            .field("built_vmm", &self.built_vmm)
            .field("boot_path", &self.boot_path)
            .field("fatal_error", &self.fatal_error)
            .finish()
    }
}

impl<F, G> MmdsRequestHandler for PrebootApiController<'_, F, G> {
    #[tracing::instrument(level = "trace", skip(self))]
    fn mmds(&mut self) -> MutexGuard<'_, Mmds> {
        self.vm_resources.locked_mmds_or_default()
    }
}

/// Error type for [`PrebootApiController::load_snapshot`]
#[derive(Debug, thiserror::Error)]
pub enum LoadSnapshotError {
    /// Loading a microVM snapshot not allowed after configuring boot-specific resources.
    #[error("Loading a microVM snapshot not allowed after configuring boot-specific resources.")]
    LoadSnapshotNotAllowed,
    /// Failed to restore from snapshot.
    #[error("Failed to restore from snapshot: {0}")]
    RestoreFromSnapshot(#[from] RestoreFromSnapshotError),
    /// Failed to resume microVM.
    #[error("Failed to resume microVM: {0}")]
    ResumeMicrovm(#[from] VmmError),
}

/// Shorthand type for a request containing a boxed VmmAction.
pub type ApiRequest = Box<VmmAction>;
/// Shorthand type for a response containing a boxed Result.
pub type ApiResponse = Box<std::result::Result<VmmData, VmmActionError>>;

impl<'a, F: Fn(&tracing::Metadata<'_>) -> bool, G: Fn(&tracing::Metadata<'_>) -> bool>
    PrebootApiController<'a, F, G>
{
    #[tracing::instrument(
        level = "trace",
        skip(
            seccomp_filters,
            instance_info,
            vm_resources,
            event_manager,
            logger_handles
        )
    )]
    /// Constructor for the PrebootApiController.
    pub fn new(
        seccomp_filters: &'a BpfThreadMap,
        instance_info: InstanceInfo,
        vm_resources: &'a mut VmResources,
        event_manager: &'a mut EventManager,
        logger_handles: LoggerHandles<F, G>,
    ) -> Self {
        Self {
            seccomp_filters,
            instance_info,
            vm_resources,
            event_manager,
            built_vmm: None,
            boot_path: false,
            fatal_error: None,
            logger_handles,
        }
    }

    #[tracing::instrument(
        level = "trace",
        skip(
            seccomp_filters,
            event_manager,
            instance_info,
            from_api,
            to_api,
            api_event_fd,
            boot_timer_enabled,
            mmds_size_limit,
            metadata_json,
            logger_handles
        )
    )]
    /// Default implementation for the function that builds and starts a microVM.
    ///
    /// Returns a populated `VmResources` object and a running `Vmm` object.
    #[allow(clippy::too_many_arguments)]
    pub fn build_microvm_from_requests(
        seccomp_filters: &BpfThreadMap,
        event_manager: &mut EventManager,
        instance_info: InstanceInfo,
        from_api: &std::sync::mpsc::Receiver<ApiRequest>,
        to_api: &std::sync::mpsc::Sender<ApiResponse>,
        api_event_fd: &utils::eventfd::EventFd,
        boot_timer_enabled: bool,
        mmds_size_limit: usize,
        metadata_json: Option<&str>,
        logger_handles: LoggerHandles<F, G>,
    ) -> Result<(VmResources, Arc<Mutex<Vmm>>), FcExitCode> {
        let mut vm_resources = VmResources::default();
        // Silence false clippy warning. Clippy suggests using
        // VmResources { boot_timer: boot_timer_enabled, ..Default::default() }; but this will
        // generate build errors because VmResources contains private fields.
        #[allow(clippy::field_reassign_with_default)]
        {
            vm_resources.mmds_size_limit = mmds_size_limit;
            vm_resources.boot_timer = boot_timer_enabled;
        }

        // Init the data store from file, if present.
        if let Some(data) = metadata_json {
            vm_resources
                .locked_mmds_or_default()
                .put_data(
                    serde_json::from_str(data)
                        .expect("MMDS error: metadata provided not valid json"),
                )
                .map_err(|err| {
                    error!("Populating MMDS from file failed: {:?}", err);
                    crate::FcExitCode::GenericError
                })?;

            info!("Successfully added metadata to mmds from file");
        }

        let mut preboot_controller = PrebootApiController::new(
            seccomp_filters,
            instance_info,
            &mut vm_resources,
            event_manager,
            logger_handles,
        );

        // Configure and start microVM through successive API calls.
        // Iterate through API calls to configure microVm.
        // The loop breaks when a microVM is successfully started, and a running Vmm is built.
        while preboot_controller.built_vmm.is_none() {
            // Get request
            let req = from_api
                .recv()
                .expect("The channel's sending half was disconnected. Cannot receive data.");

            // Also consume the API event along with the message. It is safe to unwrap()
            // because this event_fd is blocking.
            api_event_fd
                .read()
                .expect("VMM: Failed to read the API event_fd");

            // Process the request.
            let res = preboot_controller.handle_preboot_request(*req);

            // Send back the response.
            to_api.send(Box::new(res)).expect("one-shot channel closed");

            // If any fatal errors were encountered, break the loop.
            if let Some(exit_code) = preboot_controller.fatal_error {
                return Err(exit_code);
            }
        }

        // Safe to unwrap because previous loop cannot end on None.
        let vmm = preboot_controller.built_vmm.unwrap();
        Ok((vm_resources, vmm))
    }

    #[tracing::instrument(level = "trace", skip(self, request))]
    /// Handles the incoming preboot request and provides a response for it.
    /// Returns a built/running `Vmm` after handling a successful `StartMicroVm` request.
    pub fn handle_preboot_request(
        &mut self,
        request: VmmAction,
    ) -> Result<VmmData, VmmActionError> {
        use self::VmmAction::*;

        match request {
            // Supported operations allowed pre-boot.
            ConfigureBootSource(config) => self.set_boot_source(config),
            ConfigureLogger(logger_cfg) => logger_cfg
                .update(&self.logger_handles)
                .map(|()| VmmData::Empty)
                .map_err(VmmActionError::Logger),
            ConfigureMetrics(metrics_cfg) => vmm_config::metrics::init_metrics(metrics_cfg)
                .map(|()| VmmData::Empty)
                .map_err(VmmActionError::Metrics),
            GetBalloonConfig => self.balloon_config(),
            GetFullVmConfig => {
                warn!(
                    "If the VM was restored from snapshot, boot-source, machine-config.smt, and \
                     machine-config.cpu_template will all be empty."
                );
                Ok(VmmData::FullVmConfig((&*self.vm_resources).into()))
            }
            GetMMDS => self.get_mmds(),
            GetVmMachineConfig => Ok(VmmData::MachineConfiguration(MachineConfig::from(
                &self.vm_resources.vm_config,
            ))),
            GetVmInstanceInfo => Ok(VmmData::InstanceInformation(self.instance_info.clone())),
            GetVmmVersion => Ok(VmmData::VmmVersion(self.instance_info.vmm_version.clone())),
            InsertBlockDevice(config) => self.insert_block_device(config),
            InsertNetworkDevice(config) => self.insert_net_device(config),
            LoadSnapshot(config) => self
                .load_snapshot(&config)
                .map_err(VmmActionError::LoadSnapshot),
            PatchMMDS(value) => self.patch_mmds(value),
            PutCpuConfiguration(custom_cpu_template) => {
                self.set_custom_cpu_template(custom_cpu_template)
            }
            PutMMDS(value) => self.put_mmds(value),
            SetBalloonDevice(config) => self.set_balloon_device(config),
            SetVsockDevice(config) => self.set_vsock_device(config),
            SetMmdsConfiguration(config) => self.set_mmds_config(config),
            StartMicroVm => self.start_microvm(),
            UpdateVmConfiguration(config) => self.update_vm_config(config),
            SetEntropyDevice(config) => self.set_entropy_device(config),
            // Operations not allowed pre-boot.
            CreateSnapshot(_)
            | FlushMetrics
            | Pause
            | Resume
            | GetBalloonStats
            | UpdateBalloon(_)
            | UpdateBalloonStatistics(_)
            | UpdateBlockDevice(_)
            | UpdateNetworkInterface(_) => Err(VmmActionError::OperationNotSupportedPreBoot),
            #[cfg(target_arch = "x86_64")]
            SendCtrlAltDel => Err(VmmActionError::OperationNotSupportedPreBoot),
        }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn balloon_config(&mut self) -> Result<VmmData, VmmActionError> {
        self.vm_resources
            .balloon
            .get_config()
            .map(VmmData::BalloonConfig)
            .map_err(VmmActionError::BalloonConfig)
    }

    #[tracing::instrument(level = "trace", skip(self, cfg))]
    fn insert_block_device(&mut self, cfg: BlockDeviceConfig) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .set_block_device(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::DriveConfig)
    }

    #[tracing::instrument(level = "trace", skip(self, cfg))]
    fn insert_net_device(
        &mut self,
        cfg: NetworkInterfaceConfig,
    ) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .build_net_device(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::NetworkConfig)
    }

    #[tracing::instrument(level = "trace", skip(self, cfg))]
    fn set_balloon_device(&mut self, cfg: BalloonDeviceConfig) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .set_balloon_device(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::BalloonConfig)
    }

    #[tracing::instrument(level = "trace", skip(self, cfg))]
    fn set_boot_source(&mut self, cfg: BootSourceConfig) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .build_boot_source(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::BootSource)
    }

    #[tracing::instrument(level = "trace", skip(self, cfg))]
    fn set_mmds_config(&mut self, cfg: MmdsConfig) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .set_mmds_config(cfg, &self.instance_info.id)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::MmdsConfig)
    }

    #[tracing::instrument(level = "trace", skip(self, cfg))]
    fn update_vm_config(&mut self, cfg: MachineConfigUpdate) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .update_vm_config(&cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::MachineConfig)
    }

    #[tracing::instrument(level = "trace", skip(self, cpu_template))]
    fn set_custom_cpu_template(
        &mut self,
        cpu_template: CustomCpuTemplate,
    ) -> Result<VmmData, VmmActionError> {
        self.vm_resources.set_custom_cpu_template(cpu_template);
        Ok(VmmData::Empty)
    }

    #[tracing::instrument(level = "trace", skip(self, cfg))]
    fn set_vsock_device(&mut self, cfg: VsockDeviceConfig) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .set_vsock_device(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::VsockConfig)
    }

    #[tracing::instrument(level = "trace", skip(self, cfg))]
    fn set_entropy_device(&mut self, cfg: EntropyDeviceConfig) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources.build_entropy_device(cfg)?;
        Ok(VmmData::Empty)
    }

    // On success, this command will end the pre-boot stage and this controller
    // will be replaced by a runtime controller.
    #[tracing::instrument(level = "trace", skip(self))]
    fn start_microvm(&mut self) -> Result<VmmData, VmmActionError> {
        build_and_boot_microvm(
            &self.instance_info,
            self.vm_resources,
            self.event_manager,
            self.seccomp_filters,
        )
        .map(|vmm| {
            self.built_vmm = Some(vmm);
            VmmData::Empty
        })
        .map_err(VmmActionError::StartMicrovm)
    }

    // On success, this command will end the pre-boot stage and this controller
    // will be replaced by a runtime controller.
    #[tracing::instrument(level = "trace", skip(self, load_params))]
    fn load_snapshot(
        &mut self,
        load_params: &LoadSnapshotParams,
    ) -> Result<VmmData, LoadSnapshotError> {
        log_dev_preview_warning("Virtual machine snapshots", Option::None);

        let load_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

        if self.boot_path {
            let err = LoadSnapshotError::LoadSnapshotNotAllowed;
            info!("{}", err);
            return Err(err);
        }

        if load_params.enable_diff_snapshots {
            self.vm_resources.set_track_dirty_pages(true);
        }

        // Restore VM from snapshot
        let vmm = restore_from_snapshot(
            &self.instance_info,
            self.event_manager,
            self.seccomp_filters,
            load_params,
            VERSION_MAP.clone(),
            self.vm_resources,
        )
        .map_err(|err| {
            // If restore fails, we consider the process is too dirty to recover.
            self.fatal_error = Some(FcExitCode::BadConfiguration);
            err
        })?;
        // Resume VM
        if load_params.resume_vm {
            vmm.lock()
                .expect("Poisoned lock")
                .resume_vm()
                .map_err(|err| {
                    // If resume fails, we consider the process is too dirty to recover.
                    self.fatal_error = Some(FcExitCode::BadConfiguration);
                    err
                })?;
        }
        // Set the VM
        self.built_vmm = Some(vmm);

        log_dev_preview_warning(
            "Virtual machine snapshots",
            Some(format!(
                "'load snapshot' VMM action took {} us.",
                update_metric_with_elapsed_time(
                    &METRICS.latencies_us.vmm_load_snapshot,
                    load_start_us
                )
            )),
        );

        Ok(VmmData::Empty)
    }
}

/// Enables RPC interaction with a running Firecracker VMM.
#[derive(Debug)]
pub struct RuntimeApiController {
    vmm: Arc<Mutex<Vmm>>,
    vm_resources: VmResources,
}

impl MmdsRequestHandler for RuntimeApiController {
    #[tracing::instrument(level = "trace", skip(self))]
    fn mmds(&mut self) -> MutexGuard<'_, Mmds> {
        self.vm_resources.locked_mmds_or_default()
    }
}

impl RuntimeApiController {
    #[tracing::instrument(level = "trace", skip(self, request))]
    /// Handles the incoming runtime `VmmAction` request and provides a response for it.
    pub fn handle_request(&mut self, request: VmmAction) -> Result<VmmData, VmmActionError> {
        use self::VmmAction::*;
        match request {
            // Supported operations allowed post-boot.
            CreateSnapshot(snapshot_create_cfg) => self.create_snapshot(&snapshot_create_cfg),
            FlushMetrics => self.flush_metrics(),
            GetBalloonConfig => self
                .vmm
                .lock()
                .expect("Poisoned lock")
                .balloon_config()
                .map(|state| VmmData::BalloonConfig(BalloonDeviceConfig::from(state)))
                .map_err(|err| VmmActionError::BalloonConfig(BalloonConfigError::from(err))),
            GetBalloonStats => self
                .vmm
                .lock()
                .expect("Poisoned lock")
                .latest_balloon_stats()
                .map(VmmData::BalloonStats)
                .map_err(|err| VmmActionError::BalloonConfig(BalloonConfigError::from(err))),
            GetFullVmConfig => Ok(VmmData::FullVmConfig((&self.vm_resources).into())),
            GetMMDS => self.get_mmds(),
            GetVmMachineConfig => Ok(VmmData::MachineConfiguration(MachineConfig::from(
                &self.vm_resources.vm_config,
            ))),
            GetVmInstanceInfo => Ok(VmmData::InstanceInformation(
                self.vmm.lock().expect("Poisoned lock").instance_info(),
            )),
            GetVmmVersion => Ok(VmmData::VmmVersion(
                self.vmm.lock().expect("Poisoned lock").version(),
            )),
            PatchMMDS(value) => self.patch_mmds(value),
            Pause => self.pause(),
            PutMMDS(value) => self.put_mmds(value),
            Resume => self.resume(),
            #[cfg(target_arch = "x86_64")]
            SendCtrlAltDel => self.send_ctrl_alt_del(),
            UpdateBalloon(balloon_update) => self
                .vmm
                .lock()
                .expect("Poisoned lock")
                .update_balloon_config(balloon_update.amount_mib)
                .map(|_| VmmData::Empty)
                .map_err(|err| VmmActionError::BalloonConfig(BalloonConfigError::from(err))),
            UpdateBalloonStatistics(balloon_stats_update) => self
                .vmm
                .lock()
                .expect("Poisoned lock")
                .update_balloon_stats_config(balloon_stats_update.stats_polling_interval_s)
                .map(|_| VmmData::Empty)
                .map_err(|err| VmmActionError::BalloonConfig(BalloonConfigError::from(err))),
            UpdateBlockDevice(new_cfg) => self.update_block_device(new_cfg),
            UpdateNetworkInterface(netif_update) => self.update_net_rate_limiters(netif_update),

            // Operations not allowed post-boot.
            ConfigureBootSource(_)
            | ConfigureLogger(_)
            | ConfigureMetrics(_)
            | InsertBlockDevice(_)
            | InsertNetworkDevice(_)
            | LoadSnapshot(_)
            | PutCpuConfiguration(_)
            | SetBalloonDevice(_)
            | SetVsockDevice(_)
            | SetMmdsConfiguration(_)
            | SetEntropyDevice(_)
            | StartMicroVm
            | UpdateVmConfiguration(_) => Err(VmmActionError::OperationNotSupportedPostBoot),
        }
    }

    #[tracing::instrument(level = "trace", skip(vm_resources, vmm))]
    /// Creates a new `RuntimeApiController`.
    pub fn new(vm_resources: VmResources, vmm: Arc<Mutex<Vmm>>) -> Self {
        Self { vmm, vm_resources }
    }

    #[tracing::instrument(level = "trace", skip(self))]
    /// Pauses the microVM by pausing the vCPUs.
    pub fn pause(&mut self) -> Result<VmmData, VmmActionError> {
        let pause_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

        self.vmm.lock().expect("Poisoned lock").pause_vm()?;

        let elapsed_time_us =
            update_metric_with_elapsed_time(&METRICS.latencies_us.vmm_pause_vm, pause_start_us);
        info!("'pause vm' VMM action took {} us.", elapsed_time_us);

        Ok(VmmData::Empty)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    /// Resumes the microVM by resuming the vCPUs.
    pub fn resume(&mut self) -> Result<VmmData, VmmActionError> {
        let resume_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

        self.vmm.lock().expect("Poisoned lock").resume_vm()?;

        let elapsed_time_us =
            update_metric_with_elapsed_time(&METRICS.latencies_us.vmm_resume_vm, resume_start_us);
        info!("'resume vm' VMM action took {} us.", elapsed_time_us);

        Ok(VmmData::Empty)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    /// Write the metrics on user demand (flush). We use the word `flush` here to highlight the fact
    /// that the metrics will be written immediately.
    /// Defer to inner Vmm. We'll move to a variant where the Vmm simply exposes functionality like
    /// getting the dirty pages, and then we'll have the metrics flushing logic entirely on the
    /// outside.
    fn flush_metrics(&mut self) -> Result<VmmData, VmmActionError> {
        // FIXME: we're losing the bool saying whether metrics were actually written.
        METRICS
            .write()
            .map(|_| VmmData::Empty)
            .map_err(super::VmmError::Metrics)
            .map_err(VmmActionError::InternalVmm)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    /// Injects CTRL+ALT+DEL keystroke combo to the inner Vmm (if present).
    #[cfg(target_arch = "x86_64")]
    fn send_ctrl_alt_del(&mut self) -> Result<VmmData, VmmActionError> {
        self.vmm
            .lock()
            .expect("Poisoned lock")
            .send_ctrl_alt_del()
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::InternalVmm)
    }

    #[tracing::instrument(level = "trace", skip(self, create_params))]
    fn create_snapshot(
        &mut self,
        create_params: &CreateSnapshotParams,
    ) -> Result<VmmData, VmmActionError> {
        log_dev_preview_warning("Virtual machine snapshots", None);

        if create_params.snapshot_type == SnapshotType::Diff
            && !self.vm_resources.track_dirty_pages()
        {
            return Err(VmmActionError::NotSupported(
                "Diff snapshots are not allowed on uVMs with dirty page tracking disabled."
                    .to_string(),
            ));
        }

        let mut locked_vmm = self.vmm.lock().unwrap();
        let vm_info = VmInfo::from(&self.vm_resources);
        let create_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

        create_snapshot(
            &mut locked_vmm,
            &vm_info,
            create_params,
            VERSION_MAP.clone(),
        )?;

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
        Ok(VmmData::Empty)
    }

    #[tracing::instrument(level = "trace", skip(self, new_cfg))]
    /// Updates block device properties:
    ///  - path of the host file backing the emulated block device, update the disk image on the
    ///    device and its virtio configuration
    ///  - rate limiter configuration.
    fn update_block_device(
        &mut self,
        new_cfg: BlockDeviceUpdateConfig,
    ) -> Result<VmmData, VmmActionError> {
        let mut vmm = self.vmm.lock().expect("Poisoned lock");
        if let Some(new_path) = new_cfg.path_on_host {
            vmm.update_block_device_path(&new_cfg.drive_id, new_path)
                .map(|()| VmmData::Empty)
                .map_err(DriveError::DeviceUpdate)?;
        }
        if new_cfg.rate_limiter.is_some() {
            vmm.update_block_rate_limiter(
                &new_cfg.drive_id,
                RateLimiterUpdate::from(new_cfg.rate_limiter).bandwidth,
                RateLimiterUpdate::from(new_cfg.rate_limiter).ops,
            )
            .map(|()| VmmData::Empty)
            .map_err(DriveError::DeviceUpdate)?;
        }
        Ok(VmmData::Empty)
    }

    #[tracing::instrument(level = "trace", skip(self, new_cfg))]
    /// Updates configuration for an emulated net device as described in `new_cfg`.
    fn update_net_rate_limiters(
        &mut self,
        new_cfg: NetworkInterfaceUpdateConfig,
    ) -> Result<VmmData, VmmActionError> {
        self.vmm
            .lock()
            .expect("Poisoned lock")
            .update_net_rate_limiters(
                &new_cfg.iface_id,
                RateLimiterUpdate::from(new_cfg.rx_rate_limiter).bandwidth,
                RateLimiterUpdate::from(new_cfg.rx_rate_limiter).ops,
                RateLimiterUpdate::from(new_cfg.tx_rate_limiter).bandwidth,
                RateLimiterUpdate::from(new_cfg.tx_rate_limiter).ops,
            )
            .map(|()| VmmData::Empty)
            .map_err(NetworkInterfaceError::DeviceUpdate)
            .map_err(VmmActionError::NetworkConfig)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use seccompiler::BpfThreadMap;

    use super::*;
    use crate::cpu_config::templates::StaticCpuTemplate;
    use crate::devices::virtio::balloon::{BalloonConfig, BalloonError};
    use crate::devices::virtio::rng::EntropyError;
    use crate::devices::virtio::VsockError;
    use crate::vmm_config::balloon::BalloonBuilder;
    use crate::vmm_config::machine_config::VmConfig;
    use crate::vmm_config::vsock::VsockBuilder;

    impl PartialEq for VmmActionError {
        #[tracing::instrument(level = "trace", skip(self, other))]
        fn eq(&self, other: &VmmActionError) -> bool {
            use VmmActionError::*;
            matches!(
                (self, other),
                (BalloonConfig(_), BalloonConfig(_))
                    | (BootSource(_), BootSource(_))
                    | (CreateSnapshot(_), CreateSnapshot(_))
                    | (DriveConfig(_), DriveConfig(_))
                    | (InternalVmm(_), InternalVmm(_))
                    | (LoadSnapshot(_), LoadSnapshot(_))
                    | (MachineConfig(_), MachineConfig(_))
                    | (Metrics(_), Metrics(_))
                    | (Mmds(_), Mmds(_))
                    | (MmdsLimitExceeded(_), MmdsLimitExceeded(_))
                    | (MmdsConfig(_), MmdsConfig(_))
                    | (NetworkConfig(_), NetworkConfig(_))
                    | (NotSupported(_), NotSupported(_))
                    | (OperationNotSupportedPostBoot, OperationNotSupportedPostBoot)
                    | (OperationNotSupportedPreBoot, OperationNotSupportedPreBoot)
                    | (StartMicrovm(_), StartMicrovm(_))
                    | (VsockConfig(_), VsockConfig(_))
                    | (EntropyDevice(_), EntropyDevice(_))
            )
        }
    }

    // Mock `VmResources` used for testing.
    #[derive(Debug, Default)]
    pub struct MockVmRes {
        pub vm_config: VmConfig,
        pub balloon: BalloonBuilder,
        pub vsock: VsockBuilder,
        balloon_config_called: bool,
        balloon_set: bool,
        boot_src: BootSourceConfig,
        boot_cfg_set: bool,
        block_set: bool,
        vsock_set: bool,
        net_set: bool,
        entropy_set: bool,
        pub mmds: Option<Arc<Mutex<Mmds>>>,
        pub mmds_size_limit: usize,
        pub boot_timer: bool,
        // when `true`, all self methods are forced to fail
        pub force_errors: bool,
    }

    impl MockVmRes {
        #[tracing::instrument(level = "trace", skip(self))]
        pub fn balloon_config(&mut self) -> Result<BalloonConfig, BalloonError> {
            if self.force_errors {
                return Err(BalloonError::DeviceNotFound);
            }
            self.balloon_config_called = true;
            Ok(BalloonConfig::default())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn track_dirty_pages(&self) -> bool {
            self.vm_config.track_dirty_pages
        }

        #[tracing::instrument(level = "trace", skip(self, dirty_page_tracking))]
        pub fn set_track_dirty_pages(&mut self, dirty_page_tracking: bool) {
            self.vm_config.track_dirty_pages = dirty_page_tracking;
        }

        #[tracing::instrument(level = "trace", skip(self, update))]
        pub fn update_vm_config(
            &mut self,
            update: &MachineConfigUpdate,
        ) -> Result<(), VmConfigError> {
            if self.force_errors {
                return Err(VmConfigError::InvalidVcpuCount);
            }

            self.vm_config.update(update)?;

            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn set_balloon_device(
            &mut self,
            _: BalloonDeviceConfig,
        ) -> Result<(), BalloonConfigError> {
            if self.force_errors {
                return Err(BalloonConfigError::DeviceNotFound);
            }
            self.balloon_set = true;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self, boot_source))]
        pub fn build_boot_source(
            &mut self,
            boot_source: BootSourceConfig,
        ) -> Result<(), BootSourceConfigError> {
            if self.force_errors {
                return Err(BootSourceConfigError::InvalidKernelPath(
                    std::io::Error::from_raw_os_error(0),
                ));
            }
            self.boot_src = boot_source;
            self.boot_cfg_set = true;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn boot_source_config(&self) -> &BootSourceConfig {
            &self.boot_src
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn set_block_device(&mut self, _: BlockDeviceConfig) -> Result<(), DriveError> {
            if self.force_errors {
                return Err(DriveError::RootBlockDeviceAlreadyAdded);
            }
            self.block_set = true;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn build_net_device(
            &mut self,
            _: NetworkInterfaceConfig,
        ) -> Result<(), NetworkInterfaceError> {
            if self.force_errors {
                return Err(NetworkInterfaceError::GuestMacAddressInUse(String::new()));
            }
            self.net_set = true;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn set_vsock_device(&mut self, _: VsockDeviceConfig) -> Result<(), VsockConfigError> {
            if self.force_errors {
                return Err(VsockConfigError::CreateVsockDevice(
                    VsockError::BufDescMissing,
                ));
            }
            self.vsock_set = true;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn build_entropy_device(
            &mut self,
            _: EntropyDeviceConfig,
        ) -> Result<(), EntropyDeviceError> {
            if self.force_errors {
                return Err(EntropyDeviceError::CreateDevice(EntropyError::EventFd(
                    io::Error::from_raw_os_error(0),
                )));
            }
            self.entropy_set = true;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self, mmds_config))]
        pub fn set_mmds_config(
            &mut self,
            mmds_config: MmdsConfig,
            _: &str,
        ) -> Result<(), MmdsConfigError> {
            if self.force_errors {
                return Err(MmdsConfigError::InvalidIpv4Addr);
            }
            let mut mmds_guard = self.locked_mmds_or_default();
            mmds_guard
                .set_version(mmds_config.version)
                .map_err(|err| MmdsConfigError::MmdsVersion(mmds_config.version, err))?;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        /// If not initialised, create the mmds data store with the default config.
        pub fn mmds_or_default(&mut self) -> &Arc<Mutex<Mmds>> {
            self.mmds
                .get_or_insert(Arc::new(Mutex::new(Mmds::default_with_limit(
                    self.mmds_size_limit,
                ))))
        }

        #[tracing::instrument(level = "trace", skip(self))]
        /// If not initialised, create the mmds data store with the default config.
        pub fn locked_mmds_or_default(&mut self) -> MutexGuard<'_, Mmds> {
            let mmds = self.mmds_or_default();
            mmds.lock().expect("Poisoned lock")
        }

        #[tracing::instrument(level = "trace", skip(self, cpu_template))]
        /// Update the CPU configuration for the guest.
        pub fn set_custom_cpu_template(&mut self, cpu_template: CustomCpuTemplate) {
            self.vm_config.set_custom_cpu_template(cpu_template);
        }
    }

    impl From<&MockVmRes> for VmmConfig {
        #[tracing::instrument(level = "trace", skip())]
        fn from(_: &MockVmRes) -> Self {
            VmmConfig::default()
        }
    }

    impl From<&MockVmRes> for VmInfo {
        #[tracing::instrument(level = "trace", skip(value))]
        fn from(value: &MockVmRes) -> Self {
            Self {
                mem_size_mib: value.vm_config.mem_size_mib as u64,
                smt: value.vm_config.smt,
                cpu_template: StaticCpuTemplate::from(&value.vm_config.cpu_template),
                boot_source: value.boot_source_config().clone(),
            }
        }
    }

    // Mock `Vmm` used for testing.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub struct MockVmm {
        pub balloon_config_called: bool,
        pub latest_balloon_stats_called: bool,
        pub pause_called: bool,
        pub resume_called: bool,
        #[cfg(target_arch = "x86_64")]
        pub send_ctrl_alt_del_called: bool,
        pub update_balloon_config_called: bool,
        pub update_balloon_stats_config_called: bool,
        pub update_block_device_path_called: bool,
        pub update_net_rate_limiters_called: bool,
        // when `true`, all self methods are forced to fail
        pub force_errors: bool,
    }

    impl MockVmm {
        #[tracing::instrument(level = "trace", skip(self))]
        pub fn resume_vm(&mut self) -> Result<(), VmmError> {
            if self.force_errors {
                return Err(VmmError::VcpuResume);
            }
            self.resume_called = true;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn pause_vm(&mut self) -> Result<(), VmmError> {
            if self.force_errors {
                return Err(VmmError::VcpuPause);
            }
            self.pause_called = true;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        #[cfg(target_arch = "x86_64")]
        pub fn send_ctrl_alt_del(&mut self) -> Result<(), VmmError> {
            if self.force_errors {
                return Err(VmmError::I8042Error(
                    crate::devices::legacy::I8042DeviceError::InternalBufferFull,
                ));
            }
            self.send_ctrl_alt_del_called = true;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn balloon_config(&mut self) -> Result<BalloonConfig, BalloonError> {
            if self.force_errors {
                return Err(BalloonError::DeviceNotFound);
            }
            self.balloon_config_called = true;
            Ok(BalloonConfig::default())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn latest_balloon_stats(&mut self) -> Result<BalloonStats, BalloonError> {
            if self.force_errors {
                return Err(BalloonError::DeviceNotFound);
            }
            self.latest_balloon_stats_called = true;
            Ok(BalloonStats::default())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn update_balloon_config(&mut self, _: u32) -> Result<(), BalloonError> {
            if self.force_errors {
                return Err(BalloonError::DeviceNotFound);
            }
            self.update_balloon_config_called = true;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn update_balloon_stats_config(&mut self, _: u16) -> Result<(), BalloonError> {
            if self.force_errors {
                return Err(BalloonError::DeviceNotFound);
            }
            self.update_balloon_stats_config_called = true;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn update_block_device_path(&mut self, _: &str, _: String) -> Result<(), VmmError> {
            if self.force_errors {
                return Err(VmmError::DeviceManager(
                    crate::device_manager::mmio::MmioError::InvalidDeviceType,
                ));
            }
            self.update_block_device_path_called = true;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn update_block_rate_limiter(
            &mut self,
            _: &str,
            _: crate::rate_limiter::BucketUpdate,
            _: crate::rate_limiter::BucketUpdate,
        ) -> Result<(), VmmError> {
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn update_net_rate_limiters(
            &mut self,
            _: &str,
            _: crate::rate_limiter::BucketUpdate,
            _: crate::rate_limiter::BucketUpdate,
            _: crate::rate_limiter::BucketUpdate,
            _: crate::rate_limiter::BucketUpdate,
        ) -> Result<(), VmmError> {
            if self.force_errors {
                return Err(VmmError::DeviceManager(
                    crate::device_manager::mmio::MmioError::InvalidDeviceType,
                ));
            }
            self.update_net_rate_limiters_called = true;
            Ok(())
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn instance_info(&self) -> InstanceInfo {
            InstanceInfo::default()
        }

        #[tracing::instrument(level = "trace", skip(self))]
        pub fn version(&self) -> String {
            String::default()
        }
    }

    // Need to redefine this since the non-test one uses real VmResources
    // and real Vmm instead of our mocks.
    #[tracing::instrument(level = "trace", skip())]
    pub fn build_and_boot_microvm(
        _: &InstanceInfo,
        _: &VmResources,
        _: &mut EventManager,
        _: &BpfThreadMap,
    ) -> Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
        Ok(Arc::new(Mutex::new(MockVmm::default())))
    }

    // Need to redefine this since the non-test one uses real Vmm
    // instead of our mocks.
    #[tracing::instrument(level = "trace", skip())]
    pub fn create_snapshot(
        _: &mut Vmm,
        _: &VmInfo,
        _: &CreateSnapshotParams,
        _: versionize::VersionMap,
    ) -> Result<(), CreateSnapshotError> {
        Ok(())
    }

    // Need to redefine this since the non-test one uses real Vmm
    // instead of our mocks.
    #[tracing::instrument(level = "trace", skip())]
    pub fn restore_from_snapshot(
        _: &InstanceInfo,
        _: &mut EventManager,
        _: &BpfThreadMap,
        _: &LoadSnapshotParams,
        _: versionize::VersionMap,
        _: &mut MockVmRes,
    ) -> Result<Arc<Mutex<Vmm>>, RestoreFromSnapshotError> {
        Ok(Arc::new(Mutex::new(MockVmm::default())))
    }

    #[test]
    fn test_runtime_get_mmds() {
        check_runtime_request(VmmAction::GetMMDS, |result, _| {
            assert_eq!(result, Ok(VmmData::MmdsValue(Value::Null)));
        });
    }

    #[test]
    fn test_runtime_put_mmds() {
        let mmds = Arc::new(Mutex::new(Mmds::default()));

        check_runtime_request_with_mmds(
            VmmAction::PutMMDS(Value::String("string".to_string())),
            mmds.clone(),
            |result, _| {
                assert_eq!(result, Ok(VmmData::Empty));
            },
        );
        check_runtime_request_with_mmds(VmmAction::GetMMDS, mmds.clone(), |result, _| {
            assert_eq!(
                result,
                Ok(VmmData::MmdsValue(Value::String("string".to_string())))
            );
        });

        let filling = (0..51300).map(|_| "X").collect::<String>();
        let data = "{\"key\": \"".to_string() + &filling + "\"}";

        check_runtime_request_with_mmds(
            VmmAction::PutMMDS(serde_json::from_str(&data).unwrap()),
            mmds.clone(),
            |result, _| {
                assert!(matches!(result, Err(VmmActionError::MmdsLimitExceeded(_))));
            },
        );
        check_runtime_request_with_mmds(VmmAction::GetMMDS, mmds, |result, _| {
            assert_eq!(
                result,
                Ok(VmmData::MmdsValue(Value::String("string".to_string())))
            );
        });
    }

    #[tracing::instrument(level = "trace", skip(request, check_success))]
    fn check_runtime_request<F>(request: VmmAction, check_success: F)
    where
        F: FnOnce(Result<VmmData, VmmActionError>, &MockVmm),
    {
        let vmm = Arc::new(Mutex::new(MockVmm::default()));
        let mut runtime = RuntimeApiController::new(MockVmRes::default(), vmm.clone());
        let res = runtime.handle_request(request);
        check_success(res, &vmm.lock().unwrap());
    }

    #[tracing::instrument(level = "trace", skip(request, mmds, check_success))]
    fn check_runtime_request_with_mmds<F>(
        request: VmmAction,
        mmds: Arc<Mutex<Mmds>>,
        check_success: F,
    ) where
        F: FnOnce(Result<VmmData, VmmActionError>, &MockVmm),
    {
        let vm_res = MockVmRes {
            mmds: Some(mmds),
            ..Default::default()
        };
        let vmm = Arc::new(Mutex::new(MockVmm::default()));
        let mut runtime = RuntimeApiController::new(vm_res, vmm.clone());
        let res = runtime.handle_request(request);
        check_success(res, &vmm.lock().unwrap());
    }

    #[test]
    fn test_runtime_get_vm_config() {
        let req = VmmAction::GetVmMachineConfig;
        check_runtime_request(req, |result, _| {
            assert_eq!(
                result,
                Ok(VmmData::MachineConfiguration(MachineConfig::default()))
            );
        });
    }
}
