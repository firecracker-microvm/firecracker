// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{self, Debug};
use std::sync::{Arc, Mutex, MutexGuard};

use log::{error, info, warn};
use logger::*;
use mmds::data_store::Mmds;
use seccompiler::BpfThreadMap;
use serde_json::Value;

use super::builder::build_and_boot_microvm;
use super::persist::restore_from_snapshot;
use super::resources::VmResources;
use super::{Vmm, VmmError};
use crate::builder::StartMicrovmError;
use crate::cpu_config::templates::CustomCpuTemplate;
use crate::persist::{RestoreFromSnapshotError, VmInfo};
use crate::resources::VmmConfig;
use crate::version_map::VERSION_MAP;
use crate::vmm_config::balloon::{
    BalloonDeviceConfig, BalloonGetConfigError, BalloonStats, BalloonUpdateConfig,
    BalloonUpdateStatsConfig,
};
use crate::vmm_config::boot_source::{BootSourceConfig, BootSourceConfigError};
use crate::vmm_config::drive::{BlockDeviceConfig, BlockDeviceUpdateConfig, DriveError};
use crate::vmm_config::entropy::{EntropyDeviceConfig, EntropyDeviceError};
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::logger::{InitLoggerError, LoggerConfig};
use crate::vmm_config::machine_config::{MachineConfig, MachineConfigUpdate, VmConfigError};
use crate::vmm_config::metrics::{InitMetricsError, MetricsConfig};
use crate::vmm_config::mmds::{MmdsConfig, MmdsConfigError};
use crate::vmm_config::net::{
    NetworkInterfaceConfig, NetworkInterfaceError, NetworkInterfaceUpdateConfig,
};
use crate::vmm_config::snapshot::{CreateSnapshotParams, LoadSnapshotParams, SnapshotType};
use crate::vmm_config::vsock::{VsockConfigError, VsockDeviceConfig};
use crate::vmm_config::{self, RateLimiterUpdate};
use crate::EventManager;

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
#[derive(Debug, thiserror::Error)]
pub enum VmmActionError {
    /// Failed to handle pre-boot request.
    #[error("Failed to handle pre-boot request: {0}")]
    HandlePrebootRequest(HandlePrebootRequestError),
    /// Failed to handle post-boot request.
    #[error("Failed to handle post-boot request: {0}")]
    HandlePostbootRequest(HandlePostbootRequestError),
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

    fn get_mmds(&mut self) -> VmmData {
        VmmData::MmdsValue(self.mmds().data_store_value())
    }

    fn patch_mmds(&mut self, value: serde_json::Value) -> Result<(), mmds::data_store::Error> {
        self.mmds().patch_data(value)
    }

    fn put_mmds(&mut self, value: serde_json::Value) -> Result<(), mmds::data_store::Error> {
        self.mmds().put_data(value)
    }
}

/// Enables pre-boot setup and instantiation of a Firecracker VMM.
pub struct PrebootApiController<'a> {
    seccomp_filters: &'a BpfThreadMap,
    instance_info: InstanceInfo,
    vm_resources: &'a mut VmResources,
    event_manager: &'a mut EventManager,
    built_vmm: Option<Arc<Mutex<Vmm>>>,
    // Configuring boot specific resources will set this to true.
    // Loading from snapshot will not be allowed once this is true.
    boot_path: bool,
}

// TODO Remove when `EventManager` implements `std::fmt::Debug`.
impl<'a> fmt::Debug for PrebootApiController<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrebootApiController")
            .field("seccomp_filters", &self.seccomp_filters)
            .field("instance_info", &self.instance_info)
            .field("vm_resources", &self.vm_resources)
            .field("event_manager", &"?")
            .field("built_vmm", &self.built_vmm)
            .field("boot_path", &self.boot_path)
            .finish()
    }
}

impl MmdsRequestHandler for PrebootApiController<'_> {
    fn mmds(&mut self) -> MutexGuard<'_, Mmds> {
        self.vm_resources.locked_mmds_or_default()
    }
}

/// Shorthand type for a request containing a boxed VmmAction.
pub type ApiRequest = Box<VmmAction>;
/// Shorthand type for a response containing a boxed Result.
pub type ApiResponse = Box<std::result::Result<VmmData, VmmActionError>>;

/// Error type for [`PrebootApiController::build_microvm_from_requests`].
#[derive(Debug, thiserror::Error)]
pub enum BuildMicrovmFromRequestsError {
    /// MMDS error: metadata provided not valid json.
    #[error("MMDS error: metadata provided not valid json: {0}")]
    MmdsData(serde_json::Error),
    /// Populating MMDS from file failed.
    #[error("Populating MMDS from file failed: {0}")]
    PopulateMmds(mmds::data_store::Error),
    /// The channel's sending half was disconnected. Cannot receive data.
    #[error("The channel's sending half was disconnected. Cannot receive data: {0}")]
    GetRequest(std::sync::mpsc::RecvError),
    /// VMM: Failed to read the API event_fd.
    #[error("VMM: Failed to read the API event_fd: {0}")]
    ConsumeApiToken(std::io::Error),
    /// Failed to restore snapshot.
    #[error("Failed to restore snapshot: {0}")]
    SnapshotRestore(RestoreFromSnapshotError),
    /// Failed to resume snapshot.
    #[error("Failed to resume snapshot: {0}")]
    SnapshotResume(VmmError),
    /// Failed respond to API.
    #[error("Failed respond to API: {0}")]
    Respond(std::sync::mpsc::SendError<ApiResponse>),
}

/// Error type for [`PrebootApiController::handle_preboot_request`]
#[derive(Debug, thiserror::Error)]
pub enum HandlePrebootRequestError {
    /// Failed to set boot source.
    #[error("Failed to set boot source: {0}")]
    SetBootSource(BootSourceConfigError),
    /// Failed to intiailize logger.
    #[error("Failed to intiailize logger: {0}")]
    InitLogger(InitLoggerError),
    /// Failed to intiailize metrics.
    #[error("Failed to intiailize metrics: {0}")]
    InitMetrics(InitMetricsError),
    /// Failed to configure balloon device.
    #[error("Failed to configure balloon device: {0}")]
    BalloonConfig(BalloonGetConfigError),
    /// Failed to insert block device.
    #[error("Failed to insert block device: {0}")]
    InsertBlockDevice(DriveError),
    /// Failed to insert net device.
    #[error("Failed to insert net device: {0}")]
    InsertNetDevice(NetworkInterfaceError),
    /// Failed to load snapshot.
    #[error("Failed to load snapshot: {0}")]
    LoadSnapshot(LoadSnapshotError),
    /// Failed to patch mmds.
    #[error("Failed to patch mmds: {0}")]
    PatchMmds(mmds::data_store::Error),
    /// Failed to put mmds.
    #[error("Failed to put mmds: {0}")]
    PutMmds(mmds::data_store::Error),
    /// Failed to set balloon device.
    #[error("Failed to set balloon device: {0}")]
    SetBalloonDevice(BalloonGetConfigError),
    /// Failed to set vsock device.
    #[error("Failed to set vsock device: {0}")]
    SetVsockDevice(VsockConfigError),
    /// Failed to set mmds configuration.
    #[error("Failed to set mmds configuration: {0}")]
    SetMmdsConfig(MmdsConfigError),
    /// Failed to start microvm.
    #[error("Failed to start microvm: {0}")]
    StartMicrovm(StartMicrovmError),
    /// Failed to update vm config.
    #[error("Failed to update vm config: {0}")]
    UpdateVmConfig(VmConfigError),
    /// Failed to set entropy device.
    #[error("Failed to set entropy device: {0}")]
    SetEntropyDevice(EntropyDeviceError),
    /// Operation not supported pre-boot.
    #[error("Operation not supported pre-boot.")]
    OperationNotSupportedPreBoot,
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

impl<'a> PrebootApiController<'a> {
    /// Constructor for the PrebootApiController.
    pub fn new(
        seccomp_filters: &'a BpfThreadMap,
        instance_info: InstanceInfo,
        vm_resources: &'a mut VmResources,
        event_manager: &'a mut EventManager,
    ) -> Self {
        Self {
            seccomp_filters,
            instance_info,
            vm_resources,
            event_manager,
            built_vmm: None,
            boot_path: false,
        }
    }

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
    ) -> Result<(VmResources, Arc<Mutex<Vmm>>), BuildMicrovmFromRequestsError> {
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
            let data =
                serde_json::from_str(data).map_err(BuildMicrovmFromRequestsError::MmdsData)?;
            vm_resources
                .locked_mmds_or_default()
                .put_data(data)
                .map_err(BuildMicrovmFromRequestsError::PopulateMmds)?;

            info!("Successfully added metadata to mmds from file");
        }

        let mut preboot_controller = PrebootApiController::new(
            seccomp_filters,
            instance_info,
            &mut vm_resources,
            event_manager,
        );

        // Configure and start microVM through successive API calls.
        // Iterate through API calls to configure microVm.
        // The loop breaks when a microVM is successfully started, and a running Vmm is built.
        while preboot_controller.built_vmm.is_none() {
            // Get request
            let req = from_api
                .recv()
                .map_err(BuildMicrovmFromRequestsError::GetRequest)?;

            // Also consume the API event along with the message. It is safe to unwrap()
            // because this event_fd is blocking.
            api_event_fd
                .read()
                .map_err(BuildMicrovmFromRequestsError::ConsumeApiToken)?;

            // Process the request.
            let res = match preboot_controller.handle_preboot_request(*req) {
                // We consider these errors fatal and that the boot process can no longer continue.
                Err(HandlePrebootRequestError::LoadSnapshot(
                    LoadSnapshotError::RestoreFromSnapshot(err),
                )) => Err(BuildMicrovmFromRequestsError::SnapshotRestore(err)),
                Err(HandlePrebootRequestError::LoadSnapshot(LoadSnapshotError::ResumeMicrovm(
                    err,
                ))) => Err(BuildMicrovmFromRequestsError::SnapshotResume(err)),
                // If there is no error we take no action
                Ok(ok) => Ok(Ok(ok)),
                // If there is an error but it is not fatal we convert to the response error type.
                Err(err) => Ok(Err(VmmActionError::HandlePrebootRequest(err))),
            }?;

            // Send back the response.
            to_api
                .send(Box::new(res))
                .map_err(BuildMicrovmFromRequestsError::Respond)?;
        }

        // Safe to unwrap because previous loop cannot end on None.
        let vmm = preboot_controller.built_vmm.unwrap();
        Ok((vm_resources, vmm))
    }

    /// Handles the incoming preboot request and provides a response for it.
    /// Returns a built/running `Vmm` after handling a successful `StartMicroVm` request.
    pub fn handle_preboot_request(
        &mut self,
        request: VmmAction,
    ) -> Result<VmmData, HandlePrebootRequestError> {
        use self::VmmAction::*;
        type Err = HandlePrebootRequestError;

        match request {
            // Supported operations allowed pre-boot.
            ConfigureBootSource(config) => {
                self.boot_path = true;
                self.vm_resources
                    .build_boot_source(config)
                    .map(|()| VmmData::Empty)
                    .map_err(Err::SetBootSource)
            }
            ConfigureLogger(logger_cfg) => {
                vmm_config::logger::init_logger(logger_cfg, &self.instance_info)
                    .map(|()| VmmData::Empty)
                    .map_err(Err::InitLogger)
            }
            ConfigureMetrics(metrics_cfg) => vmm_config::metrics::init_metrics(metrics_cfg)
                .map(|()| VmmData::Empty)
                .map_err(Err::InitMetrics),
            GetBalloonConfig => self
                .vm_resources
                .balloon
                .get_config()
                .map(VmmData::BalloonConfig)
                .map_err(Err::BalloonConfig),
            GetFullVmConfig => {
                warn!(
                    "If the VM was restored from snapshot, boot-source, machine-config.smt, and \
                     machine-config.cpu_template will all be empty."
                );
                Ok(VmmData::FullVmConfig((&*self.vm_resources).into()))
            }
            GetMMDS => Ok(self.get_mmds()),
            GetVmMachineConfig => Ok(VmmData::MachineConfiguration(MachineConfig::from(
                &self.vm_resources.vm_config,
            ))),
            GetVmInstanceInfo => Ok(VmmData::InstanceInformation(self.instance_info.clone())),
            GetVmmVersion => Ok(VmmData::VmmVersion(self.instance_info.vmm_version.clone())),
            InsertBlockDevice(config) => {
                self.boot_path = true;
                self.vm_resources
                    .set_block_device(config)
                    .map(|()| VmmData::Empty)
                    .map_err(Err::InsertBlockDevice)
            }
            InsertNetworkDevice(config) => {
                self.boot_path = true;
                self.vm_resources
                    .build_net_device(config)
                    .map(|()| VmmData::Empty)
                    .map_err(Err::InsertNetDevice)
            }
            LoadSnapshot(config) => self.load_snapshot(&config).map_err(Err::LoadSnapshot),
            PatchMMDS(value) => self
                .patch_mmds(value)
                .map(|()| VmmData::Empty)
                .map_err(Err::PatchMmds),
            PutCpuConfiguration(custom_cpu_template) => {
                self.vm_resources
                    .set_custom_cpu_template(custom_cpu_template);
                Ok(VmmData::Empty)
            }
            PutMMDS(value) => self
                .put_mmds(value)
                .map(|()| VmmData::Empty)
                .map_err(Err::PutMmds),
            SetBalloonDevice(config) => {
                self.boot_path = true;
                self.vm_resources
                    .set_balloon_device(config)
                    .map(|()| VmmData::Empty)
                    .map_err(Err::SetBalloonDevice)
            }
            SetVsockDevice(config) => {
                self.boot_path = true;
                self.vm_resources
                    .set_vsock_device(config)
                    .map(|()| VmmData::Empty)
                    .map_err(Err::SetVsockDevice)
            }
            SetMmdsConfiguration(config) => {
                self.boot_path = true;
                self.vm_resources
                    .set_mmds_config(config, &self.instance_info.id)
                    .map(|()| VmmData::Empty)
                    .map_err(Err::SetMmdsConfig)
            }
            // On success, this command will end the pre-boot stage and this controller
            // will be replaced by a runtime controller.
            StartMicroVm => {
                let vmm = build_and_boot_microvm(
                    &self.instance_info,
                    self.vm_resources,
                    self.event_manager,
                    self.seccomp_filters,
                )
                .map_err(Err::StartMicrovm)?;
                self.built_vmm = Some(vmm);
                Ok(VmmData::Empty)
            }
            UpdateVmConfiguration(config) => {
                self.boot_path = true;
                self.vm_resources
                    .update_vm_config(&config)
                    .map(|()| VmmData::Empty)
                    .map_err(Err::UpdateVmConfig)
            }
            SetEntropyDevice(config) => {
                self.boot_path = true;
                self.vm_resources
                    .build_entropy_device(config)
                    .map_err(Err::SetEntropyDevice)?;
                Ok(VmmData::Empty)
            }
            // Operations not allowed pre-boot.
            CreateSnapshot(_)
            | FlushMetrics
            | Pause
            | Resume
            | GetBalloonStats
            | UpdateBalloon(_)
            | UpdateBalloonStatistics(_)
            | UpdateBlockDevice(_)
            | UpdateNetworkInterface(_) => Err(Err::OperationNotSupportedPreBoot),
            #[cfg(target_arch = "x86_64")]
            SendCtrlAltDel => Err(Err::OperationNotSupportedPreBoot),
        }
    }

    // On success, this command will end the pre-boot stage and this controller
    // will be replaced by a runtime controller.
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
        // If restore fails, we consider the process is too dirty to recover.
        let vmm = restore_from_snapshot(
            &self.instance_info,
            self.event_manager,
            self.seccomp_filters,
            load_params,
            VERSION_MAP.clone(),
            self.vm_resources,
        )
        .map_err(LoadSnapshotError::RestoreFromSnapshot)?;
        // Resume VM
        // If resume fails, we consider the process is too dirty to recover.
        if load_params.resume_vm {
            vmm.lock()
                .expect("Poisoned lock")
                .resume_vm()
                .map_err(LoadSnapshotError::ResumeMicrovm)?;
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
pub struct PostbootApiController {
    vmm: Arc<Mutex<Vmm>>,
    vm_resources: VmResources,
}

impl MmdsRequestHandler for PostbootApiController {
    fn mmds(&mut self) -> MutexGuard<'_, Mmds> {
        self.vm_resources.locked_mmds_or_default()
    }
}

/// Error type for [`PostbootApiController::handle_postboot_request`]
#[derive(Debug, thiserror::Error)]
pub enum HandlePostbootRequestError {
    /// Diff snapshots are not allowed on uVMs with dirty page tracking disabled.
    #[error("Diff snapshots are not allowed on uVMs with dirty page tracking disabled.")]
    DiffSnapshotDirtyPageTracking,
    /// Failed to create snapshot.
    #[error("Failed to create snapshot: {0}")]
    CreateSnapshot(crate::persist::CreateSnapshotError),
    /// Failed to flush metrics.
    #[error("Failed to flush metrics: {0}")]
    FlushMetrics(logger::MetricsError),
    /// Failed to get balloon config.
    #[error("Failed to get balloon config: {0}")]
    GetBalloonConfig(crate::BalloonError),
    /// Failed to get balloon stats.
    #[error("Failed to get balloon stats: {0}")]
    GetBalloonStats(crate::BalloonError),
    /// Failed to patch mmds.
    #[error("Failed to patch mmds: {0}")]
    PatchMmds(mmds::data_store::Error),
    /// Failed to pause vmm.
    #[error("Failed to pause vmm: {0}")]
    PauseVm(crate::VmmError),
    /// Failed to put mmds.
    #[error("Failed to put mmds: {0}")]
    PutMmds(mmds::data_store::Error),
    /// Failed to resume vmm.
    #[error("Failed to resume vmm: {0}")]
    ResumeVm(crate::VmmError),
    /// Failed to send ctrl alt del.
    #[error("Failed to send ctrl alt del: {0}")]
    SendCtrlALtDel(crate::VmmError),
    /// Failed to update ballon config.
    #[error("Failed to update ballon config: {0}")]
    UpdateBalloonConfig(crate::devices::virtio::balloon::BalloonError),
    /// Failed to update ballon stats config.
    #[error("Failed to update ballon stats config: {0}")]
    UpdateBalloonStatsConfig(crate::devices::virtio::balloon::BalloonError),
    /// Failed to update block device path.
    #[error("Failed to update block device path: {0}")]
    UpdateBlockDevicePath(crate::VmmError),
    /// Failed to update block rate limiter.
    #[error("Failed to update block rate limiter: {0}")]
    UpdateBlockRateLimiter(crate::VmmError),
    /// Failed to update net rate limiters.
    #[error("Failed to update net rate limiters: {0}")]
    UpdateNetRateLimiters(crate::VmmError),
    /// Operation not supported post boot.
    #[error("Operation not supported post boot.")]
    OperationNotSupportedPostBoot,
}

impl PostbootApiController {
    /// Handles the incoming runtime `VmmAction` request and provides a response for it.
    pub fn handle_postboot_request(
        &mut self,
        request: VmmAction,
    ) -> Result<VmmData, HandlePostbootRequestError> {
        use self::VmmAction::*;
        type Err = HandlePostbootRequestError;
        match request {
            // Supported operations allowed post-boot.
            CreateSnapshot(snapshot_create_cfg) => {
                log_dev_preview_warning("Virtual machine snapshots", None);

                if snapshot_create_cfg.snapshot_type == SnapshotType::Diff
                    && !self.vm_resources.track_dirty_pages()
                {
                    return Err(Err::DiffSnapshotDirtyPageTracking);
                }

                let mut vmm_guard = self.vmm.lock().unwrap();
                let vm_info = VmInfo::from(&self.vm_resources);
                let create_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

                crate::persist::create_snapshot(
                    &mut vmm_guard,
                    &vm_info,
                    &snapshot_create_cfg,
                    VERSION_MAP.clone(),
                )
                .map_err(Err::CreateSnapshot)?;

                match snapshot_create_cfg.snapshot_type {
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
            // Write the metrics on user demand (flush). We use the word `flush` here to highlight
            // the fact that the metrics will be written immediately.
            // Defer to inner Vmm. We'll move to a variant where the Vmm simply exposes
            // functionality like getting the dirty pages, and then we'll have the
            // metrics flushing logic entirely on the outside.
            FlushMetrics => {
                // FIXME: we're losing the bool saying whether metrics were actually written.
                METRICS
                    .write()
                    .map(|_| VmmData::Empty)
                    .map_err(Err::FlushMetrics)
            }
            GetBalloonConfig => self
                .vmm
                .lock()
                .expect("Poisoned lock")
                .balloon_config()
                .map(|state| VmmData::BalloonConfig(BalloonDeviceConfig::from(state)))
                .map_err(Err::GetBalloonConfig),
            GetBalloonStats => self
                .vmm
                .lock()
                .expect("Poisoned lock")
                .latest_balloon_stats()
                .map(VmmData::BalloonStats)
                .map_err(Err::GetBalloonStats),
            GetFullVmConfig => Ok(VmmData::FullVmConfig((&self.vm_resources).into())),
            GetMMDS => Ok(self.get_mmds()),
            GetVmMachineConfig => Ok(VmmData::MachineConfiguration(MachineConfig::from(
                &self.vm_resources.vm_config,
            ))),
            GetVmInstanceInfo => Ok(VmmData::InstanceInformation(
                self.vmm.lock().expect("Poisoned lock").instance_info(),
            )),
            GetVmmVersion => Ok(VmmData::VmmVersion(
                self.vmm.lock().expect("Poisoned lock").version(),
            )),
            PatchMMDS(value) => self
                .patch_mmds(value)
                .map(|()| VmmData::Empty)
                .map_err(Err::PatchMmds),
            // Pauses the microVM by pausing the vCPUs.
            Pause => {
                let pause_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);
                self.vmm
                    .lock()
                    .expect("Poisoned lock")
                    .pause_vm()
                    .map_err(Err::PauseVm)?;
                let elapsed_time_us = update_metric_with_elapsed_time(
                    &METRICS.latencies_us.vmm_pause_vm,
                    pause_start_us,
                );
                info!("'pause vm' VMM action took {} us.", elapsed_time_us);
                Ok(VmmData::Empty)
            }
            PutMMDS(value) => self
                .put_mmds(value)
                .map(|()| VmmData::Empty)
                .map_err(Err::PutMmds),
            // Resumes the microVM by resuming the vCPUs.
            Resume => {
                let resume_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);
                self.vmm
                    .lock()
                    .expect("Poisoned lock")
                    .resume_vm()
                    .map_err(Err::ResumeVm)?;
                let elapsed_time_us = update_metric_with_elapsed_time(
                    &METRICS.latencies_us.vmm_resume_vm,
                    resume_start_us,
                );
                info!("'resume vm' VMM action took {} us.", elapsed_time_us);
                Ok(VmmData::Empty)
            }
            // Injects CTRL+ALT+DEL keystroke combo to the inner Vmm (if present).
            #[cfg(target_arch = "x86_64")]
            SendCtrlAltDel => self
                .vmm
                .lock()
                .expect("Poisoned lock")
                .send_ctrl_alt_del()
                .map(|()| VmmData::Empty)
                .map_err(Err::SendCtrlALtDel),
            UpdateBalloon(balloon_update) => self
                .vmm
                .lock()
                .expect("Poisoned lock")
                .update_balloon_config(balloon_update.amount_mib)
                .map(|()| VmmData::Empty)
                .map_err(Err::UpdateBalloonConfig),
            UpdateBalloonStatistics(balloon_stats_update) => self
                .vmm
                .lock()
                .expect("Poisoned lock")
                .update_balloon_stats_config(balloon_stats_update.stats_polling_interval_s)
                .map(|()| VmmData::Empty)
                .map_err(Err::UpdateBalloonStatsConfig),
            // Updates block device properties:
            //  - path of the host file backing the emulated block device, update the disk image on
            //    the device and its virtio configuration
            //  - rate limiter configuration.
            UpdateBlockDevice(new_cfg) => {
                let mut vmm = self.vmm.lock().expect("Poisoned lock");
                if let Some(new_path) = new_cfg.path_on_host {
                    vmm.update_block_device_path(&new_cfg.drive_id, new_path)
                        .map_err(Err::UpdateBlockDevicePath)?;
                }
                if new_cfg.rate_limiter.is_some() {
                    vmm.update_block_rate_limiter(
                        &new_cfg.drive_id,
                        RateLimiterUpdate::from(new_cfg.rate_limiter).bandwidth,
                        RateLimiterUpdate::from(new_cfg.rate_limiter).ops,
                    )
                    .map_err(Err::UpdateBlockRateLimiter)?;
                }
                Ok(VmmData::Empty)
            }
            // Updates configuration for an emulated net device as described in `netif_update`.
            UpdateNetworkInterface(netif_update) => self
                .vmm
                .lock()
                .expect("Poisoned lock")
                .update_net_rate_limiters(
                    &netif_update.iface_id,
                    RateLimiterUpdate::from(netif_update.rx_rate_limiter).bandwidth,
                    RateLimiterUpdate::from(netif_update.rx_rate_limiter).ops,
                    RateLimiterUpdate::from(netif_update.tx_rate_limiter).bandwidth,
                    RateLimiterUpdate::from(netif_update.tx_rate_limiter).ops,
                )
                .map(|()| VmmData::Empty)
                .map_err(Err::UpdateNetRateLimiters),

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
            | UpdateVmConfiguration(_) => Err(Err::OperationNotSupportedPostBoot),
        }
    }

    /// Creates a new `PostbootApiController`.
    pub fn new(vm_resources: VmResources, vmm: Arc<Mutex<Vmm>>) -> Self {
        Self { vmm, vm_resources }
    }
}
