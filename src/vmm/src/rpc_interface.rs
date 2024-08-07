// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{self, Debug};
use std::sync::{Arc, Mutex, MutexGuard};

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
#[cfg(target_arch = "x86_64")]
use crate::logger::METRICS;
use crate::logger::{info, warn, LoggerConfig, *};
use crate::mmds::data_store::{self, Mmds};
use crate::persist::{CreateSnapshotError, RestoreFromSnapshotError, VmInfo};
use crate::resources::VmmConfig;
use crate::vmm_config::balloon::{
    BalloonConfigError, BalloonDeviceConfig, BalloonStats, BalloonUpdateConfig,
    BalloonUpdateStatsConfig,
};
use crate::vmm_config::boot_source::{BootSourceConfig, BootSourceConfigError};
use crate::vmm_config::drive::{BlockDeviceConfig, BlockDeviceUpdateConfig, DriveError};
use crate::vmm_config::entropy::{EntropyDeviceConfig, EntropyDeviceError};
#[cfg(target_arch = "x86_64")]
use crate::vmm_config::hotplug::{HotplugRequestConfig, HotplugRequestError};
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::{MachineConfig, MachineConfigUpdate, VmConfigError};
use crate::vmm_config::metrics::{MetricsConfig, MetricsConfigError};
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
    /// Hotplug resources into the VM.
    #[cfg(target_arch = "x86_64")]
    HotplugRequest(HotplugRequestConfig),
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
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmmActionError {
    /// Balloon config error: {0}
    BalloonConfig(#[from] BalloonConfigError),
    /// Boot source error: {0}
    BootSource(#[from] BootSourceConfigError),
    /// Create snapshot error: {0}
    CreateSnapshot(#[from] CreateSnapshotError),
    /// Configure CPU error: {0}
    ConfigureCpu(#[from] GuestConfigError),
    /// Drive config error: {0}
    DriveConfig(#[from] DriveError),
    /// Entropy device error: {0}
    EntropyDevice(#[from] EntropyDeviceError),
    /// Hotplug error: {0}
    #[cfg(target_arch = "x86_64")]
    HotplugRequest(#[from] HotplugRequestError),
    /// Internal VMM error: {0}
    InternalVmm(#[from] VmmError),
    /// Load snapshot error: {0}
    LoadSnapshot(#[from] LoadSnapshotError),
    /// Logger error: {0}
    Logger(#[from] crate::logger::LoggerUpdateError),
    /// Machine config error: {0}
    MachineConfig(#[from] VmConfigError),
    /// Metrics error: {0}
    Metrics(#[from] MetricsConfigError),
    #[from(ignore)]
    /// MMDS error: {0}
    Mmds(#[from] data_store::MmdsDatastoreError),
    /// MMMDS config error: {0}
    MmdsConfig(#[from] MmdsConfigError),
    #[from(ignore)]
    /// MMDS limit exceeded error: {0}
    MmdsLimitExceeded(data_store::MmdsDatastoreError),
    /// Network config error: {0}
    NetworkConfig(#[from] NetworkInterfaceError),
    /// The requested operation is not supported: {0}
    NotSupported(String),
    /// The requested operation is not supported after starting the microVM.
    OperationNotSupportedPostBoot,
    /// The requested operation is not supported before starting the microVM.
    OperationNotSupportedPreBoot,
    /// Start microvm error: {0}
    StartMicrovm(#[from] StartMicrovmError),
    /// Vsock config error: {0}
    VsockConfig(#[from] VsockConfigError),
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
                data_store::MmdsDatastoreError::DataStoreLimitExceeded => {
                    VmmActionError::MmdsLimitExceeded(
                        data_store::MmdsDatastoreError::DataStoreLimitExceeded,
                    )
                }
                _ => VmmActionError::Mmds(err),
            })
    }

    fn put_mmds(&mut self, value: serde_json::Value) -> Result<VmmData, VmmActionError> {
        self.mmds()
            .put_data(value)
            .map(|()| VmmData::Empty)
            .map_err(|err| match err {
                data_store::MmdsDatastoreError::DataStoreLimitExceeded => {
                    VmmActionError::MmdsLimitExceeded(
                        data_store::MmdsDatastoreError::DataStoreLimitExceeded,
                    )
                }
                _ => VmmActionError::Mmds(err),
            })
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
    // Some PrebootApiRequest errors are irrecoverable and Firecracker
    // should cleanly teardown if they occur.
    fatal_error: Option<BuildMicrovmFromRequestsError>,
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
            .field("fatal_error", &self.fatal_error)
            .finish()
    }
}

impl MmdsRequestHandler for PrebootApiController<'_> {
    fn mmds(&mut self) -> MutexGuard<'_, Mmds> {
        self.vm_resources.locked_mmds_or_default()
    }
}

/// Error type for [`PrebootApiController::load_snapshot`]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum LoadSnapshotError {
    /// Loading a microVM snapshot not allowed after configuring boot-specific resources.
    LoadSnapshotNotAllowed,
    /// Failed to restore from snapshot: {0}
    RestoreFromSnapshot(#[from] RestoreFromSnapshotError),
    /// Failed to resume microVM: {0}
    ResumeMicrovm(#[from] VmmError),
}

/// Shorthand type for a request containing a boxed VmmAction.
pub type ApiRequest = Box<VmmAction>;
/// Shorthand type for a response containing a boxed Result.
pub type ApiResponse = Box<std::result::Result<VmmData, VmmActionError>>;

/// Error type for `PrebootApiController::build_microvm_from_requests`.
#[derive(Debug, thiserror::Error, displaydoc::Display, derive_more::From)]
pub enum BuildMicrovmFromRequestsError {
    /// Populating MMDS from file failed: {0}.
    Mmds(data_store::MmdsDatastoreError),
    /// Loading snapshot failed.
    Restore,
    /// Resuming MicroVM after loading snapshot failed.
    Resume,
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
            fatal_error: None,
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
            vm_resources.locked_mmds_or_default().put_data(
                serde_json::from_str(data).expect("MMDS error: metadata provided not valid json"),
            )?;

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
            if let Some(preboot_error) = preboot_controller.fatal_error {
                return Err(preboot_error);
            }
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
    ) -> Result<VmmData, VmmActionError> {
        use self::VmmAction::*;

        match request {
            // Supported operations allowed pre-boot.
            ConfigureBootSource(config) => self.set_boot_source(config),
            ConfigureLogger(logger_cfg) => crate::logger::LOGGER
                .update(logger_cfg)
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
            #[cfg(target_arch = "x86_64")]
            HotplugRequest(_) => Err(VmmActionError::OperationNotSupportedPreBoot),
        }
    }

    fn balloon_config(&mut self) -> Result<VmmData, VmmActionError> {
        self.vm_resources
            .balloon
            .get_config()
            .map(VmmData::BalloonConfig)
            .map_err(VmmActionError::BalloonConfig)
    }

    fn insert_block_device(&mut self, cfg: BlockDeviceConfig) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .set_block_device(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::DriveConfig)
    }

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

    fn set_balloon_device(&mut self, cfg: BalloonDeviceConfig) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .set_balloon_device(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::BalloonConfig)
    }

    fn set_boot_source(&mut self, cfg: BootSourceConfig) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .build_boot_source(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::BootSource)
    }

    fn set_mmds_config(&mut self, cfg: MmdsConfig) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .set_mmds_config(cfg, &self.instance_info.id)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::MmdsConfig)
    }

    fn update_vm_config(&mut self, cfg: MachineConfigUpdate) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .update_vm_config(&cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::MachineConfig)
    }

    fn set_custom_cpu_template(
        &mut self,
        cpu_template: CustomCpuTemplate,
    ) -> Result<VmmData, VmmActionError> {
        self.vm_resources.set_custom_cpu_template(cpu_template);
        Ok(VmmData::Empty)
    }

    fn set_vsock_device(&mut self, cfg: VsockDeviceConfig) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .set_vsock_device(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::VsockConfig)
    }

    fn set_entropy_device(&mut self, cfg: EntropyDeviceConfig) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources.build_entropy_device(cfg)?;
        Ok(VmmData::Empty)
    }

    // On success, this command will end the pre-boot stage and this controller
    // will be replaced by a runtime controller.
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

        // Restore VM from snapshot
        let vmm = restore_from_snapshot(
            &self.instance_info,
            self.event_manager,
            self.seccomp_filters,
            load_params,
            self.vm_resources,
        )
        .map_err(|err| {
            // If restore fails, we consider the process is too dirty to recover.
            self.fatal_error = Some(BuildMicrovmFromRequestsError::Restore);
            err
        })?;
        // Resume VM
        if load_params.resume_vm {
            vmm.lock()
                .expect("Poisoned lock")
                .resume_vm()
                .map_err(|err| {
                    // If resume fails, we consider the process is too dirty to recover.
                    self.fatal_error = Some(BuildMicrovmFromRequestsError::Resume);
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
    fn mmds(&mut self) -> MutexGuard<'_, Mmds> {
        self.vm_resources.locked_mmds_or_default()
    }
}

impl RuntimeApiController {
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
            #[cfg(target_arch = "x86_64")]
            HotplugRequest(request_type) => self.handle_hotplug_request(request_type),
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

    /// Creates a new `RuntimeApiController`.
    pub fn new(vm_resources: VmResources, vmm: Arc<Mutex<Vmm>>) -> Self {
        Self { vmm, vm_resources }
    }

    /// Pauses the microVM by pausing the vCPUs.
    pub fn pause(&mut self) -> Result<VmmData, VmmActionError> {
        let pause_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

        self.vmm.lock().expect("Poisoned lock").pause_vm()?;

        let elapsed_time_us =
            update_metric_with_elapsed_time(&METRICS.latencies_us.vmm_pause_vm, pause_start_us);
        info!("'pause vm' VMM action took {} us.", elapsed_time_us);

        Ok(VmmData::Empty)
    }

    /// Resumes the microVM by resuming the vCPUs.
    pub fn resume(&mut self) -> Result<VmmData, VmmActionError> {
        let resume_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

        self.vmm.lock().expect("Poisoned lock").resume_vm()?;

        let elapsed_time_us =
            update_metric_with_elapsed_time(&METRICS.latencies_us.vmm_resume_vm, resume_start_us);
        info!("'resume vm' VMM action took {} us.", elapsed_time_us);

        Ok(VmmData::Empty)
    }

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

        create_snapshot(&mut locked_vmm, &vm_info, create_params)?;

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

    /// Updates block device properties:
    ///  - path of the host file backing the emulated block device, update the disk image on the
    ///    device and its virtio configuration
    ///  - rate limiter configuration.
    fn update_block_device(
        &mut self,
        new_cfg: BlockDeviceUpdateConfig,
    ) -> Result<VmmData, VmmActionError> {
        let mut vmm = self.vmm.lock().expect("Poisoned lock");

        // vhost-user-block updates
        if new_cfg.path_on_host.is_none() && new_cfg.rate_limiter.is_none() {
            vmm.update_vhost_user_block_config(&new_cfg.drive_id)
                .map(|()| VmmData::Empty)
                .map_err(DriveError::DeviceUpdate)?;
        }

        // virtio-block updates
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

    #[cfg(target_arch = "x86_64")]
    fn handle_hotplug_request(
        &mut self,
        cfg: HotplugRequestConfig,
    ) -> Result<VmmData, VmmActionError> {
        match cfg {
            HotplugRequestConfig::Vcpu(cfg) => {
                let result = self.vmm.lock().expect("Poisoned lock").hotplug_vcpus(cfg);
                result
                    .map_err(|err| VmmActionError::HotplugRequest(HotplugRequestError::Vcpu(err)))
                    .and_then(|machine_cfg_update| self.update_vm_config(machine_cfg_update))
            }
        }
    }

    // Currently, this method is only used for vCPU hotplugging, which is not implemented for
    // aarch64, hence we must allow `dead_code`
    #[allow(dead_code)]
    fn update_vm_config(&mut self, cfg: MachineConfigUpdate) -> Result<VmmData, VmmActionError> {
        self.vm_resources
            .update_vm_config(&cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::MachineConfig)
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;

    use seccompiler::BpfThreadMap;
    #[cfg(target_arch = "x86_64")]
    use vmm_config::hotplug::HotplugVcpuError;

    use super::*;
    // Currently, default_vmm only used for testing hotplugging, which is only implemented for
    // x86_64, so `unused_imports` must be allowed for aarch64 systems
    #[cfg(target_arch = "x86_64")]
    use crate::builder::tests::default_vmm;
    use crate::cpu_config::templates::test_utils::build_test_template;
    use crate::cpu_config::templates::{CpuTemplateType, StaticCpuTemplate};
    use crate::devices::virtio::balloon::{BalloonConfig, BalloonError};
    use crate::devices::virtio::block::CacheType;
    use crate::devices::virtio::rng::EntropyError;
    use crate::devices::virtio::vsock::VsockError;
    use crate::mmds::data_store::MmdsVersion;
    use crate::vmm_config::balloon::BalloonBuilder;
    #[cfg(target_arch = "x86_64")]
    use crate::vmm_config::hotplug::HotplugVcpuConfig;
    use crate::vmm_config::machine_config::VmConfig;
    use crate::vmm_config::snapshot::{MemBackendConfig, MemBackendType};
    use crate::vmm_config::vsock::VsockBuilder;
    use crate::HTTP_MAX_PAYLOAD_SIZE;

    impl PartialEq for VmmActionError {
        fn eq(&self, other: &VmmActionError) -> bool {
            use VmmActionError::*;
            #[cfg(target_arch = "x86_64")]
            {
                matches!(
                    (self, other),
                    (BalloonConfig(_), BalloonConfig(_))
                        | (BootSource(_), BootSource(_))
                        | (CreateSnapshot(_), CreateSnapshot(_))
                        | (DriveConfig(_), DriveConfig(_))
                        | (HotplugRequest(_), HotplugRequest(_))
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
            #[cfg(target_arch = "aarch64")]
            {
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
        pub fn balloon_config(&mut self) -> Result<BalloonConfig, BalloonError> {
            if self.force_errors {
                return Err(BalloonError::DeviceNotFound);
            }
            self.balloon_config_called = true;
            Ok(BalloonConfig::default())
        }

        pub fn track_dirty_pages(&self) -> bool {
            self.vm_config.track_dirty_pages
        }

        pub fn set_track_dirty_pages(&mut self, dirty_page_tracking: bool) {
            self.vm_config.track_dirty_pages = dirty_page_tracking;
        }

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

        pub fn boot_source_config(&self) -> &BootSourceConfig {
            &self.boot_src
        }

        pub fn set_block_device(&mut self, _: BlockDeviceConfig) -> Result<(), DriveError> {
            if self.force_errors {
                return Err(DriveError::RootBlockDeviceAlreadyAdded);
            }
            self.block_set = true;
            Ok(())
        }

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

        pub fn set_vsock_device(&mut self, _: VsockDeviceConfig) -> Result<(), VsockConfigError> {
            if self.force_errors {
                return Err(VsockConfigError::CreateVsockDevice(
                    VsockError::GuestMemoryBounds,
                ));
            }
            self.vsock_set = true;
            Ok(())
        }

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

        /// If not initialised, create the mmds data store with the default config.
        pub fn mmds_or_default(&mut self) -> &Arc<Mutex<Mmds>> {
            self.mmds
                .get_or_insert(Arc::new(Mutex::new(Mmds::default_with_limit(
                    self.mmds_size_limit,
                ))))
        }

        /// If not initialised, create the mmds data store with the default config.
        pub fn locked_mmds_or_default(&mut self) -> MutexGuard<'_, Mmds> {
            let mmds = self.mmds_or_default();
            mmds.lock().expect("Poisoned lock")
        }

        /// Update the CPU configuration for the guest.
        pub fn set_custom_cpu_template(&mut self, cpu_template: CustomCpuTemplate) {
            self.vm_config.set_custom_cpu_template(cpu_template);
        }
    }

    impl From<&MockVmRes> for VmmConfig {
        fn from(_: &MockVmRes) -> Self {
            VmmConfig::default()
        }
    }

    impl From<&MockVmRes> for VmInfo {
        fn from(value: &MockVmRes) -> Self {
            Self {
                mem_size_mib: value.vm_config.mem_size_mib as u64,
                smt: value.vm_config.smt,
                cpu_template: StaticCpuTemplate::from(&value.vm_config.cpu_template),
                boot_source: value.boot_source_config().clone(),
                huge_pages: value.vm_config.huge_pages,
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
        pub update_block_device_vhost_user_config_called: bool,
        pub update_net_rate_limiters_called: bool,
        #[cfg(target_arch = "x86_64")]
        pub hotplug_vcpus_called: bool,
        // when `true`, all self methods are forced to fail
        pub force_errors: bool,
    }

    impl MockVmm {
        pub fn resume_vm(&mut self) -> Result<(), VmmError> {
            if self.force_errors {
                return Err(VmmError::VcpuResume);
            }
            self.resume_called = true;
            Ok(())
        }

        pub fn pause_vm(&mut self) -> Result<(), VmmError> {
            if self.force_errors {
                return Err(VmmError::VcpuPause);
            }
            self.pause_called = true;
            Ok(())
        }

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

        pub fn balloon_config(&mut self) -> Result<BalloonConfig, BalloonError> {
            if self.force_errors {
                return Err(BalloonError::DeviceNotFound);
            }
            self.balloon_config_called = true;
            Ok(BalloonConfig::default())
        }

        pub fn latest_balloon_stats(&mut self) -> Result<BalloonStats, BalloonError> {
            if self.force_errors {
                return Err(BalloonError::DeviceNotFound);
            }
            self.latest_balloon_stats_called = true;
            Ok(BalloonStats::default())
        }

        pub fn update_balloon_config(&mut self, _: u32) -> Result<(), BalloonError> {
            if self.force_errors {
                return Err(BalloonError::DeviceNotFound);
            }
            self.update_balloon_config_called = true;
            Ok(())
        }

        pub fn update_balloon_stats_config(&mut self, _: u16) -> Result<(), BalloonError> {
            if self.force_errors {
                return Err(BalloonError::DeviceNotFound);
            }
            self.update_balloon_stats_config_called = true;
            Ok(())
        }

        pub fn update_block_device_path(&mut self, _: &str, _: String) -> Result<(), VmmError> {
            if self.force_errors {
                return Err(VmmError::DeviceManager(
                    crate::device_manager::mmio::MmioError::InvalidDeviceType,
                ));
            }
            self.update_block_device_path_called = true;
            Ok(())
        }

        pub fn update_block_rate_limiter(
            &mut self,
            _: &str,
            _: crate::rate_limiter::BucketUpdate,
            _: crate::rate_limiter::BucketUpdate,
        ) -> Result<(), VmmError> {
            Ok(())
        }

        pub fn update_vhost_user_block_config(&mut self, _: &str) -> Result<(), VmmError> {
            if self.force_errors {
                return Err(VmmError::DeviceManager(
                    crate::device_manager::mmio::MmioError::InvalidDeviceType,
                ));
            }
            self.update_block_device_vhost_user_config_called = true;
            Ok(())
        }

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

        #[cfg(target_arch = "x86_64")]
        pub fn hotplug_vcpus(
            &mut self,
            _: HotplugVcpuConfig,
        ) -> Result<MachineConfigUpdate, HotplugVcpuError> {
            if self.force_errors {
                return Err(HotplugVcpuError::VcpuCountTooHigh);
            }
            self.hotplug_vcpus_called = true;
            Ok(MachineConfigUpdate {
                vcpu_count: Some(1),
                mem_size_mib: None,
                smt: None,
                cpu_template: None,
                track_dirty_pages: None,
                huge_pages: None,
            })
        }
        pub fn instance_info(&self) -> InstanceInfo {
            InstanceInfo::default()
        }

        pub fn version(&self) -> String {
            String::default()
        }
    }

    // Need to redefine this since the non-test one uses real VmResources
    // and real Vmm instead of our mocks.
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
    pub fn create_snapshot(
        _: &mut Vmm,
        _: &VmInfo,
        _: &CreateSnapshotParams,
    ) -> Result<(), CreateSnapshotError> {
        Ok(())
    }

    // Need to redefine this since the non-test one uses real Vmm
    // instead of our mocks.
    pub fn restore_from_snapshot(
        _: &InstanceInfo,
        _: &mut EventManager,
        _: &BpfThreadMap,
        _: &LoadSnapshotParams,
        _: &mut MockVmRes,
    ) -> Result<Arc<Mutex<Vmm>>, RestoreFromSnapshotError> {
        Ok(Arc::new(Mutex::new(MockVmm::default())))
    }

    fn default_preboot<'a>(
        vm_resources: &'a mut VmResources,
        event_manager: &'a mut EventManager,
        seccomp_filters: &'a BpfThreadMap,
    ) -> PrebootApiController<'a> {
        let instance_info = InstanceInfo::default();
        PrebootApiController::new(seccomp_filters, instance_info, vm_resources, event_manager)
    }

    fn check_preboot_request<F>(request: VmmAction, check_success: F)
    where
        F: FnOnce(Result<VmmData, VmmActionError>, &MockVmRes),
    {
        let mut vm_resources = MockVmRes::default();
        let mut evmgr = EventManager::new().unwrap();
        let seccomp_filters = BpfThreadMap::new();
        let mut preboot = default_preboot(&mut vm_resources, &mut evmgr, &seccomp_filters);
        let res = preboot.handle_preboot_request(request);
        check_success(res, &vm_resources);
    }

    fn check_preboot_request_with_mmds<F>(
        request: VmmAction,
        mmds: Arc<Mutex<Mmds>>,
        check_success: F,
    ) where
        F: FnOnce(Result<VmmData, VmmActionError>, &MockVmRes),
    {
        let mut vm_resources = MockVmRes {
            mmds: Some(mmds),
            mmds_size_limit: HTTP_MAX_PAYLOAD_SIZE,
            ..Default::default()
        };
        let mut evmgr = EventManager::new().unwrap();
        let seccomp_filters = BpfThreadMap::new();
        let mut preboot = default_preboot(&mut vm_resources, &mut evmgr, &seccomp_filters);
        let res = preboot.handle_preboot_request(request);
        check_success(res, &vm_resources);
    }

    // Forces error and validates error kind against expected.
    fn check_preboot_request_err(request: VmmAction, expected_err: VmmActionError) {
        let mut vm_resources = MockVmRes {
            force_errors: true,
            ..Default::default()
        };
        let mut evmgr = EventManager::new().unwrap();
        let seccomp_filters = BpfThreadMap::new();
        let mut preboot = default_preboot(&mut vm_resources, &mut evmgr, &seccomp_filters);
        let err = preboot.handle_preboot_request(request).unwrap_err();
        assert_eq!(err, expected_err);
    }

    #[test]
    fn test_preboot_config_boot_src() {
        let req = VmmAction::ConfigureBootSource(BootSourceConfig::default());
        check_preboot_request(req, |result, vm_res| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vm_res.boot_cfg_set)
        });

        let req = VmmAction::ConfigureBootSource(BootSourceConfig::default());
        check_preboot_request_err(
            req,
            VmmActionError::BootSource(BootSourceConfigError::InvalidKernelCommandLine(
                String::new(),
            )),
        );
    }

    #[test]
    fn test_preboot_get_vm_config() {
        let req = VmmAction::GetVmMachineConfig;
        let expected_cfg = MachineConfig::default();
        check_preboot_request(req, |result, _| {
            assert_eq!(result, Ok(VmmData::MachineConfiguration(expected_cfg)))
        });

        let req = VmmAction::ConfigureBootSource(BootSourceConfig::default());
        check_preboot_request_err(
            req,
            VmmActionError::BootSource(BootSourceConfigError::InvalidKernelCommandLine(
                String::new(),
            )),
        );
    }

    #[test]
    fn test_preboot_get_balloon_config() {
        let req = VmmAction::GetBalloonConfig;
        let expected_cfg = BalloonDeviceConfig::default();
        check_preboot_request(req, |result, _| {
            assert_eq!(result, Ok(VmmData::BalloonConfig(expected_cfg)))
        });
    }

    #[test]
    fn test_preboot_put_cpu_config() {
        // Start testing - Provide VMM vCPU configuration in preparation for `InstanceStart`
        let req = VmmAction::PutCpuConfiguration(build_test_template());
        check_preboot_request(req, |result, vm_res| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert_eq!(
                vm_res.vm_config.cpu_template,
                Some(CpuTemplateType::Custom(build_test_template()))
            );
        });
    }

    #[test]
    fn test_preboot_set_vm_config() {
        let req =
            VmmAction::UpdateVmConfiguration(MachineConfigUpdate::from(MachineConfig::default()));
        let expected_cfg = MachineConfig::default();
        check_preboot_request(req, |result, vm_res| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert_eq!(MachineConfig::from(&vm_res.vm_config), expected_cfg);
        });

        let req =
            VmmAction::UpdateVmConfiguration(MachineConfigUpdate::from(MachineConfig::default()));
        check_preboot_request_err(
            req,
            VmmActionError::MachineConfig(VmConfigError::InvalidVcpuCount),
        );
    }

    #[test]
    fn test_preboot_set_balloon_dev() {
        let req = VmmAction::SetBalloonDevice(BalloonDeviceConfig::default());
        check_preboot_request(req, |result, vm_res| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vm_res.balloon_set)
        });

        let req = VmmAction::SetBalloonDevice(BalloonDeviceConfig::default());
        check_preboot_request_err(
            req,
            VmmActionError::BalloonConfig(BalloonConfigError::DeviceNotFound),
        );
    }

    #[test]
    fn test_preboot_insert_block_dev() {
        let config = BlockDeviceConfig {
            drive_id: String::new(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(String::new()),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };
        let req = VmmAction::InsertBlockDevice(config.clone());
        check_preboot_request(req, |result, vm_res| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vm_res.block_set)
        });

        let req = VmmAction::InsertBlockDevice(config);
        check_preboot_request_err(
            req,
            VmmActionError::DriveConfig(DriveError::RootBlockDeviceAlreadyAdded),
        );
    }

    #[test]
    fn test_preboot_insert_net_dev() {
        let req = VmmAction::InsertNetworkDevice(NetworkInterfaceConfig {
            iface_id: String::new(),
            host_dev_name: String::new(),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        });
        check_preboot_request(req, |result, vm_res| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vm_res.net_set)
        });

        let req = VmmAction::InsertNetworkDevice(NetworkInterfaceConfig {
            iface_id: String::new(),
            host_dev_name: String::new(),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        });
        check_preboot_request_err(
            req,
            VmmActionError::NetworkConfig(NetworkInterfaceError::GuestMacAddressInUse(
                String::new(),
            )),
        );
    }

    #[test]
    fn test_preboot_set_vsock_dev() {
        let req = VmmAction::SetVsockDevice(VsockDeviceConfig {
            vsock_id: Some(String::new()),
            guest_cid: 0,
            uds_path: String::new(),
        });
        check_preboot_request(req, |result, vm_res| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vm_res.vsock_set)
        });

        let req = VmmAction::SetVsockDevice(VsockDeviceConfig {
            vsock_id: Some(String::new()),
            guest_cid: 0,
            uds_path: String::new(),
        });
        check_preboot_request_err(
            req,
            VmmActionError::VsockConfig(VsockConfigError::CreateVsockDevice(
                VsockError::GuestMemoryBounds,
            )),
        );
    }

    #[test]
    fn test_preboot_set_entropy_device() {
        let req = VmmAction::SetEntropyDevice(EntropyDeviceConfig::default());
        check_preboot_request(req, |result, vm_res| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vm_res.entropy_set);
        });
    }

    #[test]
    fn test_preboot_set_mmds_config() {
        let req = VmmAction::SetMmdsConfiguration(MmdsConfig {
            ipv4_address: None,
            version: MmdsVersion::V2,
            network_interfaces: Vec::new(),
        });
        check_preboot_request(req, |result, vm_res| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert_eq!(
                vm_res.mmds.as_ref().unwrap().lock().unwrap().version(),
                MmdsVersion::V2
            );
        });

        let req = VmmAction::SetMmdsConfiguration(MmdsConfig {
            ipv4_address: None,
            version: MmdsVersion::default(),
            network_interfaces: Vec::new(),
        });
        check_preboot_request_err(
            req,
            VmmActionError::MmdsConfig(MmdsConfigError::InvalidIpv4Addr),
        );
    }

    #[test]
    fn test_preboot_get_mmds() {
        check_preboot_request(VmmAction::GetMMDS, |result, _| {
            assert_eq!(result, Ok(VmmData::MmdsValue(Value::Null)));
        });
    }

    #[test]
    fn test_runtime_get_mmds() {
        check_runtime_request(VmmAction::GetMMDS, |result, _| {
            assert_eq!(result, Ok(VmmData::MmdsValue(Value::Null)));
        });
    }

    #[test]
    fn test_preboot_put_mmds() {
        let mmds = Arc::new(Mutex::new(Mmds::default()));

        check_preboot_request_with_mmds(
            VmmAction::PutMMDS(Value::String("string".to_string())),
            mmds.clone(),
            |result, _| {
                assert_eq!(result, Ok(VmmData::Empty));
            },
        );
        check_preboot_request_with_mmds(VmmAction::GetMMDS, mmds.clone(), |result, _| {
            assert_eq!(
                result,
                Ok(VmmData::MmdsValue(Value::String("string".to_string())))
            );
        });

        let filling = (0..51300).map(|_| "X").collect::<String>();
        let data = "{\"key\": \"".to_string() + &filling + "\"}";

        check_preboot_request_with_mmds(
            VmmAction::PutMMDS(serde_json::from_str(&data).unwrap()),
            mmds.clone(),
            |result, _| {
                assert!(matches!(result, Err(VmmActionError::MmdsLimitExceeded(_))));
            },
        );
        check_preboot_request_with_mmds(VmmAction::GetMMDS, mmds, |result, _| {
            assert_eq!(
                result,
                Ok(VmmData::MmdsValue(Value::String("string".to_string())))
            );
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

    #[test]
    fn test_preboot_patch_mmds() {
        let mmds = Arc::new(Mutex::new(Mmds::default()));
        // MMDS data store is not yet initialized.
        check_preboot_request_err(
            VmmAction::PatchMMDS(Value::String("string".to_string())),
            VmmActionError::Mmds(data_store::MmdsDatastoreError::NotInitialized),
        );

        check_preboot_request_with_mmds(
            VmmAction::PutMMDS(
                serde_json::from_str(r#"{"key1": "value1", "key2": "val2"}"#).unwrap(),
            ),
            mmds.clone(),
            |result, _| {
                assert_eq!(result, Ok(VmmData::Empty));
            },
        );
        check_preboot_request_with_mmds(VmmAction::GetMMDS, mmds.clone(), |result, _| {
            assert_eq!(
                result,
                Ok(VmmData::MmdsValue(
                    serde_json::from_str(r#"{"key1": "value1", "key2": "val2"}"#).unwrap()
                ))
            );
        });

        check_preboot_request_with_mmds(
            VmmAction::PatchMMDS(
                serde_json::from_str(r#"{"key1": null, "key2": "value2"}"#).unwrap(),
            ),
            mmds.clone(),
            |result, _| {
                assert_eq!(result, Ok(VmmData::Empty));
            },
        );

        check_preboot_request_with_mmds(VmmAction::GetMMDS, mmds.clone(), |result, _| {
            assert_eq!(
                result,
                Ok(VmmData::MmdsValue(
                    serde_json::from_str(r#"{"key2": "value2"}"#).unwrap()
                ))
            );
        });

        let filling = (0..HTTP_MAX_PAYLOAD_SIZE).map(|_| "X").collect::<String>();
        let data = "{\"key\": \"".to_string() + &filling + "\"}";

        check_preboot_request_with_mmds(
            VmmAction::PatchMMDS(serde_json::from_str(&data).unwrap()),
            mmds.clone(),
            |result, _| {
                assert!(matches!(result, Err(VmmActionError::MmdsLimitExceeded(_))));
            },
        );
        check_preboot_request_with_mmds(VmmAction::GetMMDS, mmds, |result, _| {
            assert_eq!(
                result,
                Ok(VmmData::MmdsValue(
                    serde_json::from_str(r#"{"key2": "value2"}"#).unwrap()
                ))
            );
        });
    }

    #[test]
    fn test_runtime_patch_mmds() {
        let mmds = Arc::new(Mutex::new(Mmds::default()));
        // MMDS data store is not yet initialized.
        check_runtime_request_err(
            VmmAction::PatchMMDS(Value::String("string".to_string())),
            VmmActionError::Mmds(data_store::MmdsDatastoreError::NotInitialized),
        );

        check_runtime_request_with_mmds(
            VmmAction::PutMMDS(
                serde_json::from_str(r#"{"key1": "value1", "key2": "val2"}"#).unwrap(),
            ),
            mmds.clone(),
            |result, _| {
                assert_eq!(result, Ok(VmmData::Empty));
            },
        );
        check_runtime_request_with_mmds(VmmAction::GetMMDS, mmds.clone(), |result, _| {
            assert_eq!(
                result,
                Ok(VmmData::MmdsValue(
                    serde_json::from_str(r#"{"key1": "value1", "key2": "val2"}"#).unwrap()
                ))
            );
        });

        check_runtime_request_with_mmds(
            VmmAction::PatchMMDS(
                serde_json::from_str(r#"{"key1": null, "key2": "value2"}"#).unwrap(),
            ),
            mmds.clone(),
            |result, _| {
                assert_eq!(result, Ok(VmmData::Empty));
            },
        );

        check_runtime_request_with_mmds(VmmAction::GetMMDS, mmds.clone(), |result, _| {
            assert_eq!(
                result,
                Ok(VmmData::MmdsValue(
                    serde_json::from_str(r#"{"key2": "value2"}"#).unwrap()
                ))
            );
        });

        let filling = (0..HTTP_MAX_PAYLOAD_SIZE).map(|_| "X").collect::<String>();
        let data = "{\"key\": \"".to_string() + &filling + "\"}";

        check_runtime_request_with_mmds(
            VmmAction::PatchMMDS(serde_json::from_str(&data).unwrap()),
            mmds.clone(),
            |result, _| {
                assert!(matches!(result, Err(VmmActionError::MmdsLimitExceeded(_))));
            },
        );
        check_runtime_request_with_mmds(VmmAction::GetMMDS, mmds, |result, _| {
            assert_eq!(
                result,
                Ok(VmmData::MmdsValue(
                    serde_json::from_str(r#"{"key2": "value2"}"#).unwrap()
                ))
            );
        });
    }

    #[test]
    fn test_preboot_load_snapshot() {
        let mut vm_resources = MockVmRes::default();
        let mut evmgr = EventManager::new().unwrap();
        let seccomp_filters = BpfThreadMap::new();
        let mut preboot = default_preboot(&mut vm_resources, &mut evmgr, &seccomp_filters);

        // Without resume.
        let req = VmmAction::LoadSnapshot(LoadSnapshotParams {
            snapshot_path: PathBuf::new(),
            mem_backend: MemBackendConfig {
                backend_type: MemBackendType::File,
                backend_path: PathBuf::new(),
            },
            enable_diff_snapshots: false,
            resume_vm: false,
        });
        // Request should succeed.
        preboot.handle_preboot_request(req).unwrap();
        // Should have built default mock vmm.
        let vmm = preboot.built_vmm.take().unwrap();
        assert_eq!(*vmm.lock().unwrap(), MockVmm::default());

        // With resume.
        let req = VmmAction::LoadSnapshot(LoadSnapshotParams {
            snapshot_path: PathBuf::new(),
            mem_backend: MemBackendConfig {
                backend_type: MemBackendType::File,
                backend_path: PathBuf::new(),
            },
            enable_diff_snapshots: false,
            resume_vm: true,
        });
        // Request should succeed.
        preboot.handle_preboot_request(req).unwrap();
        let vmm = preboot.built_vmm.as_ref().unwrap().lock().unwrap();
        // Should have built mock vmm then called resume on it.
        assert!(vmm.resume_called);
        // Extra sanity check - pause was never called.
        assert!(!vmm.pause_called);
    }

    #[test]
    fn test_preboot_disallowed() {
        check_preboot_request_err(
            VmmAction::FlushMetrics,
            VmmActionError::OperationNotSupportedPreBoot,
        );
        check_preboot_request_err(
            VmmAction::Pause,
            VmmActionError::OperationNotSupportedPreBoot,
        );
        check_preboot_request_err(
            VmmAction::Resume,
            VmmActionError::OperationNotSupportedPreBoot,
        );
        check_preboot_request_err(
            VmmAction::GetBalloonStats,
            VmmActionError::OperationNotSupportedPreBoot,
        );
        check_preboot_request_err(
            VmmAction::UpdateBalloon(BalloonUpdateConfig { amount_mib: 0 }),
            VmmActionError::OperationNotSupportedPreBoot,
        );
        check_preboot_request_err(
            VmmAction::UpdateBalloonStatistics(BalloonUpdateStatsConfig {
                stats_polling_interval_s: 0,
            }),
            VmmActionError::OperationNotSupportedPreBoot,
        );
        check_preboot_request_err(
            VmmAction::UpdateBlockDevice(BlockDeviceUpdateConfig::default()),
            VmmActionError::OperationNotSupportedPreBoot,
        );
        check_preboot_request_err(
            VmmAction::UpdateNetworkInterface(NetworkInterfaceUpdateConfig {
                iface_id: String::new(),
                rx_rate_limiter: None,
                tx_rate_limiter: None,
            }),
            VmmActionError::OperationNotSupportedPreBoot,
        );
        check_preboot_request_err(
            VmmAction::CreateSnapshot(CreateSnapshotParams {
                snapshot_type: SnapshotType::Full,
                snapshot_path: PathBuf::new(),
                mem_file_path: PathBuf::new(),
            }),
            VmmActionError::OperationNotSupportedPreBoot,
        );
        #[cfg(target_arch = "x86_64")]
        check_preboot_request_err(
            VmmAction::SendCtrlAltDel,
            VmmActionError::OperationNotSupportedPreBoot,
        );

        #[cfg(target_arch = "x86_64")]
        check_preboot_request_err(
            VmmAction::HotplugRequest(HotplugRequestConfig::Vcpu(HotplugVcpuConfig { add: 4 })),
            VmmActionError::OperationNotSupportedPreBoot,
        );
    }

    fn check_runtime_request<F>(request: VmmAction, check_success: F)
    where
        F: FnOnce(Result<VmmData, VmmActionError>, &MockVmm),
    {
        let vmm = Arc::new(Mutex::new(MockVmm::default()));
        let mut runtime = RuntimeApiController::new(MockVmRes::default(), vmm.clone());
        let res = runtime.handle_request(request);
        check_success(res, &vmm.lock().unwrap());
    }

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

    // Forces error and validates error kind against expected.
    fn check_runtime_request_err(request: VmmAction, expected_err: VmmActionError) {
        let vmm = Arc::new(Mutex::new(MockVmm {
            force_errors: true,
            ..Default::default()
        }));
        let mut runtime = RuntimeApiController::new(MockVmRes::default(), vmm);
        let err = runtime.handle_request(request).unwrap_err();
        assert_eq!(err, expected_err);
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

    #[test]
    fn test_runtime_pause() {
        let req = VmmAction::Pause;
        check_runtime_request(req, |result, vmm| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vmm.pause_called)
        });

        let req = VmmAction::Pause;
        check_runtime_request_err(req, VmmActionError::InternalVmm(VmmError::VcpuPause));
    }

    #[test]
    fn test_runtime_resume() {
        let req = VmmAction::Resume;
        check_runtime_request(req, |result, vmm| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vmm.resume_called)
        });

        let req = VmmAction::Resume;
        check_runtime_request_err(req, VmmActionError::InternalVmm(VmmError::VcpuResume));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_runtime_ctrl_alt_del() {
        let req = VmmAction::SendCtrlAltDel;
        check_runtime_request(req, |result, vmm| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vmm.send_ctrl_alt_del_called)
        });

        let req = VmmAction::SendCtrlAltDel;
        check_runtime_request_err(
            req,
            VmmActionError::InternalVmm(VmmError::I8042Error(
                crate::devices::legacy::I8042DeviceError::InternalBufferFull,
            )),
        );
    }

    #[test]
    fn test_runtime_balloon_config() {
        let req = VmmAction::GetBalloonConfig;
        check_runtime_request(req, |result, vmm| {
            assert_eq!(
                result,
                Ok(VmmData::BalloonConfig(BalloonDeviceConfig::default()))
            );
            assert!(vmm.balloon_config_called)
        });

        let req = VmmAction::GetBalloonConfig;
        check_runtime_request_err(
            req,
            VmmActionError::BalloonConfig(BalloonConfigError::DeviceNotFound),
        );
    }

    #[test]
    fn test_runtime_latest_balloon_stats() {
        let req = VmmAction::GetBalloonStats;
        check_runtime_request(req, |result, vmm| {
            assert_eq!(result, Ok(VmmData::BalloonStats(BalloonStats::default())));
            assert!(vmm.latest_balloon_stats_called)
        });

        let req = VmmAction::GetBalloonStats;
        check_runtime_request_err(
            req,
            VmmActionError::BalloonConfig(BalloonConfigError::DeviceNotFound),
        );
    }

    #[test]
    fn test_runtime_update_balloon_config() {
        let req = VmmAction::UpdateBalloon(BalloonUpdateConfig { amount_mib: 0 });
        check_runtime_request(req, |result, vmm| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vmm.update_balloon_config_called)
        });

        let req = VmmAction::UpdateBalloon(BalloonUpdateConfig { amount_mib: 0 });
        check_runtime_request_err(
            req,
            VmmActionError::BalloonConfig(BalloonConfigError::DeviceNotFound),
        );
    }

    #[test]
    fn test_runtime_update_balloon_stats_config() {
        let req = VmmAction::UpdateBalloonStatistics(BalloonUpdateStatsConfig {
            stats_polling_interval_s: 0,
        });
        check_runtime_request(req, |result, vmm| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vmm.update_balloon_stats_config_called)
        });

        let req = VmmAction::UpdateBalloonStatistics(BalloonUpdateStatsConfig {
            stats_polling_interval_s: 0,
        });
        check_runtime_request_err(
            req,
            VmmActionError::BalloonConfig(BalloonConfigError::DeviceNotFound),
        );
    }

    #[test]
    fn test_runtime_update_block_device_path() {
        let req = VmmAction::UpdateBlockDevice(BlockDeviceUpdateConfig {
            path_on_host: Some(String::new()),
            ..Default::default()
        });
        check_runtime_request(req, |result, vmm| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vmm.update_block_device_path_called)
        });

        let req = VmmAction::UpdateBlockDevice(BlockDeviceUpdateConfig {
            path_on_host: Some(String::new()),
            ..Default::default()
        });
        check_runtime_request_err(
            req,
            VmmActionError::DriveConfig(DriveError::DeviceUpdate(VmmError::DeviceManager(
                crate::device_manager::mmio::MmioError::InvalidDeviceType,
            ))),
        );
    }

    #[test]
    fn test_runtime_update_block_device_vhost_user_config() {
        let req = VmmAction::UpdateBlockDevice(BlockDeviceUpdateConfig {
            ..Default::default()
        });
        check_runtime_request(req, |result, vmm| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vmm.update_block_device_vhost_user_config_called)
        });

        let req = VmmAction::UpdateBlockDevice(BlockDeviceUpdateConfig {
            ..Default::default()
        });
        check_runtime_request_err(
            req,
            VmmActionError::DriveConfig(DriveError::DeviceUpdate(VmmError::DeviceManager(
                crate::device_manager::mmio::MmioError::InvalidDeviceType,
            ))),
        );
    }

    #[test]
    fn test_runtime_update_net_rate_limiters() {
        let req = VmmAction::UpdateNetworkInterface(NetworkInterfaceUpdateConfig {
            iface_id: String::new(),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        });
        check_runtime_request(req, |result, vmm| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vmm.update_net_rate_limiters_called)
        });

        let req = VmmAction::UpdateNetworkInterface(NetworkInterfaceUpdateConfig {
            iface_id: String::new(),
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        });
        check_runtime_request_err(
            req,
            VmmActionError::NetworkConfig(NetworkInterfaceError::DeviceUpdate(
                VmmError::DeviceManager(crate::device_manager::mmio::MmioError::InvalidDeviceType),
            )),
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_runtime_hotplug_vcpu() {
        use crate::cpu_config::x86_64::cpuid::Cpuid;

        // Case 1. Valid input
        let mut vmm = default_vmm();
        let cpuid = Cpuid::try_from(vmm.vm.supported_cpuid().clone()).unwrap();
        let vcpu_config = crate::VcpuConfig {
            vcpu_count: 0,
            smt: false,
            cpu_config: crate::cpu_config::templates::CpuConfiguration {
                cpuid,
                msrs: std::collections::HashMap::new(),
            },
        };

        vmm.attach_vcpu_config(vcpu_config.clone());
        let config = HotplugVcpuConfig { add: 4 };
        let result = vmm.hotplug_vcpus(config);
        assert_eq!(vmm.vcpus_handles.len(), 4);
        result.unwrap();

        // Case 2. Vcpu count too low
        let mut vmm = default_vmm();
        vmm.attach_vcpu_config(vcpu_config.clone());
        vmm.hotplug_vcpus(HotplugVcpuConfig { add: 1 }).unwrap();
        assert_eq!(vmm.vcpus_handles.len(), 1);
        let config = HotplugVcpuConfig { add: 0 };
        let result = vmm.hotplug_vcpus(config);
        result.unwrap_err();
        assert_eq!(vmm.vcpus_handles.len(), 1);

        // Case 3. Vcpu count too high
        let mut vmm = default_vmm();
        vmm.attach_vcpu_config(vcpu_config.clone());
        vmm.hotplug_vcpus(HotplugVcpuConfig { add: 1 }).unwrap();
        assert_eq!(vmm.vcpus_handles.len(), 1);
        let config = HotplugVcpuConfig { add: 33 };
        let result = vmm.hotplug_vcpus(config);
        result.unwrap_err();
        assert_eq!(vmm.vcpus_handles.len(), 1);

        // Case 4. Attempted overflow of vcpus
        let mut vmm = default_vmm();
        vmm.attach_vcpu_config(vcpu_config.clone());
        vmm.hotplug_vcpus(HotplugVcpuConfig { add: 2 }).unwrap();
        assert_eq!(vmm.vcpus_handles.len(), 2);
        let config = HotplugVcpuConfig { add: 255 };
        let result = vmm.hotplug_vcpus(config);
        result.unwrap_err();
        assert_eq!(vmm.vcpus_handles.len(), 2);
    }

    #[test]
    fn test_runtime_disallowed() {
        check_runtime_request_err(
            VmmAction::ConfigureBootSource(BootSourceConfig::default()),
            VmmActionError::OperationNotSupportedPostBoot,
        );
        check_runtime_request_err(
            VmmAction::ConfigureLogger(LoggerConfig {
                log_path: Some(PathBuf::new()),
                level: Some(crate::logger::LevelFilter::Debug),
                show_level: Some(false),
                show_log_origin: Some(false),
                module: None,
            }),
            VmmActionError::OperationNotSupportedPostBoot,
        );
        check_runtime_request_err(
            VmmAction::ConfigureMetrics(MetricsConfig {
                metrics_path: PathBuf::new(),
            }),
            VmmActionError::OperationNotSupportedPostBoot,
        );
        check_runtime_request_err(
            VmmAction::InsertBlockDevice(BlockDeviceConfig {
                drive_id: String::new(),
                partuuid: None,
                is_root_device: false,
                cache_type: CacheType::Unsafe,

                is_read_only: Some(false),
                path_on_host: Some(String::new()),
                rate_limiter: None,
                file_engine_type: None,

                socket: None,
            }),
            VmmActionError::OperationNotSupportedPostBoot,
        );
        check_runtime_request_err(
            VmmAction::InsertNetworkDevice(NetworkInterfaceConfig {
                iface_id: String::new(),
                host_dev_name: String::new(),
                guest_mac: None,
                rx_rate_limiter: None,
                tx_rate_limiter: None,
            }),
            VmmActionError::OperationNotSupportedPostBoot,
        );
        check_runtime_request_err(
            VmmAction::SetVsockDevice(VsockDeviceConfig {
                vsock_id: Some(String::new()),
                guest_cid: 0,
                uds_path: String::new(),
            }),
            VmmActionError::OperationNotSupportedPostBoot,
        );
        check_runtime_request_err(
            VmmAction::SetBalloonDevice(BalloonDeviceConfig::default()),
            VmmActionError::OperationNotSupportedPostBoot,
        );
        check_runtime_request_err(
            VmmAction::SetVsockDevice(VsockDeviceConfig {
                vsock_id: Some(String::new()),
                guest_cid: 0,
                uds_path: String::new(),
            }),
            VmmActionError::OperationNotSupportedPostBoot,
        );
        check_runtime_request_err(
            VmmAction::SetMmdsConfiguration(MmdsConfig {
                ipv4_address: None,
                version: MmdsVersion::default(),
                network_interfaces: Vec::new(),
            }),
            VmmActionError::OperationNotSupportedPostBoot,
        );
        check_runtime_request_err(
            VmmAction::UpdateVmConfiguration(MachineConfigUpdate::from(MachineConfig::default())),
            VmmActionError::OperationNotSupportedPostBoot,
        );
        check_runtime_request_err(
            VmmAction::LoadSnapshot(LoadSnapshotParams {
                snapshot_path: PathBuf::new(),
                mem_backend: MemBackendConfig {
                    backend_type: MemBackendType::File,
                    backend_path: PathBuf::new(),
                },
                enable_diff_snapshots: false,
                resume_vm: false,
            }),
            VmmActionError::OperationNotSupportedPostBoot,
        );
        check_runtime_request_err(
            VmmAction::SetEntropyDevice(EntropyDeviceConfig::default()),
            VmmActionError::OperationNotSupportedPostBoot,
        );
    }

    fn verify_load_snap_disallowed_after_boot_resources(res: VmmAction, res_name: &str) {
        let mut vm_resources = MockVmRes::default();
        let mut evmgr = EventManager::new().unwrap();
        let seccomp_filters = BpfThreadMap::new();
        let mut preboot = default_preboot(&mut vm_resources, &mut evmgr, &seccomp_filters);

        preboot.handle_preboot_request(res).unwrap();

        // Load snapshot should no longer be allowed.
        let req = VmmAction::LoadSnapshot(LoadSnapshotParams {
            snapshot_path: PathBuf::new(),
            mem_backend: MemBackendConfig {
                backend_type: MemBackendType::File,
                backend_path: PathBuf::new(),
            },
            enable_diff_snapshots: false,
            resume_vm: false,
        });
        let err = preboot.handle_preboot_request(req);
        assert_eq!(
            err,
            Err(VmmActionError::LoadSnapshot(
                LoadSnapshotError::LoadSnapshotNotAllowed
            )),
            "LoadSnapshot should be disallowed after {}",
            res_name
        );
    }

    #[test]
    fn test_preboot_load_snap_disallowed_after_boot_resources() {
        // Verify LoadSnapshot not allowed after configuring various boot-specific resources.
        let req = VmmAction::ConfigureBootSource(BootSourceConfig::default());
        verify_load_snap_disallowed_after_boot_resources(req, "ConfigureBootSource");

        let config = BlockDeviceConfig {
            drive_id: String::new(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(false),
            path_on_host: Some(String::new()),
            rate_limiter: None,
            file_engine_type: None,

            socket: None,
        };

        let req = VmmAction::InsertBlockDevice(config);
        verify_load_snap_disallowed_after_boot_resources(req, "InsertBlockDevice");

        let req = VmmAction::InsertNetworkDevice(NetworkInterfaceConfig {
            iface_id: String::new(),
            host_dev_name: String::new(),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        });
        verify_load_snap_disallowed_after_boot_resources(req, "InsertNetworkDevice");

        let req = VmmAction::SetBalloonDevice(BalloonDeviceConfig::default());
        verify_load_snap_disallowed_after_boot_resources(req, "SetBalloonDevice");

        let req = VmmAction::SetVsockDevice(VsockDeviceConfig {
            vsock_id: Some(String::new()),
            guest_cid: 0,
            uds_path: String::new(),
        });
        verify_load_snap_disallowed_after_boot_resources(req, "SetVsockDevice");

        let req =
            VmmAction::UpdateVmConfiguration(MachineConfigUpdate::from(MachineConfig::default()));
        verify_load_snap_disallowed_after_boot_resources(req, "SetVmConfiguration");

        let req = VmmAction::SetMmdsConfiguration(MmdsConfig {
            ipv4_address: None,
            version: MmdsVersion::default(),
            network_interfaces: Vec::new(),
        });
        verify_load_snap_disallowed_after_boot_resources(req, "SetMmdsConfiguration");
    }
}
