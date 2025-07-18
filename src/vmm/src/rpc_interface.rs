// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{self, Debug};
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::Value;
use utils::time::{ClockType, get_time_us};

use super::builder::build_and_boot_microvm;
use super::persist::{create_snapshot, restore_from_snapshot};
use super::resources::VmResources;
use super::{Vmm, VmmError};
use crate::EventManager;
use crate::builder::StartMicrovmError;
use crate::cpu_config::templates::{CustomCpuTemplate, GuestConfigError};
use crate::logger::{LoggerConfig, info, warn, *};
use crate::mmds::data_store::{self, Mmds};
use crate::persist::{CreateSnapshotError, RestoreFromSnapshotError, VmInfo};
use crate::resources::VmmConfig;
use crate::seccomp::BpfThreadMap;
use crate::vmm_config::balloon::{
    BalloonConfigError, BalloonDeviceConfig, BalloonStats, BalloonUpdateConfig,
    BalloonUpdateStatsConfig,
};
use crate::vmm_config::boot_source::{BootSourceConfig, BootSourceConfigError};
use crate::vmm_config::drive::{BlockDeviceConfig, BlockDeviceUpdateConfig, DriveError};
use crate::vmm_config::entropy::{EntropyDeviceConfig, EntropyDeviceError};
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::{MachineConfig, MachineConfigError, MachineConfigUpdate};
use crate::vmm_config::metrics::{MetricsConfig, MetricsConfigError};
use crate::vmm_config::mmds::{MmdsConfig, MmdsConfigError};
use crate::vmm_config::net::{
    NetworkInterfaceConfig, NetworkInterfaceError, NetworkInterfaceUpdateConfig,
};
use crate::vmm_config::snapshot::{CreateSnapshotParams, LoadSnapshotParams, SnapshotType};
use crate::vmm_config::vsock::{VsockConfigError, VsockDeviceConfig};
use crate::vmm_config::{self, RateLimiterUpdate};

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
    UpdateMachineConfiguration(MachineConfigUpdate),
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
    /// Internal VMM error: {0}
    InternalVmm(#[from] VmmError),
    /// Load snapshot error: {0}
    LoadSnapshot(#[from] LoadSnapshotError),
    /// Logger error: {0}
    Logger(#[from] crate::logger::LoggerUpdateError),
    /// Machine config error: {0}
    MachineConfig(#[from] MachineConfigError),
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
    fn mmds(&mut self) -> Result<MutexGuard<'_, Mmds>, VmmActionError>;

    fn get_mmds(&mut self) -> Result<VmmData, VmmActionError> {
        Ok(VmmData::MmdsValue(self.mmds()?.data_store_value()))
    }

    fn patch_mmds(&mut self, value: serde_json::Value) -> Result<VmmData, VmmActionError> {
        self.mmds()?
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
        self.mmds()?
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
    /// The [`Vmm`] object constructed through requests
    pub built_vmm: Option<Arc<Mutex<Vmm>>>,
    // Configuring boot specific resources will set this to true.
    // Loading from snapshot will not be allowed once this is true.
    boot_path: bool,
    // Some PrebootApiRequest errors are irrecoverable and Firecracker
    // should cleanly teardown if they occur.
    fatal_error: Option<BuildMicrovmFromRequestsError>,
}

// TODO Remove when `EventManager` implements `std::fmt::Debug`.
impl fmt::Debug for PrebootApiController<'_> {
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
    fn mmds(&mut self) -> Result<MutexGuard<'_, Mmds>, VmmActionError> {
        self.vm_resources
            .locked_mmds_or_default()
            .map_err(VmmActionError::MmdsConfig)
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
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BuildMicrovmFromRequestsError {
    /// Configuring MMDS failed: {0}.
    ConfigureMmds(#[from] MmdsConfigError),
    /// Populating MMDS from file failed: {0}.
    PopulateMmds(#[from] data_store::MmdsDatastoreError),
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
        api_event_fd: &vmm_sys_util::eventfd::EventFd,
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
            vm_resources.locked_mmds_or_default()?.put_data(
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
            GetVmMachineConfig => Ok(VmmData::MachineConfiguration(
                self.vm_resources.machine_config.clone(),
            )),
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
            UpdateMachineConfiguration(config) => self.update_machine_config(config),
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

    fn update_machine_config(
        &mut self,
        cfg: MachineConfigUpdate,
    ) -> Result<VmmData, VmmActionError> {
        self.boot_path = true;
        self.vm_resources
            .update_machine_config(&cfg)
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
        let load_start_us = get_time_us(ClockType::Monotonic);

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
        .inspect_err(|_| {
            // If restore fails, we consider the process is too dirty to recover.
            self.fatal_error = Some(BuildMicrovmFromRequestsError::Restore);
        })?;
        // Resume VM
        if load_params.resume_vm {
            vmm.lock()
                .expect("Poisoned lock")
                .resume_vm()
                .inspect_err(|_| {
                    // If resume fails, we consider the process is too dirty to recover.
                    self.fatal_error = Some(BuildMicrovmFromRequestsError::Resume);
                })?;
        }
        // Set the VM
        self.built_vmm = Some(vmm);

        debug!(
            "'load snapshot' VMM action took {} us.",
            update_metric_with_elapsed_time(&METRICS.latencies_us.vmm_load_snapshot, load_start_us)
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
    fn mmds(&mut self) -> Result<MutexGuard<'_, Mmds>, VmmActionError> {
        self.vm_resources
            .locked_mmds_or_default()
            .map_err(VmmActionError::MmdsConfig)
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
            GetVmMachineConfig => Ok(VmmData::MachineConfiguration(
                self.vm_resources.machine_config.clone(),
            )),
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
            | UpdateMachineConfiguration(_) => Err(VmmActionError::OperationNotSupportedPostBoot),
        }
    }

    /// Creates a new `RuntimeApiController`.
    pub fn new(vm_resources: VmResources, vmm: Arc<Mutex<Vmm>>) -> Self {
        Self { vmm, vm_resources }
    }

    /// Pauses the microVM by pausing the vCPUs.
    pub fn pause(&mut self) -> Result<VmmData, VmmActionError> {
        let pause_start_us = get_time_us(ClockType::Monotonic);

        self.vmm.lock().expect("Poisoned lock").pause_vm()?;

        let elapsed_time_us =
            update_metric_with_elapsed_time(&METRICS.latencies_us.vmm_pause_vm, pause_start_us);
        info!("'pause vm' VMM action took {} us.", elapsed_time_us);

        Ok(VmmData::Empty)
    }

    /// Resumes the microVM by resuming the vCPUs.
    pub fn resume(&mut self) -> Result<VmmData, VmmActionError> {
        let resume_start_us = get_time_us(ClockType::Monotonic);

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
        if create_params.snapshot_type == SnapshotType::Diff {
            log_dev_preview_warning("Virtual machine diff snapshots", None);
        }

        let mut locked_vmm = self.vmm.lock().unwrap();
        let vm_info = VmInfo::from(&self.vm_resources);
        let create_start_us = get_time_us(ClockType::Monotonic);

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
                .map_err(DriveError::DeviceUpdate)?;
        }

        // virtio-block updates
        if let Some(new_path) = new_cfg.path_on_host {
            vmm.update_block_device_path(&new_cfg.drive_id, new_path)
                .map_err(DriveError::DeviceUpdate)?;
        }
        if new_cfg.rate_limiter.is_some() {
            vmm.update_block_rate_limiter(
                &new_cfg.drive_id,
                RateLimiterUpdate::from(new_cfg.rate_limiter).bandwidth,
                RateLimiterUpdate::from(new_cfg.rate_limiter).ops,
            )
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
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::HTTP_MAX_PAYLOAD_SIZE;
    use crate::builder::tests::default_vmm;
    use crate::devices::virtio::block::CacheType;
    use crate::mmds::data_store::MmdsVersion;
    use crate::seccomp::BpfThreadMap;
    use crate::vmm_config::snapshot::{MemBackendConfig, MemBackendType};

    fn default_preboot<'a>(
        vm_resources: &'a mut VmResources,
        event_manager: &'a mut EventManager,
        seccomp_filters: &'a BpfThreadMap,
    ) -> PrebootApiController<'a> {
        let instance_info = InstanceInfo::default();
        PrebootApiController::new(seccomp_filters, instance_info, vm_resources, event_manager)
    }

    fn preboot_request(request: VmmAction) -> Result<VmmData, VmmActionError> {
        let mut vm_resources = VmResources::default();
        let mut evmgr = EventManager::new().unwrap();
        let seccomp_filters = BpfThreadMap::new();
        let mut preboot = default_preboot(&mut vm_resources, &mut evmgr, &seccomp_filters);
        preboot.handle_preboot_request(request)
    }

    fn preboot_request_with_mmds(
        request: VmmAction,
        mmds: Arc<Mutex<Mmds>>,
    ) -> Result<VmmData, VmmActionError> {
        let mut vm_resources = VmResources {
            mmds: Some(mmds),
            mmds_size_limit: HTTP_MAX_PAYLOAD_SIZE,
            ..Default::default()
        };
        let mut evmgr = EventManager::new().unwrap();
        let seccomp_filters = BpfThreadMap::new();
        let mut preboot = default_preboot(&mut vm_resources, &mut evmgr, &seccomp_filters);
        preboot.handle_preboot_request(request)
    }

    #[test]
    fn test_preboot_get_vm_config() {
        assert_eq!(
            preboot_request(VmmAction::GetVmMachineConfig).unwrap(),
            VmmData::MachineConfiguration(MachineConfig::default())
        );
    }

    #[test]
    fn test_preboot_get_mmds() {
        assert_eq!(
            preboot_request(VmmAction::GetMMDS).unwrap(),
            VmmData::MmdsValue(Value::Null)
        );
    }

    #[test]
    fn test_runtime_get_mmds() {
        assert_eq!(
            runtime_request(VmmAction::GetMMDS).unwrap(),
            VmmData::MmdsValue(Value::Null)
        );
    }

    #[test]
    fn test_preboot_put_mmds() {
        let mmds = Arc::new(Mutex::new(Mmds::default()));

        assert_eq!(
            preboot_request_with_mmds(
                VmmAction::PutMMDS(Value::String("string".to_string())),
                mmds.clone()
            )
            .unwrap(),
            VmmData::Empty
        );
        assert_eq!(
            preboot_request_with_mmds(VmmAction::GetMMDS, mmds.clone()).unwrap(),
            VmmData::MmdsValue(Value::String("string".to_string()))
        );

        let filling = (0..51300).map(|_| "X").collect::<String>();
        let data = "{\"key\": \"".to_string() + &filling + "\"}";

        assert!(matches!(
            preboot_request_with_mmds(
                VmmAction::PutMMDS(serde_json::from_str(&data).unwrap()),
                mmds.clone()
            ),
            Err(VmmActionError::MmdsLimitExceeded(_))
        ));
        assert_eq!(
            preboot_request_with_mmds(VmmAction::GetMMDS, mmds).unwrap(),
            VmmData::MmdsValue(Value::String("string".to_string()))
        );
    }

    #[test]
    fn test_runtime_put_mmds() {
        let mmds = Arc::new(Mutex::new(Mmds::default()));

        assert_eq!(
            runtime_request_with_mmds(
                VmmAction::PutMMDS(Value::String("string".to_string())),
                mmds.clone()
            )
            .unwrap(),
            VmmData::Empty
        );
        assert_eq!(
            runtime_request_with_mmds(VmmAction::GetMMDS, mmds.clone()).unwrap(),
            VmmData::MmdsValue(Value::String("string".to_string()))
        );

        let filling = (0..51300).map(|_| "X").collect::<String>();
        let data = "{\"key\": \"".to_string() + &filling + "\"}";

        assert!(matches!(
            runtime_request_with_mmds(
                VmmAction::PutMMDS(serde_json::from_str(&data).unwrap()),
                mmds.clone()
            ),
            Err(VmmActionError::MmdsLimitExceeded(_))
        ));
        assert_eq!(
            runtime_request_with_mmds(VmmAction::GetMMDS, mmds).unwrap(),
            VmmData::MmdsValue(Value::String("string".to_string()))
        );
    }

    #[test]
    fn test_preboot_patch_mmds() {
        let mmds = Arc::new(Mutex::new(Mmds::default()));
        // MMDS data store is not yet initialized.
        let res = preboot_request(VmmAction::PatchMMDS(Value::String("string".to_string())));
        assert!(
            matches!(
                res,
                Err(VmmActionError::Mmds(
                    data_store::MmdsDatastoreError::NotInitialized
                ))
            ),
            "{:?}",
            res
        );

        assert_eq!(
            preboot_request_with_mmds(
                VmmAction::PutMMDS(
                    serde_json::from_str(r#"{"key1": "value1", "key2": "val2"}"#).unwrap(),
                ),
                mmds.clone()
            )
            .unwrap(),
            VmmData::Empty
        );
        assert_eq!(
            preboot_request_with_mmds(VmmAction::GetMMDS, mmds.clone()).unwrap(),
            VmmData::MmdsValue(
                serde_json::from_str(r#"{"key1": "value1", "key2": "val2"}"#).unwrap()
            )
        );

        assert_eq!(
            preboot_request_with_mmds(
                VmmAction::PatchMMDS(
                    serde_json::from_str(r#"{"key1": null, "key2": "value2"}"#).unwrap(),
                ),
                mmds.clone()
            )
            .unwrap(),
            VmmData::Empty
        );

        assert_eq!(
            preboot_request_with_mmds(VmmAction::GetMMDS, mmds.clone()).unwrap(),
            VmmData::MmdsValue(serde_json::from_str(r#"{"key2": "value2"}"#).unwrap())
        );

        let filling = (0..HTTP_MAX_PAYLOAD_SIZE).map(|_| "X").collect::<String>();
        let data = "{\"key\": \"".to_string() + &filling + "\"}";

        assert!(matches!(
            preboot_request_with_mmds(
                VmmAction::PatchMMDS(serde_json::from_str(&data).unwrap()),
                mmds.clone()
            ),
            Err(VmmActionError::MmdsLimitExceeded(_))
        ));
        assert_eq!(
            preboot_request_with_mmds(VmmAction::GetMMDS, mmds).unwrap(),
            VmmData::MmdsValue(serde_json::from_str(r#"{"key2": "value2"}"#).unwrap())
        );
    }

    #[test]
    fn test_runtime_patch_mmds() {
        let mmds = Arc::new(Mutex::new(Mmds::default()));
        // MMDS data store is not yet initialized.
        let res = runtime_request(VmmAction::PatchMMDS(Value::String("string".to_string())));
        assert!(
            matches!(
                res,
                Err(VmmActionError::Mmds(
                    data_store::MmdsDatastoreError::NotInitialized
                ))
            ),
            "{:?}",
            res
        );

        assert_eq!(
            runtime_request_with_mmds(
                VmmAction::PutMMDS(
                    serde_json::from_str(r#"{"key1": "value1", "key2": "val2"}"#).unwrap(),
                ),
                mmds.clone()
            )
            .unwrap(),
            VmmData::Empty
        );
        assert_eq!(
            runtime_request_with_mmds(VmmAction::GetMMDS, mmds.clone()).unwrap(),
            VmmData::MmdsValue(
                serde_json::from_str(r#"{"key1": "value1", "key2": "val2"}"#).unwrap()
            )
        );
        assert_eq!(
            runtime_request_with_mmds(
                VmmAction::PatchMMDS(
                    serde_json::from_str(r#"{"key1": null, "key2": "value2"}"#).unwrap(),
                ),
                mmds.clone()
            )
            .unwrap(),
            VmmData::Empty
        );

        assert_eq!(
            runtime_request_with_mmds(VmmAction::GetMMDS, mmds.clone()).unwrap(),
            VmmData::MmdsValue(serde_json::from_str(r#"{"key2": "value2"}"#).unwrap())
        );

        let filling = (0..HTTP_MAX_PAYLOAD_SIZE).map(|_| "X").collect::<String>();
        let data = "{\"key\": \"".to_string() + &filling + "\"}";

        assert!(matches!(
            runtime_request_with_mmds(
                VmmAction::PatchMMDS(serde_json::from_str(&data).unwrap()),
                mmds.clone()
            ),
            Err(VmmActionError::MmdsLimitExceeded(_))
        ));
        assert_eq!(
            runtime_request_with_mmds(VmmAction::GetMMDS, mmds).unwrap(),
            VmmData::MmdsValue(serde_json::from_str(r#"{"key2": "value2"}"#).unwrap())
        );
    }

    #[test]
    fn test_preboot_disallowed() {
        fn check_unsupported(res: Result<VmmData, VmmActionError>) {
            assert!(
                matches!(res, Err(VmmActionError::OperationNotSupportedPreBoot)),
                "{:?}",
                res
            );
        }

        check_unsupported(preboot_request(VmmAction::FlushMetrics));
        check_unsupported(preboot_request(VmmAction::Pause));
        check_unsupported(preboot_request(VmmAction::Resume));
        check_unsupported(preboot_request(VmmAction::GetBalloonStats));
        check_unsupported(preboot_request(VmmAction::UpdateBalloon(
            BalloonUpdateConfig { amount_mib: 0 },
        )));
        check_unsupported(preboot_request(VmmAction::UpdateBalloonStatistics(
            BalloonUpdateStatsConfig {
                stats_polling_interval_s: 0,
            },
        )));
        check_unsupported(preboot_request(VmmAction::UpdateBlockDevice(
            BlockDeviceUpdateConfig::default(),
        )));
        check_unsupported(preboot_request(VmmAction::UpdateNetworkInterface(
            NetworkInterfaceUpdateConfig {
                iface_id: String::new(),
                rx_rate_limiter: None,
                tx_rate_limiter: None,
            },
        )));
        check_unsupported(preboot_request(VmmAction::CreateSnapshot(
            CreateSnapshotParams {
                snapshot_type: SnapshotType::Full,
                snapshot_path: PathBuf::new(),
                mem_file_path: PathBuf::new(),
            },
        )));
        #[cfg(target_arch = "x86_64")]
        check_unsupported(preboot_request(VmmAction::SendCtrlAltDel));
    }

    fn runtime_request(request: VmmAction) -> Result<VmmData, VmmActionError> {
        let vmm = Arc::new(Mutex::new(default_vmm()));
        let mut runtime = RuntimeApiController::new(VmResources::default(), vmm.clone());
        runtime.handle_request(request)
    }

    fn runtime_request_with_mmds(
        request: VmmAction,
        mmds: Arc<Mutex<Mmds>>,
    ) -> Result<VmmData, VmmActionError> {
        let vm_res = VmResources {
            mmds: Some(mmds),
            ..Default::default()
        };
        let vmm = Arc::new(Mutex::new(default_vmm()));
        let mut runtime = RuntimeApiController::new(vm_res, vmm.clone());
        runtime.handle_request(request)
    }

    #[test]
    fn test_runtime_get_vm_config() {
        assert_eq!(
            runtime_request(VmmAction::GetVmMachineConfig).unwrap(),
            VmmData::MachineConfiguration(MachineConfig::default())
        );
    }

    #[test]
    fn test_runtime_disallowed() {
        fn check_unsupported(res: Result<VmmData, VmmActionError>) {
            assert!(
                matches!(res, Err(VmmActionError::OperationNotSupportedPostBoot)),
                "{:?}",
                res
            );
        }

        check_unsupported(runtime_request(VmmAction::ConfigureBootSource(
            BootSourceConfig::default(),
        )));
        check_unsupported(runtime_request(VmmAction::ConfigureLogger(LoggerConfig {
            log_path: Some(PathBuf::new()),
            level: Some(crate::logger::LevelFilter::Debug),
            show_level: Some(false),
            show_log_origin: Some(false),
            module: None,
        })));
        check_unsupported(runtime_request(VmmAction::ConfigureMetrics(
            MetricsConfig {
                metrics_path: PathBuf::new(),
            },
        )));
        check_unsupported(runtime_request(VmmAction::InsertBlockDevice(
            BlockDeviceConfig {
                drive_id: String::new(),
                partuuid: None,
                is_root_device: false,
                cache_type: CacheType::Unsafe,

                is_read_only: Some(false),
                path_on_host: Some(String::new()),
                rate_limiter: None,
                file_engine_type: None,

                socket: None,
            },
        )));
        check_unsupported(runtime_request(VmmAction::InsertNetworkDevice(
            NetworkInterfaceConfig {
                iface_id: String::new(),
                host_dev_name: String::new(),
                guest_mac: None,
                rx_rate_limiter: None,
                tx_rate_limiter: None,
            },
        )));
        check_unsupported(runtime_request(VmmAction::SetVsockDevice(
            VsockDeviceConfig {
                vsock_id: Some(String::new()),
                guest_cid: 0,
                uds_path: String::new(),
            },
        )));
        check_unsupported(runtime_request(VmmAction::SetBalloonDevice(
            BalloonDeviceConfig::default(),
        )));
        check_unsupported(runtime_request(VmmAction::SetVsockDevice(
            VsockDeviceConfig {
                vsock_id: Some(String::new()),
                guest_cid: 0,
                uds_path: String::new(),
            },
        )));
        check_unsupported(runtime_request(VmmAction::SetMmdsConfiguration(
            MmdsConfig {
                ipv4_address: None,
                version: MmdsVersion::default(),
                network_interfaces: Vec::new(),
                imds_compat: false,
            },
        )));
        check_unsupported(runtime_request(VmmAction::UpdateMachineConfiguration(
            MachineConfigUpdate::from(MachineConfig::default()),
        )));
        check_unsupported(runtime_request(VmmAction::LoadSnapshot(
            LoadSnapshotParams {
                snapshot_path: PathBuf::new(),
                mem_backend: MemBackendConfig {
                    backend_type: MemBackendType::File,
                    backend_path: PathBuf::new(),
                },
                track_dirty_pages: false,
                resume_vm: false,
                network_overrides: vec![],
            },
        )));
        check_unsupported(runtime_request(VmmAction::SetEntropyDevice(
            EntropyDeviceConfig::default(),
        )));
    }
}
