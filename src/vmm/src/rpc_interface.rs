// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Display, Formatter};
use std::result;
use std::sync::{Arc, Mutex};

#[cfg(not(test))]
use super::{builder::build_microvm_for_boot, resources::VmResources, Vmm};
#[cfg(all(not(test), target_arch = "x86_64"))]
use super::{persist::create_snapshot, persist::load_snapshot};

#[cfg(test)]
use tests::{build_microvm_for_boot, MockVmRes as VmResources, MockVmm as Vmm};
#[cfg(all(test, target_arch = "x86_64"))]
use tests::{create_snapshot, load_snapshot};

use super::Error as VmmError;
use crate::builder::StartMicrovmError;
#[cfg(target_arch = "x86_64")]
use crate::persist::{CreateSnapshotError, LoadSnapshotError};
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
#[derive(Debug, PartialEq)]
pub enum VmmData {
    /// No data is sent on the channel.
    Empty,
    /// The microVM configuration represented by `VmConfig`.
    MachineConfiguration(VmConfig),
}

/// Shorthand result type for external VMM commands.
pub type ActionResult = result::Result<VmmData, VmmActionError>;

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
        boot_timer_enabled: bool,
    ) -> (VmResources, Arc<Mutex<Vmm>>)
    where
        F: Fn() -> VmmAction,
        G: Fn(ActionResult),
    {
        let mut vm_resources = VmResources::default();
        vm_resources.boot_timer = boot_timer_enabled;
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
    pub fn handle_preboot_request(&mut self, request: VmmAction) -> ActionResult {
        use self::VmmAction::*;

        match request {
            // Supported operations allowed pre-boot.
            ConfigureBootSource(config) => self.set_boot_source(config),
            ConfigureLogger(logger_cfg) => {
                vmm_config::logger::init_logger(logger_cfg, &self.instance_info)
                    .map(|()| VmmData::Empty)
                    .map_err(VmmActionError::Logger)
            }
            ConfigureMetrics(metrics_cfg) => vmm_config::metrics::init_metrics(metrics_cfg)
                .map(|()| VmmData::Empty)
                .map_err(VmmActionError::Metrics),
            GetVmConfiguration => Ok(VmmData::MachineConfiguration(
                self.vm_resources.vm_config().clone(),
            )),
            InsertBlockDevice(config) => self.insert_block_device(config),
            InsertNetworkDevice(config) => self.insert_net_device(config),
            #[cfg(target_arch = "x86_64")]
            LoadSnapshot(config) => self.load_snapshot(&config),
            SetVsockDevice(config) => self.set_vsock_device(config),
            SetVmConfiguration(config) => self.set_vm_config(config),
            SetMmdsConfiguration(config) => self.set_mmds_config(config),
            StartMicroVm => self.start_microvm(),
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

    fn insert_block_device(&mut self, cfg: BlockDeviceConfig) -> ActionResult {
        self.vm_resources
            .set_block_device(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::DriveConfig)
    }

    fn insert_net_device(&mut self, cfg: NetworkInterfaceConfig) -> ActionResult {
        self.vm_resources
            .build_net_device(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::NetworkConfig)
    }

    fn set_boot_source(&mut self, cfg: BootSourceConfig) -> ActionResult {
        self.vm_resources
            .set_boot_source(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::BootSource)
    }

    fn set_mmds_config(&mut self, cfg: MmdsConfig) -> ActionResult {
        self.vm_resources
            .set_mmds_config(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::MmdsConfig)
    }

    fn set_vm_config(&mut self, cfg: VmConfig) -> ActionResult {
        self.vm_resources
            .set_vm_config(&cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::MachineConfig)
    }

    fn set_vsock_device(&mut self, cfg: VsockDeviceConfig) -> ActionResult {
        self.vm_resources
            .set_vsock_device(cfg)
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::VsockConfig)
    }

    // On success, this command will end the pre-boot stage and this controller
    // will be replaced by a runtime controller.
    fn start_microvm(&mut self) -> ActionResult {
        build_microvm_for_boot(
            &self.vm_resources,
            &mut self.event_manager,
            &self.seccomp_filter,
        )
        .map(|vmm| {
            self.built_vmm = Some(vmm);
            VmmData::Empty
        })
        .map_err(VmmActionError::StartMicrovm)
    }

    #[cfg(target_arch = "x86_64")]
    // On success, this command will end the pre-boot stage and this controller
    // will be replaced by a runtime controller.
    fn load_snapshot(&mut self, load_params: &LoadSnapshotParams) -> ActionResult {
        let load_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

        let loaded_vmm = load_snapshot(
            &mut self.event_manager,
            &self.seccomp_filter,
            load_params,
            VERSION_MAP.clone(),
        );

        let elapsed_time_us =
            update_metric_with_elapsed_time(&METRICS.latencies_us.vmm_load_snapshot, load_start_us);
        info!("'load snapshot' VMM action took {} us.", elapsed_time_us);

        loaded_vmm
            .map(|vmm| {
                self.built_vmm = Some(vmm);
                VmmData::Empty
            })
            .map_err(VmmActionError::LoadSnapshot)
    }
}

/// Enables RPC interaction with a running Firecracker VMM.
pub struct RuntimeApiController {
    vmm: Arc<Mutex<Vmm>>,
    vm_config: VmConfig,
}

impl RuntimeApiController {
    /// Handles the incoming runtime `VmmAction` request and provides a response for it.
    pub fn handle_request(&mut self, request: VmmAction) -> ActionResult {
        use self::VmmAction::*;
        match request {
            // Supported operations allowed post-boot.
            #[cfg(target_arch = "x86_64")]
            CreateSnapshot(snapshot_create_cfg) => self.create_snapshot(&snapshot_create_cfg),
            FlushMetrics => self.flush_metrics(),
            GetVmConfiguration => Ok(VmmData::MachineConfiguration(self.vm_config.clone())),
            Pause => self.pause(),
            Resume => self.resume(),
            #[cfg(target_arch = "x86_64")]
            SendCtrlAltDel => self.send_ctrl_alt_del(),
            UpdateBlockDevicePath(drive_id, new_path) => {
                self.update_block_device_path(&drive_id, new_path)
            }
            UpdateNetworkInterface(netif_update) => self.update_net_rate_limiters(netif_update),

            // Operations not allowed post-boot.
            ConfigureBootSource(_)
            | ConfigureLogger(_)
            | ConfigureMetrics(_)
            | InsertBlockDevice(_)
            | InsertNetworkDevice(_)
            | SetVsockDevice(_)
            | SetMmdsConfiguration(_)
            | SetVmConfiguration(_)
            | StartMicroVm => Err(VmmActionError::OperationNotSupportedPostBoot),
            #[cfg(target_arch = "x86_64")]
            LoadSnapshot(_) => Err(VmmActionError::OperationNotSupportedPostBoot),
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

        Ok(VmmData::Empty)
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

        Ok(VmmData::Empty)
    }

    /// Write the metrics on user demand (flush). We use the word `flush` here to highlight the fact
    /// that the metrics will be written immediately.
    /// Defer to inner Vmm. We'll move to a variant where the Vmm simply exposes functionality like
    /// getting the dirty pages, and then we'll have the metrics flushing logic entirely on the outside.
    fn flush_metrics(&mut self) -> ActionResult {
        // FIXME: we're losing the bool saying whether metrics were actually written.
        METRICS
            .write()
            .map(|_| VmmData::Empty)
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
            .map(|()| VmmData::Empty)
            .map_err(VmmActionError::InternalVmm)
    }

    #[cfg(target_arch = "x86_64")]
    fn create_snapshot(&mut self, create_params: &CreateSnapshotParams) -> ActionResult {
        let mut locked_vmm = self.vmm.lock().unwrap();
        let create_start_us = utils::time::get_time_us(utils::time::ClockType::Monotonic);

        create_snapshot(&mut locked_vmm, create_params, VERSION_MAP.clone())
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
        }
        Ok(VmmData::Empty)
    }

    /// Updates the path of the host file backing the emulated block device with id `drive_id`.
    /// We update the disk image on the device and its virtio configuration.
    fn update_block_device_path(&mut self, drive_id: &str, new_path: String) -> ActionResult {
        self.vmm
            .lock()
            .expect("Poisoned lock")
            .update_block_device_path(drive_id, new_path)
            .map(|()| VmmData::Empty)
            .map_err(DriveError::DeviceUpdate)
            .map_err(VmmActionError::DriveConfig)
    }

    /// Updates configuration for an emulated net device as described in `new_cfg`.
    fn update_net_rate_limiters(&mut self, new_cfg: NetworkInterfaceUpdateConfig) -> ActionResult {
        self.vmm
            .lock()
            .expect("Poisoned lock")
            .update_net_rate_limiters(
                &new_cfg.iface_id,
                new_cfg.rx_bytes(),
                new_cfg.rx_ops(),
                new_cfg.tx_bytes(),
                new_cfg.tx_ops(),
            )
            .map(|()| VmmData::Empty)
            .map_err(NetworkInterfaceError::DeviceUpdate)
            .map_err(VmmActionError::NetworkConfig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use devices::virtio::VsockError;
    use seccomp::BpfProgramRef;

    impl PartialEq for VmmActionError {
        fn eq(&self, other: &VmmActionError) -> bool {
            use VmmActionError::*;
            match (self, other) {
                (BootSource(_), BootSource(_)) => true,
                #[cfg(target_arch = "x86_64")]
                (CreateSnapshot(_), CreateSnapshot(_)) => true,
                (DriveConfig(_), DriveConfig(_)) => true,
                (InternalVmm(_), InternalVmm(_)) => true,
                #[cfg(target_arch = "x86_64")]
                (LoadSnapshot(_), LoadSnapshot(_)) => true,
                (Logger(_), Logger(_)) => true,
                (MachineConfig(_), MachineConfig(_)) => true,
                (Metrics(_), Metrics(_)) => true,
                (MmdsConfig(_), MmdsConfig(_)) => true,
                (NetworkConfig(_), NetworkConfig(_)) => true,
                (OperationNotSupportedPostBoot, OperationNotSupportedPostBoot) => true,
                (OperationNotSupportedPreBoot, OperationNotSupportedPreBoot) => true,
                (StartMicrovm(_), StartMicrovm(_)) => true,
                (VsockConfig(_), VsockConfig(_)) => true,
                _ => false,
            }
        }
    }

    // Mock `VmResources` used for testing.
    #[derive(Debug, Default)]
    pub struct MockVmRes {
        vm_config: VmConfig,
        boot_cfg_set: bool,
        block_set: bool,
        vsock_set: bool,
        net_set: bool,
        mmds_set: bool,
        pub boot_timer: bool,
        // when `true`, all self methods are forced to fail
        pub force_errors: bool,
    }

    impl MockVmRes {
        pub fn vm_config(&self) -> &VmConfig {
            &self.vm_config
        }

        pub fn set_vm_config(&mut self, machine_config: &VmConfig) -> Result<(), VmConfigError> {
            if self.force_errors {
                return Err(VmConfigError::InvalidVcpuCount);
            }
            self.vm_config = machine_config.clone();
            Ok(())
        }

        pub fn set_boot_source(
            &mut self,
            _: BootSourceConfig,
        ) -> Result<(), BootSourceConfigError> {
            if self.force_errors {
                return Err(BootSourceConfigError::InvalidKernelPath(
                    std::io::Error::from_raw_os_error(0),
                ));
            }
            self.boot_cfg_set = true;
            Ok(())
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
                    VsockError::BufDescMissing,
                ));
            }
            self.vsock_set = true;
            Ok(())
        }

        pub fn set_mmds_config(&mut self, _: MmdsConfig) -> Result<(), MmdsConfigError> {
            if self.force_errors {
                return Err(MmdsConfigError::InvalidIpv4Addr);
            }
            self.mmds_set = true;
            Ok(())
        }
    }

    // Mock `Vmm` used for testing.
    #[derive(Debug, Default)]
    pub struct MockVmm {
        pub pause_called: bool,
        pub resume_called: bool,
        pub send_ctrl_alt_del_called: bool,
        pub update_block_device_path_called: bool,
        pub update_net_rate_limiters_called: bool,
        // when `true`, all self methods are forced to fail
        pub force_errors: bool,
    }

    impl MockVmm {
        pub fn resume_vcpus(&mut self) -> Result<(), VmmError> {
            Ok(())
        }

        pub fn pause_vcpus(&mut self) -> Result<(), VmmError> {
            Ok(())
        }

        #[cfg(target_arch = "x86_64")]
        pub fn send_ctrl_alt_del(&mut self) -> Result<(), VmmError> {
            Ok(())
        }

        pub fn update_block_device_path(&mut self, _: &str, _: String) -> Result<(), VmmError> {
            Ok(())
        }

        pub fn update_net_rate_limiters(
            &mut self,
            _: &str,
            _: rate_limiter::BucketUpdate,
            _: rate_limiter::BucketUpdate,
            _: rate_limiter::BucketUpdate,
            _: rate_limiter::BucketUpdate,
        ) -> Result<(), VmmError> {
            Ok(())
        }
    }

    // Need to redefine this since the non-test one uses real VmResources
    // and real Vmm instead of our mocks.
    pub fn build_microvm_for_boot(
        _: &VmResources,
        _: &mut EventManager,
        _: BpfProgramRef,
    ) -> Result<Arc<Mutex<Vmm>>, StartMicrovmError> {
        Ok(Arc::new(Mutex::new(MockVmm::default())))
    }

    #[cfg(target_arch = "x86_64")]
    // Need to redefine this since the non-test one uses real Vmm
    // instead of our mocks.
    pub fn create_snapshot(
        _: &mut Vmm,
        _: &CreateSnapshotParams,
        _: versionize::VersionMap,
    ) -> std::result::Result<(), CreateSnapshotError> {
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    // Need to redefine this since the non-test one uses real Vmm
    // instead of our mocks.
    pub fn load_snapshot(
        _: &mut EventManager,
        _: BpfProgramRef,
        _: &LoadSnapshotParams,
        _: versionize::VersionMap,
    ) -> Result<Arc<Mutex<Vmm>>, LoadSnapshotError> {
        Ok(Arc::new(Mutex::new(MockVmm::default())))
    }

    fn default_preboot<'a>(
        vm_resources: &'a mut VmResources,
        event_manager: &'a mut EventManager,
    ) -> PrebootApiController<'a> {
        let instance_info = InstanceInfo {
            id: String::new(),
            started: false,
            vmm_version: String::new(),
            app_name: String::new(),
        };
        PrebootApiController::new(
            BpfProgram::new(),
            instance_info,
            vm_resources,
            event_manager,
        )
    }

    fn check_preboot_request<F>(request: VmmAction, check_success: F)
    where
        F: FnOnce(ActionResult, &MockVmRes),
    {
        let mut vm_resources = MockVmRes::default();
        let mut evmgr = EventManager::new().unwrap();
        let mut preboot = default_preboot(&mut vm_resources, &mut evmgr);
        let res = preboot.handle_preboot_request(request);
        check_success(res, &vm_resources);
    }

    // Forces error and validates error kind against expected.
    fn check_preboot_request_err(request: VmmAction, expected_err: VmmActionError) {
        let mut vm_resources = MockVmRes::default();
        vm_resources.force_errors = true;
        let mut evmgr = EventManager::new().unwrap();
        let mut preboot = default_preboot(&mut vm_resources, &mut evmgr);
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
        let req = VmmAction::GetVmConfiguration;
        let expected_cfg = VmConfig::default();
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
    fn test_preboot_set_vm_config() {
        let req = VmmAction::SetVmConfiguration(VmConfig::default());
        let expected_cfg = VmConfig::default();
        check_preboot_request(req, |result, vm_res| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert_eq!(vm_res.vm_config, expected_cfg);
        });

        let req = VmmAction::SetVmConfiguration(VmConfig::default());
        check_preboot_request_err(
            req,
            VmmActionError::MachineConfig(VmConfigError::InvalidVcpuCount),
        );
    }

    #[test]
    fn test_preboot_insert_block_dev() {
        let req = VmmAction::InsertBlockDevice(BlockDeviceConfig {
            path_on_host: String::new(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: String::new(),
            rate_limiter: None,
        });
        check_preboot_request(req, |result, vm_res| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vm_res.block_set)
        });

        let req = VmmAction::InsertBlockDevice(BlockDeviceConfig {
            path_on_host: String::new(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            drive_id: String::new(),
            rate_limiter: None,
        });
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
            allow_mmds_requests: false,
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
            allow_mmds_requests: false,
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
            vsock_id: String::new(),
            guest_cid: 0,
            uds_path: String::new(),
        });
        check_preboot_request(req, |result, vm_res| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vm_res.vsock_set)
        });

        let req = VmmAction::SetVsockDevice(VsockDeviceConfig {
            vsock_id: String::new(),
            guest_cid: 0,
            uds_path: String::new(),
        });
        check_preboot_request_err(
            req,
            VmmActionError::VsockConfig(VsockConfigError::CreateVsockDevice(
                VsockError::BufDescMissing,
            )),
        );
    }

    #[test]
    fn test_preboot_set_mmds_config() {
        let req = VmmAction::SetMmdsConfiguration(MmdsConfig { ipv4_address: None });
        check_preboot_request(req, |result, vm_res| {
            assert_eq!(result, Ok(VmmData::Empty));
            assert!(vm_res.mmds_set)
        });

        let req = VmmAction::SetMmdsConfiguration(MmdsConfig { ipv4_address: None });
        check_preboot_request_err(
            req,
            VmmActionError::MmdsConfig(MmdsConfigError::InvalidIpv4Addr),
        );
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
            VmmAction::UpdateBlockDevicePath(String::new(), String::new()),
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
        #[cfg(target_arch = "x86_64")]
        check_preboot_request_err(
            VmmAction::CreateSnapshot(CreateSnapshotParams {
                snapshot_type: SnapshotType::Full,
                snapshot_path: std::path::PathBuf::new(),
                mem_file_path: std::path::PathBuf::new(),
                version: None,
            }),
            VmmActionError::OperationNotSupportedPreBoot,
        );
        #[cfg(target_arch = "x86_64")]
        check_preboot_request_err(
            VmmAction::SendCtrlAltDel,
            VmmActionError::OperationNotSupportedPreBoot,
        );
    }
}
