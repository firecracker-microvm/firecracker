// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::From;
use std::sync::{Arc, Mutex, MutexGuard};

use logger::info;
use mmds::data_store::{Mmds, MmdsVersion};
use mmds::ns::MmdsNetworkStack;
use serde::{Deserialize, Serialize};
use utils::net::ipv4addr::is_link_local_valid;

use crate::device_manager::persist::SharedDeviceType;
use crate::vmm_config::balloon::*;
use crate::vmm_config::boot_source::{
    BootConfig, BootSource, BootSourceConfig, BootSourceConfigError,
};
use crate::vmm_config::drive::*;
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::logger::{init_logger, LoggerConfig, LoggerConfigError};
use crate::vmm_config::machine_config::{VmConfig, VmConfigError, VmUpdateConfig};
use crate::vmm_config::metrics::{init_metrics, MetricsConfig, MetricsConfigError};
use crate::vmm_config::mmds::{MmdsConfig, MmdsConfigError};
use crate::vmm_config::net::*;
use crate::vmm_config::snapshot::MemBackendConfig;
use crate::vmm_config::vsock::*;
use crate::vstate::vcpu::VcpuConfig;

type Result<E> = std::result::Result<(), E>;

/// Errors encountered when configuring microVM resources.
#[derive(Debug, derive_more::From)]
pub enum Error {
    /// Balloon device configuration error.
    BalloonDevice(BalloonConfigError),
    /// Block device configuration error.
    BlockDevice(DriveError),
    /// Boot source configuration error.
    BootSource(BootSourceConfigError),
    /// JSON is invalid.
    InvalidJson(serde_json::Error),
    /// Logger configuration error.
    Logger(LoggerConfigError),
    /// Metrics system configuration error.
    Metrics(MetricsConfigError),
    /// MMDS error.
    Mmds(mmds::data_store::Error),
    /// MMDS configuration error.
    MmdsConfig(MmdsConfigError),
    /// Net device configuration error.
    NetDevice(NetworkInterfaceError),
    /// microVM vCpus or memory configuration error.
    VmConfig(VmConfigError),
    /// Vsock device configuration error.
    VsockDevice(VsockConfigError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BalloonDevice(err) => write!(f, "Balloon device error: {}", err),
            Error::BlockDevice(err) => write!(f, "Block device error: {}", err),
            Error::BootSource(err) => write!(f, "Boot source error: {}", err),
            Error::InvalidJson(err) => write!(f, "Invalid JSON: {}", err),
            Error::Logger(err) => write!(f, "Logger error: {}", err),
            Error::Metrics(err) => write!(f, "Metrics error: {}", err),
            Error::Mmds(err) => write!(f, "MMDS error: {}", err),
            Error::MmdsConfig(err) => write!(f, "MMDS config error: {}", err),
            Error::NetDevice(err) => write!(f, "Network device error: {}", err),
            Error::VmConfig(err) => write!(f, "VM config error: {}", err),
            Error::VsockDevice(err) => write!(f, "Vsock device error: {}", err),
        }
    }
}

/// Used for configuring a vmm from one single json passed to the Firecracker process.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct VmmConfig {
    #[serde(rename = "balloon")]
    balloon_device: Option<BalloonDeviceConfig>,
    #[serde(rename = "drives")]
    block_devices: Vec<BlockDeviceConfig>,
    #[serde(rename = "boot-source")]
    boot_source: BootSourceConfig,
    #[serde(rename = "logger")]
    logger: Option<LoggerConfig>,
    #[serde(rename = "machine-config")]
    machine_config: Option<VmConfig>,
    #[serde(rename = "metrics")]
    metrics: Option<MetricsConfig>,
    #[serde(rename = "mmds-config")]
    mmds_config: Option<MmdsConfig>,
    #[serde(rename = "network-interfaces", default)]
    net_devices: Vec<NetworkInterfaceConfig>,
    #[serde(rename = "vsock")]
    vsock_device: Option<VsockDeviceConfig>,
}

/// A data structure that encapsulates the device configurations
/// held in the Vmm.
#[derive(Default)]
pub struct VmResources {
    /// The vCpu and memory configuration for this microVM.
    vm_config: VmConfig,
    /// The boot source spec (contains both config and builder) for this microVM.
    boot_source: BootSource,
    /// The block devices.
    pub block: BlockBuilder,
    /// The vsock device.
    pub vsock: VsockBuilder,
    /// The balloon device.
    pub balloon: BalloonBuilder,
    /// The network devices builder.
    pub net_builder: NetBuilder,
    /// The optional Mmds data store.
    // This is initialised on demand (if ever used), so that we don't allocate it unless it's
    // actually used.
    pub mmds: Option<Arc<Mutex<Mmds>>>,
    /// Data store limit for the mmds.
    pub mmds_size_limit: usize,
    /// Whether or not to load boot timer device.
    pub boot_timer: bool,
    /// When backed by a memory on boot, this should be set
    pub memory_backend: Option<MemBackendConfig>,
}

impl VmResources {
    /// Configures Vmm resources as described by the `config_json` param.
    pub fn from_json(
        config_json: &str,
        instance_info: &InstanceInfo,
        mmds_size_limit: usize,
        metadata_json: Option<&str>,
    ) -> std::result::Result<Self, Error> {
        let vmm_config: VmmConfig = serde_json::from_slice::<VmmConfig>(config_json.as_bytes())?;

        if let Some(logger) = vmm_config.logger {
            init_logger(logger, instance_info)?;
        }

        if let Some(metrics) = vmm_config.metrics {
            init_metrics(metrics)?;
        }

        let mut resources: Self = Self {
            mmds_size_limit,
            ..Default::default()
        };
        if let Some(machine_config) = vmm_config.machine_config {
            let machine_config = VmUpdateConfig::from(machine_config);
            resources.update_vm_config(&machine_config)?;
        }

        resources.build_boot_source(vmm_config.boot_source)?;

        for drive_config in vmm_config.block_devices.into_iter() {
            resources.set_block_device(drive_config)?;
        }

        for net_config in vmm_config.net_devices.into_iter() {
            resources.build_net_device(net_config)?;
        }

        if let Some(vsock_config) = vmm_config.vsock_device {
            resources.set_vsock_device(vsock_config)?;
        }

        if let Some(balloon_config) = vmm_config.balloon_device {
            resources.set_balloon_device(balloon_config)?;
        }

        // Init the data store from file, if present.
        if let Some(data) = metadata_json {
            resources.locked_mmds_or_default().put_data(
                serde_json::from_str(data).expect("MMDS error: metadata provided not valid json"),
            )?;
            info!("Successfully added metadata to mmds from file");
        }

        if let Some(mmds_config) = vmm_config.mmds_config {
            resources.set_mmds_config(mmds_config, &instance_info.id)?;
        }

        Ok(resources)
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

    /// Updates the resources from a restored device (used for configuring resources when
    /// restoring from a snapshot).
    pub fn update_from_restored_device(&mut self, device: SharedDeviceType) {
        match device {
            SharedDeviceType::Block(block) => {
                self.block.add_device(block);
            }

            SharedDeviceType::Network(network) => {
                self.net_builder.add_device(network);
            }

            SharedDeviceType::Balloon(balloon) => {
                self.balloon.set_device(balloon);
            }

            SharedDeviceType::Vsock(vsock) => {
                self.vsock.set_device(vsock);
            }
        }
    }

    /// Returns a VcpuConfig based on the vm config.
    pub fn vcpu_config(&self) -> VcpuConfig {
        // The unwraps are ok to use because the values are initialized using defaults if not
        // supplied by the user.
        VcpuConfig {
            vcpu_count: self.vm_config().vcpu_count,
            smt: self.vm_config().smt,
            cpu_template: self.vm_config().cpu_template,
        }
    }

    /// Returns whether dirty page tracking is enabled or not.
    pub fn track_dirty_pages(&self) -> bool {
        self.vm_config().track_dirty_pages
    }

    /// Configures the dirty page tracking functionality of the microVM.
    pub fn set_track_dirty_pages(&mut self, dirty_page_tracking: bool) {
        self.vm_config.track_dirty_pages = dirty_page_tracking;
    }

    /// Returns the config for the backing memory file
    pub fn memory_backend(&self) -> Option<MemBackendConfig> {
        self.memory_backend.clone()
    }

    /// Sets the backing memory file
    pub fn set_memory_backend(&mut self, backing_mem_file: MemBackendConfig) {
        self.memory_backend.get_or_insert(backing_mem_file);
    }

    /// Returns the VmConfig.
    pub fn vm_config(&self) -> &VmConfig {
        &self.vm_config
    }

    /// Update the machine configuration of the microVM.
    pub fn update_vm_config(
        &mut self,
        machine_config: &VmUpdateConfig,
    ) -> std::result::Result<(), VmConfigError> {
        let vcpu_count = machine_config
            .vcpu_count
            .unwrap_or(self.vm_config.vcpu_count);

        let smt = machine_config.smt.unwrap_or(self.vm_config.smt);

        if vcpu_count == 0 {
            return Err(VmConfigError::InvalidVcpuCount);
        }

        // If SMT is enabled or is to be enabled in this call
        // only allow vcpu count to be 1 or even.
        if smt && vcpu_count > 1 && vcpu_count % 2 == 1 {
            return Err(VmConfigError::InvalidVcpuCount);
        }

        self.vm_config.vcpu_count = vcpu_count;
        self.vm_config.smt = smt;

        let mem_size_mib = machine_config
            .mem_size_mib
            .unwrap_or(self.vm_config.mem_size_mib);

        if mem_size_mib == 0 {
            return Err(VmConfigError::InvalidMemorySize);
        }

        // The VM cannot have a memory size smaller than the target size
        // of the balloon device, if present.
        if self.balloon.get().is_some()
            && mem_size_mib
                < self
                    .balloon
                    .get_config()
                    .map_err(|_| VmConfigError::InvalidVmState)?
                    .amount_mib as usize
        {
            return Err(VmConfigError::IncompatibleBalloonSize);
        }

        self.vm_config.mem_size_mib = mem_size_mib;

        // Update the CPU template
        if let Some(cpu_template) = machine_config.cpu_template {
            self.vm_config.cpu_template = cpu_template;
        }

        // Update dirty page tracking
        if let Some(track_dirty_pages) = machine_config.track_dirty_pages {
            self.vm_config.track_dirty_pages = track_dirty_pages;
        }

        Ok(())
    }

    // Repopulate the MmdsConfig based on information from the data store
    // and the associated net devices.
    fn mmds_config(&self) -> Option<MmdsConfig> {
        // If the data store is not initialised, we can be sure that the user did not configure
        // mmds.
        let mmds = self.mmds.as_ref()?;

        let mut mmds_config = None;
        let net_devs_with_mmds: Vec<_> = self
            .net_builder
            .iter()
            .filter(|net| net.lock().expect("Poisoned lock").mmds_ns().is_some())
            .collect();

        if !net_devs_with_mmds.is_empty() {
            let mut inner_mmds_config = MmdsConfig {
                version: mmds.lock().expect("Poisoned lock").version(),
                network_interfaces: vec![],
                ipv4_address: None,
            };

            for net_dev in net_devs_with_mmds {
                let net = net_dev.lock().unwrap();
                inner_mmds_config.network_interfaces.push(net.id().clone());
                // Only need to get one ip address, as they will all be equal.
                if inner_mmds_config.ipv4_address.is_none() {
                    // Safe to unwrap the mmds_ns as the filter() explicitly checks for
                    // its existence.
                    inner_mmds_config.ipv4_address = Some(net.mmds_ns().unwrap().ipv4_addr());
                }
            }

            mmds_config = Some(inner_mmds_config);
        }

        mmds_config
    }

    /// Gets a reference to the boot source configuration.
    pub fn boot_source_config(&self) -> &BootSourceConfig {
        &self.boot_source.config
    }

    /// Gets a reference to the boot source builder.
    pub fn boot_source_builder(&self) -> Option<&BootConfig> {
        self.boot_source.builder.as_ref()
    }

    /// Sets a balloon device to be attached when the VM starts.
    pub fn set_balloon_device(
        &mut self,
        config: BalloonDeviceConfig,
    ) -> Result<BalloonConfigError> {
        // The balloon cannot have a target size greater than the size of
        // the guest memory.
        if config.amount_mib as usize > self.vm_config.mem_size_mib {
            return Err(BalloonConfigError::TooManyPagesRequested);
        }

        self.balloon.set(config)
    }

    /// Obtains the boot source hooks (kernel fd, command line creation and validation).
    pub fn build_boot_source(
        &mut self,
        boot_source_cfg: BootSourceConfig,
    ) -> Result<BootSourceConfigError> {
        self.set_boot_source_config(boot_source_cfg);
        self.boot_source.builder = Some(BootConfig::new(self.boot_source_config())?);
        Ok(())
    }

    /// Set the boot source configuration (contains raw kernel config details).
    pub fn set_boot_source_config(&mut self, boot_source_cfg: BootSourceConfig) {
        self.boot_source.config = boot_source_cfg;
    }

    /// Inserts a block to be attached when the VM starts.
    // Only call this function as part of user configuration.
    // If the drive_id does not exist, a new Block Device Config is added to the list.
    pub fn set_block_device(
        &mut self,
        block_device_config: BlockDeviceConfig,
    ) -> Result<DriveError> {
        self.block.insert(block_device_config)
    }

    /// Builds a network device to be attached when the VM starts.
    pub fn build_net_device(
        &mut self,
        body: NetworkInterfaceConfig,
    ) -> Result<NetworkInterfaceError> {
        let _ = self.net_builder.build(body)?;
        Ok(())
    }

    /// Sets a vsock device to be attached when the VM starts.
    pub fn set_vsock_device(&mut self, config: VsockDeviceConfig) -> Result<VsockConfigError> {
        self.vsock.insert(config)
    }

    /// Setter for mmds config.
    pub fn set_mmds_config(
        &mut self,
        config: MmdsConfig,
        instance_id: &str,
    ) -> Result<MmdsConfigError> {
        self.set_mmds_network_stack_config(&config)?;
        self.set_mmds_version(config.version, instance_id)?;

        Ok(())
    }

    /// Updates MMDS version.
    pub fn set_mmds_version(
        &mut self,
        version: MmdsVersion,
        instance_id: &str,
    ) -> Result<MmdsConfigError> {
        let mut mmds_guard = self.locked_mmds_or_default();
        mmds_guard
            .set_version(version)
            .map_err(|err| MmdsConfigError::MmdsVersion(version, err))?;
        mmds_guard.set_aad(instance_id);

        Ok(())
    }

    // Updates MMDS Network Stack for network interfaces to allow forwarding
    // requests to MMDS (or not).
    fn set_mmds_network_stack_config(&mut self, config: &MmdsConfig) -> Result<MmdsConfigError> {
        // Check IPv4 address validity.
        let ipv4_addr = match config.ipv4_addr() {
            Some(ipv4_addr) if is_link_local_valid(ipv4_addr) => Ok(ipv4_addr),
            None => Ok(MmdsNetworkStack::default_ipv4_addr()),
            _ => Err(MmdsConfigError::InvalidIpv4Addr),
        }?;

        let network_interfaces = config.network_interfaces();
        // Ensure that at least one network ID is specified.
        if network_interfaces.is_empty() {
            return Err(MmdsConfigError::EmptyNetworkIfaceList);
        }

        // Ensure all interface IDs specified correspond to existing net devices.
        if !network_interfaces.iter().all(|id| {
            self.net_builder
                .iter()
                .map(|device| device.lock().expect("Poisoned lock").id().clone())
                .any(|x| &x == id)
        }) {
            return Err(MmdsConfigError::InvalidNetworkInterfaceId);
        }

        // Safe to unwrap because we've just made sure that it's initialised.
        let mmds = self.mmds_or_default().clone();

        // Create `MmdsNetworkStack` and configure the IPv4 address for
        // existing built network devices whose names are defined in the
        // network interface ID list.
        for net_device in self.net_builder.iter_mut() {
            let mut net_device_lock = net_device.lock().expect("Poisoned lock");
            if network_interfaces.contains(net_device_lock.id()) {
                net_device_lock.configure_mmds_network_stack(ipv4_addr, mmds.clone());
            } else {
                net_device_lock.disable_mmds_network_stack();
            }
        }

        Ok(())
    }
}

impl From<&VmResources> for VmmConfig {
    fn from(resources: &VmResources) -> Self {
        VmmConfig {
            balloon_device: resources.balloon.get_config().ok(),
            block_devices: resources.block.configs(),
            boot_source: resources.boot_source_config().clone(),
            logger: None,
            machine_config: Some(resources.vm_config.clone()),
            metrics: None,
            mmds_config: resources.mmds_config(),
            net_devices: resources.net_builder.configs(),
            vsock_device: resources.vsock.config(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::linux::fs::MetadataExt;

    use devices::virtio::vsock::{VsockError, VSOCK_DEV_ID};
    use logger::{LevelFilter, LOGGER};
    use serde_json::{Map, Value};
    use utils::net::mac::MacAddr;
    use utils::tempfile::TempFile;

    use super::*;
    use crate::resources::VmResources;
    use crate::vmm_config::boot_source::{
        BootConfig, BootSource, BootSourceConfig, DEFAULT_KERNEL_CMDLINE,
    };
    use crate::vmm_config::drive::{BlockBuilder, BlockDeviceConfig, FileEngineType};
    use crate::vmm_config::machine_config::{CpuFeaturesTemplate, VmConfig, VmConfigError};
    use crate::vmm_config::net::{NetBuilder, NetworkInterfaceConfig};
    use crate::vmm_config::vsock::tests::default_config;
    use crate::vmm_config::RateLimiterConfig;
    use crate::vstate::vcpu::VcpuConfig;
    use crate::HTTP_MAX_PAYLOAD_SIZE;

    fn default_net_cfg() -> NetworkInterfaceConfig {
        NetworkInterfaceConfig {
            iface_id: "net_if1".to_string(),
            // TempFile::new_with_prefix("") generates a random file name used as random net_if
            // name.
            host_dev_name: TempFile::new_with_prefix("")
                .unwrap()
                .as_path()
                .to_str()
                .unwrap()
                .to_string(),
            guest_mac: Some(MacAddr::parse_str("01:23:45:67:89:0a").unwrap()),
            rx_rate_limiter: Some(RateLimiterConfig::default()),
            tx_rate_limiter: Some(RateLimiterConfig::default()),
        }
    }

    fn default_net_builder() -> NetBuilder {
        let mut net_builder = NetBuilder::new();
        net_builder.build(default_net_cfg()).unwrap();

        net_builder
    }

    fn default_block_cfg() -> (BlockDeviceConfig, TempFile) {
        let tmp_file = TempFile::new().unwrap();
        (
            BlockDeviceConfig {
                drive_id: "block1".to_string(),
                path_on_host: tmp_file.as_path().to_str().unwrap().to_string(),
                is_root_device: false,
                partuuid: Some("0eaa91a0-01".to_string()),
                cache_type: CacheType::Unsafe,
                is_read_only: false,
                rate_limiter: Some(RateLimiterConfig::default()),
                file_engine_type: FileEngineType::default(),
            },
            tmp_file,
        )
    }

    fn default_blocks() -> BlockBuilder {
        let mut blocks = BlockBuilder::new();
        let (cfg, _file) = default_block_cfg();
        blocks.insert(cfg).unwrap();
        blocks
    }

    fn default_boot_cfg() -> BootSource {
        let kernel_cmdline =
            linux_loader::cmdline::Cmdline::try_from(DEFAULT_KERNEL_CMDLINE, 4096).unwrap();
        let tmp_file = TempFile::new().unwrap();
        BootSource {
            config: BootSourceConfig::default(),
            builder: Some(BootConfig {
                cmdline: kernel_cmdline,
                kernel_file: File::open(tmp_file.as_path()).unwrap(),
                initrd_file: Some(File::open(tmp_file.as_path()).unwrap()),
            }),
        }
    }

    fn default_vm_resources() -> VmResources {
        VmResources {
            vm_config: VmConfig::default(),
            boot_source: default_boot_cfg(),
            block: default_blocks(),
            vsock: Default::default(),
            balloon: Default::default(),
            net_builder: default_net_builder(),
            mmds: None,
            boot_timer: false,
            mmds_size_limit: HTTP_MAX_PAYLOAD_SIZE,
            memory_backend: None,
        }
    }

    impl PartialEq for BootConfig {
        fn eq(&self, other: &Self) -> bool {
            self.cmdline.eq(&other.cmdline)
                && self.kernel_file.metadata().unwrap().st_ino()
                    == other.kernel_file.metadata().unwrap().st_ino()
                && self
                    .initrd_file
                    .as_ref()
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .st_ino()
                    == other
                        .initrd_file
                        .as_ref()
                        .unwrap()
                        .metadata()
                        .unwrap()
                        .st_ino()
        }
    }

    #[test]
    fn test_from_json() {
        let kernel_file = TempFile::new().unwrap();
        let rootfs_file = TempFile::new().unwrap();
        let default_instance_info = InstanceInfo::default();

        // We will test different scenarios with invalid resources configuration and
        // check the expected errors. We include configuration for the kernel and rootfs
        // in every json because they are mandatory fields. If we don't configure
        // these resources, it is considered an invalid json and the test will crash.

        // Invalid JSON string must yield a `serde_json` error.
        match VmResources::from_json(r#"}"#, &default_instance_info, HTTP_MAX_PAYLOAD_SIZE, None) {
            Err(Error::InvalidJson(_)) => (),
            _ => unreachable!(),
        }

        // Valid JSON string without the configuration for kernel or rootfs
        // result in an invalid JSON error.
        match VmResources::from_json(r#"{}"#, &default_instance_info, HTTP_MAX_PAYLOAD_SIZE, None) {
            Err(Error::InvalidJson(_)) => (),
            _ => unreachable!(),
        }

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
            rootfs_file.as_path().to_str().unwrap()
        );

        match VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        ) {
            Err(Error::BootSource(BootSourceConfigError::InvalidKernelPath(_))) => (),
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
            kernel_file.as_path().to_str().unwrap()
        );

        match VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        ) {
            Err(Error::BlockDevice(DriveError::InvalidBlockDevicePath(_))) => (),
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
                        "mem_size_mib": 1024
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        match VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        ) {
            Err(Error::InvalidJson(_)) => (),
            _ => unreachable!(),
        }

        // Valid config for x86 but invalid on aarch64 because smt is not available.
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
                        "mem_size_mib": 1024,
                        "smt": true
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        #[cfg(target_arch = "x86_64")]
        assert!(VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None
        )
        .is_ok());
        #[cfg(target_arch = "aarch64")]
        assert!(VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None
        )
        .is_err());

        // Valid config for x86 but invalid on aarch64 since it uses cpu_template.
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
                        "mem_size_mib": 1024,
                        "cpu_template": "C3"
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );
        #[cfg(target_arch = "x86_64")]
        assert!(VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None
        )
        .is_ok());
        #[cfg(target_arch = "aarch64")]
        assert!(VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None
        )
        .is_err());

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
                        "mem_size_mib": 0
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        match VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        ) {
            Err(Error::VmConfig(VmConfigError::InvalidMemorySize)) => (),
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
	                    "log_path": "/invalid/path"
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        match VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        ) {
            Err(Error::Logger(LoggerConfigError::InitializationFailure { .. })) => (),
            _ => unreachable!(),
        }

        // The previous call enables the logger. We need to disable it.
        LOGGER.set_max_level(LevelFilter::Off);

        // Invalid path for metrics pipe.
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
                    "metrics": {{
	                    "metrics_path": "/invalid/path"
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        match VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        ) {
            Err(Error::Metrics(MetricsConfigError::InitializationFailure { .. })) => (),
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
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        match VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        ) {
            Err(Error::NetDevice(NetworkInterfaceError::CreateNetworkDevice(
                devices::virtio::net::Error::TapOpen { .. },
            ))) => (),
            _ => unreachable!(),
        }

        // Let's try now passing a valid configuration. We won't include any logger
        // or metrics configuration because these were already initialized in other
        // tests of this module and the reinitialization of them will cause crashing.
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
                        "smt": false
                    }},
                    "mmds-config": {{
                        "version": "V2",
                        "ipv4_address": "169.254.170.2",
                        "network_interfaces": ["netif"]
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap(),
        );
        assert!(VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None
        )
        .is_ok());

        // Test all configuration, this time trying to set default configuration
        // for version and IPv4 address.
        let kernel_file = TempFile::new().unwrap();
        json = format!(
            r#"{{
                    "balloon": {{
                        "amount_mib": 0,
                        "deflate_on_oom": false,
                        "stats_polling_interval_s": 0
                    }},
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
                            "host_dev_name": "hostname9"
                        }}
                    ],
                    "machine-config": {{
                        "vcpu_count": 2,
                        "mem_size_mib": 1024,
                        "smt": false
                    }},
                    "mmds-config": {{
                        "network_interfaces": ["netif"],
                        "ipv4_address": "169.254.1.1"
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap(),
        );
        let resources = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            1200,
            Some(r#"{"key": "value"}"#),
        )
        .unwrap();
        let mut map = Map::new();
        map.insert("key".to_string(), Value::String("value".to_string()));
        assert_eq!(
            resources.mmds.unwrap().lock().unwrap().data_store_value(),
            Value::Object(map)
        );
    }

    #[test]
    fn test_cast_to_vmm_config() {
        // No mmds config.
        {
            let kernel_file = TempFile::new().unwrap();
            let rootfs_file = TempFile::new().unwrap();
            let json = format!(
                r#"{{
                    "balloon": {{
                        "amount_mib": 0,
                        "deflate_on_oom": false,
                        "stats_polling_interval_s": 0
                    }},
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
                            "host_dev_name": "hostname9"
                        }},
                        {{
                            "iface_id": "netif2",
                            "host_dev_name": "hostname10"
                        }}
                    ],
                    "machine-config": {{
                        "vcpu_count": 2,
                        "mem_size_mib": 1024,
                        "smt": false
                    }}
            }}"#,
                kernel_file.as_path().to_str().unwrap(),
                rootfs_file.as_path().to_str().unwrap(),
            );

            {
                let resources = VmResources::from_json(
                    json.as_str(),
                    &InstanceInfo::default(),
                    HTTP_MAX_PAYLOAD_SIZE,
                    None,
                )
                .unwrap();

                let initial_vmm_config =
                    serde_json::from_slice::<VmmConfig>(json.as_bytes()).unwrap();
                let vmm_config: VmmConfig = (&resources).into();
                assert_eq!(initial_vmm_config, vmm_config);
            }

            {
                // In this case the mmds data store will be initialised but the config still None.
                let resources = VmResources::from_json(
                    json.as_str(),
                    &InstanceInfo::default(),
                    HTTP_MAX_PAYLOAD_SIZE,
                    Some(r#"{"key": "value"}"#),
                )
                .unwrap();

                let initial_vmm_config =
                    serde_json::from_slice::<VmmConfig>(json.as_bytes()).unwrap();
                let vmm_config: VmmConfig = (&resources).into();
                assert_eq!(initial_vmm_config, vmm_config);
            }
        }

        // Single interface for MMDS.
        {
            let kernel_file = TempFile::new().unwrap();
            let rootfs_file = TempFile::new().unwrap();
            let json = format!(
                r#"{{
                    "balloon": {{
                        "amount_mib": 0,
                        "deflate_on_oom": false,
                        "stats_polling_interval_s": 0
                    }},
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
                            "host_dev_name": "hostname9"
                        }},
                        {{
                            "iface_id": "netif2",
                            "host_dev_name": "hostname10"
                        }}
                    ],
                    "machine-config": {{
                        "vcpu_count": 2,
                        "mem_size_mib": 1024,
                        "smt": false
                    }},
                    "mmds-config": {{
                        "network_interfaces": ["netif1"],
                        "ipv4_address": "169.254.1.1"
                    }}
            }}"#,
                kernel_file.as_path().to_str().unwrap(),
                rootfs_file.as_path().to_str().unwrap(),
            );
            let resources = VmResources::from_json(
                json.as_str(),
                &InstanceInfo::default(),
                HTTP_MAX_PAYLOAD_SIZE,
                None,
            )
            .unwrap();

            let initial_vmm_config = serde_json::from_slice::<VmmConfig>(json.as_bytes()).unwrap();
            let vmm_config: VmmConfig = (&resources).into();
            assert_eq!(initial_vmm_config, vmm_config);
        }

        // Multiple interfaces configured for MMDS.
        {
            let kernel_file = TempFile::new().unwrap();
            let rootfs_file = TempFile::new().unwrap();
            let json = format!(
                r#"{{
                    "balloon": {{
                        "amount_mib": 0,
                        "deflate_on_oom": false,
                        "stats_polling_interval_s": 0
                    }},
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
                            "host_dev_name": "hostname9"
                        }},
                        {{
                            "iface_id": "netif2",
                            "host_dev_name": "hostname10"
                        }}
                    ],
                    "machine-config": {{
                        "vcpu_count": 2,
                        "mem_size_mib": 1024,
                        "smt": false
                    }},
                    "mmds-config": {{
                        "network_interfaces": ["netif1", "netif2"],
                        "ipv4_address": "169.254.1.1"
                    }}
            }}"#,
                kernel_file.as_path().to_str().unwrap(),
                rootfs_file.as_path().to_str().unwrap(),
            );
            let resources = VmResources::from_json(
                json.as_str(),
                &InstanceInfo::default(),
                HTTP_MAX_PAYLOAD_SIZE,
                None,
            )
            .unwrap();

            let initial_vmm_config = serde_json::from_slice::<VmmConfig>(json.as_bytes()).unwrap();
            let vmm_config: VmmConfig = (&resources).into();
            assert_eq!(initial_vmm_config, vmm_config);
        }
    }

    #[test]
    fn test_vcpu_config() {
        let vm_resources = default_vm_resources();
        let expected_vcpu_config = VcpuConfig {
            vcpu_count: vm_resources.vm_config().vcpu_count,
            smt: vm_resources.vm_config().smt,
            cpu_template: vm_resources.vm_config().cpu_template,
        };

        let vcpu_config = vm_resources.vcpu_config();
        assert_eq!(vcpu_config, expected_vcpu_config);
    }

    #[test]
    fn test_vm_config() {
        let vm_resources = default_vm_resources();
        let expected_vm_cfg = VmConfig::default();

        assert_eq!(vm_resources.vm_config(), &expected_vm_cfg);
    }

    #[test]
    fn test_update_vm_config() {
        let mut vm_resources = default_vm_resources();
        let mut aux_vm_config = VmUpdateConfig {
            vcpu_count: Some(32),
            mem_size_mib: Some(512),
            smt: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
            track_dirty_pages: Some(false),
        };

        assert_ne!(
            VmUpdateConfig::from(vm_resources.vm_config.clone()),
            aux_vm_config
        );
        vm_resources.update_vm_config(&aux_vm_config).unwrap();
        assert_eq!(
            VmUpdateConfig::from(vm_resources.vm_config.clone()),
            aux_vm_config
        );

        // Invalid vcpu count.
        aux_vm_config.vcpu_count = Some(0);
        assert_eq!(
            vm_resources.update_vm_config(&aux_vm_config),
            Err(VmConfigError::InvalidVcpuCount)
        );
        aux_vm_config.vcpu_count = Some(33);
        assert_eq!(
            vm_resources.update_vm_config(&aux_vm_config),
            Err(VmConfigError::InvalidVcpuCount)
        );
        aux_vm_config.vcpu_count = Some(32);

        // Invalid mem_size_mib.
        aux_vm_config.mem_size_mib = Some(0);
        assert_eq!(
            vm_resources.update_vm_config(&aux_vm_config),
            Err(VmConfigError::InvalidMemorySize)
        );

        // Incompatible mem_size_mib with balloon size.
        vm_resources.vm_config.mem_size_mib = 128;
        vm_resources
            .set_balloon_device(BalloonDeviceConfig {
                amount_mib: 100,
                deflate_on_oom: false,
                stats_polling_interval_s: 0,
            })
            .unwrap();
        aux_vm_config.mem_size_mib = Some(90);
        assert_eq!(
            vm_resources.update_vm_config(&aux_vm_config),
            Err(VmConfigError::IncompatibleBalloonSize)
        );

        // mem_size_mib compatible with balloon size.
        aux_vm_config.mem_size_mib = Some(256);
        assert!(vm_resources.update_vm_config(&aux_vm_config).is_ok());
    }

    #[test]
    fn test_set_balloon_device() {
        let mut vm_resources = default_vm_resources();
        vm_resources.balloon = BalloonBuilder::new();
        let mut new_balloon_cfg = BalloonDeviceConfig {
            amount_mib: 100,
            deflate_on_oom: false,
            stats_polling_interval_s: 0,
        };
        assert!(vm_resources.balloon.get().is_none());
        vm_resources
            .set_balloon_device(new_balloon_cfg.clone())
            .unwrap();

        let actual_balloon_cfg = vm_resources.balloon.get_config().unwrap();
        assert_eq!(actual_balloon_cfg.amount_mib, new_balloon_cfg.amount_mib);
        assert_eq!(
            actual_balloon_cfg.deflate_on_oom,
            new_balloon_cfg.deflate_on_oom
        );
        assert_eq!(
            actual_balloon_cfg.stats_polling_interval_s,
            new_balloon_cfg.stats_polling_interval_s
        );

        let mut vm_resources = default_vm_resources();
        vm_resources.balloon = BalloonBuilder::new();
        new_balloon_cfg.amount_mib = 256;
        assert!(vm_resources.set_balloon_device(new_balloon_cfg).is_err());
    }

    #[test]
    fn test_boot_config() {
        let vm_resources = default_vm_resources();
        let expected_boot_cfg = vm_resources.boot_source.builder.as_ref().unwrap();
        let actual_boot_cfg = vm_resources.boot_source_builder().unwrap();

        assert!(actual_boot_cfg == expected_boot_cfg);
    }

    #[test]
    fn test_set_boot_source() {
        let tmp_file = TempFile::new().unwrap();
        let cmdline = "reboot=k panic=1 pci=off nomodules 8250.nr_uarts=0";
        let expected_boot_cfg = BootSourceConfig {
            kernel_image_path: String::from(tmp_file.as_path().to_str().unwrap()),
            initrd_path: Some(String::from(tmp_file.as_path().to_str().unwrap())),
            boot_args: Some(cmdline.to_string()),
        };

        let mut vm_resources = default_vm_resources();
        let boot_builder = vm_resources.boot_source_builder().unwrap();
        let tmp_ino = tmp_file.as_file().metadata().unwrap().st_ino();

        assert_ne!(
            boot_builder
                .cmdline
                .as_cstring()
                .unwrap()
                .as_bytes_with_nul(),
            [cmdline.as_bytes(), &[b'\0']].concat()
        );
        assert_ne!(
            boot_builder.kernel_file.metadata().unwrap().st_ino(),
            tmp_ino
        );
        assert_ne!(
            boot_builder
                .initrd_file
                .as_ref()
                .unwrap()
                .metadata()
                .unwrap()
                .st_ino(),
            tmp_ino
        );

        vm_resources.build_boot_source(expected_boot_cfg).unwrap();
        let boot_source_builder = vm_resources.boot_source_builder().unwrap();
        assert_eq!(
            boot_source_builder
                .cmdline
                .as_cstring()
                .unwrap()
                .as_bytes_with_nul(),
            [cmdline.as_bytes(), &[b'\0']].concat()
        );
        assert_eq!(
            boot_source_builder.kernel_file.metadata().unwrap().st_ino(),
            tmp_ino
        );
        assert_eq!(
            boot_source_builder
                .initrd_file
                .as_ref()
                .unwrap()
                .metadata()
                .unwrap()
                .st_ino(),
            tmp_ino
        );
    }

    #[test]
    fn test_set_block_device() {
        let mut vm_resources = default_vm_resources();
        let (mut new_block_device_cfg, _file) = default_block_cfg();
        let tmp_file = TempFile::new().unwrap();
        new_block_device_cfg.drive_id = "block2".to_string();
        new_block_device_cfg.path_on_host = tmp_file.as_path().to_str().unwrap().to_string();
        assert_eq!(vm_resources.block.list.len(), 1);
        vm_resources.set_block_device(new_block_device_cfg).unwrap();
        assert_eq!(vm_resources.block.list.len(), 2);
    }

    #[test]
    fn test_set_vsock_device() {
        let mut vm_resources = default_vm_resources();
        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        let new_vsock_cfg = default_config(&tmp_sock_file);
        assert!(vm_resources.vsock.get().is_none());
        vm_resources.set_vsock_device(new_vsock_cfg).unwrap();
        let actual_vsock_cfg = vm_resources.vsock.get().unwrap();
        assert_eq!(actual_vsock_cfg.lock().unwrap().id(), VSOCK_DEV_ID);
    }

    #[test]
    fn test_set_net_device() {
        let mut vm_resources = default_vm_resources();

        // Clone the existing net config in order to obtain a new one.
        let mut new_net_device_cfg = default_net_cfg();
        new_net_device_cfg.iface_id = "new_net_if".to_string();
        new_net_device_cfg.guest_mac = Some(MacAddr::parse_str("01:23:45:67:89:0c").unwrap());
        new_net_device_cfg.host_dev_name = "dummy_path2".to_string();
        assert_eq!(vm_resources.net_builder.len(), 1);

        vm_resources.build_net_device(new_net_device_cfg).unwrap();
        assert_eq!(vm_resources.net_builder.len(), 2);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!(
                "{}",
                Error::BalloonDevice(BalloonConfigError::DeviceNotActive)
            ),
            format!(
                "Balloon device error: {}",
                BalloonConfigError::DeviceNotActive
            )
        );
        assert_eq!(
            format!(
                "{}",
                Error::BlockDevice(DriveError::InvalidBlockDevicePath(String::from("path")))
            ),
            format!(
                "Block device error: {}",
                DriveError::InvalidBlockDevicePath(String::from("path"))
            )
        );
        assert_eq!(
            format!(
                "{}",
                Error::BootSource(BootSourceConfigError::InvalidKernelPath(
                    std::io::Error::from_raw_os_error(21)
                ))
            ),
            format!(
                "Boot source error: {}",
                BootSourceConfigError::InvalidKernelPath(std::io::Error::from_raw_os_error(21))
            )
        );
        assert_eq!(
            format!(
                "{}",
                Error::InvalidJson(serde_json::Error::io(std::io::Error::from_raw_os_error(21)))
            ),
            format!(
                "Invalid JSON: {}",
                serde_json::Error::io(std::io::Error::from_raw_os_error(21))
            )
        );
        assert_eq!(
            format!(
                "{}",
                Error::Logger(LoggerConfigError::InitializationFailure(
                    "error message".to_string()
                ))
            ),
            format!(
                "Logger error: {}",
                LoggerConfigError::InitializationFailure("error message".to_string())
            )
        );
        assert_eq!(
            format!(
                "{}",
                Error::Metrics(MetricsConfigError::InitializationFailure(
                    "error message".to_string()
                ))
            ),
            format!(
                "Metrics error: {}",
                MetricsConfigError::InitializationFailure("error message".to_string())
            )
        );
        assert_eq!(
            format!("{}", Error::MmdsConfig(MmdsConfigError::InvalidIpv4Addr)),
            format!("MMDS config error: {}", MmdsConfigError::InvalidIpv4Addr)
        );
        assert_eq!(
            format!(
                "{}",
                Error::NetDevice(NetworkInterfaceError::GuestMacAddressInUse(
                    "MAC".to_string()
                ))
            ),
            format!(
                "Network device error: {}",
                NetworkInterfaceError::GuestMacAddressInUse("MAC".to_string())
            )
        );
        assert_eq!(
            format!("{}", Error::VmConfig(VmConfigError::InvalidMemorySize)),
            format!("VM config error: {}", VmConfigError::InvalidMemorySize)
        );
        assert_eq!(
            format!(
                "{}",
                Error::VsockDevice(VsockConfigError::CreateVsockDevice(
                    VsockError::BufDescTooSmall
                ))
            ),
            format!(
                "Vsock device error: {}",
                VsockConfigError::CreateVsockDevice(VsockError::BufDescTooSmall)
            )
        );
    }
}
