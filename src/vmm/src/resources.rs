// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::From;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use utils::net::ipv4addr::is_link_local_valid;

use crate::cpu_config::templates::CustomCpuTemplate;
use crate::device_manager::persist::SharedDeviceType;
use crate::logger::{info, log_dev_preview_warning};
use crate::mmds;
use crate::mmds::data_store::{Mmds, MmdsVersion};
use crate::mmds::ns::MmdsNetworkStack;
use crate::vmm_config::balloon::*;
use crate::vmm_config::boot_source::{
    BootConfig, BootSource, BootSourceConfig, BootSourceConfigError,
};
use crate::vmm_config::drive::*;
use crate::vmm_config::entropy::*;
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::{
    HugePageConfig, MachineConfig, MachineConfigUpdate, VmConfig, VmConfigError,
};
use crate::vmm_config::metrics::{init_metrics, MetricsConfig, MetricsConfigError};
use crate::vmm_config::mmds::{MmdsConfig, MmdsConfigError};
use crate::vmm_config::net::*;
use crate::vmm_config::vsock::*;

/// Errors encountered when configuring microVM resources.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ResourcesError {
    /// Balloon device error: {0}
    BalloonDevice(#[from] BalloonConfigError),
    /// Block device error: {0}
    BlockDevice(#[from] DriveError),
    /// Boot source error: {0}
    BootSource(#[from] BootSourceConfigError),
    /// File operation error: {0}
    File(#[from] std::io::Error),
    /// Invalid JSON: {0}
    InvalidJson(#[from] serde_json::Error),
    /// Logger error: {0}
    Logger(#[from] crate::logger::LoggerUpdateError),
    /// Metrics error: {0}
    Metrics(#[from] MetricsConfigError),
    /// MMDS error: {0}
    Mmds(#[from] mmds::data_store::MmdsDatastoreError),
    /// MMDS config error: {0}
    MmdsConfig(#[from] MmdsConfigError),
    /// Network device error: {0}
    NetDevice(#[from] NetworkInterfaceError),
    /// VM config error: {0}
    VmConfig(#[from] VmConfigError),
    /// Vsock device error: {0}
    VsockDevice(#[from] VsockConfigError),
    /// Entropy device error: {0}
    EntropyDevice(#[from] EntropyDeviceError),
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
    #[serde(rename = "cpu-config")]
    cpu_config: Option<PathBuf>,
    #[serde(rename = "logger")]
    logger: Option<crate::logger::LoggerConfig>,
    #[serde(rename = "machine-config")]
    machine_config: Option<MachineConfig>,
    #[serde(rename = "metrics")]
    metrics: Option<MetricsConfig>,
    #[serde(rename = "mmds-config")]
    mmds_config: Option<MmdsConfig>,
    #[serde(rename = "network-interfaces", default)]
    net_devices: Vec<NetworkInterfaceConfig>,
    #[serde(rename = "vsock")]
    vsock_device: Option<VsockDeviceConfig>,
    #[serde(rename = "entropy")]
    entropy_device: Option<EntropyDeviceConfig>,
}

/// A data structure that encapsulates the device configurations
/// held in the Vmm.
#[derive(Debug, Default)]
pub struct VmResources {
    /// The vCpu and memory configuration for this microVM.
    pub vm_config: VmConfig,
    /// The boot source spec (contains both config and builder) for this microVM.
    pub boot_source: BootSource,
    /// The block devices.
    pub block: BlockBuilder,
    /// The vsock device.
    pub vsock: VsockBuilder,
    /// The balloon device.
    pub balloon: BalloonBuilder,
    /// The network devices builder.
    pub net_builder: NetBuilder,
    /// The entropy device builder.
    pub entropy: EntropyDeviceBuilder,
    /// The optional Mmds data store.
    // This is initialised on demand (if ever used), so that we don't allocate it unless it's
    // actually used.
    pub mmds: Option<Arc<Mutex<Mmds>>>,
    /// Data store limit for the mmds.
    pub mmds_size_limit: usize,
    /// Whether or not to load boot timer device.
    pub boot_timer: bool,
}

impl VmResources {
    /// Configures Vmm resources as described by the `config_json` param.
    pub fn from_json(
        config_json: &str,
        instance_info: &InstanceInfo,
        mmds_size_limit: usize,
        metadata_json: Option<&str>,
    ) -> Result<Self, ResourcesError> {
        let vmm_config = serde_json::from_str::<VmmConfig>(config_json)?;

        if let Some(logger_config) = vmm_config.logger {
            crate::logger::LOGGER.update(logger_config)?;
        }

        if let Some(metrics) = vmm_config.metrics {
            init_metrics(metrics)?;
        }

        let mut resources: Self = Self {
            mmds_size_limit,
            ..Default::default()
        };
        if let Some(machine_config) = vmm_config.machine_config {
            let machine_config = MachineConfigUpdate::from(machine_config);
            resources.update_vm_config(&machine_config)?;
        }

        if let Some(cpu_config) = vmm_config.cpu_config {
            let cpu_config_json =
                std::fs::read_to_string(cpu_config).map_err(ResourcesError::File)?;
            let cpu_template = CustomCpuTemplate::try_from(cpu_config_json.as_str())?;
            resources.set_custom_cpu_template(cpu_template);
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

        if let Some(entropy_device_config) = vmm_config.entropy_device {
            resources.build_entropy_device(entropy_device_config)?;
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
    pub fn update_from_restored_device(
        &mut self,
        device: SharedDeviceType,
    ) -> Result<(), ResourcesError> {
        match device {
            SharedDeviceType::VirtioBlock(block) => {
                self.block.add_virtio_device(block);
            }

            SharedDeviceType::Network(network) => {
                self.net_builder.add_device(network);
            }

            SharedDeviceType::Balloon(balloon) => {
                self.balloon.set_device(balloon);

                if self.vm_config.huge_pages != HugePageConfig::None {
                    return Err(ResourcesError::BalloonDevice(BalloonConfigError::HugePages));
                }
            }

            SharedDeviceType::Vsock(vsock) => {
                self.vsock.set_device(vsock);
            }
            SharedDeviceType::Entropy(entropy) => {
                self.entropy.set_device(entropy);
            }
        }

        Ok(())
    }

    /// Returns whether dirty page tracking is enabled or not.
    pub fn track_dirty_pages(&self) -> bool {
        self.vm_config.track_dirty_pages
    }

    /// Add a custom CPU template to the VM resources
    /// to configure vCPUs.
    pub fn set_custom_cpu_template(&mut self, cpu_template: CustomCpuTemplate) {
        self.vm_config.set_custom_cpu_template(cpu_template);
    }

    /// Updates the configuration of the microVM.
    pub fn update_vm_config(&mut self, update: &MachineConfigUpdate) -> Result<(), VmConfigError> {
        if update.huge_pages.is_some() && update.huge_pages != Some(HugePageConfig::None) {
            log_dev_preview_warning("Huge pages support", None);
        }

        let updated = self.vm_config.update(update)?;

        // The VM cannot have a memory size smaller than the target size
        // of the balloon device, if present.
        if self.balloon.get().is_some()
            && updated.mem_size_mib
                < self
                    .balloon
                    .get_config()
                    .map_err(|_| VmConfigError::InvalidVmState)?
                    .amount_mib as usize
        {
            return Err(VmConfigError::IncompatibleBalloonSize);
        }

        if self.balloon.get().is_some() && updated.huge_pages != HugePageConfig::None {
            return Err(VmConfigError::BalloonAndHugePages);
        }

        if self.boot_source.config.initrd_path.is_some()
            && updated.huge_pages != HugePageConfig::None
        {
            return Err(VmConfigError::InitrdAndHugePages);
        }

        self.vm_config = updated;

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
    ) -> Result<(), BalloonConfigError> {
        // The balloon cannot have a target size greater than the size of
        // the guest memory.
        if config.amount_mib as usize > self.vm_config.mem_size_mib {
            return Err(BalloonConfigError::TooManyPagesRequested);
        }

        if self.vm_config.huge_pages != HugePageConfig::None {
            return Err(BalloonConfigError::HugePages);
        }

        self.balloon.set(config)
    }

    /// Obtains the boot source hooks (kernel fd, command line creation and validation).
    pub fn build_boot_source(
        &mut self,
        boot_source_cfg: BootSourceConfig,
    ) -> Result<(), BootSourceConfigError> {
        if boot_source_cfg.initrd_path.is_some()
            && self.vm_config.huge_pages != HugePageConfig::None
        {
            return Err(BootSourceConfigError::HugePagesAndInitRd);
        }

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
    ) -> Result<(), DriveError> {
        self.block.insert(block_device_config)
    }

    /// Builds a network device to be attached when the VM starts.
    pub fn build_net_device(
        &mut self,
        body: NetworkInterfaceConfig,
    ) -> Result<(), NetworkInterfaceError> {
        let _ = self.net_builder.build(body)?;
        Ok(())
    }

    /// Sets a vsock device to be attached when the VM starts.
    pub fn set_vsock_device(&mut self, config: VsockDeviceConfig) -> Result<(), VsockConfigError> {
        self.vsock.insert(config)
    }

    /// Builds an entropy device to be attached when the VM starts.
    pub fn build_entropy_device(
        &mut self,
        body: EntropyDeviceConfig,
    ) -> Result<(), EntropyDeviceError> {
        self.entropy.insert(body)
    }

    /// Setter for mmds config.
    pub fn set_mmds_config(
        &mut self,
        config: MmdsConfig,
        instance_id: &str,
    ) -> Result<(), MmdsConfigError> {
        self.set_mmds_network_stack_config(&config)?;
        self.set_mmds_version(config.version, instance_id)?;

        Ok(())
    }

    /// Updates MMDS version.
    pub fn set_mmds_version(
        &mut self,
        version: MmdsVersion,
        instance_id: &str,
    ) -> Result<(), MmdsConfigError> {
        let mut mmds_guard = self.locked_mmds_or_default();
        mmds_guard
            .set_version(version)
            .map_err(|err| MmdsConfigError::MmdsVersion(version, err))?;
        mmds_guard.set_aad(instance_id);

        Ok(())
    }

    // Updates MMDS Network Stack for network interfaces to allow forwarding
    // requests to MMDS (or not).
    fn set_mmds_network_stack_config(
        &mut self,
        config: &MmdsConfig,
    ) -> Result<(), MmdsConfigError> {
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
            cpu_config: None,
            logger: None,
            machine_config: Some(MachineConfig::from(&resources.vm_config)),
            metrics: None,
            mmds_config: resources.mmds_config(),
            net_devices: resources.net_builder.configs(),
            vsock_device: resources.vsock.config(),
            entropy_device: resources.entropy.config(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::os::linux::fs::MetadataExt;
    use std::str::FromStr;

    use serde_json::{Map, Value};
    use utils::net::mac::MacAddr;
    use utils::tempfile::TempFile;

    use super::*;
    use crate::cpu_config::templates::{CpuTemplateType, StaticCpuTemplate};
    use crate::devices::virtio::balloon::Balloon;
    use crate::devices::virtio::block::virtio::VirtioBlockError;
    use crate::devices::virtio::block::{BlockError, CacheType};
    use crate::devices::virtio::vsock::VSOCK_DEV_ID;
    use crate::resources::VmResources;
    use crate::vmm_config::boot_source::{
        BootConfig, BootSource, BootSourceConfig, DEFAULT_KERNEL_CMDLINE,
    };
    use crate::vmm_config::drive::{BlockBuilder, BlockDeviceConfig};
    use crate::vmm_config::machine_config::{HugePageConfig, MachineConfig, VmConfigError};
    use crate::vmm_config::net::{NetBuilder, NetworkInterfaceConfig};
    use crate::vmm_config::vsock::tests::default_config;
    use crate::vmm_config::RateLimiterConfig;
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
            guest_mac: Some(MacAddr::from_str("01:23:45:67:89:0a").unwrap()),
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
                partuuid: Some("0eaa91a0-01".to_string()),
                is_root_device: false,
                cache_type: CacheType::Unsafe,

                is_read_only: Some(false),
                path_on_host: Some(tmp_file.as_path().to_str().unwrap().to_string()),
                rate_limiter: Some(RateLimiterConfig::default()),
                file_engine_type: None,

                socket: None,
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
            entropy: Default::default(),
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
        let error =
            VmResources::from_json(r#"}"#, &default_instance_info, HTTP_MAX_PAYLOAD_SIZE, None)
                .unwrap_err();
        assert!(
            matches!(error, ResourcesError::InvalidJson(_)),
            "{:?}",
            error
        );

        // Valid JSON string without the configuration for kernel or rootfs
        // result in an invalid JSON error.
        let error =
            VmResources::from_json(r#"{}"#, &default_instance_info, HTTP_MAX_PAYLOAD_SIZE, None)
                .unwrap_err();
        assert!(
            matches!(error, ResourcesError::InvalidJson(_)),
            "{:?}",
            error
        );

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

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ResourcesError::BootSource(BootSourceConfigError::InvalidKernelPath(_))
            ),
            "{:?}",
            error
        );

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

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ResourcesError::BlockDevice(DriveError::CreateBlockDevice(
                    BlockError::VirtioBackend(VirtioBlockError::BackingFile(_, _)),
                ))
            ),
            "{:?}",
            error
        );
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
        VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap();
        #[cfg(target_arch = "aarch64")]
        VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();

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

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ResourcesError::VmConfig(VmConfigError::InvalidMemorySize)
            ),
            "{:?}",
            error
        );

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

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ResourcesError::Logger(crate::logger::LoggerUpdateError(_))
            ),
            "{:?}",
            error
        );

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

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ResourcesError::Metrics(MetricsConfigError::InitializationFailure { .. })
            ),
            "{:?}",
            error
        );

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

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();

        assert!(
            matches!(
                error,
                ResourcesError::NetDevice(NetworkInterfaceError::CreateNetworkDevice(
                    crate::devices::virtio::net::NetError::TapOpen { .. },
                ))
            ),
            "{:?}",
            error
        );

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
        VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap();

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
    fn test_cpu_config_from_invalid_json() {
        // Invalid cpu config file path.
        // `VmResources::from_json()` should fail with `Error::File`.
        let kernel_file = TempFile::new().unwrap();
        let rootfs_file = TempFile::new().unwrap();
        let default_instance_info = InstanceInfo::default();

        let json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "cpu-config": "/invalid/path",
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ]
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap(),
        );

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, ResourcesError::File(_)), "{:?}", error);
    }

    #[test]
    fn test_cpu_config_from_valid_json() {
        // Valid cpu config file path.
        // `VmResources::from_json()` should succeed and it should have a custom CPU template.
        let kernel_file = TempFile::new().unwrap();
        let rootfs_file = TempFile::new().unwrap();
        let default_instance_info = InstanceInfo::default();
        let cpu_config_file = TempFile::new().unwrap();
        cpu_config_file
            .as_file()
            .write_all("{}".as_bytes())
            .unwrap();

        let json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "cpu-config": "{}",
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ]
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            cpu_config_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap(),
        );

        let vm_resources = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap();
        assert_eq!(
            vm_resources.vm_config.cpu_template,
            Some(CpuTemplateType::Custom(CustomCpuTemplate::default()))
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
                            "is_read_only": false,
                            "io_engine": "Sync"
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
                    "entropy": {{}}
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

                let initial_vmm_config = serde_json::from_str::<VmmConfig>(&json).unwrap();
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

                let initial_vmm_config = serde_json::from_str::<VmmConfig>(&json).unwrap();
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
                            "is_read_only": false,
                            "io_engine": "Sync"
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

            let initial_vmm_config = serde_json::from_str::<VmmConfig>(&json).unwrap();
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
                            "is_read_only": false,
                            "io_engine": "Sync"
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

            let initial_vmm_config = serde_json::from_str::<VmmConfig>(&json).unwrap();
            let vmm_config: VmmConfig = (&resources).into();
            assert_eq!(initial_vmm_config, vmm_config);
        }
    }

    #[test]
    fn test_update_vm_config() {
        let mut vm_resources = default_vm_resources();
        let mut aux_vm_config = MachineConfigUpdate {
            vcpu_count: Some(32),
            mem_size_mib: Some(512),
            smt: Some(false),
            #[cfg(target_arch = "x86_64")]
            cpu_template: Some(StaticCpuTemplate::T2),
            #[cfg(target_arch = "aarch64")]
            cpu_template: Some(StaticCpuTemplate::V1N1),
            track_dirty_pages: Some(false),
            huge_pages: Some(HugePageConfig::None),
        };

        assert_ne!(
            MachineConfigUpdate::from(MachineConfig::from(&vm_resources.vm_config)),
            aux_vm_config
        );
        vm_resources.update_vm_config(&aux_vm_config).unwrap();
        assert_eq!(
            MachineConfigUpdate::from(MachineConfig::from(&vm_resources.vm_config)),
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

        // Check that SMT is not supported on aarch64, and that on x86_64 enabling it requires vcpu
        // count to be even.
        aux_vm_config.smt = Some(true);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(
            vm_resources.update_vm_config(&aux_vm_config),
            Err(VmConfigError::SmtNotSupported)
        );
        aux_vm_config.vcpu_count = Some(3);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            vm_resources.update_vm_config(&aux_vm_config),
            Err(VmConfigError::InvalidVcpuCount)
        );
        aux_vm_config.vcpu_count = Some(32);
        #[cfg(target_arch = "x86_64")]
        vm_resources.update_vm_config(&aux_vm_config).unwrap();
        aux_vm_config.smt = Some(false);

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
        vm_resources.update_vm_config(&aux_vm_config).unwrap();

        // mem_size_mib incompatible with huge pages configuration
        aux_vm_config.mem_size_mib = Some(129);
        aux_vm_config.huge_pages = Some(HugePageConfig::Hugetlbfs2M);
        assert_eq!(
            vm_resources.update_vm_config(&aux_vm_config).unwrap_err(),
            VmConfigError::InvalidMemorySize
        );

        // mem_size_mib compatible with huge page configuration
        aux_vm_config.mem_size_mib = Some(2048);
        // Remove the balloon device config that's added by `default_vm_resources` as it would
        // trigger the "ballooning incompatible with huge pages" check.
        vm_resources.balloon = BalloonBuilder::new();
        vm_resources.update_vm_config(&aux_vm_config).unwrap();
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
        vm_resources
            .set_balloon_device(new_balloon_cfg)
            .unwrap_err();
    }

    #[test]
    fn test_negative_restore_balloon_device_with_huge_pages() {
        let mut vm_resources = default_vm_resources();
        vm_resources.balloon = BalloonBuilder::new();
        vm_resources
            .update_vm_config(&MachineConfigUpdate {
                huge_pages: Some(HugePageConfig::Hugetlbfs2M),
                ..Default::default()
            })
            .unwrap();
        let err = vm_resources
            .update_from_restored_device(SharedDeviceType::Balloon(Arc::new(Mutex::new(
                Balloon::new(128, false, 0, true).unwrap(),
            ))))
            .unwrap_err();
        assert!(
            matches!(
                err,
                ResourcesError::BalloonDevice(BalloonConfigError::HugePages)
            ),
            "{:?}",
            err
        );
    }

    #[test]
    fn test_set_entropy_device() {
        let mut vm_resources = default_vm_resources();
        vm_resources.entropy = EntropyDeviceBuilder::new();
        let entropy_device_cfg = EntropyDeviceConfig::default();

        assert!(vm_resources.entropy.get().is_none());
        vm_resources
            .build_entropy_device(entropy_device_cfg.clone())
            .unwrap();

        let actual_entropy_cfg = vm_resources.entropy.config().unwrap();
        assert_eq!(actual_entropy_cfg, entropy_device_cfg);
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
        let cmdline = "reboot=k panic=1 pci=off nomodule 8250.nr_uarts=0";
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
        new_block_device_cfg.path_on_host = Some(tmp_file.as_path().to_str().unwrap().to_string());
        assert_eq!(vm_resources.block.devices.len(), 1);
        vm_resources.set_block_device(new_block_device_cfg).unwrap();
        assert_eq!(vm_resources.block.devices.len(), 2);
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
        new_net_device_cfg.guest_mac = Some(MacAddr::from_str("01:23:45:67:89:0c").unwrap());
        new_net_device_cfg.host_dev_name = "dummy_path2".to_string();
        assert_eq!(vm_resources.net_builder.len(), 1);

        vm_resources.build_net_device(new_net_device_cfg).unwrap();
        assert_eq!(vm_resources.net_builder.len(), 2);
    }
}
