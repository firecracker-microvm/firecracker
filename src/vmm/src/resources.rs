// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]

use std::fs::{File, OpenOptions};
use std::path::PathBuf;

use vmm_config::boot_source::{
    BootConfig, BootSourceConfig, BootSourceConfigError, DEFAULT_KERNEL_CMDLINE,
};
use vmm_config::drive::*;
use vmm_config::logger::{init_logger, LoggerConfig, LoggerConfigError};
use vmm_config::machine_config::{VmConfig, VmConfigError};
use vmm_config::metrics::{init_metrics, MetricsConfig, MetricsConfigError};
use vmm_config::net::*;
use vmm_config::vsock::*;
use vstate::VcpuConfig;

type Result<E> = std::result::Result<(), E>;

/// Errors encountered when configuring microVM resources.
#[derive(Debug)]
pub enum Error {
    /// JSON is invalid.
    InvalidJson,
    /// Block device configuration error.
    BlockDevice(DriveError),
    /// Net device configuration error.
    NetDevice(NetworkInterfaceError),
    /// Boot source configuration error.
    BootSource(BootSourceConfigError),
    /// Logger configuration error.
    Logger(LoggerConfigError),
    /// Metrics system configuration error.
    Metrics(MetricsConfigError),
    /// microVM vCpus or memory configuration error.
    VmConfig(VmConfigError),
}

/// Used for configuring a vmm from one single json passed to the Firecracker process.
#[derive(Deserialize)]
pub struct VmmConfig {
    #[serde(rename = "boot-source")]
    boot_source: BootSourceConfig,
    #[serde(rename = "drives")]
    block_devices: Vec<BlockDeviceConfig>,
    #[serde(rename = "network-interfaces", default)]
    net_devices: Vec<NetworkInterfaceConfig>,
    #[serde(rename = "logger")]
    logger: Option<LoggerConfig>,
    #[serde(rename = "machine-config")]
    machine_config: Option<VmConfig>,
    #[serde(rename = "metrics")]
    metrics: Option<MetricsConfig>,
    #[serde(rename = "vsock")]
    vsock_device: Option<VsockDeviceConfig>,
}

/// A data structure that encapsulates the device configurations
/// held in the Vmm.
#[derive(Default)]
pub struct VmResources {
    /// The vCpu and memory configuration for this microVM.
    vm_config: VmConfig,
    /// The boot configuration for this microVM.
    boot_config: Option<BootConfig>,
    /// The configurations for block devices.
    pub block: BlockDeviceConfigs,
    /// The configurations for network interface devices.
    pub network_interface: NetworkInterfaceConfigs,
    /// The configurations for vsock devices.
    pub vsock: Option<VsockDeviceConfig>,
}

impl VmResources {
    /// Configures Vmm resources as described by the `config_json` param.
    pub fn from_json(
        config_json: &str,
        firecracker_version: &str,
    ) -> std::result::Result<Self, Error> {
        let vmm_config: VmmConfig = serde_json::from_slice::<VmmConfig>(config_json.as_bytes())
            .map_err(|_| Error::InvalidJson)?;

        if let Some(logger) = vmm_config.logger {
            init_logger(logger, firecracker_version).map_err(Error::Logger)?;
        }

        if let Some(metrics) = vmm_config.metrics {
            init_metrics(metrics).map_err(Error::Metrics)?;
        }

        let mut resources: Self = Self::default();
        if let Some(machine_config) = vmm_config.machine_config {
            resources
                .set_vm_config(&machine_config)
                .map_err(Error::VmConfig)?;
        }
        resources
            .set_boot_source(vmm_config.boot_source)
            .map_err(Error::BootSource)?;
        for drive_config in vmm_config.block_devices.into_iter() {
            resources
                .set_block_device(drive_config)
                .map_err(Error::BlockDevice)?;
        }
        for net_config in vmm_config.net_devices.into_iter() {
            resources
                .set_net_device(net_config)
                .map_err(Error::NetDevice)?;
        }
        if let Some(vsock_config) = vmm_config.vsock_device {
            resources.set_vsock_device(vsock_config);
        }
        Ok(resources)
    }

    /// Returns a VcpuConfig based on the vm config.
    pub fn vcpu_config(&self) -> VcpuConfig {
        // The unwraps are ok to use because the values are initialized using defaults if not
        // supplied by the user.
        VcpuConfig {
            vcpu_count: self.vm_config().vcpu_count.unwrap(),
            ht_enabled: self.vm_config().ht_enabled.unwrap(),
            cpu_template: self.vm_config().cpu_template,
        }
    }

    /// Returns the VmConfig.
    pub fn vm_config(&self) -> &VmConfig {
        &self.vm_config
    }

    /// Set the machine configuration of the microVM.
    pub fn set_vm_config(&mut self, machine_config: &VmConfig) -> Result<VmConfigError> {
        if machine_config.vcpu_count == Some(0) {
            return Err(VmConfigError::InvalidVcpuCount);
        }

        if machine_config.mem_size_mib == Some(0) {
            return Err(VmConfigError::InvalidMemorySize);
        }

        let ht_enabled = machine_config
            .ht_enabled
            .unwrap_or_else(|| self.vm_config.ht_enabled.unwrap());

        let vcpu_count_value = machine_config
            .vcpu_count
            .unwrap_or_else(|| self.vm_config.vcpu_count.unwrap());

        // If hyperthreading is enabled or is to be enabled in this call
        // only allow vcpu count to be 1 or even.
        if ht_enabled && vcpu_count_value > 1 && vcpu_count_value % 2 == 1 {
            return Err(VmConfigError::InvalidVcpuCount);
        }

        // Update all the fields that have a new value.
        self.vm_config.vcpu_count = Some(vcpu_count_value);
        self.vm_config.ht_enabled = Some(ht_enabled);

        if machine_config.mem_size_mib.is_some() {
            self.vm_config.mem_size_mib = machine_config.mem_size_mib;
        }

        if machine_config.cpu_template.is_some() {
            self.vm_config.cpu_template = machine_config.cpu_template;
        }

        Ok(())
    }

    /// Gets a reference to the boot source configuration.
    pub fn boot_source(&self) -> Option<&BootConfig> {
        self.boot_config.as_ref()
    }

    /// Set the guest boot source configuration.
    pub fn set_boot_source(
        &mut self,
        boot_source_cfg: BootSourceConfig,
    ) -> Result<BootSourceConfigError> {
        use self::BootSourceConfigError::{
            InvalidInitrdPath, InvalidKernelCommandLine, InvalidKernelPath,
        };

        // Validate boot source config.
        let kernel_file =
            File::open(&boot_source_cfg.kernel_image_path).map_err(InvalidKernelPath)?;
        let initrd_file: Option<File> = match &boot_source_cfg.initrd_path {
            Some(path) => Some(File::open(path).map_err(InvalidInitrdPath)?),
            None => None,
        };
        let mut cmdline = kernel::cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
        let boot_args = match boot_source_cfg.boot_args.as_ref() {
            None => DEFAULT_KERNEL_CMDLINE,
            Some(str) => str.as_str(),
        };
        cmdline
            .insert_str(boot_args)
            .map_err(|e| InvalidKernelCommandLine(e.to_string()))?;

        self.boot_config = Some(BootConfig {
            cmdline,
            kernel_file,
            initrd_file,
        });
        Ok(())
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

    /// Updates the path of the host file backing the emulated block device with id `drive_id`.
    pub fn update_block_device_path(
        &mut self,
        drive_id: String,
        path_on_host: String,
    ) -> Result<DriveError> {
        // Get the block device configuration specified by drive_id.
        let block_device_index = self
            .block
            .get_index_of_drive_id(&drive_id)
            .ok_or(DriveError::InvalidBlockDeviceID)?;

        let file_path = PathBuf::from(path_on_host);
        // Try to open the file specified by path_on_host using the permissions of the block_device.
        let _ = OpenOptions::new()
            .read(true)
            .write(!self.block.config_list[block_device_index].is_read_only())
            .open(&file_path)
            .map_err(DriveError::CannotOpenBlockDevice)?;

        // Update the path of the block device with the specified path_on_host.
        self.block.config_list[block_device_index].path_on_host = file_path;

        Ok(())
    }

    /// Inserts a network device to be attached when the VM starts.
    pub fn set_net_device(
        &mut self,
        body: NetworkInterfaceConfig,
    ) -> Result<NetworkInterfaceError> {
        self.network_interface.insert(body)
    }

    /// Updates configuration for an emulated net device as described in `new_cfg`.
    pub fn update_net_rate_limiters(
        &mut self,
        new_cfg: NetworkInterfaceUpdateConfig,
    ) -> Result<NetworkInterfaceError> {
        let old_cfg = self
            .network_interface
            .iter_mut()
            .find(|&&mut ref c| c.iface_id == new_cfg.iface_id)
            .ok_or(NetworkInterfaceError::DeviceIdNotFound)?;

        macro_rules! update_rate_limiter {
            ($rate_limiter: ident) => {{
                if let Some(new_rlim_cfg) = new_cfg.$rate_limiter {
                    if let Some(ref mut old_rlim_cfg) = old_cfg.$rate_limiter {
                        // We already have an RX rate limiter set, so we'll update it.
                        old_rlim_cfg.update(&new_rlim_cfg);
                    } else {
                        // No old RX rate limiter; create one now.
                        old_cfg.$rate_limiter = Some(new_rlim_cfg);
                    }
                }
            }};
        }

        update_rate_limiter!(rx_rate_limiter);
        update_rate_limiter!(tx_rate_limiter);
        Ok(())
    }

    /// Sets a vsock device to be attached when the VM starts.
    pub fn set_vsock_device(&mut self, config: VsockDeviceConfig) {
        self.vsock = Some(config);
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::linux::fs::MetadataExt;

    use super::*;
    use dumbo::MacAddr;
    use resources::VmResources;
    use utils::tempfile::TempFile;
    use vmm_config::boot_source::{BootConfig, BootSourceConfig, DEFAULT_KERNEL_CMDLINE};
    use vmm_config::drive::{BlockDeviceConfig, BlockDeviceConfigs, DriveError};
    use vmm_config::machine_config::{CpuFeaturesTemplate, VmConfig, VmConfigError};
    use vmm_config::net::{
        NetworkInterfaceConfig, NetworkInterfaceConfigs, NetworkInterfaceError,
        NetworkInterfaceUpdateConfig,
    };
    use vmm_config::vsock::VsockDeviceConfig;
    use vmm_config::{RateLimiterConfig, TokenBucketConfig};
    use vstate::VcpuConfig;

    fn default_net_cfgs() -> NetworkInterfaceConfigs {
        let mut net_if_cfgs = NetworkInterfaceConfigs::new();
        net_if_cfgs
            .insert(NetworkInterfaceConfig {
                iface_id: "net_if1".to_string(),
                // TempFile::new_with_prefix("") generates a random file name used as random net_if name.
                host_dev_name: TempFile::new_with_prefix("")
                    .unwrap()
                    .as_path()
                    .to_str()
                    .unwrap()
                    .to_string(),
                guest_mac: Some(MacAddr::parse_str("01:23:45:67:89:0a").unwrap()),
                rx_rate_limiter: Some(RateLimiterConfig::default()),
                tx_rate_limiter: Some(RateLimiterConfig::default()),
                allow_mmds_requests: false,
            })
            .unwrap();

        net_if_cfgs
    }

    fn default_block_cfgs() -> BlockDeviceConfigs {
        let mut block_cfgs = BlockDeviceConfigs::new();
        block_cfgs
            .insert(BlockDeviceConfig {
                drive_id: "block1".to_string(),
                path_on_host: TempFile::new().unwrap().as_path().to_path_buf(),
                is_root_device: false,
                partuuid: Some("0eaa91a0-01".to_string()),
                is_read_only: false,
                rate_limiter: Some(RateLimiterConfig::default()),
            })
            .unwrap();

        block_cfgs
    }

    fn default_boot_cfg() -> BootConfig {
        let mut kernel_cmdline = kernel::cmdline::Cmdline::new(4096);
        kernel_cmdline.insert_str(DEFAULT_KERNEL_CMDLINE).unwrap();
        let tmp_file = TempFile::new().unwrap();
        BootConfig {
            cmdline: kernel_cmdline,
            kernel_file: File::open(tmp_file.as_path()).unwrap(),
            initrd_file: Some(File::open(tmp_file.as_path()).unwrap()),
        }
    }

    fn default_vm_resources() -> VmResources {
        VmResources {
            vm_config: VmConfig::default(),
            boot_config: Some(default_boot_cfg()),
            block: default_block_cfgs(),
            network_interface: default_net_cfgs(),
            vsock: None,
        }
    }

    impl PartialEq for BootConfig {
        fn eq(&self, other: &Self) -> bool {
            self.cmdline.as_str().eq(other.cmdline.as_str())
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

        // We will test different scenarios with invalid resources configuration and
        // check the expected errors. We include configuration for the kernel and rootfs
        // in every json because they are mandatory fields. If we don't configure
        // these resources, it is considered an invalid json and the test will crash.

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

        match VmResources::from_json(json.as_str(), "some_version") {
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

        match VmResources::from_json(json.as_str(), "some_version") {
            Err(Error::BlockDevice(DriveError::InvalidBlockDevicePath)) => (),
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
                        "mem_size_mib": 1024,
                        "ht_enabled": false
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        match VmResources::from_json(json.as_str(), "some_version") {
            Err(Error::VmConfig(VmConfigError::InvalidVcpuCount)) => (),
            _ => unreachable!(),
        }

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
                        "mem_size_mib": 0,
                        "ht_enabled": false
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        match VmResources::from_json(json.as_str(), "some_version") {
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
	                    "log_fifo": "/invalid/path"
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        match VmResources::from_json(json.as_str(), "some_version") {
            Err(Error::Logger(LoggerConfigError::InitializationFailure { .. })) => (),
            _ => unreachable!(),
        }

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
	                    "metrics_fifo": "/invalid/path"
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        match VmResources::from_json(json.as_str(), "some_version") {
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

        match VmResources::from_json(json.as_str(), "some_version") {
            Err(Error::NetDevice(NetworkInterfaceError::HostDeviceNameInUse { .. })) => (),
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
                            "ht_enabled": false
                     }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap(),
        );

        assert!(VmResources::from_json(json.as_str(), "some_version").is_ok());
    }

    #[test]
    fn test_vcpu_config() {
        let vm_resources = default_vm_resources();
        let expected_vcpu_config = VcpuConfig {
            vcpu_count: vm_resources.vm_config().vcpu_count.unwrap(),
            ht_enabled: vm_resources.vm_config().ht_enabled.unwrap(),
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
    fn test_set_vm_config() {
        let mut vm_resources = default_vm_resources();
        let mut aux_vm_config = VmConfig {
            vcpu_count: Some(32),
            mem_size_mib: Some(512),
            ht_enabled: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
        };

        assert_ne!(vm_resources.vm_config, aux_vm_config);
        vm_resources.set_vm_config(&aux_vm_config).unwrap();
        assert_eq!(vm_resources.vm_config, aux_vm_config);

        // Invalid vcpu count.
        aux_vm_config.vcpu_count = Some(0);
        assert_eq!(
            vm_resources.set_vm_config(&aux_vm_config),
            Err(VmConfigError::InvalidVcpuCount)
        );
        aux_vm_config.vcpu_count = Some(33);
        assert_eq!(
            vm_resources.set_vm_config(&aux_vm_config),
            Err(VmConfigError::InvalidVcpuCount)
        );
        aux_vm_config.vcpu_count = Some(32);

        // Invalid mem_size_mib.
        aux_vm_config.mem_size_mib = Some(0);
        assert_eq!(
            vm_resources.set_vm_config(&aux_vm_config),
            Err(VmConfigError::InvalidMemorySize)
        );
    }

    #[test]
    fn test_boot_config() {
        let vm_resources = default_vm_resources();
        let expected_boot_cfg = vm_resources.boot_config.as_ref().unwrap();
        let actual_boot_cfg = vm_resources.boot_source().unwrap();

        assert_eq!(actual_boot_cfg, expected_boot_cfg);
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
        let boot_cfg = vm_resources.boot_source().unwrap();
        let tmp_ino = tmp_file.as_file().metadata().unwrap().st_ino();

        assert_ne!(boot_cfg.cmdline.as_str(), cmdline);
        assert_ne!(boot_cfg.kernel_file.metadata().unwrap().st_ino(), tmp_ino);
        assert_ne!(
            boot_cfg
                .initrd_file
                .as_ref()
                .unwrap()
                .metadata()
                .unwrap()
                .st_ino(),
            tmp_ino
        );

        vm_resources.set_boot_source(expected_boot_cfg).unwrap();
        let boot_cfg = vm_resources.boot_source().unwrap();
        assert_eq!(boot_cfg.cmdline.as_str(), cmdline);
        assert_eq!(boot_cfg.kernel_file.metadata().unwrap().st_ino(), tmp_ino);
        assert_eq!(
            boot_cfg
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

        // Clone the existing block config in order to obtain a new one.
        let mut new_block_device_cfg = vm_resources.block.config_list.get(0).unwrap().clone();
        let tmp_file = TempFile::new().unwrap();
        new_block_device_cfg.drive_id = "block2".to_string();
        new_block_device_cfg.path_on_host = tmp_file.as_path().to_path_buf();
        assert_eq!(vm_resources.block.config_list.len(), 1);

        vm_resources.set_block_device(new_block_device_cfg).unwrap();
        assert_eq!(vm_resources.block.config_list.len(), 2);
    }

    #[test]
    fn test_set_vsock_device() {
        let mut vm_resources = default_vm_resources();
        let new_vsock_cfg = VsockDeviceConfig {
            vsock_id: "new_vsock".to_string(),
            guest_cid: 1,
            uds_path: String::from("uds_path"),
        };
        assert!(vm_resources.vsock.is_none());
        vm_resources.set_vsock_device(new_vsock_cfg.clone());
        let actual_vsock_cfg = vm_resources.vsock.as_ref().unwrap().clone();
        assert_eq!(actual_vsock_cfg, new_vsock_cfg);
    }

    #[test]
    fn test_set_net_device() {
        let mut vm_resources = default_vm_resources();

        // Clone the existing net config in order to obtain a new one.
        let mut new_net_device_cfg = vm_resources
            .network_interface
            .iter()
            .next()
            .unwrap()
            .clone();
        new_net_device_cfg.iface_id = "new_net_if".to_string();
        new_net_device_cfg.guest_mac = Some(MacAddr::parse_str("01:23:45:67:89:0c").unwrap());
        new_net_device_cfg.host_dev_name = "dummy_path2".to_string();
        assert_eq!(vm_resources.network_interface.len(), 1);

        vm_resources.set_net_device(new_net_device_cfg).unwrap();
        assert_eq!(vm_resources.network_interface.len(), 2);
    }

    #[test]
    fn test_update_block_device() {
        let tmp_file = TempFile::new().unwrap();
        let mut vm_resources = default_vm_resources();
        let expected_file_path = tmp_file.as_path().to_path_buf();
        let block_cfg_to_be_updated = vm_resources.block.config_list.get(0).unwrap().clone();
        assert_ne!(block_cfg_to_be_updated.path_on_host, expected_file_path);
        vm_resources
            .update_block_device_path(
                block_cfg_to_be_updated.drive_id.clone(),
                String::from(expected_file_path.to_str().unwrap()),
            )
            .unwrap();
        let updated_block_cfg = vm_resources.block.config_list.get(0).unwrap();
        assert_eq!(updated_block_cfg.path_on_host, expected_file_path);

        // InvalidBlockDeviceId.
        assert_eq!(
            vm_resources.update_block_device_path("id_does_not_exist".to_string(), "".to_string()),
            Err(DriveError::InvalidBlockDeviceID)
        );

        // CannotOpenBlockDevice.
        assert!(vm_resources
            .update_block_device_path(
                block_cfg_to_be_updated.drive_id.clone(),
                "/does/not/exist".to_string()
            )
            .is_err());
    }

    #[test]
    fn test_update_net_rate_limiters() {
        let bw_tb = TokenBucketConfig {
            size: 15,
            one_time_burst: Some(5),
            refill_time: 5,
        };

        let ops_tb = TokenBucketConfig {
            size: 10,
            one_time_burst: Some(2),
            refill_time: 2,
        };

        let expected_rl_cfg = RateLimiterConfig {
            bandwidth: Some(bw_tb),
            ops: Some(ops_tb),
        };

        let mut vm_resources = default_vm_resources();
        let actual_net_cfg = vm_resources.network_interface.iter().next().unwrap();
        let actual_rx_rl_cfg = actual_net_cfg.rx_rate_limiter.unwrap();
        let actual_tx_rl_cfg = actual_net_cfg.tx_rate_limiter.unwrap();
        assert_ne!(actual_rx_rl_cfg, expected_rl_cfg);
        assert_ne!(actual_tx_rl_cfg, expected_rl_cfg);

        let mut net_if_cfg_update = NetworkInterfaceUpdateConfig {
            iface_id: actual_net_cfg.iface_id.clone(),
            rx_rate_limiter: Some(expected_rl_cfg),
            tx_rate_limiter: Some(expected_rl_cfg),
        };
        vm_resources
            .update_net_rate_limiters(net_if_cfg_update.clone())
            .unwrap();
        let actual_net_cfg = vm_resources.network_interface.iter().next().unwrap();
        let actual_rx_rl_cfg = actual_net_cfg.rx_rate_limiter.unwrap();
        let actual_tx_rl_cfg = actual_net_cfg.tx_rate_limiter.unwrap();
        assert_eq!(actual_rx_rl_cfg, expected_rl_cfg);
        assert_eq!(actual_tx_rl_cfg, expected_rl_cfg);

        // DeviceIdNotFound.
        net_if_cfg_update.iface_id = "net_if_does_not_exist".to_string();
        match vm_resources.update_net_rate_limiters(net_if_cfg_update) {
            Err(NetworkInterfaceError::DeviceIdNotFound { .. }) => (),
            _ => unreachable!(),
        }
    }
}
