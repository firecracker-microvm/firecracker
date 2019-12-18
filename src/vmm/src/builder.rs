// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};
use std::process;

use super::{serde_json, VmmConfig, FC_EXIT_CODE_INVALID_JSON};

use error::{ErrorKind, Result, UserResult, VmmActionError};

use kernel::{cmdline as kernel_cmdline, loader as kernel_loader};
use vmm_config;
use vmm_config::boot_source::{BootSourceConfig, KernelConfig, DEFAULT_KERNEL_CMDLINE};
use vmm_config::device_config::DeviceConfigs;
use vmm_config::drive::{BlockDeviceConfig, BlockDeviceConfigs, DriveError};
use vmm_config::instance_info::InstanceInfo;
use vmm_config::logger::{LoggerConfig, LoggerConfigError, LoggerLevel, LoggerWriter};
use vmm_config::machine_config::{VmConfig, VmConfigError};
use vmm_config::net::{
    NetworkInterfaceConfig, NetworkInterfaceConfigs, NetworkInterfaceError,
    NetworkInterfaceUpdateConfig,
};
use vmm_config::vsock::{VsockDeviceConfig, VsockError};

/// Enables pre-boot setup, instantiation and real time configuration of a Firecracker VMM.
pub struct VmmBuilder {
    device_configs: DeviceConfigs,
    //    epoll_context: EpollContext,
    kernel_config: Option<KernelConfig>,
    vm_config: VmConfig,
    //    shared_info: Arc<RwLock<InstanceInfo>>,
    seccomp_level: u32,
}

impl VmmBuilder {
    /// Creates a new `VmmBuilder`.
    pub fn new(seccomp_level: u32) -> Result<Self> {
        let device_configs = DeviceConfigs::new(
            BlockDeviceConfigs::new(),
            NetworkInterfaceConfigs::new(),
            None,
        );

        Ok(VmmBuilder {
            device_configs,
            kernel_config: None,
            vm_config: VmConfig::default(),
            seccomp_level,
        })
    }

    /// Configures Vmm resources as described by the `config_json` param.
    pub fn from_json(
        config_json: &String,
        seccomp_level: u32,
        firecracker_version: String,
    ) -> std::result::Result<Self, VmmActionError> {
        let mut builder: Self = Self::new(seccomp_level).expect("Cannot create VmmBuilder");
        let vmm_config: VmmConfig = serde_json::from_slice::<VmmConfig>(config_json.as_bytes())
            .unwrap_or_else(|e| {
                error!("Invalid json: {}", e);
                process::exit(i32::from(FC_EXIT_CODE_INVALID_JSON));
            });

        if let Some(logger) = vmm_config.logger {
            vmm_config::logger::init_logger(logger, firecracker_version)
                .map_err(|e| VmmActionError::Logger(ErrorKind::User, e))?;
        }
        if let Some(machine_config) = vmm_config.machine_config {
            builder.with_vm_config(machine_config)?;
        }
        builder.with_boot_source(vmm_config.boot_source)?;
        for drive_config in vmm_config.block_devices.into_iter() {
            builder.with_block_device(drive_config)?;
        }
        for net_config in vmm_config.net_devices.into_iter() {
            builder.with_net_device(net_config)?;
        }
        if let Some(vsock_config) = vmm_config.vsock_device {
            builder.with_vsock_device(vsock_config)?;
        }
        Ok(builder)
    }

    /// Returns the VmConfig.
    pub fn vm_config(&self) -> &VmConfig {
        &self.vm_config
    }

    /// Set the machine configuration of the microVM.
    pub fn with_vm_config(&mut self, machine_config: VmConfig) -> UserResult {
        if machine_config.vcpu_count == Some(0) {
            return Err(VmConfigError::InvalidVcpuCount.into());
        }

        if machine_config.mem_size_mib == Some(0) {
            return Err(VmConfigError::InvalidMemorySize.into());
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
            return Err(VmConfigError::InvalidVcpuCount.into());
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

    fn with_kernel_config(&mut self, kernel_config: KernelConfig) {
        self.kernel_config = Some(kernel_config);
    }

    /// Set the guest boot source configuration.
    pub fn with_boot_source(&mut self, boot_source_cfg: BootSourceConfig) -> UserResult {
        use BootSourceConfigError::{
            InvalidKernelCommandLine, InvalidKernelPath, UpdateNotAllowedPostBoot,
        };
        use ErrorKind::User;
        use VmmActionError::BootSource;

        let kernel_file = File::open(boot_source_cfg.kernel_image_path)
            .map_err(|e| BootSource(User, InvalidKernelPath(e)))?;

        let mut cmdline = kernel_cmdline::Cmdline::new(arch::CMDLINE_MAX_SIZE);
        cmdline
            .insert_str(
                boot_source_cfg
                    .boot_args
                    .unwrap_or_else(|| String::from(DEFAULT_KERNEL_CMDLINE)),
            )
            .map_err(|e| BootSource(User, InvalidKernelCommandLine(e.to_string())))?;

        let kernel_config = KernelConfig {
            kernel_file,
            cmdline,
        };
        self.with_kernel_config(kernel_config);

        Ok(())
    }

    /// Inserts a block to be attached when the VM starts.
    // Only call this function as part of user configuration.
    // If the drive_id does not exist, a new Block Device Config is added to the list.
    pub fn with_block_device(&mut self, block_device_config: BlockDeviceConfig) -> UserResult {
        self.device_configs
            .block
            .insert(block_device_config)
            .map_err(VmmActionError::from)
    }

    /// Inserts a network device to be attached when the VM starts.
    pub fn with_net_device(&mut self, body: NetworkInterfaceConfig) -> UserResult {
        self.device_configs
            .network_interface
            .insert(body)
            .map_err(|e| VmmActionError::NetworkConfig(ErrorKind::User, e))
    }

    /// Sets a vsock device to be attached when the VM starts.
    pub fn with_vsock_device(&mut self, config: VsockDeviceConfig) -> UserResult {
        self.device_configs.vsock = Some(config);
        Ok(())
    }
}
