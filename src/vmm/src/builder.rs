// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{File, OpenOptions};

use super::{VmmConfig, FC_EXIT_CODE_INVALID_JSON};

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
        let mut builder = Self::new(seccomp_level).expect("Cannot create VmmBuilder");
        let vmm_config = serde_json::from_slice::<VmmConfig>(config_json.as_bytes())
            .unwrap_or_else(|e| {
                error!("Invalid json: {}", e);
                std::process::exit(i32::from(FC_EXIT_CODE_INVALID_JSON));
            });

        if let Some(logger) = vmm_config.logger {
            vmm_config::logger::init_logger(logger, firecracker_version)
                .map_err(|e| VmmActionError::Logger(ErrorKind::User, e))?;
        }
        builder.with_boot_source(vmm_config.boot_source)?;
        Ok(builder)
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
}
