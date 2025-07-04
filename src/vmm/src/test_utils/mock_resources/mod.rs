// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(missing_docs)]

use std::path::PathBuf;

use crate::cpu_config::templates::CustomCpuTemplate;
use crate::resources::VmResources;
use crate::vmm_config::boot_source::BootSourceConfig;
use crate::vmm_config::machine_config::{MachineConfig, MachineConfigUpdate};

pub const DEFAULT_BOOT_ARGS: &str = "reboot=k panic=1 pci=off";
#[cfg(target_arch = "x86_64")]
pub const DEFAULT_KERNEL_IMAGE: &str = "test_elf.bin";
#[cfg(target_arch = "aarch64")]
pub const DEFAULT_KERNEL_IMAGE: &str = "test_pe.bin";
#[cfg(target_arch = "riscv64")]
pub const DEFAULT_KERNEL_IMAGE: &str = "test_pe_riscv.bin"; // Fake file, to pass compilation
#[cfg(target_arch = "x86_64")]
pub const NOISY_KERNEL_IMAGE: &str = "test_noisy_elf.bin";
#[cfg(target_arch = "aarch64")]
pub const NOISY_KERNEL_IMAGE: &str = "test_pe.bin";
#[cfg(target_arch = "riscv64")]
pub const NOISY_KERNEL_IMAGE: &str = "test_pe_noisy.bin"; // Fake file, to pass compilation

pub fn kernel_image_path(kernel_image: Option<&str>) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("src/test_utils/mock_resources");
    path.push(kernel_image.unwrap_or(DEFAULT_KERNEL_IMAGE));
    path.as_os_str().to_str().unwrap().to_string()
}

macro_rules! generate_from {
    ($src_type: ty, $dst_type: ty) => {
        impl From<$src_type> for $dst_type {
            fn from(src: $src_type) -> $dst_type {
                src.0
            }
        }
    };
}

#[derive(Debug)]
pub struct MockBootSourceConfig(BootSourceConfig);

impl MockBootSourceConfig {
    pub fn new() -> MockBootSourceConfig {
        MockBootSourceConfig(BootSourceConfig {
            kernel_image_path: kernel_image_path(None),
            initrd_path: None,
            boot_args: None,
        })
    }

    pub fn with_default_boot_args(mut self) -> Self {
        self.0.boot_args = Some(DEFAULT_BOOT_ARGS.to_string());
        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_kernel(mut self, kernel_image: &str) -> Self {
        self.0.kernel_image_path = kernel_image_path(Some(kernel_image));
        self
    }
}

impl Default for MockBootSourceConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
pub struct MockVmResources(VmResources);

impl MockVmResources {
    pub fn new() -> MockVmResources {
        MockVmResources::default()
    }

    pub fn with_boot_source(mut self, boot_source_cfg: BootSourceConfig) -> Self {
        self.0.build_boot_source(boot_source_cfg).unwrap();
        self
    }

    pub fn with_vm_config(mut self, vm_config: MachineConfig) -> Self {
        let machine_config = MachineConfigUpdate::from(vm_config);
        self.0.update_machine_config(&machine_config).unwrap();
        self
    }

    pub fn set_cpu_template(&mut self, cpu_template: CustomCpuTemplate) {
        self.0.machine_config.set_custom_cpu_template(cpu_template);
    }
}

#[derive(Debug, Default)]
pub struct MockVmConfig(MachineConfig);

impl MockVmConfig {
    pub fn new() -> MockVmConfig {
        MockVmConfig::default()
    }

    pub fn with_dirty_page_tracking(mut self) -> Self {
        self.0.track_dirty_pages = true;
        self
    }
}

generate_from!(MockBootSourceConfig, BootSourceConfig);
generate_from!(MockVmResources, VmResources);
generate_from!(MockVmConfig, MachineConfig);
