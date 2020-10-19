// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use vmm::resources::VmResources;
use vmm::vmm_config::boot_source::BootSourceConfig;
use vmm::vmm_config::machine_config::VmConfig;

pub const DEFAULT_BOOT_ARGS: &str = "reboot=k panic=1 pci=off";
#[cfg(target_arch = "x86_64")]
pub const DEFAULT_KERNEL_IMAGE: &str = "test_elf.bin";
#[cfg(target_arch = "aarch64")]
pub const DEFAULT_KERNEL_IMAGE: &str = "test_pe.bin";
#[cfg(target_arch = "x86_64")]
pub const NOISY_KERNEL_IMAGE: &str = "test_noisy_elf.bin";

fn kernel_image_path(kernel_image: Option<&str>) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests/mock_resources");
    path.push(kernel_image.unwrap_or(DEFAULT_KERNEL_IMAGE));
    path.as_os_str().to_str().unwrap().to_string()
}

macro_rules! generate_into {
    ($src_type: ty, $dst_type: ty) => {
        impl Into<$dst_type> for $src_type {
            fn into(self) -> $dst_type {
                self.0
            }
        }
    };
}

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

#[derive(Default)]
pub struct MockVmResources(VmResources);

impl MockVmResources {
    pub fn new() -> MockVmResources {
        MockVmResources::default()
    }

    pub fn with_boot_source(mut self, boot_source_cfg: BootSourceConfig) -> Self {
        self.0.set_boot_source(boot_source_cfg).unwrap();
        self
    }

    pub fn with_vm_config(mut self, vm_config: VmConfig) -> Self {
        self.0.set_vm_config(&vm_config).unwrap();
        self
    }
}

#[derive(Default)]
pub struct MockVmConfig(VmConfig);

impl MockVmConfig {
    pub fn new() -> MockVmConfig {
        MockVmConfig::default()
    }

    pub fn with_dirty_page_tracking(mut self) -> Self {
        self.0.track_dirty_pages = true;
        self
    }
}

generate_into!(MockBootSourceConfig, BootSourceConfig);
generate_into!(MockVmResources, VmResources);
generate_into!(MockVmConfig, VmConfig);
