// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use vmm::resources::VmResources;
use vmm::vmm_config::boot_source::BootSourceConfig;

pub const DEFAULT_BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 pci=off";

fn default_kernel_image_path() -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    #[cfg(target_arch = "x86_64")]
    path.push("tests/mock_resources/test_elf.bin");
    #[cfg(target_arch = "aarch64")]
    path.push("tests/mock_resources/test_pe.bin");
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
            kernel_image_path: default_kernel_image_path(),
            initrd_path: None,
            boot_args: None,
        })
    }

    pub fn with_default_boot_args(mut self) -> Self {
        self.0.boot_args = Some(DEFAULT_BOOT_ARGS.to_string());
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
}

generate_into!(MockBootSourceConfig, BootSourceConfig);
generate_into!(MockVmResources, VmResources);
