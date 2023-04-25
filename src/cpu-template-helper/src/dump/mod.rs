// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use vmm::builder::{build_microvm_for_boot, StartMicrovmError};
use vmm::resources::VmResources;
use vmm::seccomp_filters::{get_filters, SeccompConfig};
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::{DumpCpuConfigError, EventManager, HTTP_MAX_PAYLOAD_SIZE};

#[cfg(target_arch = "aarch64")]
use crate::dump::aarch64::config_to_template;
#[cfg(target_arch = "x86_64")]
use crate::dump::x86_64::config_to_template;

const CPU_TEMPLATE_HELPER_VERSION: &str = env!("FIRECRACKER_VERSION");

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to create VmResources.
    #[error("Failed to create VmResources: {0}")]
    CreateVmResources(vmm::resources::Error),
    /// Failed to build microVM.
    #[error("Failed to build microVM: {0}")]
    BuildMicroVm(#[from] StartMicrovmError),
    /// Failed to dump CPU configuration.
    #[error("Failed to dump CPU config: {0}")]
    DumpCpuConfig(#[from] DumpCpuConfigError),
    /// Failed to serialize CPU configuration in custom CPU template format.
    #[error("Failed to serialize CPU configuration in custom CPU template format: {0}")]
    Serialize(#[from] serde_json::Error),
}

pub fn dump(config: String) -> Result<String, Error> {
    // Prepare resources from the given config file.
    let instance_info = InstanceInfo {
        id: "anonymous-instance".to_string(),
        state: VmState::NotStarted,
        vmm_version: CPU_TEMPLATE_HELPER_VERSION.to_string(),
        app_name: "cpu-template-helper".to_string(),
    };
    let vm_resources = VmResources::from_json(&config, &instance_info, HTTP_MAX_PAYLOAD_SIZE, None)
        .map_err(Error::CreateVmResources)?;
    let mut event_manager = EventManager::new().unwrap();
    let seccomp_filters = get_filters(SeccompConfig::None).unwrap();

    // Build a microVM.
    let vmm = build_microvm_for_boot(
        &instance_info,
        &vm_resources,
        &mut event_manager,
        &seccomp_filters,
    )?;

    // Get CPU configuration.
    let cpu_configs = vmm.lock().unwrap().dump_cpu_config()?;

    // Convert CPU config to CPU template.
    let cpu_template = config_to_template(&cpu_configs[0]);

    // Serialize it.
    Ok(serde_json::to_string_pretty(&cpu_template)?)
}

#[cfg(test)]
mod tests {
    use utils::tempfile::TempFile;
    use vmm::utilities::mock_resources::kernel_image_path;

    use super::*;
    use crate::tests::generate_config;

    #[test]
    fn test_valid_config() {
        let kernel_image_path = kernel_image_path(None);
        let tmp_file = TempFile::new().unwrap();
        let valid_config =
            generate_config(&kernel_image_path, tmp_file.as_path().to_str().unwrap());

        assert!(dump(valid_config).is_ok());
    }

    #[test]
    fn test_invalid_config() {
        let tmp_file = TempFile::new().unwrap();
        let invalid_kernel_path_config = generate_config(
            "/invalid_kernel_image_path",
            tmp_file.as_path().to_str().unwrap(),
        );

        match dump(invalid_kernel_path_config) {
            Ok(_) => panic!("Should fail with `No such file or directory`."),
            Err(Error::CreateVmResources(_)) => (),
            Err(err) => panic!("Unexpected error: {err}"),
        }
    }
}
