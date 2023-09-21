// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use std::sync::{Arc, Mutex};

use vmm::cpu_config::templates::CustomCpuTemplate;
use vmm::{DumpCpuConfigError, Vmm};

#[cfg(target_arch = "aarch64")]
use crate::template::dump::aarch64::config_to_template;
#[cfg(target_arch = "x86_64")]
use crate::template::dump::x86_64::config_to_template;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DumpError {
    /// Failed to dump CPU config: {0}
    DumpCpuConfig(#[from] DumpCpuConfigError),
}

pub fn dump(vmm: Arc<Mutex<Vmm>>) -> Result<CustomCpuTemplate, DumpError> {
    // Get CPU configuration.
    let cpu_configs = vmm.lock().unwrap().dump_cpu_config()?;

    // Convert CPU config to CPU template.
    Ok(config_to_template(&cpu_configs[0]))
}

#[cfg(test)]
mod tests {
    use utils::tempfile::TempFile;
    use vmm::utilities::mock_resources::kernel_image_path;

    use super::*;
    use crate::tests::generate_config;
    use crate::utils::build_microvm_from_config;

    #[test]
    fn test_dump() {
        let kernel_image_path = kernel_image_path(None);
        let tmp_file = TempFile::new().unwrap();
        let valid_config =
            generate_config(&kernel_image_path, tmp_file.as_path().to_str().unwrap());
        let (vmm, _) = build_microvm_from_config(&valid_config).unwrap();

        assert!(dump(vmm).is_ok());
    }
}
