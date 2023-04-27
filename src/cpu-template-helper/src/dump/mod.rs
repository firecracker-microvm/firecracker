// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use std::sync::{Arc, Mutex};

use vmm::{DumpCpuConfigError, Vmm};

#[cfg(target_arch = "aarch64")]
use crate::dump::aarch64::config_to_template;
#[cfg(target_arch = "x86_64")]
use crate::dump::x86_64::config_to_template;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to dump CPU configuration.
    #[error("Failed to dump CPU config: {0}")]
    DumpCpuConfig(#[from] DumpCpuConfigError),
    /// Failed to serialize CPU configuration in custom CPU template format.
    #[error("Failed to serialize CPU configuration in custom CPU template format: {0}")]
    Serialize(#[from] serde_json::Error),
}

pub fn dump(vmm: Arc<Mutex<Vmm>>) -> Result<String, Error> {
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
