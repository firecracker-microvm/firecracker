// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use crate::fingerprint::{Fingerprint, FingerprintField};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum FingerprintCompareError {
    /// Difference detected between source and target:\n{0}
    DiffDetected(String),
    /// Failed to serialize/deserialize JSON: {0}
    Serde(#[from] serde_json::Error),
}

#[derive(Serialize)]
struct Diff<'a, T: Serialize> {
    name: String,
    prev: &'a T,
    curr: &'a T,
}

pub fn compare(
    prev: Fingerprint,
    curr: Fingerprint,
    filters: Vec<FingerprintField>,
) -> Result<(), FingerprintCompareError> {
    let compare =
        |field: &FingerprintField, val1, val2| -> Option<Result<String, serde_json::Error>> {
            if val1 != val2 {
                let diff = Diff {
                    name: format!("{field:#?}"),
                    prev: val1,
                    curr: val2,
                };
                Some(serde_json::to_string_pretty(&diff))
            } else {
                None
            }
        };

    let results = filters
        .into_iter()
        .filter_map(|filter| {
            match filter {
                FingerprintField::firecracker_version => compare(
                    &filter,
                    &prev.firecracker_version,
                    &curr.firecracker_version,
                ),
                FingerprintField::kernel_version => {
                    compare(&filter, &prev.kernel_version, &curr.kernel_version)
                }
                FingerprintField::microcode_version => {
                    compare(&filter, &prev.microcode_version, &curr.microcode_version)
                }
                FingerprintField::bios_version => {
                    compare(&filter, &prev.bios_version, &curr.bios_version)
                }
                FingerprintField::bios_revision => {
                    compare(&filter, &prev.bios_revision, &curr.bios_revision)
                }
                FingerprintField::guest_cpu_config => {
                    if prev.guest_cpu_config != curr.guest_cpu_config {
                        let cpu_configs =
                            vec![prev.guest_cpu_config.clone(), curr.guest_cpu_config.clone()];

                        // This `strip()` call always succeed since the number of inputs is two.
                        let cpu_configs = crate::template::strip::strip(cpu_configs).unwrap();

                        let diff = Diff {
                            name: format!("{filter:#?}"),
                            prev: &cpu_configs[0],
                            curr: &cpu_configs[1],
                        };
                        Some(serde_json::to_string_pretty(&diff))
                    } else {
                        None
                    }
                }
            }
        })
        .collect::<Result<Vec<_>, serde_json::Error>>()?;

    if results.is_empty() {
        Ok(())
    } else {
        Err(FingerprintCompareError::DiffDetected(results.join("\n")))
    }
}

#[cfg(test)]
mod tests {
    use clap::ValueEnum;
    use vmm::cpu_config::templates::CustomCpuTemplate;

    use super::*;

    fn build_sample_fingerprint() -> Fingerprint {
        Fingerprint {
            firecracker_version: crate::utils::CPU_TEMPLATE_HELPER_VERSION.to_string(),
            kernel_version: "sample_kernel_version".to_string(),
            microcode_version: "sample_microcode_version".to_string(),
            bios_version: "sample_bios_version".to_string(),
            bios_revision: "sample_bios_revision".to_string(),
            guest_cpu_config: CustomCpuTemplate::default(),
        }
    }

    #[test]
    fn test_compare_same_fingerprints() {
        // Compare two identical fingerprints and verify `Ok` is returned.
        let f1 = build_sample_fingerprint();
        let f2 = build_sample_fingerprint();
        let filters = FingerprintField::value_variants().to_vec();
        compare(f1, f2, filters).unwrap();
    }

    #[test]
    #[rustfmt::skip]
    fn test_compare_different_fingerprints() {
        // Compare two fingerprints that different on `kernel_version` and `microcode_version` with
        // a filter of `kernel_version`, and verify that `Err` is returned and only `kernel_version`
        // change detected.
        let f1 = build_sample_fingerprint();
        let mut f2 = build_sample_fingerprint();
        f2.kernel_version = "different_kernel_version".to_string();
        f2.microcode_version = "different_microcode_version".to_string();
        let filters = vec![FingerprintField::kernel_version];
        let result = compare(f1, f2, filters);
        match result {
            Err(FingerprintCompareError::DiffDetected(err)) => {
                assert_eq!(
                    err,
                    "{\
                    \n  \"name\": \"kernel_version\",\
                    \n  \"prev\": \"sample_kernel_version\",\
                    \n  \"curr\": \"different_kernel_version\"\
                    \n}"
                    .to_string()
                );
            }
            _ => panic!("Should detect difference of `kernel_version`"),
        }
    }
}
