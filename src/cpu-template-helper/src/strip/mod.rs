// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::guest_config::templates::CustomCpuTemplate;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to serialize/deserialize.
    #[error("Failed to serialize/deserialize: {0}")]
    Serde(#[from] serde_json::Error),
}

pub fn strip(input: Vec<String>) -> Result<Vec<String>, Error> {
    // Deserialize `Vec<String>` to `Vec<CustomCpuTemplate>`.
    let input = input
        .iter()
        .map(|s| serde_json::from_str::<CustomCpuTemplate>(s))
        .collect::<Result<Vec<_>, serde_json::Error>>()?;

    // TODO: Add actual implementation to strip.

    // Serialize `Vec<CustomCpuTemplate>` to `Vec<String>`.
    let result = input
        .iter()
        .map(serde_json::to_string_pretty)
        .collect::<Result<Vec<_>, serde_json::Error>>()?;
    Ok(result)
}
