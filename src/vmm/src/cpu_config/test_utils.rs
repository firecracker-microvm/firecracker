// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use crate::cpu_config::templates::CustomCpuTemplate;

/// Get a static CPU template stored as a JSON file.
pub fn get_json_template(filename: &str) -> CustomCpuTemplate {
    let json_path = [
        env!("CARGO_MANIFEST_DIR"),
        "../../tests/data/custom_cpu_templates",
        filename,
    ]
    .iter()
    .collect::<PathBuf>();

    serde_json::from_str(&std::fs::read_to_string(json_path).unwrap()).unwrap()
}
