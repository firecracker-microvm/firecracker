// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use serde::Deserialize;

/// The body of a PUT /serial request.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SerialConfig {
    /// Named pipe or file used as output for guest serial console.
    pub serial_out_path: Option<PathBuf>,
}
