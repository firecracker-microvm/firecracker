// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use vmm::cpu_config::templates::CustomCpuTemplate;

pub mod dump;

#[derive(Serialize, Deserialize)]
pub struct Fingerprint {
    pub firecracker_version: String,
    pub kernel_version: String,
    pub microcode_version: String,
    pub bios_version: String,
    pub bios_revision: String,
    pub guest_cpu_config: CustomCpuTemplate,
}
