// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::guest_config::templates::{CpuConfiguration, CustomCpuTemplate};

#[allow(unused_variables)]
pub fn config_to_template(cpu_config: &CpuConfiguration) -> CustomCpuTemplate {
    // TODO: add implementation of conversion from &CpuConfiguration to CustomCpuTemplate.
    CustomCpuTemplate {
        reg_modifiers: vec![],
    }
}
