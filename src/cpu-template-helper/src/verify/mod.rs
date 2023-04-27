// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[allow(unused_variables)]
pub fn verify(
    cpu_template: vmm::guest_config::templates::CustomCpuTemplate,
    cpu_config: vmm::guest_config::templates::CustomCpuTemplate,
) -> Result<(), String> {
    // This is a placeholder of `verify()`.
    // TODO: Add arch-specific `verify()` under arch-specific module.
    Ok(())
}
