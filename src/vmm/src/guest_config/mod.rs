// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Contains common types for vmm to use internally
/// as well as by user interface related code.
pub mod common;
#[cfg(cpuid)]
pub mod cpuid;

// TODO Remove allow(unused) once implementation added
/// Module containing type implementations needed for x86 CPU configuration
#[allow(unused)]
#[cfg(target_arch = "x86_64")]
pub mod x86_config {

    use crate::guest_config::common::{ConfigurationModifier, CpuConfiguration, CustomCpuTemplate};

    impl ConfigurationModifier for CpuConfiguration {
        fn apply_template(&self, cpu_template: CustomCpuTemplate) -> Box<CpuConfiguration> {
            // TODO - Apply template
            get_host_cpu_configuration()
        }
    }

    fn get_host_cpu_configuration() -> Box<CpuConfiguration> {
        // TODO - Retrieve host configuration

        Box::new(CpuConfiguration::new(Vec::new()))
    }
}

// TODO Remove allow(unused) once implementation added
/// Module containing type implementations needed for aarch64 (ARM) CPU configuration
#[allow(unused)]
#[cfg(target_arch = "aarch64")]
pub mod aarch64_config {

    use crate::guest_config::common::{ConfigurationModifier, CpuConfiguration, CustomCpuTemplate};

    impl ConfigurationModifier for CpuConfiguration {
        fn apply_template(&self, cpu_template: CustomCpuTemplate) -> Box<CpuConfiguration> {
            // TODO - Apply template
            get_host_cpu_configuration()
        }
    }

    fn get_host_cpu_configuration() -> Box<CpuConfiguration> {
        // TODO - Retrieve host configuration

        Box::new(CpuConfiguration::new(Vec::new()))
    }
}
