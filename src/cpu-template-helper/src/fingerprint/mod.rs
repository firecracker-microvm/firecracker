// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use vmm::cpu_config::templates::CustomCpuTemplate;

pub mod compare;
pub mod dump;

macro_rules! declare_fingerprint_struct_and_enum {
    ($($field_name:ident : $field_type:ty),+) => {
        #[derive(Debug, Serialize, Deserialize)]
        pub struct Fingerprint {
            $(pub $field_name: $field_type),+
        }

        #[allow(non_camel_case_types)]
        #[derive(clap::ValueEnum, Clone, Debug)]
        #[value(rename_all = "snake_case")]
        pub enum FingerprintField {
            $($field_name),+
        }
    };
}

// This macro is expanded as follows:
// ```rs
// #[derive(Serialize, Deserialize)]
// pub struct Fingerprint {
//     pub firecracker_version: String,
//     pub kernel_version: String,
//     pub microcode_version: String,
//     pub bios_version: String,
//     pub bios_revision: String,
//     pub guest_cpu_config: CustomCpuTemplate,
// }
//
// #[allow(non_camel_case_types)]
// #[derive(clap::ValueEnum, Clone, Debug)]
// #[value(rename_all = "snake_case")]
// pub enum FingerprintField {
//     firecracker_version,
//     kernel_version,
//     microcode_version,
//     bios_version,
//     bios_revision,
//     guest_cpu_config,
// }
// ```
declare_fingerprint_struct_and_enum!(
    firecracker_version: String,
    kernel_version: String,
    microcode_version: String,
    bios_version: String,
    bios_revision: String,
    guest_cpu_config: CustomCpuTemplate
);
