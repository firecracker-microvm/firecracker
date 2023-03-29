// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::read_to_string;
use std::path::PathBuf;

use vmm::resources::VmResources;
use vmm::seccomp_filters::{get_filters, SeccompConfig};
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::{EventManager, HTTP_MAX_PAYLOAD_SIZE};

pub fn dump(config_file: PathBuf, _output_file: PathBuf) {
    // Prepare resources for vmm::builder::build_microvm_for_boot().
    let instance_info = InstanceInfo {
        id: "cpu-template-helper".to_string(),
        state: VmState::NotStarted,
        vmm_version: crate::CPU_TEMPLATE_HELPER_VERSION.to_string(),
        app_name: "Firecracker".to_string(),
    };

    let config_json =
        read_to_string(config_file).expect("Unable to open or read from the configuration file");
    let vm_resources =
        VmResources::from_json(&config_json, &instance_info, HTTP_MAX_PAYLOAD_SIZE, None)
            .expect("Failed to create VmResources");

    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    let seccomp_filters =
        get_filters(SeccompConfig::None).expect("Failed to create empty seccomp filters");

    // Build microVM
    let _vmm = vmm::builder::build_microvm_for_boot(
        &instance_info,
        &vm_resources,
        &mut event_manager,
        &seccomp_filters,
    )
    .expect("Failed to build microVM");

    // TODO: get CPU configuration

    // TODO: convert CPU configuration into CPU template format

    // TODO: save into output_file
}
