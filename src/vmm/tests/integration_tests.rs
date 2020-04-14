// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate devices;
extern crate polly;
extern crate seccomp;
extern crate vm_memory;
extern crate vmm;
extern crate vmm_sys_util;

mod mock_devices;
mod mock_resources;

use std::io;

use polly::event_manager::EventManager;
use seccomp::SeccompLevel;
use vmm::builder::{build_microvm, setup_serial_device};
use vmm::default_syscalls::get_seccomp_filter;
use vmm::resources::VmResources;
use vmm::vmm_config::boot_source::BootSourceConfig;
use vmm_sys_util::tempfile::TempFile;

use mock_devices::MockSerialInput;
use mock_resources::{MockBootSourceConfig, MockVmResources};

#[test]
fn test_setup_serial_device() {
    let read_tempfile = TempFile::new().unwrap();
    let read_handle = MockSerialInput(read_tempfile.into_file());
    let mut event_manager = EventManager::new().unwrap();

    assert!(setup_serial_device(
        &mut event_manager,
        Box::new(read_handle),
        Box::new(io::stdout()),
    )
    .is_ok());
}

#[test]
fn test_build_microvm() {
    {
        // Error case: no boot source configured.
        let resources: VmResources = MockVmResources::new().into();
        let mut event_manager = EventManager::new().unwrap();
        let empty_seccomp_filter = get_seccomp_filter(SeccompLevel::None).unwrap();

        let vmm_ret = build_microvm(&resources, &mut event_manager, &empty_seccomp_filter);
        assert_eq!(format!("{:?}", vmm_ret.err()), "Some(MissingKernelConfig)");
    }

    {
        // Success case.
        let boot_source_cfg: BootSourceConfig = MockBootSourceConfig::new().with_boot_args().into();
        let resources: VmResources = MockVmResources::new()
            .with_boot_source(boot_source_cfg)
            .into();

        let mut event_manager = EventManager::new().unwrap();
        let empty_seccomp_filter = get_seccomp_filter(SeccompLevel::None).unwrap();

        let vmm = build_microvm(&resources, &mut event_manager, &empty_seccomp_filter).unwrap();
        vmm.lock().unwrap().stop(0);
    }
}
