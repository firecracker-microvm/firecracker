// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate devices;
extern crate libc;
extern crate polly;
extern crate seccomp;
extern crate utils;
extern crate vm_memory;
extern crate vmm;
extern crate vmm_sys_util;

mod mock_devices;
mod mock_resources;
mod mock_seccomp;

use std::io;
use std::thread;
use std::time::Duration;

use polly::event_manager::EventManager;
use seccomp::{BpfProgram, SeccompLevel};
use utils::signal::register_signal_handler;
use vmm::builder::{build_microvm, setup_serial_device};
use vmm::default_syscalls::get_seccomp_filter;
use vmm::resources::VmResources;
use vmm::vmm_config::boot_source::BootSourceConfig;
use vmm_sys_util::tempfile::TempFile;

use mock_devices::MockSerialInput;
use mock_resources::{MockBootSourceConfig, MockVmResources};
use mock_seccomp::{mock_sigsys_handler, MockSeccomp, SIGSYS_RECEIVED};

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
        // This exits the process, so we won't get the output from cargo.
        vmm.lock().unwrap().stop(0);
    }
}

#[test]
fn test_vmm_seccomp() {
    // Tests the behavior of a customized seccomp filter on the VMM.
    let boot_source_cfg: BootSourceConfig = MockBootSourceConfig::new().with_boot_args().into();
    let resources: VmResources = MockVmResources::new()
        .with_boot_source(boot_source_cfg)
        .into();
    let mut event_manager = EventManager::new().unwrap();

    register_signal_handler(libc::SIGSYS, mock_sigsys_handler).unwrap();
    // The customer "forgot" to whitelist the KVM_RUN ioctl.
    let filter: BpfProgram = MockSeccomp::new().without_kvm_run().into();

    let vmm = build_microvm(&resources, &mut event_manager, &filter).unwrap();
    // Give the signal handler some time to complete.
    thread::sleep(Duration::from_millis(30));
    assert!(unsafe { SIGSYS_RECEIVED });
    // This exits the process, so we won't get the output from cargo.
    vmm.lock().unwrap().stop(0);
}
