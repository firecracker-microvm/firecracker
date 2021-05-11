// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(missing_docs)]

use crate::Vmm;
use std::io;
use std::panic;
use std::sync::{Arc, Mutex};

use crate::builder::build_microvm_for_boot;
use crate::default_syscalls::get_empty_filters;
use crate::resources::VmResources;
use crate::utilities::mock_resources::{MockBootSourceConfig, MockVmConfig, MockVmResources};
use crate::vmm_config::boot_source::BootSourceConfig;
use polly::event_manager::EventManager;
use utils::terminal::Terminal;

const VMM_ERR_EXIT: i32 = 42;

pub fn create_vmm(_kernel_image: Option<&str>, is_diff: bool) -> (Arc<Mutex<Vmm>>, EventManager) {
    let mut event_manager = EventManager::new().unwrap();
    let mut empty_seccomp_filters = get_empty_filters();

    let boot_source_cfg = MockBootSourceConfig::new().with_default_boot_args();
    #[cfg(target_arch = "aarch64")]
    let boot_source_cfg: BootSourceConfig = boot_source_cfg.into();
    #[cfg(target_arch = "x86_64")]
    let boot_source_cfg: BootSourceConfig = match _kernel_image {
        Some(kernel) => boot_source_cfg.with_kernel(kernel).into(),
        None => boot_source_cfg.into(),
    };
    let mock_vm_res = MockVmResources::new().with_boot_source(boot_source_cfg);
    let resources: VmResources = if is_diff {
        mock_vm_res
            .with_vm_config(MockVmConfig::new().with_dirty_page_tracking().into())
            .into()
    } else {
        mock_vm_res.into()
    };

    (
        build_microvm_for_boot(&resources, &mut event_manager, &mut empty_seccomp_filters).unwrap(),
        event_manager,
    )
}

pub fn default_vmm(kernel_image: Option<&str>) -> (Arc<Mutex<Vmm>>, EventManager) {
    create_vmm(kernel_image, false)
}

#[cfg(target_arch = "x86_64")]
pub fn dirty_tracking_vmm(kernel_image: Option<&str>) -> (Arc<Mutex<Vmm>>, EventManager) {
    create_vmm(kernel_image, true)
}

pub fn wait_vmm_child_process(vmm_pid: i32) {
    // Parent process: wait for the vmm to exit.
    let mut vmm_status: i32 = -1;
    let pid_done = unsafe { libc::waitpid(vmm_pid, &mut vmm_status, 0) };
    assert_eq!(pid_done, vmm_pid);
    restore_stdin();
    // If any panics occurred, its exit status will be != 0.
    assert!(libc::WIFEXITED(vmm_status));
    assert_eq!(libc::WEXITSTATUS(vmm_status), 0);
}

pub fn restore_stdin() {
    let stdin = io::stdin();
    stdin.lock().set_canon_mode().unwrap();
}

pub fn set_panic_hook() {
    panic::set_hook(Box::new(move |_| {
        restore_stdin();
        unsafe {
            libc::exit(VMM_ERR_EXIT);
        }
    }));
}
