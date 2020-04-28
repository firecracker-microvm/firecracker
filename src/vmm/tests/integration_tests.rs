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
mod test_utils;

use std::io;
use std::thread;
use std::time::Duration;

use polly::event_manager::EventManager;
use seccomp::{BpfProgram, SeccompLevel};
use vmm::builder::{build_microvm, setup_serial_device};
use vmm::default_syscalls::get_seccomp_filter;
use vmm::resources::VmResources;
use vmm::vmm_config::boot_source::BootSourceConfig;
use vmm_sys_util::tempfile::TempFile;

use mock_devices::MockSerialInput;
use mock_resources::{MockBootSourceConfig, MockVmResources};
use mock_seccomp::MockSeccomp;
use test_utils::{restore_stdin, set_panic_hook};

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
    // Error case: no boot source configured.
    let resources: VmResources = MockVmResources::new().into();
    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filter = get_seccomp_filter(SeccompLevel::None).unwrap();

    let vmm_ret = build_microvm(&resources, &mut event_manager, &empty_seccomp_filter);
    assert_eq!(format!("{:?}", vmm_ret.err()), "Some(MissingKernelConfig)");

    // Success case.
    // Child process will run the vmm and exit.
    // Parent will wait for child to exit and assert on exit status 0.
    let pid = unsafe { libc::fork() };
    match pid {
        0 => {
            // Child process: build and run vmm.
            // If the vmm thread panics, the `wait()` in the parent doesn't exit.
            // Force the child to exit on panic to unblock the waiting parent.
            set_panic_hook();

            let boot_source_cfg: BootSourceConfig =
                MockBootSourceConfig::new().with_default_boot_args().into();
            let resources: VmResources = MockVmResources::new()
                .with_boot_source(boot_source_cfg)
                .into();
            let mut event_manager = EventManager::new().unwrap();
            let empty_seccomp_filter = get_seccomp_filter(SeccompLevel::None).unwrap();

            let vmm = build_microvm(&resources, &mut event_manager, &empty_seccomp_filter).unwrap();

            // On x86_64, the vmm should exit once its workload completes and signals the exit event.
            // On aarch64, the test kernel doesn't exit, so the vmm is force-stopped.
            let _ = event_manager.run_with_timeout(500).unwrap();

            #[cfg(target_arch = "x86_64")]
            vmm.lock().unwrap().stop(-1); // If we got here, something went wrong.
            #[cfg(target_arch = "aarch64")]
            vmm.lock().unwrap().stop(0);
        }
        vmm_pid => {
            // Parent process: wait for the vmm to exit.
            let mut vmm_status: i32 = -1;
            let pid_done = unsafe { libc::waitpid(vmm_pid, &mut vmm_status, 0) };
            assert_eq!(pid_done, vmm_pid);
            restore_stdin();
            // If any panics occurred, its exit status will be != 0.
            assert!(unsafe { libc::WIFEXITED(vmm_status) });
            assert_eq!(unsafe { libc::WEXITSTATUS(vmm_status) }, 0);
        }
    }
}

#[test]
fn test_vmm_seccomp() {
    // Tests the behavior of a customized seccomp filter on the VMM.
    let pid = unsafe { libc::fork() };
    match pid {
        0 => {
            // Child process: build vmm and (try to) run it.
            let boot_source_cfg: BootSourceConfig =
                MockBootSourceConfig::new().with_default_boot_args().into();
            let resources: VmResources = MockVmResources::new()
                .with_boot_source(boot_source_cfg)
                .into();
            let mut event_manager = EventManager::new().unwrap();

            // The customer "forgot" to whitelist the KVM_RUN ioctl.
            let filter: BpfProgram = MockSeccomp::new().without_kvm_run().into();
            let vmm = build_microvm(&resources, &mut event_manager, &filter).unwrap();
            // Give the vCPUs a chance to attempt KVM_RUN.
            thread::sleep(Duration::from_millis(200));
            // Should never get here.
            vmm.lock().unwrap().stop(-1);
        }
        vmm_pid => {
            // Parent process: wait for the vmm to exit.
            let mut vmm_status: i32 = -1;
            let pid_done = unsafe { libc::waitpid(vmm_pid, &mut vmm_status, 0) };
            assert_eq!(pid_done, vmm_pid);
            restore_stdin();
            // The seccomp fault should have caused death by SIGSYS.
            assert!(unsafe { libc::WIFSIGNALED(vmm_status) });
            assert_eq!(unsafe { libc::WTERMSIG(vmm_status) }, libc::SIGSYS);
        }
    }
}
