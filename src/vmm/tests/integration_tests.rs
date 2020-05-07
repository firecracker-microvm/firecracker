// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate devices;
extern crate libc;
extern crate polly;
extern crate seccomp;
extern crate snapshot;
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
#[cfg(target_arch = "x86_64")]
use snapshot::Snapshot;
use vmm::builder::{build_microvm_for_boot, setup_serial_device};
use vmm::default_syscalls::get_seccomp_filter;
#[cfg(target_arch = "x86_64")]
use vmm::persist;
#[cfg(target_arch = "x86_64")]
use vmm::persist::MicrovmState;
use vmm::resources::VmResources;
#[cfg(target_arch = "x86_64")]
use vmm::version_map::VERSION_MAP;
use vmm::vmm_config::boot_source::BootSourceConfig;
#[cfg(target_arch = "x86_64")]
use vmm::vmm_config::snapshot::{CreateSnapshotParams, SnapshotType};
use vmm_sys_util::tempfile::TempFile;

use mock_devices::MockSerialInput;
#[cfg(target_arch = "x86_64")]
use mock_resources::NOISY_KERNEL_IMAGE;
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

    let vmm_ret = build_microvm_for_boot(&resources, &mut event_manager, &empty_seccomp_filter);
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

            let vmm = build_microvm_for_boot(&resources, &mut event_manager, &empty_seccomp_filter)
                .unwrap();

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
            let vmm = build_microvm_for_boot(&resources, &mut event_manager, &filter).unwrap();
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

#[test]
fn test_pause_resume_microvm() {
    // Tests that pausing and resuming a microVM work as expected.
    let pid = unsafe { libc::fork() };
    match pid {
        0 => {
            // Child process: build and run vmm, then attempts to pause and resume it.
            set_panic_hook();

            let boot_source_cfg: BootSourceConfig =
                MockBootSourceConfig::new().with_default_boot_args().into();
            let resources: VmResources = MockVmResources::new()
                .with_boot_source(boot_source_cfg)
                .into();
            let mut event_manager = EventManager::new().unwrap();
            let empty_seccomp_filter = get_seccomp_filter(SeccompLevel::None).unwrap();

            let vmm = build_microvm_for_boot(&resources, &mut event_manager, &empty_seccomp_filter)
                .unwrap();

            assert!(vmm.lock().unwrap().pause_vcpus().is_ok());
            // Pausing again the microVM should not fail (microVM remains in the
            // `Paused` state).
            assert!(vmm.lock().unwrap().pause_vcpus().is_ok());
            assert!(vmm.lock().unwrap().resume_vcpus().is_ok());

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
fn test_dirty_bitmap_error() {
    // Error case: dirty tracking disabled.
    let pid = unsafe { libc::fork() };
    match pid {
        0 => {
            set_panic_hook();
            let boot_source_cfg: BootSourceConfig =
                MockBootSourceConfig::new().with_default_boot_args().into();
            let resources: VmResources = MockVmResources::new()
                .with_boot_source(boot_source_cfg)
                .into();
            let mut event_manager = EventManager::new().unwrap();
            let empty_seccomp_filter = get_seccomp_filter(SeccompLevel::None).unwrap();

            let vmm = build_microvm_for_boot(&resources, &mut event_manager, &empty_seccomp_filter)
                .unwrap();
            // The vmm will start with dirty page tracking = OFF.
            // With dirty tracking disabled, the underlying KVM_GET_DIRTY_LOG ioctl will fail
            // with errno 2 (ENOENT) because KVM can't find any guest memory regions with dirty
            // page tracking enabled.
            assert_eq!(
                format!("{:?}", vmm.lock().unwrap().get_dirty_bitmap().err()),
                "Some(DirtyBitmap(Error(2)))"
            );

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
#[cfg(target_arch = "x86_64")]
fn test_dirty_bitmap_success() {
    // This test is `x86_64`-only until we come up with an `aarch64` kernel that dirties a lot
    // of pages.
    let pid = unsafe { libc::fork() };
    match pid {
        0 => {
            set_panic_hook();
            let boot_source_cfg: BootSourceConfig = MockBootSourceConfig::new()
                .with_default_boot_args()
                .with_kernel(NOISY_KERNEL_IMAGE)
                .into();
            let resources: VmResources = MockVmResources::new()
                .with_boot_source(boot_source_cfg)
                .into();
            let mut event_manager = EventManager::new().unwrap();
            let empty_seccomp_filter = get_seccomp_filter(SeccompLevel::None).unwrap();

            // The vmm will start with dirty page tracking = OFF.
            let vmm = build_microvm_for_boot(&resources, &mut event_manager, &empty_seccomp_filter)
                .unwrap();
            assert!(vmm.lock().unwrap().set_dirty_page_tracking(true).is_ok());
            // Let it churn for a while and dirty some pages...
            thread::sleep(Duration::from_millis(100));
            let bitmap = vmm.lock().unwrap().get_dirty_bitmap().unwrap();
            let num_dirty_pages: u32 = bitmap
                .iter()
                .map(|(_, bitmap_per_region)| {
                    // Gently coerce to u32
                    let num_dirty_pages_per_region: u32 =
                        bitmap_per_region.iter().map(|n| n.count_ones()).sum();
                    num_dirty_pages_per_region
                })
                .sum();
            assert!(num_dirty_pages > 0);
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

#[cfg(target_arch = "x86_64")]
fn create_snapshot(is_diff: bool) {
    let snapshot_file = TempFile::new().unwrap();
    let memory_file = TempFile::new().unwrap();

    let pid = unsafe { libc::fork() };
    match pid {
        0 => {
            set_panic_hook();
            let boot_source_cfg: BootSourceConfig = MockBootSourceConfig::new()
                .with_default_boot_args()
                .with_kernel(NOISY_KERNEL_IMAGE)
                .into();
            let resources: VmResources = MockVmResources::new()
                .with_boot_source(boot_source_cfg)
                .into();
            let mut event_manager = EventManager::new().unwrap();
            let empty_seccomp_filter = get_seccomp_filter(SeccompLevel::None).unwrap();

            let vmm = build_microvm_for_boot(&resources, &mut event_manager, &empty_seccomp_filter)
                .unwrap();
            assert!(vmm.lock().unwrap().set_dirty_page_tracking(true).is_ok());

            // Be sure that the microVM is running.
            thread::sleep(Duration::from_millis(200));

            // Pause microVM.
            vmm.lock().unwrap().pause_vcpus().unwrap();

            // Create snapshot.
            let snapshot_type = match is_diff {
                true => SnapshotType::Diff,
                _ => SnapshotType::Full,
            };
            let snapshot_params = CreateSnapshotParams {
                snapshot_type,
                snapshot_path: snapshot_file.as_path().to_path_buf(),
                mem_file_path: memory_file.as_path().to_path_buf(),
                version: Some(String::from("0.23.0")),
            };

            {
                let mut locked_vmm = vmm.lock().unwrap();
                persist::create_snapshot(&mut locked_vmm, snapshot_params, VERSION_MAP.clone())
                    .unwrap();
            }

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

            // Check that we can deserialize the microVM state from `snapshot_file`.
            let restored_microvm_state: MicrovmState =
                Snapshot::load(&mut snapshot_file.as_file(), VERSION_MAP.clone()).unwrap();

            let memory_file_size_mib = memory_file.as_file().metadata().unwrap().len() >> 20;
            assert_eq!(
                restored_microvm_state.vm_info.mem_size_mib,
                memory_file_size_mib
            );

            // The microVM had no devices and one vCPU.
            assert_eq!(restored_microvm_state.device_states.block_devices.len(), 0);
            assert_eq!(restored_microvm_state.device_states.net_devices.len(), 0);
            assert!(restored_microvm_state.device_states.vsock_device.is_none());
            assert_eq!(restored_microvm_state.vcpu_states.len(), 1);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_create_snapshot() {
    // Create diff snapshot.
    create_snapshot(true);
    // Create full snapshot.
    create_snapshot(false);
}
