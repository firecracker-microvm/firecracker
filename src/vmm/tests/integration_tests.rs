// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation, clippy::tests_outside_test_module)]

use std::io::{Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use vmm::builder::build_and_boot_microvm;
use vmm::devices::virtio::block::CacheType;
use vmm::persist::{MicrovmState, MicrovmStateError, VmInfo, snapshot_state_sanity_check};
use vmm::resources::VmResources;
use vmm::rpc_interface::{
    LoadSnapshotError, PrebootApiController, RuntimeApiController, VmmAction, VmmActionError,
};
use vmm::seccomp::get_empty_filters;
use vmm::snapshot::Snapshot;
use vmm::test_utils::mock_resources::{MockVmResources, NOISY_KERNEL_IMAGE};
use vmm::test_utils::{create_vmm, default_vmm, default_vmm_no_boot};
use vmm::vmm_config::balloon::BalloonDeviceConfig;
use vmm::vmm_config::boot_source::BootSourceConfig;
use vmm::vmm_config::drive::BlockDeviceConfig;
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vmm_config::machine_config::{MachineConfig, MachineConfigUpdate};
use vmm::vmm_config::net::NetworkInterfaceConfig;
use vmm::vmm_config::snapshot::{
    CreateSnapshotParams, LoadSnapshotParams, MemBackendConfig, MemBackendType, SnapshotType,
};
use vmm::vmm_config::vsock::VsockDeviceConfig;
use vmm::{DumpCpuConfigError, EventManager, FcExitCode, Vmm};
use vmm_sys_util::tempfile::TempFile;

#[allow(unused_mut, unused_variables)]
fn check_booted_microvm(vmm: Arc<Mutex<Vmm>>, mut evmgr: EventManager) {
    // On x86_64, the vmm should exit once its workload completes and signals the exit event.
    // On aarch64, the test kernel doesn't exit, so the vmm is force-stopped.
    #[cfg(target_arch = "x86_64")]
    evmgr.run_with_timeout(500).unwrap();
    #[cfg(target_arch = "aarch64")]
    vmm.lock().unwrap().stop(FcExitCode::Ok);

    assert_eq!(
        vmm.lock().unwrap().shutdown_exit_code(),
        Some(FcExitCode::Ok)
    );
}

#[test]
fn test_build_and_boot_microvm() {
    // Error case: no boot source configured.
    {
        let resources: VmResources = MockVmResources::new().into();
        let mut event_manager = EventManager::new().unwrap();
        let empty_seccomp_filters = get_empty_filters();

        let vmm_ret = build_and_boot_microvm(
            &InstanceInfo::default(),
            &resources,
            &mut event_manager,
            &empty_seccomp_filters,
        );
        assert_eq!(format!("{:?}", vmm_ret.err()), "Some(MissingKernelConfig)");
    }

    for pci_enabled in [false, true] {
        for memory_hotplug in [false, true] {
            let (vmm, evmgr) = create_vmm(None, false, true, pci_enabled, memory_hotplug);
            check_booted_microvm(vmm, evmgr);
        }
    }
}

#[allow(unused_mut, unused_variables)]
fn check_build_microvm(vmm: Arc<Mutex<Vmm>>, mut evmgr: EventManager) {
    // The built microVM should be in the `VmState::Paused` state here.
    assert_eq!(vmm.lock().unwrap().instance_info().state, VmState::Paused);

    // The microVM should be able to resume and exit successfully.
    // On x86_64, the vmm should exit once its workload completes and signals the exit event.
    // On aarch64, the test kernel doesn't exit, so the vmm is force-stopped.
    vmm.lock().unwrap().resume_vm().unwrap();
    #[cfg(target_arch = "x86_64")]
    evmgr.run_with_timeout(500).unwrap();
    #[cfg(target_arch = "aarch64")]
    vmm.lock().unwrap().stop(FcExitCode::Ok);
    assert_eq!(
        vmm.lock().unwrap().shutdown_exit_code(),
        Some(FcExitCode::Ok)
    );
}

#[test]
fn test_build_microvm() {
    for pci_enabled in [false, true] {
        for memory_hotplug in [false, true] {
            let (vmm, evmgr) = create_vmm(None, false, false, pci_enabled, memory_hotplug);
            check_build_microvm(vmm, evmgr);
        }
    }
}

fn pause_resume_microvm(vmm: Arc<Mutex<Vmm>>) {
    let mut api_controller = RuntimeApiController::new(VmResources::default(), vmm.clone());

    // There's a race between this thread and the vcpu thread, but this thread
    // should be able to pause vcpu thread before it finishes running its test-binary.
    api_controller.handle_request(VmmAction::Pause).unwrap();
    // Pausing again the microVM should not fail (microVM remains in the
    // `Paused` state).
    api_controller.handle_request(VmmAction::Pause).unwrap();
    api_controller.handle_request(VmmAction::Resume).unwrap();

    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

#[test]
fn test_pause_resume_microvm() {
    for pci_enabled in [false, true] {
        for memory_hotplug in [false, true] {
            // Tests that pausing and resuming a microVM work as expected.
            let (vmm, _) = create_vmm(None, false, true, pci_enabled, memory_hotplug);

            pause_resume_microvm(vmm);
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dirty_bitmap_success() {
    let vmms = [
        vmm::test_utils::dirty_tracking_vmm(Some(NOISY_KERNEL_IMAGE)),
        default_vmm(Some(NOISY_KERNEL_IMAGE)),
    ];

    for (vmm, _) in vmms {
        // Let it churn for a while and dirty some pages...
        thread::sleep(Duration::from_millis(100));
        let bitmap = vmm.lock().unwrap().vm.get_dirty_bitmap().unwrap();
        let num_dirty_pages: u32 = bitmap
            .values()
            .map(|bitmap_per_region| {
                // Gently coerce to u32
                let num_dirty_pages_per_region: u32 =
                    bitmap_per_region.iter().map(|n| n.count_ones()).sum();
                num_dirty_pages_per_region
            })
            .sum();
        assert!(num_dirty_pages > 0);
        vmm.lock().unwrap().stop(FcExitCode::Ok);
    }
}

#[test]
fn test_disallow_snapshots_without_pausing() {
    let (vmm, _) = default_vmm(Some(NOISY_KERNEL_IMAGE));
    let vm_info = VmInfo {
        mem_size_mib: 1u64,
        ..Default::default()
    };

    // Verify saving state while running is not allowed.
    assert!(matches!(
        vmm.lock().unwrap().save_state(&vm_info),
        Err(MicrovmStateError::NotAllowed(_))
    ));

    // Pause microVM.
    vmm.lock().unwrap().pause_vm().unwrap();
    // It is now allowed.
    vmm.lock().unwrap().save_state(&vm_info).unwrap();
    // Stop.
    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

#[test]
fn test_disallow_dump_cpu_config_without_pausing() {
    let (vmm, _) = default_vmm_no_boot(Some(NOISY_KERNEL_IMAGE));

    // This call should succeed since the microVM is in the paused state before boot.
    vmm.lock().unwrap().dump_cpu_config().unwrap();

    // Boot the microVM.
    vmm.lock().unwrap().resume_vm().unwrap();

    // Verify this call is not allowed while running.
    assert!(matches!(
        vmm.lock().unwrap().dump_cpu_config(),
        Err(DumpCpuConfigError::NotAllowed(_))
    ));

    // Stop the microVM.
    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

fn verify_create_snapshot(
    is_diff: bool,
    pci_enabled: bool,
    memory_hotplug: bool,
) -> (TempFile, TempFile) {
    let snapshot_file = TempFile::new().unwrap();
    let memory_file = TempFile::new().unwrap();

    let (vmm, _) = create_vmm(
        Some(NOISY_KERNEL_IMAGE),
        is_diff,
        true,
        pci_enabled,
        memory_hotplug,
    );
    let resources = VmResources {
        machine_config: MachineConfig {
            mem_size_mib: 1,
            track_dirty_pages: is_diff,
            ..Default::default()
        },
        ..Default::default()
    };
    let vm_info = VmInfo::from(&resources);
    let mut controller = RuntimeApiController::new(resources, vmm.clone());

    // Be sure that the microVM is running.
    thread::sleep(Duration::from_millis(200));

    // Pause microVM.
    controller.handle_request(VmmAction::Pause).unwrap();

    // Create snapshot.
    let snapshot_type = match is_diff {
        true => SnapshotType::Diff,
        false => SnapshotType::Full,
    };
    let snapshot_params = CreateSnapshotParams {
        snapshot_type,
        snapshot_path: snapshot_file.as_path().to_path_buf(),
        mem_file_path: memory_file.as_path().to_path_buf(),
    };

    controller
        .handle_request(VmmAction::CreateSnapshot(snapshot_params))
        .unwrap();

    vmm.lock().unwrap().stop(FcExitCode::Ok);

    // Check that we can deserialize the microVM state from `snapshot_file`.
    let restored_microvm_state: MicrovmState =
        Snapshot::load(&mut snapshot_file.as_file()).unwrap().data;

    assert_eq!(restored_microvm_state.vm_info, vm_info);

    // Verify deserialized data.
    // The default vmm has no devices and one vCPU.
    assert_eq!(
        restored_microvm_state
            .device_states
            .mmio_state
            .block_devices
            .len(),
        0
    );
    assert_eq!(
        restored_microvm_state
            .device_states
            .mmio_state
            .net_devices
            .len(),
        0
    );
    assert!(
        restored_microvm_state
            .device_states
            .mmio_state
            .vsock_device
            .is_none()
    );
    assert_eq!(restored_microvm_state.vcpu_states.len(), 1);

    (snapshot_file, memory_file)
}

fn verify_load_snapshot(snapshot_file: TempFile, memory_file: TempFile) {
    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();
    let mut vm_resources = VmResources::default();

    let mut preboot_api_controller = PrebootApiController::new(
        &empty_seccomp_filters,
        InstanceInfo::default(),
        &mut vm_resources,
        &mut event_manager,
    );

    preboot_api_controller
        .handle_preboot_request(VmmAction::LoadSnapshot(LoadSnapshotParams {
            snapshot_path: snapshot_file.as_path().to_path_buf(),
            mem_backend: MemBackendConfig {
                backend_path: memory_file.as_path().to_path_buf(),
                backend_type: MemBackendType::File,
            },
            track_dirty_pages: false,
            resume_vm: true,
            network_overrides: vec![],
        }))
        .unwrap();

    let vmm = preboot_api_controller.built_vmm.take().unwrap();

    assert_eq!(vmm.lock().unwrap().instance_info.state, VmState::Running);
    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

#[test]
fn test_create_and_load_snapshot() {
    for diff_snap in [false, true] {
        for pci_enabled in [false, true] {
            for memory_hotplug in [false, true] {
                // Create snapshot.
                let (snapshot_file, memory_file) =
                    verify_create_snapshot(diff_snap, pci_enabled, memory_hotplug);
                // Create a new microVm from snapshot. This only tests code-level logic; it verifies
                // that a microVM can be built with no errors from given snapshot.
                // It does _not_ verify that the guest is actually restored properly. We're using
                // python integration tests for that.
                verify_load_snapshot(snapshot_file, memory_file);
            }
        }
    }
}

#[test]
fn test_snapshot_load_sanity_checks() {
    let microvm_state = get_microvm_state_from_snapshot(false);
    check_snapshot(microvm_state);
    let microvm_state = get_microvm_state_from_snapshot(true);
    check_snapshot(microvm_state);
}

fn check_snapshot(mut microvm_state: MicrovmState) {
    use vmm::persist::SnapShotStateSanityCheckError;
    snapshot_state_sanity_check(&microvm_state).unwrap();

    // Remove memory regions.
    microvm_state.vm_state.memory.regions.clear();

    // Validate sanity checks fail because there is no mem region in state.
    assert_eq!(
        snapshot_state_sanity_check(&microvm_state),
        Err(SnapShotStateSanityCheckError::NoMemory)
    );
}

fn get_microvm_state_from_snapshot(pci_enabled: bool) -> MicrovmState {
    // Create a diff snapshot
    let (snapshot_file, _) = verify_create_snapshot(true, pci_enabled, false);

    // Deserialize the microVM state.
    snapshot_file.as_file().seek(SeekFrom::Start(0)).unwrap();
    Snapshot::load(&mut snapshot_file.as_file()).unwrap().data
}

fn verify_load_snap_disallowed_after_boot_resources(res: VmmAction, res_name: &str) {
    let (snapshot_file, memory_file) = verify_create_snapshot(false, false, false);

    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();
    let mut vm_resources = VmResources::default();

    let mut preboot_api_controller = PrebootApiController::new(
        &empty_seccomp_filters,
        InstanceInfo::default(),
        &mut vm_resources,
        &mut event_manager,
    );

    preboot_api_controller.handle_preboot_request(res).unwrap();

    // Load snapshot should no longer be allowed.
    let req = VmmAction::LoadSnapshot(LoadSnapshotParams {
        snapshot_path: snapshot_file.as_path().to_path_buf(),
        mem_backend: MemBackendConfig {
            backend_path: memory_file.as_path().to_path_buf(),
            backend_type: MemBackendType::File,
        },
        track_dirty_pages: false,
        resume_vm: false,
        network_overrides: vec![],
    });
    let err = preboot_api_controller.handle_preboot_request(req);
    assert!(
        matches!(
            err.unwrap_err(),
            VmmActionError::LoadSnapshot(LoadSnapshotError::LoadSnapshotNotAllowed)
        ),
        "LoadSnapshot should be disallowed after {}",
        res_name
    );
}

#[test]
fn test_preboot_load_snap_disallowed_after_boot_resources() {
    let tmp_file = TempFile::new().unwrap();
    let tmp_file = tmp_file.as_path().to_str().unwrap().to_string();
    // Verify LoadSnapshot not allowed after configuring various boot-specific resources.
    let req = VmmAction::ConfigureBootSource(BootSourceConfig {
        kernel_image_path: tmp_file.clone(),
        ..Default::default()
    });
    verify_load_snap_disallowed_after_boot_resources(req, "ConfigureBootSource");

    let config = BlockDeviceConfig {
        drive_id: String::new(),
        partuuid: None,
        is_root_device: false,
        cache_type: CacheType::Unsafe,

        is_read_only: Some(false),
        path_on_host: Some(tmp_file),
        rate_limiter: None,
        file_engine_type: None,

        socket: None,
    };

    let req = VmmAction::InsertBlockDevice(config);
    verify_load_snap_disallowed_after_boot_resources(req, "InsertBlockDevice");

    let req = VmmAction::InsertNetworkDevice(NetworkInterfaceConfig {
        iface_id: String::new(),
        host_dev_name: String::new(),
        guest_mac: None,
        rx_rate_limiter: None,
        tx_rate_limiter: None,
    });
    verify_load_snap_disallowed_after_boot_resources(req, "InsertNetworkDevice");

    let req = VmmAction::SetBalloonDevice(BalloonDeviceConfig::default());
    verify_load_snap_disallowed_after_boot_resources(req, "SetBalloonDevice");

    let req = VmmAction::SetVsockDevice(VsockDeviceConfig {
        vsock_id: Some(String::new()),
        guest_cid: 0,
        uds_path: String::new(),
    });
    verify_load_snap_disallowed_after_boot_resources(req, "SetVsockDevice");

    let req =
        VmmAction::UpdateMachineConfiguration(MachineConfigUpdate::from(MachineConfig::default()));
    verify_load_snap_disallowed_after_boot_resources(req, "SetVmConfiguration");
}
