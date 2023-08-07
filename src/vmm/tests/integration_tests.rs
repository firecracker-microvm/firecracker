// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::{Seek, SeekFrom};
use std::thread;
use std::time::Duration;

use snapshot::Snapshot;
use utils::tempfile::TempFile;
use vmm::builder::{build_and_boot_microvm, build_microvm_from_snapshot};
use vmm::persist::{self, snapshot_state_sanity_check, MicrovmState, MicrovmStateError, VmInfo};
use vmm::resources::VmResources;
use vmm::seccomp_filters::get_empty_filters;
use vmm::utilities::mock_resources::{MockVmResources, NOISY_KERNEL_IMAGE};
#[cfg(target_arch = "x86_64")]
use vmm::utilities::test_utils::dirty_tracking_vmm;
use vmm::utilities::test_utils::{create_vmm, default_vmm, default_vmm_no_boot};
use vmm::version_map::VERSION_MAP;
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vmm_config::snapshot::{CreateSnapshotParams, SnapshotType, Version};
use vmm::{DumpCpuConfigError, EventManager, FcExitCode};

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

    // Success case.
    let (vmm, mut _evmgr) = default_vmm(None);

    // On x86_64, the vmm should exit once its workload completes and signals the exit event.
    // On aarch64, the test kernel doesn't exit, so the vmm is force-stopped.
    #[cfg(target_arch = "x86_64")]
    _evmgr.run_with_timeout(500).unwrap();
    #[cfg(target_arch = "aarch64")]
    vmm.lock().unwrap().stop(FcExitCode::Ok);

    assert_eq!(
        vmm.lock().unwrap().shutdown_exit_code(),
        Some(FcExitCode::Ok)
    );
}

#[test]
fn test_build_microvm() {
    // The built microVM should be in the `VmState::Paused` state here.
    let (vmm, mut _evtmgr) = default_vmm_no_boot(None);
    assert_eq!(vmm.lock().unwrap().instance_info().state, VmState::Paused);

    // The microVM should be able to resume and exit successfully.
    // On x86_64, the vmm should exit once its workload completes and signals the exit event.
    // On aarch64, the test kernel doesn't exit, so the vmm is force-stopped.
    vmm.lock().unwrap().resume_vm().unwrap();
    #[cfg(target_arch = "x86_64")]
    _evtmgr.run_with_timeout(500).unwrap();
    #[cfg(target_arch = "aarch64")]
    vmm.lock().unwrap().stop(FcExitCode::Ok);
    assert_eq!(
        vmm.lock().unwrap().shutdown_exit_code(),
        Some(FcExitCode::Ok)
    );
}

#[test]
fn test_pause_resume_microvm() {
    // Tests that pausing and resuming a microVM work as expected.
    let (vmm, _) = default_vmm(None);

    // There's a race between this thread and the vcpu thread, but this thread
    // should be able to pause vcpu thread before it finishes running its test-binary.
    assert!(vmm.lock().unwrap().pause_vm().is_ok());
    // Pausing again the microVM should not fail (microVM remains in the
    // `Paused` state).
    assert!(vmm.lock().unwrap().pause_vm().is_ok());
    assert!(vmm.lock().unwrap().resume_vm().is_ok());
    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

#[test]
fn test_dirty_bitmap_error() {
    // Error case: dirty tracking disabled.
    let (vmm, _) = default_vmm(None);

    // The vmm will start with dirty page tracking = OFF.
    // With dirty tracking disabled, the underlying KVM_GET_DIRTY_LOG ioctl will fail
    // with errno 2 (ENOENT) because KVM can't find any guest memory regions with dirty
    // page tracking enabled.
    assert_eq!(
        format!("{:?}", vmm.lock().unwrap().get_dirty_bitmap().err()),
        "Some(DirtyBitmap(Error(2)))"
    );
    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dirty_bitmap_success() {
    // The vmm will start with dirty page tracking = ON.
    let (vmm, _) = dirty_tracking_vmm(Some(NOISY_KERNEL_IMAGE));

    // Let it churn for a while and dirty some pages...
    thread::sleep(Duration::from_millis(100));
    let bitmap = vmm.lock().unwrap().get_dirty_bitmap().unwrap();
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

fn verify_create_snapshot(is_diff: bool) -> (TempFile, TempFile) {
    let snapshot_file = TempFile::new().unwrap();
    let memory_file = TempFile::new().unwrap();

    let (vmm, _) = create_vmm(Some(NOISY_KERNEL_IMAGE), is_diff, true);

    // Be sure that the microVM is running.
    thread::sleep(Duration::from_millis(200));

    // Pause microVM.
    vmm.lock().unwrap().pause_vm().unwrap();

    // Create snapshot.
    let snapshot_type = match is_diff {
        true => SnapshotType::Diff,
        false => SnapshotType::Full,
    };
    let snapshot_params = CreateSnapshotParams {
        snapshot_type,
        snapshot_path: snapshot_file.as_path().to_path_buf(),
        mem_file_path: memory_file.as_path().to_path_buf(),
        version: Some(Version::new(0, 24, 0)),
    };
    let vm_info = VmInfo {
        mem_size_mib: 1u64,
        ..Default::default()
    };

    {
        let mut locked_vmm = vmm.lock().unwrap();
        persist::create_snapshot(
            &mut locked_vmm,
            &vm_info,
            &snapshot_params,
            VERSION_MAP.clone(),
        )
        .unwrap();
    }

    vmm.lock().unwrap().stop(FcExitCode::Ok);

    // Check that we can deserialize the microVM state from `snapshot_file`.
    let snapshot_path = snapshot_file.as_path().to_path_buf();
    let snapshot_file_metadata = std::fs::metadata(snapshot_path).unwrap();
    let snapshot_len = snapshot_file_metadata.len() as usize;
    let (restored_microvm_state, _) = Snapshot::load::<_, MicrovmState>(
        &mut snapshot_file.as_file(),
        snapshot_len,
        VERSION_MAP.clone(),
    )
    .unwrap();

    assert_eq!(restored_microvm_state.vm_info, vm_info);

    // Verify deserialized data.
    // The default vmm has no devices and one vCPU.
    assert_eq!(restored_microvm_state.device_states.block_devices.len(), 0);
    assert_eq!(restored_microvm_state.device_states.net_devices.len(), 0);
    assert!(restored_microvm_state.device_states.vsock_device.is_none());
    assert_eq!(restored_microvm_state.vcpu_states.len(), 1);

    (snapshot_file, memory_file)
}

fn verify_load_snapshot(snapshot_file: TempFile, memory_file: TempFile) {
    use utils::vm_memory::GuestMemoryMmap;
    use vmm::memory_snapshot::SnapshotMemory;

    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();

    // Deserialize microVM state.
    let snapshot_file_metadata = snapshot_file.as_file().metadata().unwrap();
    let snapshot_len = snapshot_file_metadata.len() as usize;
    snapshot_file.as_file().seek(SeekFrom::Start(0)).unwrap();
    let (microvm_state, _) = Snapshot::load::<_, MicrovmState>(
        &mut snapshot_file.as_file(),
        snapshot_len,
        VERSION_MAP.clone(),
    )
    .unwrap();
    let mem = GuestMemoryMmap::restore(
        Some(memory_file.as_file()),
        &microvm_state.memory_state,
        false,
    )
    .unwrap();

    let vm_resources = &mut VmResources::default();

    // Build microVM from state.
    let vmm = build_microvm_from_snapshot(
        &InstanceInfo::default(),
        &mut event_manager,
        microvm_state,
        mem,
        None,
        false,
        &empty_seccomp_filters,
        vm_resources,
    )
    .unwrap();
    // For now we're happy we got this far, we don't test what the guest is actually doing.
    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

#[test]
fn test_create_and_load_snapshot() {
    // Create diff snapshot.
    let (snapshot_file, memory_file) = verify_create_snapshot(true);
    // Create a new microVm from snapshot. This only tests code-level logic; it verifies
    // that a microVM can be built with no errors from given snapshot.
    // It does _not_ verify that the guest is actually restored properly. We're using
    // python integration tests for that.
    verify_load_snapshot(snapshot_file, memory_file);

    // Create full snapshot.
    let (snapshot_file, memory_file) = verify_create_snapshot(false);
    // Create a new microVm from snapshot. This only tests code-level logic; it verifies
    // that a microVM can be built with no errors from given snapshot.
    // It does _not_ verify that the guest is actually restored properly. We're using
    // python integration tests for that.
    verify_load_snapshot(snapshot_file, memory_file);
}

#[test]
fn test_snapshot_load_sanity_checks() {
    use vmm::persist::SnapShotStateSanityCheckError;
    use vmm::vmm_config::machine_config::MAX_SUPPORTED_VCPUS;

    let mut microvm_state = get_microvm_state_from_snapshot();

    assert!(snapshot_state_sanity_check(&microvm_state).is_ok());

    // Remove memory regions.
    microvm_state.memory_state.regions.clear();

    // Validate sanity checks fail because there is no mem region in state.
    assert_eq!(
        snapshot_state_sanity_check(&microvm_state),
        Err(SnapShotStateSanityCheckError::NoMemory)
    );

    // Create MAX_SUPPORTED_VCPUS vCPUs starting from 1 vCPU.
    for _ in 0..MAX_SUPPORTED_VCPUS.ilog2() {
        microvm_state
            .vcpu_states
            .append(&mut microvm_state.vcpu_states.clone());
    }

    // After this line we will have 33 vCPUs, FC max si 32.
    microvm_state
        .vcpu_states
        .push(microvm_state.vcpu_states[0].clone());

    // Validate sanity checks fail because there are too many vCPUs.
    assert_eq!(
        snapshot_state_sanity_check(&microvm_state),
        Err(SnapShotStateSanityCheckError::InvalidVcpuCount)
    );

    // Remove all vCPUs states from microvm state.
    microvm_state.vcpu_states.clear();

    // Validate sanity checks fail because there is no vCPU in state.
    assert_eq!(
        snapshot_state_sanity_check(&microvm_state),
        Err(SnapShotStateSanityCheckError::InvalidVcpuCount)
    );
}

fn get_microvm_state_from_snapshot() -> MicrovmState {
    // Create a diff snapshot
    let (snapshot_file, _) = verify_create_snapshot(true);

    // Deserialize the microVM state.
    let snapshot_file_metadata = snapshot_file.as_file().metadata().unwrap();
    let snapshot_len = snapshot_file_metadata.len() as usize;
    snapshot_file.as_file().seek(SeekFrom::Start(0)).unwrap();
    let (state, _) = Snapshot::load(
        &mut snapshot_file.as_file(),
        snapshot_len,
        VERSION_MAP.clone(),
    )
    .unwrap();
    state
}
