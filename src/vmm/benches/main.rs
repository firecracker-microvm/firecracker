// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Benchmark testing
//
// Test serialization and deserialzation of a MicrovmState for a default VMM:
//  - 1 VCPU
//  - 128 MB memory size
//  - no devices

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use snapshot::Snapshot;
use std::path::Path;
use std::thread;
use std::time::Duration;
use utils::tempfile::TempFile;
use versionize::VersionMap;
use vmm::persist;
use vmm::persist::MicrovmState;
use vmm::utilities::mock_resources::NOISY_KERNEL_IMAGE;
use vmm::utilities::test_utils::{create_vmm, set_panic_hook, wait_vmm_child_process};
use vmm::version_map::VERSION_MAP;
use vmm::vmm_config::snapshot::{CreateSnapshotParams, SnapshotType};

#[inline]
pub fn bench_restore_snapshot(
    mut snapshot_reader: &[u8],
    snapshot_len: usize,
    vm: VersionMap,
    crc: bool,
) {
    if crc {
        Snapshot::load::<&[u8], MicrovmState>(&mut snapshot_reader, snapshot_len, vm).unwrap();
    } else {
        Snapshot::unchecked_load::<&[u8], MicrovmState>(&mut snapshot_reader, vm).unwrap();
    }
}

#[inline]
pub fn bench_create_snapshot<W: std::io::Write>(
    mut snapshot_writer: &mut W,
    vm: VersionMap,
    crc: bool,
    state: &mut MicrovmState,
) {
    let mut snapshot = Snapshot::new(vm.clone(), vm.latest_version());

    if crc {
        snapshot.save(&mut snapshot_writer, state).unwrap();
    } else {
        snapshot
            .save_without_crc(&mut snapshot_writer, state)
            .unwrap();
    }
}

fn create_microvm_state(is_diff: bool) -> MicrovmState {
    let snapshot_file = TempFile::new().unwrap();
    let memory_file = TempFile::new().unwrap();

    let pid = unsafe { libc::fork() };
    match pid {
        0 => {
            set_panic_hook();

            let (vmm, _) = create_vmm(Some(NOISY_KERNEL_IMAGE), is_diff);

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
                version: None,
            };

            {
                let mut locked_vmm = vmm.lock().unwrap();
                persist::create_snapshot(&mut locked_vmm, &snapshot_params, VERSION_MAP.clone())
                    .unwrap();
            }

            vmm.lock().unwrap().stop();
        }
        vmm_pid => {
            // Parent process: wait for the vmm to exit.
            wait_vmm_child_process(vmm_pid);
        }
    }

    // Deserialize the microVM state from `snapshot_file`.
    let snapshot_path = snapshot_file.as_path().to_path_buf();
    let snapshot_file_metadata = std::fs::metadata(snapshot_path).unwrap();
    let snapshot_len = snapshot_file_metadata.len() as usize;
    let microvm_state: MicrovmState = Snapshot::load(
        &mut snapshot_file.as_file(),
        snapshot_len,
        VERSION_MAP.clone(),
    )
    .unwrap();

    microvm_state
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let version_map = VERSION_MAP.clone();

    // Create the microvm state
    let mut state = create_microvm_state(false);

    // Setup benchmarking with CRC
    let mut snapshot_state_with_crc = vec![0u8; 1024 * 1024 * 128];
    let mut slice = &mut snapshot_state_with_crc.as_mut_slice();
    bench_create_snapshot(&mut slice, version_map.clone(), true, &mut state);
    let snapshot_len =
        slice.as_ptr() as usize - snapshot_state_with_crc.as_slice().as_ptr() as usize;
    println!("Snapshot length with CRC: {} bytes.", snapshot_len);

    c.bench_function("Serialize MicrovmState CRC", |b| {
        b.iter(|| {
            bench_create_snapshot(
                &mut snapshot_state_with_crc.as_mut_slice(),
                black_box(version_map.clone()),
                black_box(true),
                black_box(&mut state),
            )
        })
    });

    c.bench_function("Deserialize MicrovmState CRC", |b| {
        b.iter(|| {
            bench_restore_snapshot(
                &mut snapshot_state_with_crc.as_mut_slice(),
                black_box(snapshot_len),
                black_box(version_map.clone()),
                black_box(true),
            )
        })
    });

    // Setup benchmarking without CRC
    let mut snapshot_state_without_crc = vec![0u8; 1024 * 1024 * 128];
    let mut slice = &mut snapshot_state_without_crc.as_mut_slice();
    bench_create_snapshot(&mut slice, version_map.clone(), false, &mut state);
    let snapshot_len =
        slice.as_ptr() as usize - snapshot_state_without_crc.as_slice().as_ptr() as usize;
    println!("Snapshot length without CRC: {} bytes.", snapshot_len);

    c.bench_function("Serialize MicrovmState", |b| {
        b.iter(|| {
            bench_create_snapshot(
                black_box(&mut snapshot_state_without_crc.as_mut_slice()),
                black_box(version_map.clone()),
                black_box(false),
                black_box(&mut state),
            )
        })
    });

    c.bench_function("Deserialize MicrovmState", |b| {
        b.iter(|| {
            bench_restore_snapshot(
                black_box(&mut snapshot_state_without_crc.as_mut_slice()),
                black_box(snapshot_len),
                black_box(version_map.clone()),
                black_box(false),
            )
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(200).output_directory(Path::new("../../build/vmm_benchmark"));
    targets = criterion_benchmark
}

criterion_main! {
    benches
}
