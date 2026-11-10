#[cfg(feature = "afl_fuzz")]
#[macro_use]
extern crate afl;

use fuzzer::*;

#[cfg(feature = "afl_fuzz")]
afl_main!(fuzzing::target);

#[cfg(feature = "stdin_fuzz")]
stdin_main!(fuzzing::target);

/// Fuzzer for vCPU restore functionality
///
/// This fuzzer loads a randomized vcpu state and tries to execute KVM_RUN. It can catch the
/// following issues:
/// - Crashes during deserialization of vcpu states
/// - Inability to restore a vcpu state that was retrieved from a microvm
/// - crashes in KVM due to invalid vcpu states
mod fuzzing {
    use std::io::{Cursor, Write};
    use std::path::PathBuf;

    use bincode::Options;
    use serde::{Deserialize, Serialize};
    use vmm::persist::{MicrovmState, VirtioDevicesState, restore_from_snapshot};
    use vmm::resources::VmResources;
    use vmm::seccomp::get_empty_filters;
    use vmm::snapshot::Snapshot;
    use vmm::vmm_config::instance_info::InstanceInfo;
    use vmm::vmm_config::snapshot::{
        LoadSnapshotParams, MemBackendConfig, MemBackendType, SnapshotLoadHugePageConfig,
    };
    use vmm::{EventManager, FcExitCode};

    #[derive(Serialize, Deserialize, Debug)]
    pub struct FuzzData {
        pub snapfile: Vec<u8>,
        pub memfile: Vec<u8>,
    }

    pub const MAX_MEMORY: usize = 8 * 1024 * 1024; // 8MB

    pub fn target(input: &[u8]) {
        // Deserialize input into `FuzzData` or return early if it fails
        let mut data = match bincode::DefaultOptions::new()
            .allow_trailing_bytes()
            .with_limit(MAX_MEMORY as u64)
            .with_fixint_encoding()
            .deserialize::<FuzzData>(input)
        {
            Ok(data) => data,
            Err(_) => return,
        };

        if data.snapfile.len() < 8 {
            return;
        }

        // Ensure the CRC check always passes (as mutations that AFL does to the fuzz input are
        // very unlikely to result in a valid CRC).
        let crc_offset = data.snapfile.len() - 8;
        let checksum = crc64::crc64(0, &data.snapfile[..crc_offset]);
        data.snapfile[crc_offset..].copy_from_slice(&checksum.to_le_bytes());

        // Parse the snapshot state to determine the expected guest memory size, then extend
        // the memfd to that size as a sparse file. This avoids needing a full-size memory file —
        // the kernel lazily zero-fills pages beyond the fuzz data, similar to pmem/DAX semantics.
        let snap = Snapshot::<MicrovmState>::load(&mut Cursor::new(&data.snapfile)).ok();

        let required_mem_size = snap
            .as_ref()
            .map(|s| {
                s.data
                    .vm_state
                    .memory
                    .regions
                    .iter()
                    .fold(0u64, |acc, r| acc.saturating_add(r.size as u64))
            })
            .unwrap_or(0);

        // File::set_len calls `ftruncate64` under-the-hood on Linux. It takes `off64_t` as a
        // parameter, which is equivalent to `i64`
        if required_mem_size > i64::MAX as u64 {
            return;
        }

        // Remove any leftover vsock socket from a previous iteration to prevent
        // EADDRINUSE when the restore path calls UnixListener::bind().
        if let Some(snap) = &snap {
            let ds = &snap.data.device_states;
            let uds_path = match &ds.virtio_state {
                VirtioDevicesState::Mmio(state) => state
                    .vsock_device
                    .as_ref()
                    .map(|d| &d.device_state.backend.uds_path),
                VirtioDevicesState::Pci(state) => state
                    .virtio_devices
                    .vsock_device
                    .as_ref()
                    .map(|d| &d.device_state.backend.uds_path),
            };
            if let Some(path) = uds_path {
                let _ = std::fs::remove_file(path);
            }
        }

        let (mut memory_file, memory_path) = fuzzer::make_memfd("snap_mem");
        memory_file.write_all(&data.memfile).unwrap();
        if required_mem_size > data.memfile.len() as u64 {
            memory_file.set_len(required_mem_size).unwrap();
        }
        let (mut state_file, state_path) = fuzzer::make_memfd("snap_state");
        state_file.write_all(&data.snapfile).unwrap();

        // Pmem restore mmaps its backing file — create a dummy one via memfd so the
        // initial (un-mutated) seed can proceed past pmem device initialization.
        // The path is baked into the snapshot state; we just need the fd alive.
        let (mut pmem_file, _pmem_path) = fuzzer::make_memfd("snap_pmem");
        pmem_file.write_all(&[0u8; 4096]).unwrap();

        let vm_resources = &mut VmResources::default();
        let mut event_manager = EventManager::new().unwrap();
        let empty_seccomp_filters = get_empty_filters();

        let load_params = LoadSnapshotParams {
            snapshot_path: PathBuf::from(state_path),
            mem_backend: MemBackendConfig {
                backend_path: PathBuf::from(memory_path),
                backend_type: MemBackendType::File,
            },
            track_dirty_pages: false,
            resume_vm: true,
            network_overrides: vec![],
            vsock_override: None,
            drive_overrides: vec![],
            pmem_overrides: vec![],
            clock_realtime: false,
            huge_pages: SnapshotLoadHugePageConfig::Snapshot,
        };

        let Ok(vmm) = restore_from_snapshot(
            &InstanceInfo::default(),
            &mut event_manager,
            &empty_seccomp_filters,
            &load_params,
            vm_resources,
        ) else {
            return;
        };

        vmm.lock().unwrap().stop(FcExitCode::Ok);
    }
}

#[cfg(test)]
mod seed_gen {
    //! Module containing "unit tests" that do not test things but rather generate input seeds for
    //! AFL

    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;

    use vmm::EventManager;
    use vmm::builder::build_microvm_for_boot;
    use vmm::devices::virtio::block::CacheType;
    use vmm::persist::{VmInfo, create_snapshot};
    use vmm::resources::VmResources;
    use vmm::seccomp::get_empty_filters;
    use vmm::vmm_config::balloon::{BalloonBuilder, BalloonDeviceConfig};
    use vmm::vmm_config::boot_source::BootSourceConfig;
    use vmm::vmm_config::drive::{BlockBuilder, BlockDeviceConfig, FileEngineType};
    use vmm::vmm_config::entropy::{EntropyDeviceBuilder, EntropyDeviceConfig};
    use vmm::vmm_config::instance_info::InstanceInfo;
    use vmm::vmm_config::machine_config::{HugePageConfig, MachineConfig};
    use vmm::vmm_config::memory_hotplug::MemoryHotplugConfig;
    use vmm::vmm_config::net::NetBuilder;
    use vmm::vmm_config::pmem::{PmemBuilder, PmemConfig};
    use vmm::vmm_config::snapshot::{CreateSnapshotParams, SnapshotType};
    use vmm::vmm_config::vsock::{VsockBuilder, VsockDeviceConfig};

    use crate::fuzzing::FuzzData;

    fn generate_seed(pci_enabled: bool, seed_name: &str) {
        let mut event_manager = EventManager::new().unwrap();
        let mut block_builder = BlockBuilder::new();
        block_builder
            .insert(
                BlockDeviceConfig {
                    drive_id: "block".to_string(),
                    partuuid: None,
                    is_root_device: false,
                    cache_type: CacheType::Writeback,
                    is_read_only: None,
                    discard: None,
                    num_queues: None,
                    path_on_host: Some("/dev/null".into()),
                    rate_limiter: None,
                    file_engine_type: Some(FileEngineType::Sync),
                    blk_size: None,
                    topology: None,
                    socket: None,
                    ..Default::default()
                },
                false,
            )
            .unwrap();
        let mut vsock_builder = VsockBuilder::new();
        let vsock_uds_path = format!("/tmp/fuzzer-vsock-{seed_name}.sock");
        // Remove any stale socket from a previous run.
        let _ = std::fs::remove_file(&vsock_uds_path);
        vsock_builder
            .insert(VsockDeviceConfig {
                vsock_id: Some("vsock0".to_string()),
                guest_cid: 3,
                uds_path: vsock_uds_path,
                dmb_size_mib: None,
            })
            .unwrap();
        let mut balloon_builder = BalloonBuilder::new();
        balloon_builder
            .set(BalloonDeviceConfig {
                amount_mib: 64,
                deflate_on_oom: false,
                stats_polling_interval_s: 0,
                free_page_reporting: true,
                free_page_hinting: true,
            })
            .unwrap();
        // Net omitted — restore needs TAP, which would block other device restore paths.
        let net_builder = NetBuilder::new();
        let mut entropy_builder = EntropyDeviceBuilder::new();
        entropy_builder
            .insert(EntropyDeviceConfig { rate_limiter: None })
            .unwrap();
        let pmem_builder = PmemBuilder::default();
        let mut vm_resources = VmResources {
            machine_config: MachineConfig {
                vcpu_count: 1,
                mem_size_mib: 128,
                smt: false,
                cpu_template: None,
                track_dirty_pages: false,
                huge_pages: HugePageConfig::None,
                pcie_hotplug_ports: 0,
            },
            boot_source: Default::default(),
            block: block_builder,
            vsock: vsock_builder,
            balloon: balloon_builder,
            net_builder: net_builder,
            entropy: entropy_builder,
            mmds: None,
            mmds_size_limit: 0,
            boot_timer: false,
            pci_enabled,
            pmem: pmem_builder,
            serial_out_path: None,
            serial_rate_limiter_cfg: None,
            memory_hotplug: None,
            ..Default::default()
        };
        let current_artifacts_path = std::fs::read_to_string("../build/current_artifacts").unwrap();
        let full_artifacts_path = format!("../{}/", current_artifacts_path.trim());
        // try and find a kernel. cant hardcode the path because the patch version might change
        let kernel_image_path = std::fs::read_dir(full_artifacts_path)
            .unwrap()
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                let file_name = entry.file_name(); // temp var for lifetime reasons
                let file_name = file_name.to_str().unwrap();

                file_name.starts_with("vmlinux") && !file_name.ends_with(".config")
            })
            .next()
            .unwrap()
            .path()
            .to_str()
            .unwrap()
            .into();

        vm_resources
            .build_boot_source(BootSourceConfig {
                kernel_image_path,
                initrd_path: None,
                boot_args: None,
            })
            .unwrap();

        // Pmem needs a real backing file — use memfd for a stable /proc/self/fd path.
        let (mut pmem_file, pmem_path) = fuzzer::make_memfd("seed_pmem");
        pmem_file.write_all(&[0u8; 4096]).unwrap();
        vm_resources
            .build_pmem_device(PmemConfig {
                id: "pmem0".to_string(),
                path_on_host: pmem_path,
                root_device: false,
                read_only: true,
                rate_limiter: None,
            })
            .unwrap();

        // Add memory hotplug
        vm_resources
            .set_memory_hotplug_config(MemoryHotplugConfig {
                total_size_mib: 256,
                block_size_mib: 128,
                slot_size_mib: 128,
            })
            .unwrap();

        let vmm = build_microvm_for_boot(
            &InstanceInfo::default(),
            &vm_resources,
            &mut event_manager,
            &get_empty_filters(),
        )
        .unwrap();
        let vm_info = VmInfo::from(&vm_resources);

        let _ = std::fs::create_dir_all("in/snapshot");
        let state_file = PathBuf::from(format!("in/snapshot/{seed_name}.in"));
        let throwaway_file = PathBuf::from(format!("throwaway-{seed_name}-please-delete-me"));

        let snapshot_params = CreateSnapshotParams {
            snapshot_type: SnapshotType::Full,
            snapshot_path: state_file.clone(),
            mem_file_path: throwaway_file.clone(),
            sync_snapshot_files: true,
        };
        let mut locked_vmm = vmm.lock().unwrap();
        create_snapshot(&mut locked_vmm, &vm_info, &snapshot_params).unwrap();

        std::fs::remove_file(throwaway_file).unwrap();

        let state = std::fs::read(&state_file).unwrap();

        let fuzz_data = FuzzData {
            snapfile: state,
            // Using a full memory file would be way too large (each fuzz iteration would be way too
            // slow), so just use a little scratch area of RAM
            memfile: vec![0; 8096],
        };
        let seed_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(state_file)
            .unwrap();
        bincode::serialize_into(seed_file, &fuzz_data).unwrap();
    }

    #[test]
    fn generate_valid_state() {
        generate_seed(false, &format!("{}_mmio", std::env::consts::ARCH));
    }

    #[test]
    fn generate_valid_state_pci() {
        generate_seed(true, &format!("{}_pci", std::env::consts::ARCH));
    }
}
