// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines state structures for saving/restoring a Firecracker microVM.

use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::builder::{self, StartMicrovmError};
use crate::device_manager::persist::Error as DevicePersistError;
use crate::mem_size_mib;
use crate::vmm_config::machine_config::MAX_SUPPORTED_VCPUS;
use crate::vmm_config::snapshot::{CreateSnapshotParams, LoadSnapshotParams, SnapshotType};
use crate::vstate::{self, vcpu::VcpuState, vm::VmState};

use crate::device_manager::persist::DeviceStates;
use crate::memory_snapshot;
use crate::memory_snapshot::{GuestMemoryState, SnapshotMemory};
#[cfg(target_arch = "x86_64")]
use crate::version_map::FC_V0_23_SNAP_VERSION;
use crate::version_map::{FC_V1_0_SNAP_VERSION, FC_VERSION_TO_SNAP_VERSION};
use crate::{Error as VmmError, EventManager, Vmm};
#[cfg(target_arch = "x86_64")]
use cpuid::common::{get_vendor_id_from_cpuid, get_vendor_id_from_host};

use crate::vmm_config::instance_info::InstanceInfo;
#[cfg(target_arch = "aarch64")]
use arch::regs::{get_manufacturer_id_from_host, get_manufacturer_id_from_state};
use logger::{error, info};
use seccompiler::BpfThreadMap;
use snapshot::Snapshot;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use virtio_gen::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::GuestMemoryMmap;

#[cfg(target_arch = "x86_64")]
const FC_V0_23_MAX_DEVICES: u32 = 11;

/// Holds information related to the VM that is not part of VmState.
#[derive(Debug, PartialEq, Versionize)]
// NOTICE: Any changes to this structure require a snapshot version bump.
pub struct VmInfo {
    /// Guest memory size.
    pub mem_size_mib: u64,
}

/// Contains the necesary state for saving/restoring a microVM.
#[derive(Versionize)]
// NOTICE: Any changes to this structure require a snapshot version bump.
pub struct MicrovmState {
    /// Miscellaneous VM info.
    pub vm_info: VmInfo,
    /// Memory state.
    pub memory_state: GuestMemoryState,
    /// VM KVM state.
    pub vm_state: VmState,
    /// Vcpu states.
    pub vcpu_states: Vec<VcpuState>,
    /// Device states.
    pub device_states: DeviceStates,
}

/// Errors related to saving and restoring Microvm state.
#[derive(Debug)]
pub enum MicrovmStateError {
    /// Compatibility checks failed.
    IncompatibleState(String),
    /// Provided MicroVM state is invalid.
    InvalidInput,
    /// Operation not allowed.
    NotAllowed(String),
    /// Failed to restore devices.
    RestoreDevices(DevicePersistError),
    /// Failed to restore Vcpu state.
    RestoreVcpuState(vstate::vcpu::Error),
    /// Failed to restore VM state.
    RestoreVmState(vstate::vm::Error),
    /// Failed to save Vcpu state.
    SaveVcpuState(vstate::vcpu::Error),
    /// Failed to save VM state.
    SaveVmState(vstate::vm::Error),
    /// Failed to send event.
    SignalVcpu(vstate::vcpu::Error),
    /// Vcpu is in unexpected state.
    UnexpectedVcpuResponse,
}

impl Display for MicrovmStateError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::MicrovmStateError::*;
        match self {
            IncompatibleState(msg) => write!(f, "Compatibility checks failed: {}", msg),
            InvalidInput => write!(f, "Provided MicroVM state is invalid."),
            NotAllowed(msg) => write!(f, "Operation not allowed: {}", msg),
            RestoreDevices(err) => write!(f, "Cannot restore devices. Error: {:?}", err),
            RestoreVcpuState(err) => write!(f, "Cannot restore Vcpu state. Error: {:?}", err),
            RestoreVmState(err) => write!(f, "Cannot restore Vm state. Error: {:?}", err),
            SaveVcpuState(err) => write!(f, "Cannot save Vcpu state. Error: {:?}", err),
            SaveVmState(err) => write!(f, "Cannot save Vm state. Error: {:?}", err),
            SignalVcpu(err) => write!(f, "Cannot signal Vcpu: {:?}", err),
            UnexpectedVcpuResponse => write!(f, "Vcpu is in unexpected state."),
        }
    }
}

/// Errors associated with creating a snapshot.
#[derive(Debug)]
pub enum CreateSnapshotError {
    /// Failed to get dirty bitmap.
    DirtyBitmap(VmmError),
    /// The virtio devices uses a features that is incompatible with older versions of Firecracker.
    IncompatibleVirtioFeature(&'static str),
    /// Invalid microVM version format
    InvalidVersionFormat,
    /// MicroVM version does not support snapshot.
    UnsupportedVersion,
    /// Failed to write memory to snapshot.
    Memory(memory_snapshot::Error),
    /// Failed to open memory backing file.
    MemoryBackingFile(&'static str, io::Error),
    /// Failed to save MicrovmState.
    MicrovmState(MicrovmStateError),
    /// Failed to serialize microVM state.
    SerializeMicrovmState(snapshot::Error),
    /// Failed to open the snapshot backing file.
    SnapshotBackingFile(&'static str, io::Error),
    #[cfg(target_arch = "x86_64")]
    /// Number of devices exceeds the maximum supported devices for the snapshot data version.
    TooManyDevices(usize),
}

impl Display for CreateSnapshotError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::CreateSnapshotError::*;
        match self {
            DirtyBitmap(err) => write!(f, "Cannot get dirty bitmap: {}", err),
            IncompatibleVirtioFeature(feature) => write!(
                f,
                "The virtio devices use a features that is incompatible \
                with older versions of Firecracker: {}",
                feature
            ),
            InvalidVersionFormat => write!(f, "Invalid microVM version format"),
            UnsupportedVersion => write!(
                f,
                "Cannot translate microVM version to snapshot data version",
            ),
            Memory(err) => write!(f, "Cannot write memory file: {}", err),
            MemoryBackingFile(action, err) => write!(
                f,
                "Cannot perform {} on the memory backing file: {}",
                action, err
            ),
            MicrovmState(err) => write!(f, "Cannot save the microVM state: {}", err),
            SerializeMicrovmState(err) => {
                write!(f, "Cannot serialize the microVM state: {:?}", err)
            }
            SnapshotBackingFile(action, err) => write!(
                f,
                "Cannot perform {} on the snapshot backing file: {}",
                action, err
            ),
            #[cfg(target_arch = "x86_64")]
            TooManyDevices(val) => write!(
                f,
                "Too many devices attached: {}. The maximum number allowed \
                 for the snapshot data version requested is {}.",
                val, FC_V0_23_MAX_DEVICES
            ),
        }
    }
}

/// Errors associated with loading a snapshot.
#[derive(Debug)]
pub enum LoadSnapshotError {
    /// Failed to build a microVM from snapshot.
    BuildMicroVm(StartMicrovmError),
    /// Failed to deserialize memory.
    DeserializeMemory(memory_snapshot::Error),
    /// Failed to deserialize microVM state.
    DeserializeMicrovmState(snapshot::Error),
    /// Failed to open memory backing file.
    MemoryBackingFile(io::Error),
    /// Failed to resume Vm after loading snapshot.
    ResumeMicroVm(VmmError),
    /// Failed to open the snapshot backing file.
    SnapshotBackingFile(&'static str, io::Error),
    /// Snapshot cpu vendor differs than host cpu vendor.
    CpuVendorCheck(String),
    /// Snapshot failed sanity checks.
    InvalidSnapshot(String),
}

impl Display for LoadSnapshotError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::LoadSnapshotError::*;
        match self {
            BuildMicroVm(err) => write!(f, "Cannot build a microVM from snapshot: {}", err),
            DeserializeMemory(err) => write!(f, "Cannot deserialize memory: {}", err),
            DeserializeMicrovmState(err) => {
                write!(f, "Cannot deserialize the microVM state: {:?}", err)
            }
            MemoryBackingFile(err) => write!(f, "Cannot open the memory file: {}", err),
            ResumeMicroVm(err) => write!(
                f,
                "Failed to resume microVM after loading snapshot: {}",
                err
            ),
            SnapshotBackingFile(action, err) => write!(
                f,
                "Cannot perform {} on the snapshot backing file: {}",
                action, err
            ),
            CpuVendorCheck(err) => write!(f, "CPU vendor check failed: {}", err),
            InvalidSnapshot(err) => write!(f, "Snapshot sanity check failed: {}", err),
        }
    }
}

/// Creates a Microvm snapshot.
pub fn create_snapshot(
    vmm: &mut Vmm,
    params: &CreateSnapshotParams,
    version_map: VersionMap,
) -> std::result::Result<(), CreateSnapshotError> {
    // Fail early from invalid target version.
    let snapshot_data_version = get_snapshot_data_version(&params.version, &version_map, &vmm)?;

    let microvm_state = vmm
        .save_state()
        .map_err(CreateSnapshotError::MicrovmState)?;

    snapshot_state_to_file(
        &microvm_state,
        &params.snapshot_path,
        snapshot_data_version,
        version_map,
    )?;

    snapshot_memory_to_file(vmm, &params.mem_file_path, &params.snapshot_type)?;

    Ok(())
}

fn snapshot_state_to_file(
    microvm_state: &MicrovmState,
    snapshot_path: &Path,
    snapshot_data_version: u16,
    version_map: VersionMap,
) -> std::result::Result<(), CreateSnapshotError> {
    use self::CreateSnapshotError::*;
    let mut snapshot_file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(snapshot_path)
        .map_err(|e| SnapshotBackingFile("open", e))?;

    let mut snapshot = Snapshot::new(version_map, snapshot_data_version);
    snapshot
        .save(&mut snapshot_file, microvm_state)
        .map_err(SerializeMicrovmState)?;
    snapshot_file
        .flush()
        .map_err(|e| SnapshotBackingFile("flush", e))?;
    snapshot_file
        .sync_all()
        .map_err(|e| SnapshotBackingFile("sync_all", e))
}

fn snapshot_memory_to_file(
    vmm: &Vmm,
    mem_file_path: &Path,
    snapshot_type: &SnapshotType,
) -> std::result::Result<(), CreateSnapshotError> {
    use self::CreateSnapshotError::*;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(mem_file_path)
        .map_err(|e| MemoryBackingFile("open", e))?;

    // Set the length of the file to the full size of the memory area.
    let mem_size_mib = mem_size_mib(vmm.guest_memory());
    file.set_len((mem_size_mib * 1024 * 1024) as u64)
        .map_err(|e| MemoryBackingFile("set_length", e))?;

    match snapshot_type {
        SnapshotType::Diff => {
            let dirty_bitmap = vmm.get_dirty_bitmap().map_err(DirtyBitmap)?;
            vmm.guest_memory()
                .dump_dirty(&mut file, &dirty_bitmap)
                .map_err(Memory)
        }
        SnapshotType::Full => vmm.guest_memory().dump(&mut file).map_err(Memory),
    }?;
    file.flush().map_err(|e| MemoryBackingFile("flush", e))?;
    file.sync_all()
        .map_err(|e| MemoryBackingFile("sync_all", e))
}

/// Validate the microVM version and translate it to its corresponding snapshot data format.
pub fn get_snapshot_data_version(
    maybe_fc_version: &Option<String>,
    version_map: &VersionMap,
    vmm: &Vmm,
) -> std::result::Result<u16, CreateSnapshotError> {
    let fc_version = match maybe_fc_version {
        None => return Ok(version_map.latest_version()),
        Some(version) => version,
    };
    validate_fc_version_format(fc_version)?;
    let data_version = *FC_VERSION_TO_SNAP_VERSION
        .get(fc_version)
        .ok_or(CreateSnapshotError::UnsupportedVersion)?;

    #[cfg(target_arch = "x86_64")]
    if data_version <= FC_V0_23_SNAP_VERSION {
        validate_devices_number(vmm.mmio_device_manager.used_irqs_count())?;
    }

    if data_version < FC_V1_0_SNAP_VERSION {
        vmm.mmio_device_manager
            .for_each_virtio_device(|_virtio_type, _id, _info, dev| {
                if dev
                    .lock()
                    .expect("Poisoned lock")
                    .has_feature(u64::from(VIRTIO_RING_F_EVENT_IDX))
                {
                    return Err(CreateSnapshotError::IncompatibleVirtioFeature(
                        "notification suppression",
                    ));
                }
                Ok(())
            })?;
    }

    Ok(data_version)
}

/// Validates that snapshot CPU vendor matches the host CPU vendor.
#[cfg(target_arch = "x86_64")]
pub fn validate_cpu_vendor(
    microvm_state: &MicrovmState,
) -> std::result::Result<(), LoadSnapshotError> {
    let host_vendor_id = get_vendor_id_from_host().map_err(|_| {
        LoadSnapshotError::CpuVendorCheck("Failed to read vendor from host.".to_owned())
    })?;

    let snapshot_vendor_id = get_vendor_id_from_cpuid(&microvm_state.vcpu_states[0].cpuid)
        .map_err(|_| {
            error!("Snapshot CPU vendor is missing.");
            LoadSnapshotError::CpuVendorCheck("Failed to read vendor from CPUID.".to_owned())
        })?;

    if host_vendor_id != snapshot_vendor_id {
        let error_string = format!(
            "Host CPU vendor id: {:?} differs from the snapshotted one: {:?}",
            &host_vendor_id, &snapshot_vendor_id
        );
        error!("{}", error_string);
        return Err(LoadSnapshotError::CpuVendorCheck(error_string));
    } else {
        info!("Snapshot CPU vendor id: {:?}", &snapshot_vendor_id);
    }

    Ok(())
}

/// Validate that Snapshot Manufacturer ID matches
/// the one from the Host
///
/// The manufacturer ID for the Snapshot is taken from each VCPU state.
#[cfg(target_arch = "aarch64")]
pub fn validate_cpu_manufacturer_id(
    microvm_state: &MicrovmState,
) -> std::result::Result<(), LoadSnapshotError> {
    let host_man_id = get_manufacturer_id_from_host()
        .map_err(|e| LoadSnapshotError::CpuVendorCheck(e.to_string()))?;

    for state in &microvm_state.vcpu_states {
        let state_man_id = get_manufacturer_id_from_state(state.regs.as_slice())
            .map_err(|e| LoadSnapshotError::CpuVendorCheck(e.to_string()))?;

        if host_man_id != state_man_id {
            let error_string = format!(
                "Host CPU manufacturer ID: {} differs from snapshotted one: {}",
                &host_man_id, &state_man_id
            );
            error!("{}", error_string);
            return Err(LoadSnapshotError::CpuVendorCheck(error_string));
        } else {
            info!("Snapshot CPU manufacturer ID: {:?}", &state_man_id);
        }
    }

    Ok(())
}

/// Performs sanity checks against the state file and returns specific errors.
pub fn snapshot_state_sanity_check(
    microvm_state: &MicrovmState,
) -> std::result::Result<(), LoadSnapshotError> {
    // Check if the snapshot contains at least 1 vCPU state entry.
    if microvm_state.vcpu_states.is_empty()
        || microvm_state.vcpu_states.len() > MAX_SUPPORTED_VCPUS.into()
    {
        return Err(LoadSnapshotError::InvalidSnapshot(
            "Invalid vCPU count.".to_owned(),
        ));
    }

    // Check if the snapshot contains at least 1 mem region.
    // Upper bound check will be done when creating guest memory by comparing against
    // KVM max supported value kvm_context.max_memslots().
    if microvm_state.memory_state.regions.is_empty() {
        return Err(LoadSnapshotError::InvalidSnapshot(
            "No memory region defined.".to_owned(),
        ));
    }

    #[cfg(target_arch = "x86_64")]
    validate_cpu_vendor(&microvm_state)?;
    #[cfg(target_arch = "aarch64")]
    validate_cpu_manufacturer_id(&microvm_state)?;

    Ok(())
}

/// Loads a Microvm snapshot producing a 'paused' Microvm.
pub fn restore_from_snapshot(
    instance_info: &InstanceInfo,
    event_manager: &mut EventManager,
    seccomp_filters: &BpfThreadMap,
    params: &LoadSnapshotParams,
    version_map: VersionMap,
) -> std::result::Result<Arc<Mutex<Vmm>>, LoadSnapshotError> {
    use self::LoadSnapshotError::*;
    let track_dirty_pages = params.enable_diff_snapshots;
    let microvm_state = snapshot_state_from_file(&params.snapshot_path, version_map)?;

    // Some sanity checks before building the microvm.
    snapshot_state_sanity_check(&microvm_state)?;

    let guest_memory = guest_memory_from_file(
        &params.mem_file_path,
        &microvm_state.memory_state,
        track_dirty_pages,
    )?;
    builder::build_microvm_from_snapshot(
        instance_info,
        event_manager,
        microvm_state,
        guest_memory,
        track_dirty_pages,
        seccomp_filters,
    )
    .map_err(BuildMicroVm)
}

fn snapshot_state_from_file(
    snapshot_path: &Path,
    version_map: VersionMap,
) -> std::result::Result<MicrovmState, LoadSnapshotError> {
    use self::LoadSnapshotError::{DeserializeMicrovmState, SnapshotBackingFile};
    let mut snapshot_reader =
        File::open(snapshot_path).map_err(|e| SnapshotBackingFile("open", e))?;
    let metadata = std::fs::metadata(snapshot_path)
        .map_err(|e| SnapshotBackingFile("metadata retrieval", e))?;
    let snapshot_len = metadata.len() as usize;
    Snapshot::load(&mut snapshot_reader, snapshot_len, version_map).map_err(DeserializeMicrovmState)
}

fn guest_memory_from_file(
    mem_file_path: &Path,
    mem_state: &GuestMemoryState,
    track_dirty_pages: bool,
) -> std::result::Result<GuestMemoryMmap, LoadSnapshotError> {
    use self::LoadSnapshotError::{DeserializeMemory, MemoryBackingFile};
    let mem_file = File::open(mem_file_path).map_err(MemoryBackingFile)?;
    GuestMemoryMmap::restore(&mem_file, mem_state, track_dirty_pages).map_err(DeserializeMemory)
}

#[cfg(target_arch = "x86_64")]
fn validate_devices_number(device_number: usize) -> std::result::Result<(), CreateSnapshotError> {
    use self::CreateSnapshotError::TooManyDevices;
    if device_number > FC_V0_23_MAX_DEVICES as usize {
        return Err(TooManyDevices(device_number));
    }
    Ok(())
}

fn validate_fc_version_format(version: &str) -> Result<(), CreateSnapshotError> {
    let v: Vec<_> = version.match_indices('.').collect();
    if v.len() != 2
        || version[v[0].0..]
            .trim_start_matches('.')
            .parse::<f32>()
            .is_err()
        || version[..v[1].0].parse::<f32>().is_err()
    {
        Err(CreateSnapshotError::InvalidVersionFormat)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::tests::{
        default_kernel_cmdline, default_vmm, insert_balloon_device, insert_block_devices,
        insert_net_device, insert_vsock_device, CustomBlockConfig,
    };
    #[cfg(target_arch = "aarch64")]
    use crate::construct_kvm_mpidrs;
    use crate::memory_snapshot::SnapshotMemory;
    use crate::version_map::{FC_VERSION_TO_SNAP_VERSION, VERSION_MAP};
    use crate::vmm_config::balloon::BalloonDeviceConfig;
    use crate::vmm_config::drive::CacheType;
    use crate::vmm_config::net::NetworkInterfaceConfig;
    use crate::vmm_config::vsock::tests::default_config;
    use crate::Vmm;

    use snapshot::Persist;
    use utils::{errno, tempfile::TempFile};

    #[cfg(target_arch = "aarch64")]
    const FC_VERSION_0_23_0: &str = "0.23.0";

    fn default_vmm_with_devices() -> Vmm {
        let mut event_manager = EventManager::new().expect("Cannot create EventManager");
        let mut vmm = default_vmm();
        let mut cmdline = default_kernel_cmdline();

        // Add a balloon device.
        let balloon_config = BalloonDeviceConfig {
            amount_mib: 0,
            deflate_on_oom: false,
            stats_polling_interval_s: 0,
        };
        insert_balloon_device(&mut vmm, &mut cmdline, &mut event_manager, balloon_config);

        // Add a block device.
        let drive_id = String::from("root");
        let block_configs = vec![CustomBlockConfig::new(
            drive_id,
            true,
            None,
            true,
            CacheType::Unsafe,
        )];
        insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);

        // Add net device.
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        };
        insert_net_device(
            &mut vmm,
            &mut cmdline,
            &mut event_manager,
            network_interface,
        );

        // Add vsock device.
        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        let vsock_config = default_config(&tmp_sock_file);

        insert_vsock_device(&mut vmm, &mut cmdline, &mut event_manager, vsock_config);

        vmm
    }

    #[test]
    fn test_microvmstate_versionize() {
        let vmm = default_vmm_with_devices();
        let states = vmm.mmio_device_manager.save();

        // Only checking that all devices are saved, actual device state
        // is tested by that device's tests.
        assert_eq!(states.block_devices.len(), 1);
        assert_eq!(states.net_devices.len(), 1);
        assert!(states.vsock_device.is_some());
        assert!(states.balloon_device.is_some());

        let memory_state = vmm.guest_memory().describe();
        let vcpu_states = vec![VcpuState::default()];
        #[cfg(target_arch = "aarch64")]
        let mpidrs = construct_kvm_mpidrs(&vcpu_states);
        let microvm_state = MicrovmState {
            device_states: states,
            memory_state,
            vcpu_states,
            vm_info: VmInfo { mem_size_mib: 1u64 },
            #[cfg(target_arch = "aarch64")]
            vm_state: vmm.vm.save_state(&mpidrs).unwrap(),
            #[cfg(target_arch = "x86_64")]
            vm_state: vmm.vm.save_state().unwrap(),
        };

        let mut buf = vec![0; 10000];
        let mut version_map = VersionMap::new();

        assert!(microvm_state
            .serialize(&mut buf.as_mut_slice(), &version_map, 1)
            .is_err());

        version_map
            .new_version()
            .set_type_version(DeviceStates::type_id(), 2);
        microvm_state
            .serialize(&mut buf.as_mut_slice(), &version_map, 2)
            .unwrap();

        let restored_microvm_state =
            MicrovmState::deserialize(&mut buf.as_slice(), &version_map, 2).unwrap();

        assert_eq!(restored_microvm_state.vm_info, microvm_state.vm_info);
        assert_eq!(
            restored_microvm_state.device_states,
            microvm_state.device_states
        )
    }

    #[test]
    fn test_get_snapshot_data_version() {
        let vmm = default_vmm_with_devices();

        assert_eq!(
            VERSION_MAP.latest_version(),
            get_snapshot_data_version(&None, &VERSION_MAP, &vmm).unwrap()
        );
        // Validate sanity checks fail because of invalid target version.
        assert!(get_snapshot_data_version(&Some(String::from("foo")), &VERSION_MAP, &vmm).is_err());

        for version in FC_VERSION_TO_SNAP_VERSION.keys() {
            let res = get_snapshot_data_version(&Some(version.to_owned()), &VERSION_MAP, &vmm);

            #[cfg(target_arch = "x86_64")]
            assert!(res.is_ok());

            #[cfg(target_arch = "aarch64")]
            match version.as_str() {
                // Validate sanity checks fail because aarch64 does not support "0.23.0"
                // snapshot target version.
                FC_VERSION_0_23_0 => assert!(res.is_err()),
                _ => assert!(res.is_ok()),
            }
        }

        assert!(
            get_snapshot_data_version(&Some("a.bb.c".to_string()), &VERSION_MAP, &vmm).is_err()
        );
        assert!(get_snapshot_data_version(&Some("0.24".to_string()), &VERSION_MAP, &vmm).is_err());
        assert!(
            get_snapshot_data_version(&Some("0.24.0.1".to_string()), &VERSION_MAP, &vmm).is_err()
        );
        assert!(
            get_snapshot_data_version(&Some("0.24.x".to_string()), &VERSION_MAP, &vmm).is_err()
        );

        assert!(get_snapshot_data_version(&Some("0.24.0".to_string()), &VERSION_MAP, &vmm).is_ok());
    }

    #[test]
    fn test_create_snapshot_error_display() {
        use crate::persist::CreateSnapshotError::*;
        use vm_memory::GuestMemoryError;

        let err = DirtyBitmap(VmmError::DirtyBitmap(kvm_ioctls::Error::new(20)));
        let _ = format!("{}{:?}", err, err);

        let err = InvalidVersionFormat;
        let _ = format!("{}{:?}", err, err);

        let err = UnsupportedVersion;
        let _ = format!("{}{:?}", err, err);

        let err = Memory(memory_snapshot::Error::WriteMemory(
            GuestMemoryError::HostAddressNotAvailable,
        ));
        let _ = format!("{}{:?}", err, err);

        let err = MemoryBackingFile("open", io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);

        let err = MicrovmState(MicrovmStateError::UnexpectedVcpuResponse);
        let _ = format!("{}{:?}", err, err);

        let err = SerializeMicrovmState(snapshot::Error::InvalidMagic(0));
        let _ = format!("{}{:?}", err, err);

        let err = SnapshotBackingFile("open", io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);

        #[cfg(target_arch = "x86_64")]
        {
            let err = TooManyDevices(0);
            let _ = format!("{}{:?}", err, err);
        }
    }

    #[test]
    fn test_load_snapshot_error_display() {
        use crate::persist::LoadSnapshotError::*;

        let err = BuildMicroVm(StartMicrovmError::InitrdLoad);
        let _ = format!("{}{:?}", err, err);

        let err = DeserializeMemory(memory_snapshot::Error::FileHandle(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{}{:?}", err, err);

        let err = DeserializeMicrovmState(snapshot::Error::Io(0));
        let _ = format!("{}{:?}", err, err);

        let err = MemoryBackingFile(io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);

        let err = SnapshotBackingFile("open", io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);

        let err = CpuVendorCheck(String::new());
        let _ = format!("{}{:?}", err, err);
    }

    #[test]
    fn test_microvm_state_error_display() {
        use crate::persist::MicrovmStateError::*;

        let err = InvalidInput;
        let _ = format!("{}{:?}", err, err);

        let err = NotAllowed(String::from(""));
        let _ = format!("{}{:?}", err, err);

        let err = RestoreDevices(DevicePersistError::MmioTransport);
        let _ = format!("{}{:?}", err, err);

        let err = RestoreVcpuState(vstate::vcpu::Error::VcpuTlsInit);
        let _ = format!("{}{:?}", err, err);

        let err = RestoreVmState(vstate::vm::Error::NotEnoughMemorySlots);
        let _ = format!("{}{:?}", err, err);

        let err = SaveVcpuState(vstate::vcpu::Error::VcpuTlsNotPresent);
        let _ = format!("{}{:?}", err, err);

        let err = SaveVmState(vstate::vm::Error::NotEnoughMemorySlots);
        let _ = format!("{}{:?}", err, err);

        let err = SignalVcpu(vstate::vcpu::Error::SignalVcpu(errno::Error::new(0)));
        let _ = format!("{}{:?}", err, err);

        let err = UnexpectedVcpuResponse;
        let _ = format!("{}{:?}", err, err);
    }
}
