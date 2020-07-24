// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines state structures for saving/restoring a Firecracker microVM.

// Currently only supports x86_64.
#![cfg(target_arch = "x86_64")]

use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::builder::{self, StartMicrovmError};
use crate::device_manager::persist::Error as DevicePersistError;
use crate::vmm_config::snapshot::{CreateSnapshotParams, LoadSnapshotParams, SnapshotType};
use crate::vstate::{self, VcpuState, VmState};

use device_manager::persist::DeviceStates;
use memory_snapshot;
use memory_snapshot::{GuestMemoryState, SnapshotMemory};
use polly::event_manager::EventManager;
use seccomp::BpfProgramRef;
use snapshot::Snapshot;
use version_map::FC_VERSION_TO_SNAP_VERSION;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_memory::{GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use crate::Vmm;

/// Holds information related to the VM that is not part of VmState.
#[derive(Debug, PartialEq, Versionize)]
pub struct VmInfo {
    /// Guest memory size.
    pub mem_size_mib: u64,
}

/// Contains the necesary state for saving/restoring a microVM.
#[derive(Versionize)]
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
    /// Provided MicroVM state is invalid.
    InvalidInput,
    /// Failed to restore devices.
    RestoreDevices(DevicePersistError),
    /// Failed to restore Vcpu state.
    RestoreVcpuState(vstate::Error),
    /// Failed to restore VM state.
    RestoreVmState(vstate::Error),
    /// Failed to save Vcpu state.
    SaveVcpuState(vstate::Error),
    /// Failed to save VM state.
    SaveVmState(vstate::Error),
    /// Failed to send event.
    SignalVcpu(vstate::Error),
    /// Vcpu is in unexpected state.
    UnexpectedVcpuResponse,
}

impl Display for MicrovmStateError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::MicrovmStateError::*;
        match self {
            InvalidInput => write!(f, "Provided MicroVM state is invalid."),
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
    DirtyBitmap,
    /// Failed to translate microVM version to snapshot data version.
    InvalidVersion,
    /// Failed to save VM state.
    InvalidVmState(vstate::Error),
    /// Failed to write memory to snapshot.
    Memory(memory_snapshot::Error),
    /// Failed to open memory backing file.
    MemoryBackingFile(io::Error),
    /// Failed to save MicrovmState.
    MicrovmState(MicrovmStateError),
    /// Failed to serialize microVM state.
    SerializeMicrovmState(snapshot::Error),
    /// Failed to open the snapshot backing file.
    SnapshotBackingFile(io::Error),
}

impl Display for CreateSnapshotError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::CreateSnapshotError::*;
        match self {
            DirtyBitmap => write!(f, "Cannot get dirty bitmap"),
            InvalidVersion => write!(
                f,
                "Cannot translate microVM version to snapshot data version"
            ),
            InvalidVmState(err) => write!(f, "Cannot save Vm state. Error: {:?}", err),
            Memory(err) => write!(f, "Cannot write memory file: {:?}", err),
            MemoryBackingFile(err) => write!(f, "Cannot open memory file: {:?}", err),
            MicrovmState(err) => write!(f, "Cannot save microvm state: {}", err),
            SerializeMicrovmState(err) => write!(f, "Cannot serialize MicrovmState: {:?}", err),
            SnapshotBackingFile(err) => write!(f, "Cannot open snapshot file: {:?}", err),
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
    /// Failed to open the snapshot backing file.
    SnapshotBackingFile(io::Error),
}

impl Display for LoadSnapshotError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::LoadSnapshotError::*;
        match self {
            BuildMicroVm(err) => write!(f, "Cannot build a microVM from snapshot: {}", err),
            DeserializeMemory(err) => write!(f, "Cannot deserialize memory: {}", err),
            DeserializeMicrovmState(err) => write!(f, "Cannot deserialize MicrovmState: {:?}", err),
            MemoryBackingFile(err) => write!(f, "Cannot open memory file: {}", err),
            SnapshotBackingFile(err) => write!(f, "Cannot open snapshot file: {}", err),
        }
    }
}

/// Creates a Microvm snapshot.
pub fn create_snapshot(
    vmm: &mut Vmm,
    params: &CreateSnapshotParams,
    version_map: VersionMap,
) -> std::result::Result<(), CreateSnapshotError> {
    let microvm_state = vmm
        .save_state()
        .map_err(CreateSnapshotError::MicrovmState)?;

    snapshot_memory_to_file(vmm, &params.mem_file_path, &params.snapshot_type)?;

    snapshot_state_to_file(
        &microvm_state,
        &params.snapshot_path,
        &params.version,
        version_map,
    )?;

    Ok(())
}

fn snapshot_state_to_file(
    microvm_state: &MicrovmState,
    snapshot_path: &PathBuf,
    version: &Option<String>,
    version_map: VersionMap,
) -> std::result::Result<(), CreateSnapshotError> {
    use self::CreateSnapshotError::*;
    let mut snapshot_file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(snapshot_path)
        .map_err(SnapshotBackingFile)?;

    // Translate the microVM version to its corresponding snapshot data format.
    let snapshot_data_version = match version {
        Some(version) => match FC_VERSION_TO_SNAP_VERSION.get(version) {
            Some(data_version) => Ok(*data_version),
            _ => Err(InvalidVersion),
        },
        _ => Ok(version_map.latest_version()),
    }?;

    let mut snapshot = Snapshot::new(version_map, snapshot_data_version);
    snapshot
        .save(&mut snapshot_file, microvm_state)
        .map_err(SerializeMicrovmState)?;

    Ok(())
}

fn snapshot_memory_to_file(
    vmm: &Vmm,
    mem_file_path: &PathBuf,
    snapshot_type: &SnapshotType,
) -> std::result::Result<(), CreateSnapshotError> {
    use self::CreateSnapshotError::*;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(mem_file_path)
        .map_err(MemoryBackingFile)?;

    // Set the length of the file to the full size of the memory area.
    let mem_size_mib = mem_size_mib(vmm.guest_memory());
    file.set_len((mem_size_mib * 1024 * 1024) as u64)
        .map_err(MemoryBackingFile)?;

    match snapshot_type {
        SnapshotType::Diff => {
            let dirty_bitmap = vmm.get_dirty_bitmap().map_err(|_| DirtyBitmap)?;
            vmm.guest_memory()
                .dump_dirty(&mut file, &dirty_bitmap)
                .map_err(Memory)
        }
        SnapshotType::Full => vmm.guest_memory().dump(&mut file).map_err(Memory),
    }
}

pub(crate) fn mem_size_mib(guest_memory: &GuestMemoryMmap) -> u64 {
    guest_memory.map_and_fold(0, |(_, region)| region.len(), |a, b| a + b) >> 20
}

/// Loads a Microvm snapshot producing a 'paused' Microvm.
pub fn load_snapshot(
    event_manager: &mut EventManager,
    seccomp_filter: BpfProgramRef,
    params: &LoadSnapshotParams,
    version_map: VersionMap,
) -> std::result::Result<Arc<Mutex<Vmm>>, LoadSnapshotError> {
    use self::LoadSnapshotError::*;
    let track_dirty = params.enable_diff_snapshots;
    let microvm_state = snapshot_state_from_file(&params.snapshot_path, version_map)?;
    let guest_memory = guest_memory_from_file(&params.mem_file_path, &microvm_state.memory_state)?;
    builder::build_microvm_from_snapshot(
        event_manager,
        microvm_state,
        guest_memory,
        track_dirty,
        seccomp_filter,
    )
    .map_err(BuildMicroVm)
}

fn snapshot_state_from_file(
    snapshot_path: &PathBuf,
    version_map: VersionMap,
) -> std::result::Result<MicrovmState, LoadSnapshotError> {
    use self::LoadSnapshotError::{DeserializeMicrovmState, SnapshotBackingFile};
    let mut snapshot_reader =
        std::io::BufReader::new(File::open(snapshot_path).map_err(SnapshotBackingFile)?);
    Snapshot::load(&mut snapshot_reader, version_map).map_err(DeserializeMicrovmState)
}

fn guest_memory_from_file(
    mem_file_path: &PathBuf,
    mem_state: &GuestMemoryState,
) -> std::result::Result<GuestMemoryMmap, LoadSnapshotError> {
    use self::LoadSnapshotError::{DeserializeMemory, MemoryBackingFile};
    let mem_file = File::open(mem_file_path).map_err(MemoryBackingFile)?;
    GuestMemoryMmap::restore(&mem_file, mem_state).map_err(DeserializeMemory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::tests::{
        default_kernel_cmdline, default_vmm, insert_block_devices, insert_net_device,
        insert_vsock_device, CustomBlockConfig,
    };
    use crate::memory_snapshot::SnapshotMemory;
    use crate::vmm_config::net::NetworkInterfaceConfig;
    use crate::vmm_config::vsock::tests::default_config;
    use crate::vstate::tests::default_vcpu_state;
    use crate::Vmm;

    use polly::event_manager::EventManager;
    use snapshot::Persist;
    use utils::tempfile::TempFile;

    fn default_vmm_with_devices(event_manager: &mut EventManager) -> Vmm {
        let mut vmm = default_vmm();
        let mut cmdline = default_kernel_cmdline();

        // Add a block device.
        let drive_id = String::from("root");
        let block_configs = vec![CustomBlockConfig::new(drive_id, true, None, true)];
        insert_block_devices(&mut vmm, &mut cmdline, event_manager, block_configs);

        // Add net device.
        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname"),
            guest_mac: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
            allow_mmds_requests: true,
        };
        insert_net_device(&mut vmm, &mut cmdline, event_manager, network_interface);

        // Add vsock device.
        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        let vsock_config = default_config(&tmp_sock_file);

        insert_vsock_device(&mut vmm, &mut cmdline, event_manager, vsock_config);

        vmm
    }

    #[test]
    fn test_microvmstate_versionize() {
        let mut event_manager = EventManager::new().expect("Cannot create EventManager");
        let vmm = default_vmm_with_devices(&mut event_manager);
        let states = vmm.mmio_device_manager.save();

        // Only checking that all devices are saved, actual device state
        // is tested by that device's tests.
        assert_eq!(states.block_devices.len(), 1);
        assert_eq!(states.net_devices.len(), 1);
        assert!(states.vsock_device.is_some());

        let memory_state = vmm.guest_memory().describe();

        let microvm_state = MicrovmState {
            device_states: states,
            memory_state,
            vcpu_states: vec![default_vcpu_state()],
            vm_info: VmInfo { mem_size_mib: 1u64 },
            vm_state: vmm.vm.save_state().unwrap(),
        };

        let mut buf = vec![0; 10000];
        let version_map = VersionMap::new();

        microvm_state
            .serialize(&mut buf.as_mut_slice(), &version_map, 1)
            .unwrap();

        let restored_microvm_state =
            MicrovmState::deserialize(&mut buf.as_slice(), &version_map, 1).unwrap();

        assert_eq!(restored_microvm_state.vm_info, microvm_state.vm_info);
        assert_eq!(
            restored_microvm_state.device_states,
            microvm_state.device_states
        )
    }

    #[test]
    fn test_create_snapshot_error_display() {
        use persist::CreateSnapshotError::*;
        use vm_memory::GuestMemoryError;

        let err = DirtyBitmap;
        let _ = format!("{}{:?}", err, err);

        let err = InvalidVersion;
        let _ = format!("{}{:?}", err, err);

        let err = InvalidVmState(vstate::Error::NotEnoughMemorySlots);
        let _ = format!("{}{:?}", err, err);

        let err = Memory(memory_snapshot::Error::WriteMemory(
            GuestMemoryError::HostAddressNotAvailable,
        ));
        let _ = format!("{}{:?}", err, err);

        let err = MemoryBackingFile(io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);

        let err = MicrovmState(MicrovmStateError::UnexpectedVcpuResponse);
        let _ = format!("{}{:?}", err, err);

        let err = SerializeMicrovmState(snapshot::Error::InvalidMagic(0));
        let _ = format!("{}{:?}", err, err);

        let err = SnapshotBackingFile(io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);
    }

    #[test]
    fn test_load_snapshot_error_display() {
        use persist::LoadSnapshotError::*;

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

        let err = SnapshotBackingFile(io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);
    }

    #[test]
    fn test_microvm_state_error_display() {
        use persist::MicrovmStateError::*;

        let err = InvalidInput;
        let _ = format!("{}{:?}", err, err);

        let err = RestoreDevices(DevicePersistError::MmioTransport);
        let _ = format!("{}{:?}", err, err);

        let err = RestoreVcpuState(vstate::Error::HTNotInitialized);
        let _ = format!("{}{:?}", err, err);

        let err = RestoreVmState(vstate::Error::NotEnoughMemorySlots);
        let _ = format!("{}{:?}", err, err);

        let err = SaveVcpuState(vstate::Error::HTNotInitialized);
        let _ = format!("{}{:?}", err, err);

        let err = SaveVmState(vstate::Error::NotEnoughMemorySlots);
        let _ = format!("{}{:?}", err, err);

        let err = SignalVcpu(vstate::Error::VcpuCountNotInitialized);
        let _ = format!("{}{:?}", err, err);

        let err = UnexpectedVcpuResponse;
        let _ = format!("{}{:?}", err, err);
    }
}
