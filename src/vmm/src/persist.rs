// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines state structures for saving/restoring a Firecracker microVM.

// Currently only supports x86_64.
#![cfg(target_arch = "x86_64")]

use std::fmt::{Display, Formatter};
use std::fs::OpenOptions;
use std::path::PathBuf;

use device_manager::persist::DeviceStates;
use memory_snapshot;
use memory_snapshot::{GuestMemoryState, SnapshotMemory};
use snapshot::Snapshot;
use version_map::FC_VERSION_TO_SNAP_VERSION;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_memory::{GuestMemory, GuestMemoryMmap, GuestMemoryRegion};
use vmm_config::snapshot::{CreateSnapshotParams, SnapshotType};
use vstate;
use vstate::{VcpuState, VmState};

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
    /// Memory state error.
    Memory(memory_snapshot::Error),
    /// Failed to restore VM state.
    RestoreVcpuState(vstate::Error),
    /// Failed to restore Vcpu state.
    RestoreVmState(vstate::Error),
    /// Failed to save VM state.
    SaveVcpuState(vstate::Error),
    /// Failed to save Vcpu state.
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
            Memory(err) => write!(f, "Memory error: {:?}", err),
            RestoreVcpuState(err) => write!(f, "Unable to restore Vcpu state. Error: {:?}", err),
            RestoreVmState(err) => write!(f, "Unable to restore Vm state. Error: {:?}", err),
            SaveVcpuState(err) => write!(f, "Unable to save Vcpu state. Error: {:?}", err),
            SaveVmState(err) => write!(f, "Unable to save Vm state. Error: {:?}", err),
            SignalVcpu(err) => write!(f, "Unable to signal Vcpu: {:?}", err),
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
    MemoryBackingFile(std::io::Error),
    /// Failed to save MicrovmState.
    MicrovmState(MicrovmStateError),
    /// Failed to serialize microVM state.
    SerializeMicrovmState(snapshot::Error),
    /// Failed to open the snapshot backing file.
    SnapshotBackingFile(std::io::Error),
}

impl Display for CreateSnapshotError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::CreateSnapshotError::*;
        match self {
            DirtyBitmap => write!(f, "Unable to get dirty bitmap"),
            InvalidVersion => write!(
                f,
                "Unable to translate microVM version to snapshot data version"
            ),
            InvalidVmState(err) => write!(f, "Unable to save Vm state. Error: {:?}", err),
            Memory(err) => write!(f, "Unable to write memory file: {:?}", err),
            MemoryBackingFile(err) => write!(f, "Unable to open memory file: {:?}", err),
            MicrovmState(err) => write!(f, "Unable to save microvm state: {}", err),
            SerializeMicrovmState(err) => write!(f, "Unable to serialize MicrovmState: {:?}", err),
            SnapshotBackingFile(err) => write!(f, "Unable to open snapshot file: {:?}", err),
        }
    }
}

/// Creates a Microvm snapshot.
pub fn create_snapshot(
    vmm: &mut Vmm,
    params: CreateSnapshotParams,
    version_map: VersionMap,
) -> std::result::Result<(), CreateSnapshotError> {
    let microvm_state = vmm
        .save_state()
        .map_err(CreateSnapshotError::MicrovmState)?;

    snapshot_memory_to_file(vmm, &params.mem_file_path, params.snapshot_type)?;

    snapshot_state_to_file(
        &microvm_state,
        &params.snapshot_path,
        params.version,
        version_map,
    )?;

    Ok(())
}

fn snapshot_state_to_file(
    microvm_state: &MicrovmState,
    snapshot_path: &PathBuf,
    version: Option<String>,
    version_map: VersionMap,
) -> std::result::Result<(), CreateSnapshotError> {
    let mut snapshot_file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(snapshot_path)
        .map_err(CreateSnapshotError::SnapshotBackingFile)?;

    // Translate the microVM version to its corresponding snapshot data format.
    let snapshot_data_version = match version {
        Some(version) => match FC_VERSION_TO_SNAP_VERSION.get(&version) {
            Some(data_version) => Ok(*data_version),
            _ => Err(CreateSnapshotError::InvalidVersion),
        },
        _ => Ok(version_map.latest_version()),
    }?;

    let mut snapshot = Snapshot::new(version_map, snapshot_data_version);
    snapshot
        .save(&mut snapshot_file, microvm_state)
        .map_err(CreateSnapshotError::SerializeMicrovmState)?;

    Ok(())
}

fn snapshot_memory_to_file(
    vmm: &Vmm,
    mem_file_path: &PathBuf,
    snapshot_type: SnapshotType,
) -> std::result::Result<(), CreateSnapshotError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(mem_file_path.clone())
        .map_err(CreateSnapshotError::MemoryBackingFile)?;

    // Set the length of the file to the full size of the memory area.
    let mem_size_mib = mem_size_mib(vmm.guest_memory());
    file.set_len((mem_size_mib * 1024 * 1024) as u64)
        .map_err(CreateSnapshotError::MemoryBackingFile)?;

    match snapshot_type {
        SnapshotType::Diff => {
            let dirty_bitmap = vmm
                .get_dirty_bitmap()
                .map_err(|_| CreateSnapshotError::DirtyBitmap)?;
            vmm.guest_memory()
                .dump_dirty(&mut file, &dirty_bitmap)
                .map_err(CreateSnapshotError::Memory)
        }
        SnapshotType::Full => vmm
            .guest_memory()
            .dump(&mut file)
            .map_err(CreateSnapshotError::Memory),
    }
}

pub(crate) fn mem_size_mib(guest_memory: &GuestMemoryMmap) -> u64 {
    guest_memory.map_and_fold(0, |(_, region)| region.len(), |a, b| a + b) >> 20
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
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
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
    fn test_create_snapshot_error_messages() {
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

        let err = MemoryBackingFile(std::io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);

        let err = MicrovmState(MicrovmStateError::UnexpectedVcpuResponse);
        let _ = format!("{}{:?}", err, err);

        let err = SerializeMicrovmState(snapshot::Error::InvalidMagic(0));
        let _ = format!("{}{:?}", err, err);

        let err = SnapshotBackingFile(std::io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);
    }

    #[test]
    fn test_save_microvm_state_error_messages() {
        use persist::MicrovmStateError::*;

        let err = UnexpectedVcpuResponse;
        let _ = format!("{}{:?}", err, err);

        let err = SaveVmState(vstate::Error::NotEnoughMemorySlots);
        let _ = format!("{}{:?}", err, err);

        let err = SignalVcpu(vstate::Error::VcpuCountNotInitialized);
        let _ = format!("{}{:?}", err, err);
    }
}
