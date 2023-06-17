// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines state structures for saving/restoring a Firecracker microVM.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::os::unix::prelude::FromRawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};

use libc::memfd_create;
use logger::{error, info, warn};
use seccompiler::BpfThreadMap;
use serde::Serialize;
use snapshot::Snapshot;
use userfaultfd::{FeatureFlags, Uffd, UffdBuilder};
use utils::sock_ctrl_msg::ScmSocket;
use utils::vm_memory::{GuestMemory, GuestMemoryMmap};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use virtio_gen::virtio_ring::VIRTIO_RING_F_EVENT_IDX;

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::vcpu::{get_manufacturer_id_from_host, get_manufacturer_id_from_state};
use crate::builder::{self, BuildMicrovmFromSnapshotError};
use crate::cpu_config::templates::StaticCpuTemplate;
#[cfg(target_arch = "x86_64")]
use crate::cpu_config::x86_64::cpuid::common::get_vendor_id_from_host;
#[cfg(target_arch = "x86_64")]
use crate::cpu_config::x86_64::cpuid::CpuidTrait;
use crate::device_manager::persist::{DeviceStates, Error as DevicePersistError};
use crate::devices::virtio::TYPE_NET;
use crate::memory_snapshot::{mem_dump_dirty, GuestMemoryState, SnapshotMemory};
use crate::resources::VmResources;
use crate::rpc_interface::LoadSnapshotError;
#[cfg(target_arch = "x86_64")]
use crate::version_map::FC_V0_23_SNAP_VERSION;
use crate::version_map::{FC_V1_0_SNAP_VERSION, FC_V1_1_SNAP_VERSION, FC_VERSION_TO_SNAP_VERSION};
use crate::vmm_config::boot_source::BootSourceConfig;
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::MAX_SUPPORTED_VCPUS;
use crate::vmm_config::snapshot::{
    CreateSnapshotParams, LoadSnapshotParams, MemBackendType, SnapshotType,
};
use crate::vstate::vcpu::{VcpuSendEventError, VcpuState};
use crate::vstate::vm::VmState;
use crate::{mem_size_mib, memory_snapshot, vstate, Error as VmmError, EventManager, Vmm};

#[cfg(target_arch = "x86_64")]
const FC_V0_23_MAX_DEVICES: u32 = 11;

/// Holds information related to the VM that is not part of VmState.
#[derive(Clone, Debug, Default, PartialEq, Eq, Versionize, Serialize)]
// NOTICE: Any changes to this structure require a snapshot version bump.
pub struct VmInfo {
    /// Guest memory size.
    pub mem_size_mib: u64,
    /// smt information
    #[version(start = 2, default_fn = "def_smt", ser_fn = "ser_smt")]
    pub smt: bool,
    /// CPU template type
    #[version(
        start = 2,
        default_fn = "def_cpu_template",
        ser_fn = "ser_cpu_template"
    )]
    pub cpu_template: StaticCpuTemplate,
    /// Boot source information.
    #[version(start = 2, default_fn = "def_boot_source", ser_fn = "ser_boot_source")]
    pub boot_source: BootSourceConfig,
}

impl VmInfo {
    fn def_smt(_: u16) -> bool {
        warn!("SMT field not found in snapshot.");
        false
    }

    fn ser_smt(&mut self, _target_version: u16) -> VersionizeResult<()> {
        // v1.1 and older versions do not include smt info.
        warn!("Saving to older snapshot version, SMT information will not be saved.");
        Ok(())
    }

    fn def_cpu_template(_: u16) -> StaticCpuTemplate {
        warn!("CPU template field not found in snapshot.");
        StaticCpuTemplate::default()
    }

    fn ser_cpu_template(&mut self, _target_version: u16) -> VersionizeResult<()> {
        // v1.1 and older versions do not include cpu template info.
        warn!("Saving to older snapshot version, CPU template information will not be saved.");
        Ok(())
    }

    fn def_boot_source(_: u16) -> BootSourceConfig {
        warn!("Boot source information not found in snapshot.");
        BootSourceConfig::default()
    }

    fn ser_boot_source(&mut self, _target_version: u16) -> VersionizeResult<()> {
        // v1.1 and older versions do not include boot source info.
        warn!("Saving to older snapshot version, boot source information will not be saved.");
        Ok(())
    }
}

impl From<&VmResources> for VmInfo {
    fn from(value: &VmResources) -> Self {
        Self {
            mem_size_mib: value.vm_config.mem_size_mib as u64,
            smt: value.vm_config.smt,
            cpu_template: StaticCpuTemplate::from(&value.vm_config.cpu_template),
            boot_source: value.boot_source_config().clone(),
        }
    }
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

/// This describes the mapping between Firecracker base virtual address and
/// offset in the buffer or file backend for a guest memory region. It is used
/// to tell an external process/thread where to populate the guest memory data
/// for this range.
///
/// E.g. Guest memory contents for a region of `size` bytes can be found in the
/// backend at `offset` bytes from the beginning, and should be copied/populated
/// into `base_host_address`.
#[derive(Clone, Debug, Serialize)]
pub struct GuestRegionUffdMapping {
    /// Base host virtual address where the guest memory contents for this
    /// region should be copied/populated.
    pub base_host_virt_addr: u64,
    /// Region size.
    pub size: usize,
    /// Offset in the backend file/buffer where the region contents are.
    pub offset: u64,
}

/// Errors related to saving and restoring Microvm state.
#[derive(Debug, thiserror::Error)]
pub enum MicrovmStateError {
    /// Compatibility checks failed.
    #[error("Compatibility checks failed: {0}")]
    IncompatibleState(String),
    /// Provided MicroVM state is invalid.
    #[error("Provided MicroVM state is invalid.")]
    InvalidInput,
    /// Operation not allowed.
    #[error("Operation not allowed: {0}")]
    NotAllowed(String),
    /// Failed to restore devices.
    #[error("Cannot restore devices: {0:?}")]
    RestoreDevices(DevicePersistError),
    /// Failed to restore Vcpu state.
    #[error("Cannot restore Vcpu state: {0:?}")]
    RestoreVcpuState(vstate::vcpu::Error),
    /// Failed to restore VM state.
    #[error("Cannot restore Vm state: {0:?}")]
    RestoreVmState(vstate::vm::Error),
    /// Failed to save Vcpu state.
    #[error("Cannot save Vcpu state: {0:?}")]
    SaveVcpuState(vstate::vcpu::Error),
    /// Failed to save VM state.
    #[error("Cannot save Vm state: {0:?}")]
    SaveVmState(vstate::vm::Error),
    /// Failed to send event.
    #[error("Cannot signal Vcpu: {0:?}")]
    SignalVcpu(VcpuSendEventError),
    /// Vcpu is in unexpected state.
    #[error("Vcpu is in unexpected state.")]
    UnexpectedVcpuResponse,
}

/// Errors associated with creating a snapshot.
#[derive(Debug, thiserror::Error)]
pub enum CreateSnapshotError {
    /// Failed to get dirty bitmap.
    #[error("Cannot get dirty bitmap: {0}")]
    DirtyBitmap(VmmError),
    /// The virtio devices uses a features that is incompatible with older versions of Firecracker.
    #[error(
        "The virtio devices use a features that is incompatible with older versions of \
         Firecracker: {0}"
    )]
    IncompatibleVirtioFeature(&'static str),
    /// Invalid microVM version format
    #[error("Invalid microVM version format")]
    InvalidVersionFormat,
    /// MicroVM version does not support snapshot.
    #[error("Cannot translate microVM version to snapshot data version")]
    UnsupportedVersion,
    /// Failed to write memory to snapshot.
    #[error("Cannot write memory file: {0}")]
    Memory(memory_snapshot::Error),
    /// Failed to open memory backing file.
    #[error("Cannot perform {0} on the memory backing file: {1}")]
    MemoryBackingFile(&'static str, io::Error),
    /// Failed to save MicrovmState.
    #[error("Cannot save the microVM state: {0}")]
    MicrovmState(MicrovmStateError),
    /// Failed to serialize microVM state.
    #[error("Cannot serialize the microVM state: {0}")]
    SerializeMicrovmState(snapshot::Error),
    /// Failed to open the snapshot backing file.
    #[error("Cannot perform {0} on the snapshot backing file: {1}")]
    SnapshotBackingFile(&'static str, io::Error),
    /// Number of devices exceeds the maximum supported devices for the snapshot data version.
    #[cfg(target_arch = "x86_64")]
    #[error(
        "Too many devices attached: {0}. The maximum number allowed for the snapshot data version \
         requested is {FC_V0_23_MAX_DEVICES}."
    )]
    TooManyDevices(usize),
}

/// Creates a Microvm snapshot.
pub fn create_snapshot(
    vmm: &mut Vmm,
    vm_info: &VmInfo,
    params: &CreateSnapshotParams,
    version_map: VersionMap,
) -> std::result::Result<(), CreateSnapshotError> {
    // Fail early from invalid target version.
    let snapshot_data_version = get_snapshot_data_version(&params.version, &version_map, vmm)?;

    let microvm_state = vmm
        .save_state(vm_info)
        .map_err(CreateSnapshotError::MicrovmState)?;

    snapshot_state_to_file(
        &microvm_state,
        &params.snapshot_path,
        snapshot_data_version,
        version_map,
    )?;

    if params.snapshot_type == SnapshotType::Full {
        snapshot_memory_to_file(vmm, &params.mem_file_path, &params.snapshot_type)?;
    }

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
        .truncate(true)
        .open(snapshot_path)
        .map_err(|err| SnapshotBackingFile("open", err))?;

    let mut snapshot = Snapshot::new(version_map, snapshot_data_version);
    snapshot
        .save(&mut snapshot_file, microvm_state)
        .map_err(SerializeMicrovmState)?;
    snapshot_file
        .flush()
        .map_err(|err| SnapshotBackingFile("flush", err))?;
    snapshot_file
        .sync_all()
        .map_err(|err| SnapshotBackingFile("sync_all", err))
}

fn snapshot_memory_to_file(
    vmm: &Vmm,
    mem_file_path: &Path,
    snapshot_type: &SnapshotType,
) -> std::result::Result<(), CreateSnapshotError> {
    use self::CreateSnapshotError::*;

    let mut file = if mem_file_path.to_string_lossy() == "memfd" {
        let fd = unsafe {
            let memfd_name = CString::new("diff").unwrap();
            memfd_create(memfd_name.as_ptr(), 0)
        };
        if fd == -1 {
            return Err(MemoryBackingFile(
                "memfd_create",
                std::io::Error::last_os_error(),
            ));
        }

        unsafe { File::from_raw_fd(fd) }
    } else {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(mem_file_path)
            .map_err(|err| MemoryBackingFile("open", err))?
    };

    // Set the length of the file to the full size of the memory area.
    let mem_size_mib = mem_size_mib(vmm.guest_memory());
    file.set_len(mem_size_mib * 1024 * 1024)
        .map_err(|err| MemoryBackingFile("set_length", err))?;

    match snapshot_type {
        SnapshotType::Diff => {
            let dirty_bitmap = vmm.get_dirty_bitmap().map_err(DirtyBitmap)?;

            mem_dump_dirty(
                vmm.guest_memory(),
                file.as_raw_fd(),
                (mem_size_mib * 1024 * 1024) as usize,
                &dirty_bitmap,
            )
            .map_err(Memory)
        }
        SnapshotType::Full => vmm.guest_memory().dump(&mut file).map_err(Memory),
    }?;

    Ok(())
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

    if data_version < FC_V1_1_SNAP_VERSION {
        vmm.mmio_device_manager
            .for_each_virtio_device(|virtio_type, _id, _info, dev| {
                // Incompatibility between current version and all versions smaller than 1.0.
                // Also, incompatibility between v1.1 and v1.0 for VirtIO net device
                if dev
                    .lock()
                    .expect("Poisoned lock")
                    .has_feature(u64::from(VIRTIO_RING_F_EVENT_IDX))
                    && (data_version < FC_V1_0_SNAP_VERSION || virtio_type == TYPE_NET)
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

/// Error type for [`validate_cpu_vendor`].
#[cfg(target_arch = "x86_64")]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidateCpuVendorError {
    /// Failed to read host vendor.
    #[error("Failed to read host vendor: {0}")]
    Host(#[from] crate::cpu_config::x86_64::cpuid::common::GetCpuidError),
    /// Failed to read snapshot vendor.
    #[error("Failed to read snapshot vendor")]
    Snapshot,
}

/// Validates that snapshot CPU vendor matches the host CPU vendor.
///
/// # Errors
///
/// When:
/// - Failed to read host vendor.
/// - Failed to read snapshot vendor.
#[cfg(target_arch = "x86_64")]
pub fn validate_cpu_vendor(
    microvm_state: &MicrovmState,
) -> std::result::Result<bool, ValidateCpuVendorError> {
    let host_vendor_id = get_vendor_id_from_host()?;

    let snapshot_vendor_id = microvm_state.vcpu_states[0]
        .cpuid
        .vendor_id()
        .ok_or(ValidateCpuVendorError::Snapshot)?;

    if host_vendor_id == snapshot_vendor_id {
        info!("Snapshot CPU vendor id: {:?}", &snapshot_vendor_id);
        Ok(true)
    } else {
        error!(
            "Host CPU vendor id: {:?} differs from the snapshotted one: {:?}",
            &host_vendor_id, &snapshot_vendor_id
        );
        Ok(false)
    }
}

/// Error type for [`validate_cpu_manufacturer_id`].
#[cfg(target_arch = "aarch64")]
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidateCpuManufacturerIdError {
    /// Failed to read host vendor.
    #[error("Failed to get manufacturer ID from host: {0}")]
    Host(String),
    /// Failed to read host vendor.
    #[error("Failed to get manufacturer ID from state: {0}")]
    Snapshot(String),
}

/// Validate that Snapshot Manufacturer ID matches
/// the one from the Host
///
/// The manufacturer ID for the Snapshot is taken from each VCPU state.
/// # Errors
///
/// When:
/// - Failed to read host vendor.
/// - Failed to read snapshot vendor.
#[cfg(target_arch = "aarch64")]
pub fn validate_cpu_manufacturer_id(
    microvm_state: &MicrovmState,
) -> std::result::Result<bool, ValidateCpuManufacturerIdError> {
    let host_man_id = get_manufacturer_id_from_host()
        .map_err(|err| ValidateCpuManufacturerIdError::Host(err.to_string()))?;

    for state in &microvm_state.vcpu_states {
        let state_man_id = get_manufacturer_id_from_state(&state.regs)
            .map_err(|err| ValidateCpuManufacturerIdError::Snapshot(err.to_string()))?;

        if host_man_id != state_man_id {
            error!(
                "Host CPU manufacturer ID: {} differs from snapshotted one: {}",
                &host_man_id, &state_man_id
            );
            return Ok(false);
        } else {
            info!("Snapshot CPU manufacturer ID: {:?}", &state_man_id);
        }
    }
    Ok(true)
}
/// Error type for [`snapshot_state_sanity_check`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SnapShotStateSanityCheckError {
    /// Invalid vCPU count.
    #[error("Invalid vCPU count.")]
    InvalidVcpuCount,
    /// No memory region defined.
    #[error("No memory region defined.")]
    NoMemory,
    /// Failed to validate vCPU vendor.
    #[cfg(target_arch = "x86_64")]
    #[error("Failed to validate vCPU vendor: {0}")]
    ValidateCpuVendor(#[from] ValidateCpuVendorError),
    /// Failed to validate vCPU manufacturer id.
    #[error("Failed to validate vCPU manufacturer id: {0}")]
    #[cfg(target_arch = "aarch64")]
    ValidateCpuManufacturerId(#[from] ValidateCpuManufacturerIdError),
}

/// Performs sanity checks against the state file and returns specific errors.
pub fn snapshot_state_sanity_check(
    microvm_state: &MicrovmState,
) -> std::result::Result<(), SnapShotStateSanityCheckError> {
    // Check if the snapshot contains at least 1 vCPU state entry.
    if microvm_state.vcpu_states.is_empty()
        || microvm_state.vcpu_states.len() > MAX_SUPPORTED_VCPUS.into()
    {
        return Err(SnapShotStateSanityCheckError::InvalidVcpuCount);
    }

    // Check if the snapshot contains at least 1 mem region.
    // Upper bound check will be done when creating guest memory by comparing against
    // KVM max supported value kvm_context.max_memslots().
    if microvm_state.memory_state.regions.is_empty() {
        return Err(SnapShotStateSanityCheckError::NoMemory);
    }

    #[cfg(target_arch = "x86_64")]
    validate_cpu_vendor(microvm_state)?;
    #[cfg(target_arch = "aarch64")]
    validate_cpu_manufacturer_id(microvm_state)?;

    Ok(())
}

/// Describes a descriptor that connects to the memory used by the VM. This could either be the a file descriptor
/// or a UFFD descriptor.
#[derive(Debug)]
pub enum MemoryDescriptor {
    /// A file descriptor that connects to the user fault process.
    Uffd(Uffd),
    /// A file descriptor of the backing memory file.
    File(Arc<File>),
}

/// Error type for [`restore_from_snapshot`].
#[derive(Debug, thiserror::Error)]
pub enum RestoreFromSnapshotError {
    /// Failed to get snapshot state from file.
    #[error("Failed to get snapshot state from file: {0}")]
    File(#[from] SnapshotStateFromFileError),
    /// Invalid snapshot state.
    #[error("Invalid snapshot state: {0}")]
    Invalid(#[from] SnapShotStateSanityCheckError),
    /// Failed to load guest memory
    #[error("Failed to load guest memory: {0}")]
    GuestMemory(#[from] RestoreFromSnapshotGuestMemoryError),
    /// Failed to build microVM from snapshot.
    #[error("Failed to build microVM from snapshot: {0}")]
    Build(#[from] BuildMicrovmFromSnapshotError),
}
/// Sub-Error type for [`restore_from_snapshot`] to contain either [`GuestMemoryFromFileError`] or
/// [`GuestMemoryFromUffdError`] within [`RestoreFromSnapshotError`].
#[derive(Debug, thiserror::Error)]
pub enum RestoreFromSnapshotGuestMemoryError {
    /// Error creating guest memory from file.
    #[error("Error creating guest memory from file: {0}")]
    File(#[from] GuestMemoryFromFileError),
    /// Error creating guest memory from uffd.
    #[error("Error creating guest memory from uffd: {0}")]
    Uffd(#[from] GuestMemoryFromUffdError),
}

/// Loads a Microvm snapshot producing a 'paused' Microvm.
pub fn restore_from_snapshot(
    instance_info: &InstanceInfo,
    event_manager: &mut EventManager,
    seccomp_filters: &BpfThreadMap,
    params: &LoadSnapshotParams,
    version_map: VersionMap,
    vm_resources: &mut VmResources,
) -> std::result::Result<Arc<Mutex<Vmm>>, RestoreFromSnapshotError> {
    let microvm_state = snapshot_state_from_file(&params.snapshot_path, version_map)?;

    // Some sanity checks before building the microvm.
    snapshot_state_sanity_check(&microvm_state)?;

    let mem_backend_path = &params.mem_backend.backend_path;
    let mem_state = &microvm_state.memory_state;
    let track_dirty_pages = params.enable_diff_snapshots;
    let (guest_memory, memory_descriptor) = match params.mem_backend.backend_type {
        MemBackendType::File => {
            let (guest_memory, file) =
                guest_memory_from_file(mem_backend_path, mem_state, track_dirty_pages)
                    .map_err(RestoreFromSnapshotGuestMemoryError::File)?;
            (guest_memory, Some(MemoryDescriptor::File(Arc::new(file))))
        }
        MemBackendType::Uffd => {
            let (guest_memory, uffd) =
                guest_memory_from_uffd(mem_backend_path, mem_state, track_dirty_pages)
                    .map_err(RestoreFromSnapshotGuestMemoryError::Uffd)?;

            (guest_memory, uffd.map(MemoryDescriptor::Uffd))
        }
    };
    builder::build_microvm_from_snapshot(
        instance_info,
        event_manager,
        microvm_state,
        guest_memory,
        memory_descriptor,
        track_dirty_pages,
        seccomp_filters,
        vm_resources,
    )
    .map_err(RestoreFromSnapshotError::Build)
}

/// Error type for [`snapshot_state_from_file`]
#[derive(Debug, thiserror::Error)]
pub enum SnapshotStateFromFileError {
    /// Failed to open snapshot file.
    #[error("Failed to open snapshot file: {0}")]
    Open(std::io::Error),
    /// Failed to read snapshot file metadata.
    #[error("Failed to read snapshot file metadata: {0}")]
    Meta(std::io::Error),
    /// Failed to load snapshot state from file.
    #[error("Failed to load snapshot state from file: {0}")]
    Load(#[from] snapshot::Error),
}

fn snapshot_state_from_file(
    snapshot_path: &Path,
    version_map: VersionMap,
) -> std::result::Result<MicrovmState, SnapshotStateFromFileError> {
    let mut snapshot_reader =
        File::open(snapshot_path).map_err(SnapshotStateFromFileError::Open)?;
    let metadata = std::fs::metadata(snapshot_path).map_err(SnapshotStateFromFileError::Meta)?;
    let snapshot_len = metadata.len() as usize;
    Snapshot::load(&mut snapshot_reader, snapshot_len, version_map)
        .map_err(SnapshotStateFromFileError::Load)
}

/// Error type for [`guest_memory_from_file`].
#[derive(Debug, thiserror::Error)]
pub enum GuestMemoryFromFileError {
    /// Failed to load guest memory.
    #[error("Failed to load guest memory: {0}")]
    File(#[from] std::io::Error),
    /// Failed to restore guest memory.
    #[error("Failed to restore guest memory: {0}")]
    Restore(#[from] crate::memory_snapshot::Error),
}

fn guest_memory_from_file(
    mem_file_path: &Path,
    mem_state: &GuestMemoryState,
    track_dirty_pages: bool,
) -> std::result::Result<(GuestMemoryMmap, File), GuestMemoryFromFileError> {
    let mem_file = File::open(mem_file_path)?;

    Ok((
        GuestMemoryMmap::restore(Some(&mem_file), mem_state, track_dirty_pages)
            .map_err(GuestMemoryFromFileError::Restore)?,
        mem_file,
    ))
}

/// Error type for [`guest_memory_from_uffd`]
#[derive(Debug, thiserror::Error)]
pub enum GuestMemoryFromUffdError {
    /// Failed to restore guest memory.
    #[error("Failed to restore guest memory: {0}")]
    Restore(#[from] crate::memory_snapshot::Error),
    /// Failed to UFFD object.
    #[error("Failed to UFFD object: {0}")]
    Create(userfaultfd::Error),
    /// Failed to register memory address range with the userfaultfd object.
    #[error("Failed to register memory address range with the userfaultfd object: {0}")]
    Register(userfaultfd::Error),
    /// Failed to connect to UDS Unix stream.
    #[error("Failed to connect to UDS Unix stream: {0}")]
    Connect(#[from] std::io::Error),
    /// Failed to send file descriptor.
    #[error("Failed to sends file descriptor: {0}")]
    Send(#[from] utils::errno::Error),

    /// No memfd received
    #[error("No memfd received")]
    NoMemFdReceived,
    /// Receiving memfd went wrong
    #[error("Failed to receive memfd: {0}")]
    Receive(utils::errno::Error),
}

pub(crate) fn guest_memory_from_uffd(
    mem_uds_path: &Path,
    mem_state: &GuestMemoryState,
    track_dirty_pages: bool,
) -> std::result::Result<(GuestMemoryMmap, Option<Uffd>), GuestMemoryFromUffdError> {
    use self::GuestMemoryFromUffdError::{Connect, Create, Receive, Restore, Send};

    let mut socket = UnixStream::connect(mem_uds_path).map_err(Connect)?;

    let mut buf = [0u8; 8];
    let (_, memfd) = socket.recv_with_fd(&mut buf).map_err(Receive)?;

    if memfd.is_none() {
        return Err(GuestMemoryFromUffdError::NoMemFdReceived);
    }

    let memfd = memfd.unwrap();

    let guest_memory =
        GuestMemoryMmap::restore(Some(&memfd), mem_state, track_dirty_pages).map_err(Restore)?;

    let uffd = UffdBuilder::new()
        .require_features(
            FeatureFlags::EVENT_REMOVE
                | FeatureFlags::EVENT_REMAP
                | FeatureFlags::EVENT_FORK
                | FeatureFlags::EVENT_UNMAP
                | FeatureFlags::MISSING_SHMEM
                | FeatureFlags::MINOR_SHMEM
                | FeatureFlags::PAGEFAULT_FLAG_WP,
        )
        .user_mode_only(false)
        .create()
        .map_err(Create)?;

    let mut backend_mappings = Vec::with_capacity(guest_memory.num_regions());
    for (mem_region, state_region) in guest_memory.iter().zip(mem_state.regions.iter()) {
        let host_base_addr = mem_region.as_ptr();
        let size = mem_region.size();

        backend_mappings.push(GuestRegionUffdMapping {
            base_host_virt_addr: host_base_addr as u64,
            size,
            offset: state_region.offset,
        });
    }

    // This is safe to unwrap() because we control the contents of the vector
    // (i.e GuestRegionUffdMapping entries).
    let backend_mappings = serde_json::to_string(&backend_mappings).unwrap();

    socket
        .send_with_fd(
            backend_mappings.as_bytes(),
            // In the happy case we can close the fd since the other process has it open and is
            // using it to serve us pages.
            //
            // The problem is that if other process crashes/exits, firecracker guest memory
            // will simply revert to anon-mem behavior which would lead to silent errors and
            // undefined behavior.
            //
            // To tackle this scenario, the page fault handler can notify Firecracker of any
            // crashes/exits. There is no need for Firecracker to explicitly send its process ID.
            // The external process can obtain Firecracker's PID by calling `getsockopt` with
            // `libc::SO_PEERCRED` option like so:
            //
            // let mut val = libc::ucred { pid: 0, gid: 0, uid: 0 };
            // let mut ucred_size: u32 = mem::size_of::<libc::ucred>() as u32;
            // libc::getsockopt(
            //      socket.as_raw_fd(),
            //      libc::SOL_SOCKET,
            //      libc::SO_PEERCRED,
            //      &mut val as *mut _ as *mut _,
            //      &mut ucred_size as *mut libc::socklen_t,
            // );
            //
            // Per this linux man page: https://man7.org/linux/man-pages/man7/unix.7.html,
            // `SO_PEERCRED` returns the credentials (PID, UID and GID) of the peer process
            // connected to this socket. The returned credentials are those that were in effect
            // at the time of the `connect` call.
            //
            // Moreover, Firecracker holds a copy of the UFFD fd as well, so that even if the
            // page fault handler process does not tear down Firecracker when necessary, the
            // uffd will still be alive but with no one to serve faults, leading to guest freeze.
            uffd.as_raw_fd(),
        )
        .map_err(Send)?;

    // Wait for UFFD to be ready.
    // TODO: maybe add a timeout?
    let mut buf = [0; 2];
    socket.read_exact(&mut buf).map_err(Connect)?;

    Ok((guest_memory, Some(uffd)))
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
    use snapshot::Persist;
    use utils::errno;
    use utils::tempfile::TempFile;

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
            vm_info: VmInfo {
                mem_size_mib: 1u64,
                ..Default::default()
            },
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
        use utils::vm_memory::GuestMemoryError;

        use crate::persist::CreateSnapshotError::*;

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

        let err = SignalVcpu(VcpuSendEventError(errno::Error::new(0)));
        let _ = format!("{}{:?}", err, err);

        let err = UnexpectedVcpuResponse;
        let _ = format!("{}{:?}", err, err);
    }
}
