// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines state structures for saving/restoring a Firecracker microVM.

use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};

use seccompiler::BpfThreadMap;
use serde::Serialize;
use snapshot::Snapshot;
use userfaultfd::{FeatureFlags, Uffd, UffdBuilder};
use utils::sock_ctrl_msg::ScmSocket;
use utils::u64_to_usize;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::vcpu::{get_manufacturer_id_from_host, get_manufacturer_id_from_state};
use crate::builder::{self, BuildMicrovmFromSnapshotError};
use crate::cpu_config::templates::StaticCpuTemplate;
#[cfg(target_arch = "x86_64")]
use crate::cpu_config::x86_64::cpuid::common::get_vendor_id_from_host;
#[cfg(target_arch = "x86_64")]
use crate::cpu_config::x86_64::cpuid::CpuidTrait;
use crate::device_manager::persist::{DevicePersistError, DeviceStates};
use crate::logger::{info, warn};
use crate::resources::VmResources;
use crate::vmm_config::boot_source::BootSourceConfig;
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::MAX_SUPPORTED_VCPUS;
use crate::vmm_config::snapshot::{
    CreateSnapshotParams, LoadSnapshotParams, MemBackendType, SnapshotType,
};
use crate::vstate::memory::{
    GuestMemory, GuestMemoryExtension, GuestMemoryMmap, GuestMemoryState, MemoryError,
};
use crate::vstate::vcpu::{VcpuSendEventError, VcpuState};
use crate::vstate::vm::VmState;
use crate::{mem_size_mib, vstate, EventManager, Vmm, VmmError};

#[cfg(target_arch = "x86_64")]
const FC_V0_23_MAX_DEVICES: u32 = 11;

/// Holds information related to the VM that is not part of VmState.
#[derive(Clone, Debug, Default, PartialEq, Eq, Versionize, Serialize)]
// NOTICE: Any changes to this structure require a snapshot version bump.
pub struct VmInfo {
    /// Guest memory size.
    pub mem_size_mib: u64,
    /// smt information
    #[version(start = 2, default_fn = "def_smt")]
    pub smt: bool,
    /// CPU template type
    #[version(start = 2, default_fn = "def_cpu_template")]
    pub cpu_template: StaticCpuTemplate,
    /// Boot source information.
    #[version(start = 2, default_fn = "def_boot_source")]
    pub boot_source: BootSourceConfig,
}

impl VmInfo {
    fn def_smt(_: u16) -> bool {
        warn!("SMT field not found in snapshot.");
        false
    }

    fn def_cpu_template(_: u16) -> StaticCpuTemplate {
        warn!("CPU template field not found in snapshot.");
        StaticCpuTemplate::default()
    }

    fn def_boot_source(_: u16) -> BootSourceConfig {
        warn!("Boot source information not found in snapshot.");
        BootSourceConfig::default()
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
#[derive(Debug, Default, Versionize)]
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
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MicrovmStateError {
    /// Compatibility checks failed: {0}
    IncompatibleState(String),
    /// Provided MicroVM state is invalid.
    InvalidInput,
    /// Operation not allowed: {0}
    NotAllowed(String),
    /// Cannot restore devices: {0}
    RestoreDevices(DevicePersistError),
    /// Cannot restore Vcpu state: {0}
    RestoreVcpuState(vstate::vcpu::VcpuError),
    /// Cannot restore Vm state: {0}
    RestoreVmState(vstate::vm::VmError),
    /// Cannot save Vcpu state: {0}
    SaveVcpuState(vstate::vcpu::VcpuError),
    /// Cannot save Vm state: {0}
    SaveVmState(vstate::vm::VmError),
    /// Cannot signal Vcpu: {0}
    SignalVcpu(VcpuSendEventError),
    /// Vcpu is in unexpected state.
    UnexpectedVcpuResponse,
}

/// Errors associated with creating a snapshot.
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CreateSnapshotError {
    /// Cannot get dirty bitmap: {0}
    DirtyBitmap(VmmError),
    /// The virtio devices use a features that is incompatible with older versions of Firecracker: {0}
    IncompatibleVirtioFeature(&'static str),
    /// Invalid microVM version format
    InvalidVersionFormat,
    /// Cannot translate microVM version to snapshot data version
    UnsupportedVersion,
    /// Cannot write memory file: {0}
    Memory(MemoryError),
    /// Cannot perform {0} on the memory backing file: {1}
    MemoryBackingFile(&'static str, io::Error),
    /// Cannot save the microVM state: {0}
    MicrovmState(MicrovmStateError),
    /// Cannot serialize the microVM state: {0}
    SerializeMicrovmState(snapshot::Error),
    /// Cannot perform {0} on the snapshot backing file: {1}
    SnapshotBackingFile(&'static str, io::Error),
    /// Size mismatch when writing diff snapshot on top of base layer: base layer size is {0} but diff layer is size {1}.
    SnapshotBackingFileLengthMismatch(u64, u64),
    #[cfg(target_arch = "x86_64")]
    /// Too many devices attached: {0}. The maximum number allowed for the snapshot data version requested is {FC_V0_23_MAX_DEVICES:}.
    TooManyDevices(usize),
}

/// Creates a Microvm snapshot.
pub fn create_snapshot(
    vmm: &mut Vmm,
    vm_info: &VmInfo,
    params: &CreateSnapshotParams,
    version_map: VersionMap,
) -> Result<(), CreateSnapshotError> {
    let snapshot_data_version = version_map.latest_version();

    let microvm_state = vmm
        .save_state(vm_info)
        .map_err(CreateSnapshotError::MicrovmState)?;

    snapshot_state_to_file(
        &microvm_state,
        &params.snapshot_path,
        snapshot_data_version,
        version_map,
    )?;

    snapshot_memory_to_file(vmm, &params.mem_file_path, params.snapshot_type)?;

    Ok(())
}

fn snapshot_state_to_file(
    microvm_state: &MicrovmState,
    snapshot_path: &Path,
    snapshot_data_version: u16,
    version_map: VersionMap,
) -> Result<(), CreateSnapshotError> {
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

/// Takes a snapshot of the virtual machine running inside the given [`Vmm`] and saves it to
/// `mem_file_path`.
///
/// If `snapshot_type` is [`SnapshotType::Diff`], and `mem_file_path` exists and is a snapshot file
/// of matching size, then the diff snapshot will be directly merged into the existing snapshot.
/// Otherwise, existing files are simply overwritten.
fn snapshot_memory_to_file(
    vmm: &Vmm,
    mem_file_path: &Path,
    snapshot_type: SnapshotType,
) -> Result<(), CreateSnapshotError> {
    use self::CreateSnapshotError::*;

    // Need to check this here, as we create the file in the line below
    let file_existed = mem_file_path.exists();

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(mem_file_path)
        .map_err(|err| MemoryBackingFile("open", err))?;

    // Determine what size our total memory area is.
    let mem_size_mib = mem_size_mib(vmm.guest_memory());
    let expected_size = mem_size_mib * 1024 * 1024;

    if file_existed {
        let file_size = file
            .metadata()
            .map_err(|e| MemoryBackingFile("get_metadata", e))?
            .len();

        // Here we only truncate the file if the size mismatches.
        // - For full snapshots, the entire file's contents will be overwritten anyway. We have to
        //   avoid truncating here to deal with the edge case where it represents the snapshot file
        //   from which this very microVM was loaded (as modifying the memory file would be
        //   reflected in the mmap of the file, meaning a truncate operation would zero out guest
        //   memory, and thus corrupt the VM).
        // - For diff snapshots, we want to merge the diff layer directly into the file.
        if file_size != expected_size {
            file.set_len(0)
                .map_err(|err| MemoryBackingFile("truncate", err))?;
        }
    }

    // Set the length of the file to the full size of the memory area.
    file.set_len(expected_size)
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
    file.flush()
        .map_err(|err| MemoryBackingFile("flush", err))?;
    file.sync_all()
        .map_err(|err| MemoryBackingFile("sync_all", err))
}

/// Validates that snapshot CPU vendor matches the host CPU vendor.
///
/// # Errors
///
/// When:
/// - Failed to read host vendor.
/// - Failed to read snapshot vendor.
#[cfg(target_arch = "x86_64")]
pub fn validate_cpu_vendor(microvm_state: &MicrovmState) {
    let host_vendor_id = get_vendor_id_from_host();
    let snapshot_vendor_id = microvm_state.vcpu_states[0].cpuid.vendor_id();
    match (host_vendor_id, snapshot_vendor_id) {
        (Ok(host_id), Some(snapshot_id)) => {
            info!("Host CPU vendor ID: {host_id:?}");
            info!("Snapshot CPU vendor ID: {snapshot_id:?}");
            if host_id != snapshot_id {
                warn!("Host CPU vendor ID differs from the snapshotted one",);
            }
        }
        (Ok(host_id), None) => {
            info!("Host CPU vendor ID: {host_id:?}");
            warn!("Snapshot CPU vendor ID: couldn't get from the snapshot");
        }
        (Err(_), Some(snapshot_id)) => {
            warn!("Host CPU vendor ID: couldn't get from the host");
            info!("Snapshot CPU vendor ID: {snapshot_id:?}");
        }
        (Err(_), None) => {
            warn!("Host CPU vendor ID: couldn't get from the host");
            warn!("Snapshot CPU vendor ID: couldn't get from the snapshot");
        }
    }
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
pub fn validate_cpu_manufacturer_id(microvm_state: &MicrovmState) {
    let host_cpu_id = get_manufacturer_id_from_host();
    let snapshot_cpu_id = get_manufacturer_id_from_state(&microvm_state.vcpu_states[0].regs);
    match (host_cpu_id, snapshot_cpu_id) {
        (Ok(host_id), Ok(snapshot_id)) => {
            info!("Host CPU manufacturer ID: {host_id:?}");
            info!("Snapshot CPU manufacturer ID: {snapshot_id:?}");
            if host_id != snapshot_id {
                warn!("Host CPU manufacturer ID differs from the snapshotted one",);
            }
        }
        (Ok(host_id), Err(_)) => {
            info!("Host CPU manufacturer ID: {host_id:?}");
            warn!("Snapshot CPU manufacturer ID: couldn't get from the snapshot");
        }
        (Err(_), Ok(snapshot_id)) => {
            warn!("Host CPU manufacturer ID: couldn't get from the host");
            info!("Snapshot CPU manufacturer ID: {snapshot_id:?}");
        }
        (Err(_), Err(_)) => {
            warn!("Host CPU manufacturer ID: couldn't get from the host");
            warn!("Snapshot CPU manufacturer ID: couldn't get from the snapshot");
        }
    }
}
/// Error type for [`snapshot_state_sanity_check`].
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum SnapShotStateSanityCheckError {
    /// Invalid vCPU count.
    InvalidVcpuCount,
    /// No memory region defined.
    NoMemory,
}

/// Performs sanity checks against the state file and returns specific errors.
pub fn snapshot_state_sanity_check(
    microvm_state: &MicrovmState,
) -> Result<(), SnapShotStateSanityCheckError> {
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
    validate_cpu_vendor(microvm_state);
    #[cfg(target_arch = "aarch64")]
    validate_cpu_manufacturer_id(microvm_state);

    Ok(())
}

/// Error type for [`restore_from_snapshot`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum RestoreFromSnapshotError {
    /// Failed to get snapshot state from file: {0}
    File(#[from] SnapshotStateFromFileError),
    /// Invalid snapshot state: {0}
    Invalid(#[from] SnapShotStateSanityCheckError),
    /// Failed to load guest memory: {0}
    GuestMemory(#[from] RestoreFromSnapshotGuestMemoryError),
    /// Failed to build microVM from snapshot: {0}
    Build(#[from] BuildMicrovmFromSnapshotError),
}
/// Sub-Error type for [`restore_from_snapshot`] to contain either [`GuestMemoryFromFileError`] or
/// [`GuestMemoryFromUffdError`] within [`RestoreFromSnapshotError`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum RestoreFromSnapshotGuestMemoryError {
    /// Error creating guest memory from file: {0}
    File(#[from] GuestMemoryFromFileError),
    /// Error creating guest memory from uffd: {0}
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
) -> Result<Arc<Mutex<Vmm>>, RestoreFromSnapshotError> {
    let microvm_state = snapshot_state_from_file(&params.snapshot_path, version_map)?;

    // Some sanity checks before building the microvm.
    snapshot_state_sanity_check(&microvm_state)?;

    let mem_backend_path = &params.mem_backend.backend_path;
    let mem_state = &microvm_state.memory_state;
    let track_dirty_pages = params.enable_diff_snapshots;

    let (guest_memory, uffd) = match params.mem_backend.backend_type {
        MemBackendType::File => (
            guest_memory_from_file(mem_backend_path, mem_state, track_dirty_pages)
                .map_err(RestoreFromSnapshotGuestMemoryError::File)?,
            None,
        ),
        MemBackendType::Uffd => guest_memory_from_uffd(
            mem_backend_path,
            mem_state,
            track_dirty_pages,
            // We enable the UFFD_FEATURE_EVENT_REMOVE feature only if a balloon device
            // is present in the microVM state.
            microvm_state.device_states.balloon_device.is_some(),
        )
        .map_err(RestoreFromSnapshotGuestMemoryError::Uffd)?,
    };
    builder::build_microvm_from_snapshot(
        instance_info,
        event_manager,
        microvm_state,
        guest_memory,
        uffd,
        track_dirty_pages,
        seccomp_filters,
        vm_resources,
    )
    .map_err(RestoreFromSnapshotError::Build)
}

/// Error type for [`snapshot_state_from_file`]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SnapshotStateFromFileError {
    /// Failed to open snapshot file: {0}
    Open(std::io::Error),
    /// Failed to read snapshot file metadata: {0}
    Meta(std::io::Error),
    /// Failed to load snapshot state from file: {0}
    Load(#[from] snapshot::Error),
}

fn snapshot_state_from_file(
    snapshot_path: &Path,
    version_map: VersionMap,
) -> Result<MicrovmState, SnapshotStateFromFileError> {
    let mut snapshot_reader =
        File::open(snapshot_path).map_err(SnapshotStateFromFileError::Open)?;
    let metadata = std::fs::metadata(snapshot_path).map_err(SnapshotStateFromFileError::Meta)?;
    let snapshot_len = u64_to_usize(metadata.len());
    let (state, _) = Snapshot::load(&mut snapshot_reader, snapshot_len, version_map)
        .map_err(SnapshotStateFromFileError::Load)?;
    Ok(state)
}

/// Error type for [`guest_memory_from_file`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum GuestMemoryFromFileError {
    /// Failed to load guest memory: {0}
    File(#[from] std::io::Error),
    /// Failed to restore guest memory: {0}
    Restore(#[from] MemoryError),
}

fn guest_memory_from_file(
    mem_file_path: &Path,
    mem_state: &GuestMemoryState,
    track_dirty_pages: bool,
) -> Result<GuestMemoryMmap, GuestMemoryFromFileError> {
    let mem_file = File::open(mem_file_path)?;
    let guest_mem = GuestMemoryMmap::from_state(Some(&mem_file), mem_state, track_dirty_pages)?;
    Ok(guest_mem)
}

/// Error type for [`guest_memory_from_uffd`]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum GuestMemoryFromUffdError {
    /// Failed to restore guest memory: {0}
    Restore(#[from] MemoryError),
    /// Failed to UFFD object: {0}
    Create(userfaultfd::Error),
    /// Failed to register memory address range with the userfaultfd object: {0}
    Register(userfaultfd::Error),
    /// Failed to connect to UDS Unix stream: {0}
    Connect(#[from] std::io::Error),
    /// Failed to sends file descriptor: {0}
    Send(#[from] utils::errno::Error),
}

fn guest_memory_from_uffd(
    mem_uds_path: &Path,
    mem_state: &GuestMemoryState,
    track_dirty_pages: bool,
    enable_balloon: bool,
) -> Result<(GuestMemoryMmap, Option<Uffd>), GuestMemoryFromUffdError> {
    let guest_memory = GuestMemoryMmap::from_state(None, mem_state, track_dirty_pages)?;

    let mut uffd_builder = UffdBuilder::new();

    if enable_balloon {
        // We enable this so that the page fault handler can add logic
        // for treating madvise(MADV_DONTNEED) events triggerd by balloon inflation.
        uffd_builder.require_features(FeatureFlags::EVENT_REMOVE);
    }

    let uffd = uffd_builder
        .close_on_exec(true)
        .non_blocking(true)
        .user_mode_only(false)
        .create()
        .map_err(GuestMemoryFromUffdError::Create)?;

    let mut backend_mappings = Vec::with_capacity(guest_memory.num_regions());
    for (mem_region, state_region) in guest_memory.iter().zip(mem_state.regions.iter()) {
        let host_base_addr = mem_region.as_ptr();
        let size = mem_region.size();

        uffd.register(host_base_addr.cast(), size as _)
            .map_err(GuestMemoryFromUffdError::Register)?;
        backend_mappings.push(GuestRegionUffdMapping {
            base_host_virt_addr: host_base_addr as u64,
            size,
            offset: state_region.offset,
        });
    }

    // This is safe to unwrap() because we control the contents of the vector
    // (i.e GuestRegionUffdMapping entries).
    let backend_mappings = serde_json::to_string(&backend_mappings).unwrap();

    let socket = UnixStream::connect(mem_uds_path)?;
    socket.send_with_fd(
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
    )?;

    Ok((guest_memory, Some(uffd)))
}

#[cfg(test)]
mod tests {
    use snapshot::Persist;
    use utils::tempfile::TempFile;

    use super::*;
    use crate::builder::tests::{
        default_kernel_cmdline, default_vmm, insert_balloon_device, insert_block_devices,
        insert_net_device, insert_vsock_device, CustomBlockConfig,
    };
    #[cfg(target_arch = "aarch64")]
    use crate::construct_kvm_mpidrs;
    use crate::devices::virtio::block_common::CacheType;
    use crate::vmm_config::balloon::BalloonDeviceConfig;
    use crate::vmm_config::net::NetworkInterfaceConfig;
    use crate::vmm_config::vsock::tests::default_config;
    use crate::Vmm;

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
        assert_eq!(states.virtio_block_devices.len(), 1);
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
}
