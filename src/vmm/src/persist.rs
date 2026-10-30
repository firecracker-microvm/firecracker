// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines state structures for saving/restoring a Firecracker microVM.

use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::utils::Version;
use serde::{Deserialize, Serialize};
use userfaultfd::{FeatureFlags, Uffd, UffdBuilder};

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::vcpu::get_manufacturer_id_from_host;
use crate::builder::{self, BuildMicrovmFromSnapshotError};
use crate::cpu_config::templates::StaticCpuTemplate;
#[cfg(target_arch = "x86_64")]
use crate::cpu_config::x86_64::cpuid::CpuidTrait;
#[cfg(target_arch = "x86_64")]
use crate::cpu_config::x86_64::cpuid::common::get_vendor_id_from_host;
use crate::device_manager::{DevicePersistError, DevicesState};
// Re-exported so external crates inspecting a `MicrovmState` snapshot can match on the
// serialised virtio transport variant.
pub use crate::device_manager::VirtioDevicesState;
use crate::logger::{info, warn};
use crate::mem_backend::{Handshake, HandshakeError};
use crate::resources::VmResources;
use crate::seccomp::BpfThreadMap;
use crate::snapshot::Snapshot;
use crate::utils::u64_to_usize;
use crate::vmm_config::boot_source::BootSourceConfig;
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::{HugePageConfig, MachineConfigError, MachineConfigUpdate};
use crate::vmm_config::snapshot::{CreateSnapshotParams, LoadSnapshotParams, MemBackendType};
use crate::vstate::kvm::KvmState;
use crate::vstate::memory::{
    self, GuestMemoryState, GuestRegionMmap, GuestRegionType, MemfdBacking, MemoryError,
};
use crate::vstate::vcpu::{VcpuSendEventError, VcpuState};
use crate::vstate::vm::{VmError, VmState};
use crate::{EventManager, Vmm, vstate};

/// Holds information related to the VM that is not part of VmState.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct VmInfo {
    /// Guest memory size.
    pub mem_size_mib: u64,
    /// smt information
    pub smt: bool,
    /// CPU template type
    pub cpu_template: StaticCpuTemplate,
    /// Boot source information.
    pub boot_source: BootSourceConfig,
    /// Huge page configuration
    pub huge_pages: HugePageConfig,
    /// Number of PCIe hot-plug ports
    pub pcie_hotplug_ports: u8,
}

impl From<&VmResources> for VmInfo {
    fn from(value: &VmResources) -> Self {
        Self {
            mem_size_mib: value.machine_config.mem_size_mib as u64,
            smt: value.machine_config.smt,
            cpu_template: StaticCpuTemplate::from(&value.machine_config.cpu_template),
            boot_source: value.boot_source.config.clone(),
            huge_pages: value.machine_config.huge_pages,
            pcie_hotplug_ports: value.machine_config.pcie_hotplug_ports,
        }
    }
}

impl From<&Vmm> for VmInfo {
    fn from(value: &Vmm) -> Self {
        let machine_config = &value.machine_config;
        Self {
            mem_size_mib: machine_config.mem_size_mib as u64,
            smt: machine_config.smt,
            cpu_template: StaticCpuTemplate::from(&machine_config.cpu_template),
            boot_source: value.boot_source_config.clone(),
            huge_pages: machine_config.huge_pages,
            pcie_hotplug_ports: machine_config.pcie_hotplug_ports,
        }
    }
}

/// Contains the necessary state for saving/restoring a microVM.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MicrovmState {
    /// Miscellaneous VM info.
    pub vm_info: VmInfo,
    /// KVM KVM state.
    pub kvm_state: KvmState,
    /// VM KVM state.
    pub vm_state: VmState,
    /// Vcpu states.
    pub vcpu_states: Vec<VcpuState>,
    /// Device states.
    pub device_states: DevicesState,
}

/// Errors related to saving and restoring Microvm state.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MicrovmStateError {
    /// Operation not allowed: {0}
    NotAllowed(String),
    /// Cannot restore devices: {0}
    RestoreDevices(#[from] DevicePersistError),
    /// Cannot save Vcpu state: {0}
    SaveVcpuState(vstate::vcpu::VcpuError),
    /// Cannot save KvmVm state: {0}
    SaveVmState(vstate::vm::KvmVmError),
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
    DirtyBitmap(#[from] VmError),
    /// Cannot write memory file: {0}
    Memory(#[from] MemoryError),
    /// Cannot perform {0} on the memory backing file: {1}
    MemoryBackingFile(&'static str, io::Error),
    /// Cannot save the microVM state: {0}
    MicrovmState(MicrovmStateError),
    /// Cannot serialize the microVM state: {0}
    SerializeMicrovmState(#[from] crate::snapshot::SnapshotError),
    /// Cannot perform {0} on the snapshot backing file: {1}
    SnapshotBackingFile(&'static str, io::Error),
}

/// Snapshot version
pub const SNAPSHOT_VERSION: Version = Version::new(13, 0, 0);

/// Creates a Microvm snapshot.
pub fn create_snapshot(
    vmm: &mut Vmm,
    vm_info: &VmInfo,
    params: &CreateSnapshotParams,
) -> Result<(), CreateSnapshotError> {
    let microvm_state = vmm
        .save_state(vm_info)
        .map_err(CreateSnapshotError::MicrovmState)?;

    snapshot_state_to_file(
        &microvm_state,
        &params.snapshot_path,
        params.sync_snapshot_files,
    )?;

    let kvm_vm = vmm.vm.as_kvm().ok_or_else(|| {
        CreateSnapshotError::MicrovmState(MicrovmStateError::NotAllowed(
            "snapshot requires KVM".into(),
        ))
    })?;
    // Devices record which queue pages they wrote, but only report them to the dirty bitmap
    // when asked, to keep the data path free of contention on the bitmap.
    vmm.device_manager.commit_dirty();

    kvm_vm.snapshot_memory_to_file(
        &params.mem_file_path,
        params.snapshot_type,
        params.sync_snapshot_files,
    )?;

    Ok(())
}

fn snapshot_state_to_file(
    microvm_state: &MicrovmState,
    snapshot_path: &Path,
    sync_snapshot_files: bool,
) -> Result<(), CreateSnapshotError> {
    use self::CreateSnapshotError::*;
    let mut snapshot_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(snapshot_path)
        .map_err(|err| SnapshotBackingFile("open", err))?;

    let snapshot = Snapshot::new(microvm_state);
    snapshot.save(&mut snapshot_file)?;
    snapshot_file
        .flush()
        .map_err(|err| SnapshotBackingFile("flush", err))?;
    if sync_snapshot_files {
        snapshot_file
            .sync_all()
            .map_err(|err| SnapshotBackingFile("sync_all", err))?;
    }
    Ok(())
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
    let snapshot_cpu_id = microvm_state.vcpu_states[0].regs.manifacturer_id();
    match (host_cpu_id, snapshot_cpu_id) {
        (Some(host_id), Some(snapshot_id)) => {
            info!("Host CPU manufacturer ID: {host_id:?}");
            info!("Snapshot CPU manufacturer ID: {snapshot_id:?}");
            if host_id != snapshot_id {
                warn!("Host CPU manufacturer ID differs from the snapshotted one",);
            }
        }
        (Some(host_id), None) => {
            info!("Host CPU manufacturer ID: {host_id:?}");
            warn!("Snapshot CPU manufacturer ID: couldn't get from the snapshot");
        }
        (None, Some(snapshot_id)) => {
            warn!("Host CPU manufacturer ID: couldn't get from the host");
            info!("Snapshot CPU manufacturer ID: {snapshot_id:?}");
        }
        (None, None) => {
            warn!("Host CPU manufacturer ID: couldn't get from the host");
            warn!("Snapshot CPU manufacturer ID: couldn't get from the snapshot");
        }
    }
}
/// Error type for [`snapshot_state_sanity_check`].
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum SnapShotStateSanityCheckError {
    /// No memory region defined.
    NoMemory,
    /// No DRAM memory region defined.
    NoDramMemory,
    /// DRAM memory has more than a single slot.
    DramMemoryTooManySlots,
    /// DRAM memory is unplugged.
    DramMemoryUnplugged,
}

/// Performs sanity checks against the state file and returns specific errors.
pub fn snapshot_state_sanity_check(
    microvm_state: &MicrovmState,
) -> Result<(), SnapShotStateSanityCheckError> {
    // Check that the snapshot contains at least 1 mem region, that at least one is Dram,
    // and that Dram region contains a single plugged slot.
    // Upper bound check will be done when creating guest memory by comparing against
    // KVM max supported value kvm_context.max_memslots().
    let regions = &microvm_state.vm_state.memory.regions;

    if regions.is_empty() {
        return Err(SnapShotStateSanityCheckError::NoMemory);
    }

    if !regions
        .iter()
        .any(|r| r.region_type == GuestRegionType::Dram)
    {
        return Err(SnapShotStateSanityCheckError::NoDramMemory);
    }

    for dram_region in regions
        .iter()
        .filter(|r| r.region_type == GuestRegionType::Dram)
    {
        if dram_region.plugged.len() != 1 {
            return Err(SnapShotStateSanityCheckError::DramMemoryTooManySlots);
        }

        if !dram_region.plugged[0] {
            return Err(SnapShotStateSanityCheckError::DramMemoryUnplugged);
        }
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
    vm_resources: &mut VmResources,
) -> Result<Arc<Mutex<Vmm>>, RestoreFromSnapshotError> {
    let mut microvm_state = snapshot_state_from_file(&params.snapshot_path)?;
    for entry in &params.network_overrides {
        // Only the active transport carries virtio device state, so we look at whichever
        // variant this snapshot was saved with. The MMIO and PCI transports wrap their net
        // devices in distinct types, so we map down to the shared inner `NetState` in each arm.
        let device_state = match &mut microvm_state.device_states.virtio_state {
            VirtioDevicesState::Mmio(mmio_state) => mmio_state
                .net_devices
                .iter_mut()
                .map(|device| &mut device.device_state)
                .find(|x| x.id == entry.iface_id),
            VirtioDevicesState::Pci(pci_state) => pci_state
                .net_devices
                .iter_mut()
                .map(|device| &mut device.device_state)
                .find(|x| x.id == entry.iface_id),
        };
        device_state
            .map(|device_state| device_state.tap_if_name.clone_from(&entry.host_dev_name))
            .ok_or(SnapshotStateFromFileError::UnknownNetworkDevice)?;
    }

    if let Some(vsock_override) = &params.vsock_override {
        // There should only ever be at most one vsock device, therefore this
        // should correctly find it and modify the path if such a device exists.
        let device_state = match &mut microvm_state.device_states.virtio_state {
            VirtioDevicesState::Mmio(mmio_state) => mmio_state
                .vsock_device
                .as_mut()
                .map(|device| &mut device.device_state),
            VirtioDevicesState::Pci(pci_state) => pci_state
                .vsock_device
                .as_mut()
                .map(|device| &mut device.device_state),
        }
        .ok_or(SnapshotStateFromFileError::UnknownVsockDevice)?;

        device_state
            .backend
            .uds_path
            .clone_from(&vsock_override.uds_path);
    }

    let track_dirty_pages = params.track_dirty_pages;

    let vcpu_count = microvm_state
        .vcpu_states
        .len()
        .try_into()
        .map_err(|_| MachineConfigError::InvalidVcpuCount)
        .map_err(BuildMicrovmFromSnapshotError::VmUpdateConfig)?;

    // Due to questionable past API design decisions whether the restored VM
    // uses PCI is decided by the snapshot and not by the --enable-pci flag of
    // the process doing the restore. Set the option based on the snapshot
    // state.
    let pci_enabled = matches!(
        microvm_state.device_states.virtio_state,
        VirtioDevicesState::Pci(_)
    );
    if pci_enabled != vm_resources.pci_enabled {
        warn!(
            "The snapshot's PCI configuration does not match --enable-pci; \
             following the snapshot configuration."
        );
    }
    vm_resources.pci_enabled = pci_enabled;

    vm_resources
        .update_machine_config(&MachineConfigUpdate {
            vcpu_count: Some(vcpu_count),
            mem_size_mib: Some(u64_to_usize(microvm_state.vm_info.mem_size_mib)),
            smt: Some(microvm_state.vm_info.smt),
            cpu_template: Some(microvm_state.vm_info.cpu_template),
            track_dirty_pages: Some(track_dirty_pages),
            huge_pages: Some(params.huge_pages.resolve(microvm_state.vm_info.huge_pages)),
            pcie_hotplug_ports: Some(microvm_state.vm_info.pcie_hotplug_ports),
            mem_backend: None,
            #[cfg(feature = "gdb")]
            gdb_socket_path: None,
        })
        .map_err(BuildMicrovmFromSnapshotError::VmUpdateConfig)?;

    // Some sanity checks before building the microvm.
    snapshot_state_sanity_check(&microvm_state)?;

    let mem_backend_path = &params.mem_backend.backend_path;
    let mem_state = &microvm_state.vm_state.memory;

    let (guest_memory, uffd) = match params.mem_backend.backend_type {
        MemBackendType::File => {
            if vm_resources.machine_config.huge_pages.is_hugetlbfs() {
                return Err(RestoreFromSnapshotGuestMemoryError::File(
                    GuestMemoryFromFileError::HugetlbfsSnapshot,
                )
                .into());
            }
            (
                guest_memory_from_file(
                    mem_backend_path,
                    mem_state,
                    track_dirty_pages,
                    vm_resources.machine_config.huge_pages,
                )
                .map_err(RestoreFromSnapshotGuestMemoryError::File)?,
                None,
            )
        }
        MemBackendType::Uffd | MemBackendType::SharedMemfd => guest_memory_from_uffd(
            mem_backend_path,
            mem_state,
            track_dirty_pages,
            vm_resources.machine_config.huge_pages,
            params.mem_backend.backend_type == MemBackendType::SharedMemfd,
        )
        .map_err(RestoreFromSnapshotGuestMemoryError::Uffd)?,
    };
    builder::build_microvm_from_snapshot(
        instance_info,
        event_manager,
        microvm_state,
        guest_memory,
        uffd,
        seccomp_filters,
        vm_resources,
        params.clock_realtime,
    )
    .map_err(RestoreFromSnapshotError::Build)
}

/// Error type for [`snapshot_state_from_file`]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SnapshotStateFromFileError {
    /// Failed to open snapshot file: {0}
    Open(#[from] std::io::Error),
    /// Failed to load snapshot state from file: {0}
    Load(#[from] crate::snapshot::SnapshotError),
    /// Unknown Network Device.
    UnknownNetworkDevice,
    /// Unknown Vsock Device.
    UnknownVsockDevice,
}

fn snapshot_state_from_file(
    snapshot_path: &Path,
) -> Result<MicrovmState, SnapshotStateFromFileError> {
    let mut snapshot_reader = File::open(snapshot_path)?;
    let snapshot = Snapshot::load(&mut snapshot_reader)?;

    Ok(snapshot.data)
}

/// Error type for [`guest_memory_from_file`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum GuestMemoryFromFileError {
    /// Failed to load guest memory: {0}
    File(#[from] std::io::Error),
    /// Failed to restore guest memory: {0}
    Restore(#[from] MemoryError),
    /// Cannot restore hugetlbfs backed snapshot by mapping the memory file. Please use uffd.
    HugetlbfsSnapshot,
}

fn guest_memory_from_file(
    mem_file_path: &Path,
    mem_state: &GuestMemoryState,
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
) -> Result<Vec<GuestRegionMmap>, GuestMemoryFromFileError> {
    let mem_file = File::open(mem_file_path)?;
    let guest_mem = memory::snapshot_file(
        mem_file,
        &mem_state.regions(),
        track_dirty_pages,
        huge_pages,
    )?;
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
    /// {0}
    Handshake(#[from] HandshakeError),
}

/// Creates guest memory for a restore served by a page fault handler: anonymous, or backed by a
/// single memfd laid out like the memory file when `share_memfd` is set. The handler at
/// `mem_uds_path` receives the userfaultfd, followed by the memfd when there is one.
fn guest_memory_from_uffd(
    mem_uds_path: &Path,
    mem_state: &GuestMemoryState,
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
    share_memfd: bool,
) -> Result<(Vec<GuestRegionMmap>, Option<Uffd>), GuestMemoryFromUffdError> {
    let regions = mem_state.regions();
    let (guest_memory, memfd) = if share_memfd {
        let total_size = regions
            .iter()
            .try_fold(0u64, |acc, &(_, size)| acc.checked_add(size as u64))
            .ok_or(MemoryError::OffsetTooLarge)?;
        let mut backing = MemfdBacking::new(total_size, huge_pages)?;
        let guest_memory = backing.allocate(&regions, track_dirty_pages, huge_pages)?;
        (guest_memory, Some(backing.file))
    } else {
        (
            memory::anonymous(&regions, track_dirty_pages, huge_pages)?,
            None,
        )
    };
    let handshake = Handshake::new(guest_memory.iter(), huge_pages);

    let mut uffd_builder = UffdBuilder::new();

    // We only make use of this if balloon devices are present, but we can enable it unconditionally
    // because the only place the kernel checks this is in a hook from madvise, e.g. it doesn't
    // actively change the behavior of UFFD, only passively. Without balloon devices
    // we never call madvise anyway, so no need to put this into a conditional.
    uffd_builder.require_features(FeatureFlags::EVENT_REMOVE);

    let uffd = uffd_builder
        .close_on_exec(true)
        .non_blocking(true)
        .user_mode_only(false)
        .create()
        .map_err(GuestMemoryFromUffdError::Create)?;

    for mem_region in guest_memory.iter() {
        uffd.register(mem_region.as_ptr().cast(), mem_region.size() as _)
            .map_err(GuestMemoryFromUffdError::Register)?;
    }

    // The uffd always comes first, so that a handler written for the plain UFFD protocol (which
    // reads a single fd) keeps working; the memfd, when shared, comes last.
    let mut fds = vec![uffd.as_raw_fd()];
    if let Some(memfd) = &memfd {
        fds.push(memfd.as_raw_fd());
    }
    handshake.send(mem_uds_path, &fds)?;

    Ok((guest_memory, Some(uffd)))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::FileExt;
    use std::os::unix::net::UnixListener;

    use vm_memory::{Bytes, MemoryRegionAddress};
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::Vmm;
    #[cfg(target_arch = "x86_64")]
    use crate::builder::tests::insert_vmclock_device;
    #[cfg(target_arch = "x86_64")]
    use crate::builder::tests::insert_vmgenid_device;
    use crate::builder::tests::{
        CustomBlockConfig, default_kernel_cmdline, default_vmm, insert_balloon_device,
        insert_block_devices, insert_net_device, insert_vsock_device,
    };
    #[cfg(target_arch = "aarch64")]
    use crate::construct_kvm_mpidrs;
    use crate::devices::virtio::block::CacheType;
    use crate::mem_backend::receive_handshake;
    use crate::snapshot::Persist;
    use crate::vmm_config::balloon::BalloonDeviceConfig;
    use crate::vmm_config::net::NetworkInterfaceConfig;
    use crate::vmm_config::vsock::tests::default_config;
    use crate::vstate::memory::{GuestMemoryRegionState, GuestRegionType};

    fn default_vmm_with_devices() -> Vmm {
        let mut event_manager = EventManager::new().expect("Cannot create EventManager");
        let mut vmm = default_vmm();
        let mut cmdline = default_kernel_cmdline();

        // Add a balloon device.
        let balloon_config = BalloonDeviceConfig {
            amount_mib: 0,
            deflate_on_oom: false,
            stats_polling_interval_s: 0,
            free_page_hinting: false,
            free_page_reporting: false,
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
            mtu: None,
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

        #[cfg(target_arch = "x86_64")]
        insert_vmgenid_device(&mut vmm);
        #[cfg(target_arch = "x86_64")]
        insert_vmclock_device(&mut vmm);

        vmm
    }

    #[test]
    fn test_microvm_state_snapshot() {
        let vmm = default_vmm_with_devices();
        let states = vmm.device_manager.save();

        // Only checking that all devices are saved, actual device state
        // is tested by that device's tests.
        let VirtioDevicesState::Mmio(mmio_state) = &states.virtio_state else {
            panic!("expected MMIO virtio device state");
        };
        assert_eq!(mmio_state.block_devices.len(), 1);
        assert_eq!(mmio_state.net_devices.len(), 1);
        assert!(mmio_state.vsock_device.is_some());
        assert!(mmio_state.balloon_device.is_some());

        let vcpu_states = vec![VcpuState::default()];
        #[cfg(target_arch = "aarch64")]
        let mpidrs = construct_kvm_mpidrs(&vcpu_states);
        let microvm_state = MicrovmState {
            device_states: states,
            vcpu_states,
            kvm_state: Default::default(),
            vm_info: VmInfo {
                mem_size_mib: 1u64,
                ..Default::default()
            },
            #[cfg(target_arch = "aarch64")]
            vm_state: vmm.vm.as_kvm().unwrap().save_state(&mpidrs).unwrap(),
            #[cfg(target_arch = "x86_64")]
            vm_state: vmm.vm.as_kvm().unwrap().save_state().unwrap(),
        };

        let serialized_data = bitcode::serialize(&microvm_state).unwrap();

        let restored_microvm_state: MicrovmState = bitcode::deserialize(&serialized_data).unwrap();

        assert_eq!(restored_microvm_state.vm_info, microvm_state.vm_info);
        let (VirtioDevicesState::Mmio(restored_mmio), VirtioDevicesState::Mmio(mmio)) = (
            &restored_microvm_state.device_states.virtio_state,
            &microvm_state.device_states.virtio_state,
        ) else {
            panic!("expected MMIO virtio device state");
        };
        assert_eq!(restored_mmio, mmio)
    }

    /// Restoring with `SharedMemfd` hands the handler the uffd and then the memfd, one memfd
    /// as large as guest memory, laid out like the memory file.
    #[test]
    fn test_guest_memory_from_uffd_shared_memfd() {
        let mem_state = GuestMemoryState {
            regions: vec![
                GuestMemoryRegionState {
                    base_address: 0,
                    size: 0x20000,
                    region_type: GuestRegionType::Dram,
                    plugged: vec![true],
                },
                GuestMemoryRegionState {
                    base_address: 0x100000,
                    size: 0x10000,
                    region_type: GuestRegionType::Dram,
                    plugged: vec![true],
                },
            ],
        };

        let uds_path = TempFile::new().unwrap();
        let uds_path = uds_path.as_path();
        std::fs::remove_file(uds_path).unwrap();
        let listener = UnixListener::bind(uds_path).expect("Cannot bind to socket path");

        let (guest_memory, uffd) =
            guest_memory_from_uffd(uds_path, &mem_state, false, HugePageConfig::None, true)
                .unwrap();
        let uffd = uffd.unwrap();
        let (mappings, files) = receive_handshake(&listener);

        assert_eq!(
            mappings,
            Handshake::new(guest_memory.iter(), HugePageConfig::None).regions
        );
        assert_eq!(files.len(), 2);
        // The uffd is an anonymous inode, the memfd a regular (shmem) file as large as all the
        // regions together.
        assert!(!files[0].metadata().unwrap().file_type().is_file());
        let memfd = &files[1];
        assert!(memfd.metadata().unwrap().file_type().is_file());
        assert_eq!(memfd.metadata().unwrap().len(), 0x30000);

        // What is written through the memfd is what the guest sees, at the region's offset.
        let page_size = crate::arch::host_page_size();
        let pattern = vec![0xABu8; page_size];
        memfd.write_all_at(&pattern, 0x20000).unwrap();
        let mut read_back = vec![0u8; page_size];
        guest_memory[1]
            .read_slice(&mut read_back, MemoryRegionAddress(0))
            .unwrap();
        assert_eq!(read_back, pattern);

        // Without sharing, the handshake carries the uffd alone.
        drop(uffd);
        let (_, uffd) =
            guest_memory_from_uffd(uds_path, &mem_state, false, HugePageConfig::None, false)
                .unwrap();
        let (_, files) = receive_handshake(&listener);
        assert!(uffd.is_some());
        assert_eq!(files.len(), 1);
        assert!(!files[0].metadata().unwrap().file_type().is_file());
    }
}
