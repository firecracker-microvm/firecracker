// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enclave build orchestrator.
//!
//! Loads a pre-built EIF image or builds one from kernel+initrd+boot_args,
//! then boots a Nitro Enclave from `VmResources`.

use std::sync::{Arc, Mutex};

use event_manager::SubscriberOps;

use crate::device_manager::nitro_enclave::NeDevices;
use crate::device_manager::{AttachDeviceError, DeviceManager, VirtioDevices};
use crate::logger::info;
use crate::nitro_enclave::cpu_accounting::AccountingThreads;
use crate::nitro_enclave::eif;
use crate::nitro_enclave::enclave_vm::{EnclaveVm, MAX_SUPPORTED_ENCLAVE_VCPUS};
use crate::nitro_enclave::ne_ioctl;
use crate::nitro_enclave::ne_ioctl::NitroEnclavesDevFd;
use crate::nitro_enclave::serial_console::ConsoleReader;
use crate::resources::VmResources;
use crate::seccomp::BpfThreadMap;
use crate::utils::mib_to_bytes;
use crate::vmm_config::boot_source::{
    BootConfig, DEFAULT_ENCLAVE_KERNEL_CMDLINE, append_root_device_cmdline, build_cmdline,
};
use crate::vmm_config::enclave::{EnclaveConfig, EnclaveNumaNode};
use crate::vmm_config::instance_info::{InstanceInfo, VmState};
use crate::vmm_config::machine_config::MachineConfig;
use crate::vstate::vm::Vm;
use crate::{EventManager, Vmm};

/// Errors from building and booting an enclave.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EnclaveBuilderError {
    /// Boot source not configured (kernel_image_path required)
    NoBootSource,
    /// mem_size_mib ({0}) must be a multiple of 2 for an enclave
    MemSizeNotAligned(usize),
    /// Failed to open /dev/nitro_enclaves: {0}
    OpenDevice(std::io::Error),
    /// Failed to read EIF image: {0}
    ReadEif(std::io::Error),
    /// Invalid kernel command line: {0}
    InvalidKernelCommandLine(String),
    /// Failed to build EIF from kernel+initrd: {0}
    EifBuild(#[from] eif::EifError),
    /// Enclave VM error: {0}
    EnclaveVm(#[from] crate::nitro_enclave::enclave_vm::EnclaveVmError),
    /// Info page was not created
    NoInfoPage,
    /// Serial console error: {0}
    Console(std::io::Error),
    /// cpu_ids length ({config_count}) != vcpu_count ({vcpu_count})
    CpuCountMismatch {
        /// Number of CPU IDs in the config.
        config_count: usize,
        /// Expected vCPU count from machine config.
        vcpu_count: usize,
    },
    /// The number of vCPUs ({requested}) exceeds the maximum for a Nitro Enclave VM ({max}).
    TooManyVcpus {
        /// Requested vCPU count from the machine config.
        requested: u16,
        /// Maximum vCPUs supported by a Nitro Enclave VM.
        max: u16,
    },
    /// Hypervisor does not support required matched flags: requested={requested:#06x}, supported={supported:#06x}
    UnsupportedFlags {
        /// Matched flags requested by the enclave config.
        requested: u64,
        /// Matched flags supported by the hypervisor.
        supported: u32,
    },
    /// Failed to query hypervisor-supported flags: {0}
    GetSupportedFlags(std::io::Error),
    /// Failed to attach enclave device: {0}
    AttachDevice(AttachDeviceError),
    /// Failed to start CPU-accounting threads: {0}
    Accounting(#[from] crate::nitro_enclave::cpu_accounting::AccountingError),
    /// Required "vcpu" seccomp filter not found
    MissingSeccompFilters,
    /// Invalid numa_nodes config: {0}
    NumaValidationError(String),
    /// A Nitro Enclave does not support a {0} device
    UnsupportedDevice(&'static str),
}

/// Resolve the kernel command line for the enclave.
///
/// Uses the user-provided cmdline if set, otherwise falls back to
/// [`DEFAULT_ENCLAVE_KERNEL_CMDLINE`]. In debug mode, appends `console=ttyS0`
/// if no `console=` argument is already present. If no `root=` argument is
/// present, derives one from the root block device.
fn resolve_enclave_cmdline(
    boot_config: &BootConfig,
    enclave_config: &EnclaveConfig,
    vm_resources: &VmResources,
) -> Result<String, EnclaveBuilderError> {
    let map_err = |e: linux_loader::cmdline::Error| {
        EnclaveBuilderError::InvalidKernelCommandLine(e.to_string())
    };

    let mut cmdline = match boot_config.cmdline.clone() {
        Some(c) => c,
        None => build_cmdline(DEFAULT_ENCLAVE_KERNEL_CMDLINE).map_err(map_err)?,
    };

    // In debug mode add a serial console, but only if the user hasn't already
    // specified one — `linux_loader::cmdline` does not deduplicate, so inserting
    // unconditionally would emit a second `console=` token.
    if enclave_config.debug_mode {
        let has_console = cmdline
            .as_cstring()
            .map(|c| c.to_str().unwrap_or("").contains("console="))
            .unwrap_or(false);
        if !has_console {
            cmdline.insert_str("console=ttyS0").map_err(map_err)?;
        }
    }

    // Add root= from the root block device.
    for block in &vm_resources.block.devices {
        let locked = block.lock().expect("Poisoned lock");
        if locked.root_device() {
            append_root_device_cmdline(
                &mut cmdline,
                locked.partuuid().as_deref(),
                locked.read_only(),
            )
            .map_err(map_err)?;
            break;
        }
    }

    let cstring = cmdline.as_cstring().map_err(map_err)?;
    Ok(cstring.to_str().unwrap_or("").to_owned())
}

/// Reject a vCPU count above the enclave-path maximum.
fn validate_enclave_vcpu_count(vcpu_count: u16) -> Result<(), EnclaveBuilderError> {
    if vcpu_count > MAX_SUPPORTED_ENCLAVE_VCPUS {
        return Err(EnclaveBuilderError::TooManyVcpus {
            requested: vcpu_count,
            max: MAX_SUPPORTED_ENCLAVE_VCPUS,
        });
    }
    Ok(())
}

/// Reject devices the enclave cannot serve.
///
/// Balloon, pmem and memory hotplug have no Nitro Enclave transport, so they
/// would be configured successfully and then never reach the guest. A vhost-user
/// block is attached like any other block, but its backend maps guest memory by
/// fd, and an enclave's names /dev/nitro_enclaves rather than something a
/// backend can map.
fn validate_supported_devices(vm_resources: &VmResources) -> Result<(), EnclaveBuilderError> {
    let has_vhost_user_block = vm_resources
        .block
        .devices
        .iter()
        .any(|b| b.lock().expect("Poisoned lock").is_vhost_user());
    for (present, name) in [
        (vm_resources.balloon.get().is_some(), "balloon"),
        (!vm_resources.pmem.configs.is_empty(), "pmem"),
        (vm_resources.memory_hotplug.is_some(), "memory hotplug"),
        (has_vhost_user_block, "vhost-user block"),
    ] {
        if present {
            return Err(EnclaveBuilderError::UnsupportedDevice(name));
        }
    }
    Ok(())
}
/// Build and boot a Nitro Enclave from the given VM resources and enclave config.
///
/// If `kernel_image_path` points to a pre-built EIF file (detected by magic bytes),
/// it is loaded directly. Otherwise, an EIF is built from `kernel_image_path` +
/// `initrd_path` + `boot_args`.
pub fn build_and_boot_enclave(
    instance_info: &InstanceInfo,
    vm_resources: &VmResources,
    enclave_config: &EnclaveConfig,
    event_manager: &mut EventManager,
    seccomp_filters: &BpfThreadMap,
) -> Result<Arc<Mutex<Vmm>>, EnclaveBuilderError> {
    let boot_config = vm_resources
        .boot_source
        .builder
        .as_ref()
        .ok_or(EnclaveBuilderError::NoBootSource)?;
    let kernel_path = &vm_resources.boot_source.config.kernel_image_path;

    // Enclave RAM is donated in 2 MiB-aligned regions, so the total must be a
    // multiple of 2 MiB.
    let mem_size_mib = vm_resources.machine_config.mem_size_mib;
    if !mem_size_mib.is_multiple_of(2) {
        return Err(EnclaveBuilderError::MemSizeNotAligned(mem_size_mib));
    }

    validate_supported_devices(vm_resources)?;

    let vcpu_count = vm_resources.machine_config.vcpu_count;
    validate_enclave_vcpu_count(vcpu_count)?;

    let numa_nodes = validate_numa_config(enclave_config, &vm_resources.machine_config)?;
    let multi_numa = numa_nodes.len() > 1;

    let mut required_matched = ne_ioctl::start_flags::NE_ENCLAVE_PCIE_MODE
        | ne_ioctl::start_flags::NE_ENCLAVE_PCIE_VIRTIO_MODE;
    if enclave_config.cpu_overcommit {
        required_matched |= ne_ioctl::start_flags::NE_ENCLAVE_CPU_OVERCOMMIT_MODE;
    }
    if enclave_config.cpu_accounting {
        required_matched |= ne_ioctl::start_flags::NE_ENCLAVE_CPU_ACCOUNTING_MODE;
    }
    if enclave_config.hotplug_mode {
        required_matched |= ne_ioctl::start_flags::NE_ENCLAVE_PCIE_HOTPLUG_MODE;
    }
    // Only a multi-node placement requests a multi-NUMA guest topology; the
    // node-0 default keeps the single-node flags.
    if multi_numa {
        required_matched |= ne_ioctl::start_flags::NE_ENCLAVE_PCIE_NUMA_MODE;
    }
    // Matched flags live in bits 6-15, guaranteed to fit in u16 by the mask.
    #[allow(clippy::cast_possible_truncation)]
    let pcie_flags =
        (required_matched & ne_ioctl::start_flags::NE_ENCLAVE_FLAG_MATCHED_MASK) as u16;

    // TODO(enclave): write EIF directly into CMA memory instead of buffering in a Vec
    let eif_data = if eif::is_eif(&boot_config.kernel_file) {
        info!("Loading pre-built EIF from {kernel_path}");
        std::fs::read(kernel_path).map_err(EnclaveBuilderError::ReadEif)?
    } else {
        let boot_args = resolve_enclave_cmdline(boot_config, enclave_config, vm_resources)?;
        let default_mem = mib_to_bytes(vm_resources.machine_config.mem_size_mib) as u64;
        let default_cpus = vm_resources.machine_config.vcpu_count as u64;
        info!(
            "Building EIF from kernel={kernel_path} initrd={:?}",
            vm_resources.boot_source.config.initrd_path
        );
        eif::build_eif(
            &boot_config.kernel_file,
            boot_config.initrd_file.as_ref(),
            &boot_args,
            default_mem,
            default_cpus,
            pcie_flags,
        )?
    };
    info!("EIF ready: {} bytes", eif_data.len());

    let dev_fd = NitroEnclavesDevFd::open().map_err(EnclaveBuilderError::OpenDevice)?;
    let supported_flags = dev_fd
        .get_supported_flags()
        .map_err(EnclaveBuilderError::GetSupportedFlags)?;
    let missing = required_matched & !u64::from(supported_flags);
    if missing != 0 {
        return Err(EnclaveBuilderError::UnsupportedFlags {
            requested: required_matched,
            supported: supported_flags,
        });
    }
    info!(
        "Hypervisor supported flags=0x{:04x}, required matched=0x{:04x}",
        supported_flags, required_matched
    );

    let mut create_flags = required_matched;
    if enclave_config.direct_mode {
        create_flags |= ne_ioctl::start_flags::NE_ENCLAVE_DIRECT_MODE;
    }
    #[allow(clippy::cast_possible_truncation)]
    let create_flags = create_flags as u32;

    // EnclaveVm retains the normalized config so GET /enclave reports what
    // launched, not the raw request order.
    let mut normalized_config = enclave_config.clone();
    normalized_config.numa_nodes = Some(numa_nodes.clone());
    let mut enclave_vm = EnclaveVm::new(dev_fd, create_flags, normalized_config)?;
    info!(
        "Enclave VM created: slot_uid={}, direct_mode={}, cpu_overcommit={}, \
         cpu_accounting={}, create_flags=0x{:x}",
        enclave_vm.slot_uid(),
        enclave_config.direct_mode,
        enclave_config.cpu_overcommit,
        enclave_config.cpu_accounting,
        create_flags
    );

    if let Some(ref ids) = enclave_config.cpu_ids {
        if ids.len() != vcpu_count as usize {
            return Err(EnclaveBuilderError::CpuCountMismatch {
                config_count: ids.len(),
                vcpu_count: vcpu_count as usize,
            });
        }
        for &cpu_id in ids {
            enclave_vm.add_vcpu(cpu_id)?;
        }
        info!("Added {} vCPUs (explicit): {:?}", ids.len(), ids);
    } else {
        // No explicit cpu_ids: request each node's vCPUs on its parent node.
        for node in &numa_nodes {
            let hint = i32::from(node.parent_numa);
            for _ in 0..node.vcpu_count {
                enclave_vm.add_any_vcpu(hint)?;
            }
        }
        info!(
            "Added {vcpu_count} vCPUs via NE_ADD_ANY_VCPU across {} NUMA node(s)",
            numa_nodes.len()
        );
    }

    enclave_vm.install_info_page()?;
    info!("Info page installed");

    enclave_vm.load_and_add_memory(&eif_data, enclave_config.direct_mode, &numa_nodes)?;
    info!(
        "Allocated {} MiB, loaded EIF, and donated memory to enclave",
        vm_resources.machine_config.mem_size_mib
    );

    // A DMB size selects confidential mode (per-device DMB); `None` selects
    // direct mode, where devices use the donated enclave RAM directly.
    // Device attachment must happen before the VM is started.
    let mut device_manager = DeviceManager {
        virtio_devices: VirtioDevices::Enclave(NeDevices::default()),
        ..Default::default()
    };
    attach_enclave_devices(
        &mut device_manager,
        &enclave_vm,
        vm_resources,
        enclave_vm.dmb_size_mib(),
        event_manager,
    )?;

    let mut start_flags: u64 = 0;
    if enclave_config.debug_mode {
        start_flags |= ne_ioctl::start_flags::NE_ENCLAVE_DEBUG_MODE;
    }
    info!(
        "Starting enclave with start_flags=0x{:x} (debug={})",
        start_flags, enclave_config.debug_mode
    );

    // CID 0 tells the kernel to auto-assign the enclave's vsock CID.
    // The assigned CID is unused since enclave mode doesn't use vhost-vsock.
    let assigned_cid = enclave_vm.start(start_flags, 0)?;
    info!("Enclave started with CID={assigned_cid}");

    let info_page = enclave_vm
        .info_page()
        .ok_or(EnclaveBuilderError::NoInfoPage)?;
    // The serial ring buffer in the info page is only populated in debug mode.
    if enclave_config.debug_mode {
        let console = ConsoleReader::new(
            info_page,
            vm_resources.serial_out_path.as_deref(),
            vm_resources.serial_rate_limiter(),
        )
        .map_err(EnclaveBuilderError::Console)?;
        let console = Arc::new(Mutex::new(console));
        // Polled periodically, and retained on the EnclaveVm for a final drain.
        event_manager.add_subscriber(console.clone());
        enclave_vm.set_console(console);
        info!("Serial console reader started");
    }

    // CPU accounting (Parent-PID visibility): spawn one thread per enclave vCPU
    // that binds itself via NE_ACCOUNT_VCPU so the NE driver attributes that
    // vCPU's guest time to it. Gated strictly on cpu_accounting (NOT
    // cpu_overcommit) — the ioctl is only valid on a CPU_ACCOUNTING enclave.
    // Failures are fatal: the threads' handshake reports per-vCPU binding
    // errors and `?` aborts the launch.
    if enclave_config.cpu_accounting {
        let vcpu_filter = seccomp_filters
            .get("vcpu")
            .ok_or(EnclaveBuilderError::MissingSeccompFilters)?
            .clone();
        let threads =
            AccountingThreads::spawn(enclave_vm.enclave_fd(), vcpu_count as u32, vcpu_filter)?;
        info!("Spawned {vcpu_count} CPU-accounting threads");
        // Owned by the EnclaveVm so they are stopped + joined on its drop.
        enclave_vm.set_accounting_threads(threads);
    }

    let vmm = Vmm {
        instance_info: instance_info.clone(),
        machine_config: vm_resources.machine_config.clone(),
        boot_source_config: vm_resources.boot_source.config.clone(),
        shutdown_exit_code: None,
        vm: Vm::Enclave(enclave_vm),
        device_manager,
    };
    let vmm = Arc::new(Mutex::new(vmm));
    // Enclave VMs are already running after the NE start ioctl — there is no
    // paused/resume lifecycle like KVM VMs, so go straight to Running.
    vmm.lock().unwrap().instance_info.state = VmState::Running;
    event_manager.add_subscriber(vmm.clone());

    Ok(vmm)
}

/// Attach enclave virtio devices to the enclave via the NE transport.
///
/// Each device backend is registered with the event manager and wired
/// to the enclave via NE_ADD_DEVICE + NE_SET_VRING_KICK/CALL.
fn attach_enclave_devices(
    device_manager: &mut DeviceManager,
    enclave_vm: &EnclaveVm,
    vm_resources: &VmResources,
    dmb_size_mib: Option<u64>,
    event_manager: &mut EventManager,
) -> Result<(), EnclaveBuilderError> {
    if let Some(entropy) = vm_resources.entropy.get() {
        info!("Attaching enclave entropy device");
        device_manager
            .attach_ne_virtio_device(entropy.clone(), enclave_vm, dmb_size_mib, event_manager)
            .map_err(EnclaveBuilderError::AttachDevice)?;
    }

    for block in &vm_resources.block.devices {
        info!("Attaching enclave block device");
        device_manager
            .attach_ne_virtio_device(block.clone(), enclave_vm, dmb_size_mib, event_manager)
            .map_err(EnclaveBuilderError::AttachDevice)?;
    }

    for net in vm_resources.net_builder.iter() {
        info!("Attaching enclave net device");
        device_manager
            .attach_ne_virtio_device(net.clone(), enclave_vm, dmb_size_mib, event_manager)
            .map_err(EnclaveBuilderError::AttachDevice)?;
    }

    if let Some(vsock) = vm_resources.vsock.get() {
        info!("Attaching enclave vsock device");
        device_manager
            .attach_ne_virtio_device(vsock.clone(), enclave_vm, dmb_size_mib, event_manager)
            .map_err(EnclaveBuilderError::AttachDevice)?;
    }

    Ok(())
}

/// Validate and normalize the per-NUMA-node placement from the enclave config.
///
/// An absent `numa_nodes` places the whole enclave on parent node 0; an explicit
/// empty list is rejected. The returned nodes are sorted ascending by
/// `parent_numa`, so element 0 is guest node 0 -- the EIF / GPA-low region and the
/// DMB anchor.
fn validate_numa_config(
    enclave_config: &EnclaveConfig,
    machine_config: &MachineConfig,
) -> Result<Vec<EnclaveNumaNode>, EnclaveBuilderError> {
    let Some(nodes) = enclave_config.numa_nodes.as_ref() else {
        return Ok(vec![EnclaveNumaNode {
            parent_numa: 0,
            vcpu_count: machine_config.vcpu_count,
            mem_size_mib: machine_config.mem_size_mib,
        }]);
    };
    let err = EnclaveBuilderError::NumaValidationError;
    if nodes.is_empty() {
        return Err(err("numa_nodes must not be empty".into()));
    }

    let vcpu_total: u32 = nodes.iter().map(|n| u32::from(n.vcpu_count)).sum();
    if vcpu_total != u32::from(machine_config.vcpu_count) {
        return Err(err(format!(
            "vCPU total {vcpu_total} != machine vcpu_count {}",
            machine_config.vcpu_count
        )));
    }
    // checked_add: mem_size_mib is untrusted and a wrapping sum could land back
    // on machine_mem, slipping past the mismatch check.
    let mem_total = nodes
        .iter()
        .try_fold(0usize, |acc, n| acc.checked_add(n.mem_size_mib));
    if mem_total != Some(machine_config.mem_size_mib) {
        return Err(err(format!(
            "memory total {mem_total:?} MiB != machine mem_size_mib {} MiB",
            machine_config.mem_size_mib
        )));
    }

    let mut normalized = nodes.clone();
    normalized.sort_by_key(|n| n.parent_numa);

    // Reject parent_numa well above the kernel's MAX_NUMNODES as a sanity bound.
    const MAX_PARENT_NUMA: u16 = 1 << 12;
    const SECTION_MIB: usize = 128;
    let last = normalized.len() - 1;
    for (idx, node) in normalized.iter().enumerate() {
        if node.parent_numa > MAX_PARENT_NUMA {
            return Err(err(format!(
                "parent_numa {} exceeds maximum {MAX_PARENT_NUMA}",
                node.parent_numa
            )));
        }
        if node.vcpu_count == 0 {
            return Err(err(format!(
                "parent_numa {} has vcpu_count 0",
                node.parent_numa
            )));
        }
        if node.mem_size_mib == 0 {
            return Err(err(format!(
                "parent_numa {} has mem_size_mib 0",
                node.parent_numa
            )));
        }
        // A node's size sets the NEXT node's guest base, so every node but the
        // last must land on a 128 MiB sparsemem section or a guest NUMA boundary
        // would fall mid-section. The last node's size ends the address space and
        // constrains nothing.
        if idx != last && !node.mem_size_mib.is_multiple_of(SECTION_MIB) {
            return Err(err(format!(
                "parent_numa {} mem_size_mib {} must be a multiple of {SECTION_MIB} MiB \
                 (every node but the last)",
                node.parent_numa, node.mem_size_mib
            )));
        }
    }
    // Sorted above, so duplicate parent_numa values are adjacent.
    if let Some(pair) = normalized
        .windows(2)
        .find(|p| p[0].parent_numa == p[1].parent_numa)
    {
        return Err(err(format!(
            "duplicate parent_numa {}",
            pair[0].parent_numa
        )));
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_enclave_vcpu_count() {
        // At and below the ceiling is accepted.
        validate_enclave_vcpu_count(1).unwrap();
        validate_enclave_vcpu_count(MAX_SUPPORTED_ENCLAVE_VCPUS).unwrap();

        // Above the ceiling is rejected. (EnclaveBuilderError has no PartialEq, so
        // match rather than assert_eq!.)
        let over = MAX_SUPPORTED_ENCLAVE_VCPUS + 1;
        let err = validate_enclave_vcpu_count(over).unwrap_err();
        assert!(matches!(
            err,
            EnclaveBuilderError::TooManyVcpus { requested, max }
                if requested == over && max == MAX_SUPPORTED_ENCLAVE_VCPUS
        ));
    }

    #[test]
    fn test_validate_supported_devices() {
        use crate::vmm_config::balloon::BalloonBuilder;
        use crate::vmm_config::memory_hotplug::MemoryHotplugConfig;
        use crate::vmm_config::pmem::PmemConfig;

        // BalloonBuilder's Default installs a balloon under cfg(test), so start
        // from an explicitly empty one.
        let clean = || VmResources {
            balloon: BalloonBuilder::new(),
            ..Default::default()
        };

        // Nothing configured is accepted.
        validate_supported_devices(&clean()).unwrap();

        // The cfg(test) Default is itself the balloon case.
        let balloon = VmResources::default();

        let mut pmem = clean();
        pmem.pmem.configs.push(PmemConfig::default());

        let mut hotplug = clean();
        hotplug.memory_hotplug = Some(MemoryHotplugConfig::default());

        for (expected, resources) in [
            ("balloon", balloon),
            ("pmem", pmem),
            ("memory hotplug", hotplug),
        ] {
            let err = validate_supported_devices(&resources).unwrap_err();
            assert!(
                matches!(err, EnclaveBuilderError::UnsupportedDevice(name) if name == expected),
                "{err:?}"
            );
        }
        // The vhost-user case needs a built Block, so it is left to the
        // integration tests.
    }
    fn machine(vcpu_count: u16, mem_size_mib: usize) -> MachineConfig {
        MachineConfig {
            vcpu_count,
            mem_size_mib,
            ..Default::default()
        }
    }

    fn config(nodes: Option<Vec<EnclaveNumaNode>>) -> EnclaveConfig {
        EnclaveConfig {
            numa_nodes: nodes,
            ..Default::default()
        }
    }

    fn node(parent_numa: u16, vcpu_count: u16, mem_size_mib: usize) -> EnclaveNumaNode {
        EnclaveNumaNode {
            parent_numa,
            vcpu_count,
            mem_size_mib,
        }
    }

    #[track_caller]
    fn assert_numa_err(err: EnclaveBuilderError, needle: &str) {
        match err {
            EnclaveBuilderError::NumaValidationError(msg) => assert!(
                msg.contains(needle),
                "message {msg:?} does not contain {needle:?}"
            ),
            other => panic!("expected NumaValidationError, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_numa_config_defaults_to_node_zero() {
        // Absent numa_nodes places the whole enclave on parent node 0; an explicit
        // empty list is still an invalid config.
        assert_eq!(
            validate_numa_config(&config(None), &machine(2, 512)).unwrap(),
            vec![node(0, 2, 512)]
        );
        let err = validate_numa_config(&config(Some(vec![])), &machine(2, 512)).unwrap_err();
        assert_numa_err(err, "must not be empty");
    }

    #[test]
    fn test_validate_numa_config_section_rule_skips_last_node() {
        // Last node unaligned: accepted (its size ends the address space).
        let nodes = vec![node(0, 1, 256), node(1, 1, 258)];
        assert_eq!(
            validate_numa_config(&config(Some(nodes)), &machine(2, 514)).unwrap(),
            vec![node(0, 1, 256), node(1, 1, 258)]
        );
        // Non-last node unaligned: rejected, it would put node 1's base
        // mid-section.
        let nodes = vec![node(0, 1, 258), node(1, 1, 256)];
        let err = validate_numa_config(&config(Some(nodes)), &machine(2, 514)).unwrap_err();
        assert_numa_err(err, "must be a multiple of 128 MiB");
    }

    #[test]
    fn test_validate_numa_config_vcpu_mismatch() {
        let nodes = vec![node(0, 1, 256), node(1, 1, 256)];
        let err = validate_numa_config(&config(Some(nodes)), &machine(4, 512)).unwrap_err();
        assert_numa_err(err, "vCPU total 2 != machine vcpu_count 4");
    }

    #[test]
    fn test_validate_numa_config_mem_mismatch() {
        let nodes = vec![node(0, 1, 256), node(1, 1, 256)];
        let err = validate_numa_config(&config(Some(nodes)), &machine(2, 1024)).unwrap_err();
        assert_numa_err(err, "memory total");
    }

    #[test]
    fn test_validate_numa_config_zero_vcpus() {
        let nodes = vec![node(0, 2, 256), node(1, 0, 256)];
        let err = validate_numa_config(&config(Some(nodes)), &machine(2, 512)).unwrap_err();
        assert_numa_err(err, "parent_numa 1 has vcpu_count 0");
    }

    #[test]
    fn test_validate_numa_config_duplicate_node() {
        let nodes = vec![node(0, 1, 256), node(0, 1, 256)];
        let err = validate_numa_config(&config(Some(nodes)), &machine(2, 512)).unwrap_err();
        assert_numa_err(err, "duplicate parent_numa 0");
    }

    #[test]
    fn test_validate_numa_config_zero_memory() {
        let nodes = vec![node(0, 1, 512), node(1, 1, 0)];
        let err = validate_numa_config(&config(Some(nodes)), &machine(2, 512)).unwrap_err();
        assert_numa_err(err, "parent_numa 1 has mem_size_mib 0");
    }

    #[test]
    fn test_validate_numa_config_parent_numa_out_of_range() {
        let huge = (1 << 12) + 1;
        let nodes = vec![node(huge, 2, 512)];
        let err = validate_numa_config(&config(Some(nodes)), &machine(2, 512)).unwrap_err();
        assert_numa_err(err, "exceeds maximum 4096");
    }

    #[test]
    fn test_validate_numa_config_parent_numa_at_max_accepted() {
        let nodes = vec![node(1 << 12, 2, 512)];
        let out = validate_numa_config(&config(Some(nodes)), &machine(2, 512)).unwrap();
        assert_eq!(out[0].parent_numa, 1 << 12);
    }

    #[test]
    fn test_validate_numa_config_mem_sum_overflow_rejected() {
        // A wrapping mem_size_mib sum must not slip past the mismatch check: two
        // nodes whose sizes overflow usize back to machine_mem are rejected via
        // the checked_add path.
        let nodes = vec![node(0, 1, 512), node(1, 1, usize::MAX - 512 + 1)];
        let err = validate_numa_config(&config(Some(nodes)), &machine(2, 512)).unwrap_err();
        assert_numa_err(err, "memory total");
    }

    #[test]
    fn test_validate_numa_config_normalizes_sorted_by_parent_numa() {
        // Input given out of order (parent_numa 2 then 0 then 1); output must be
        // sorted ascending so element 0 is guest node 0.
        let nodes = vec![node(2, 1, 128), node(0, 1, 128), node(1, 1, 128)];
        let out = validate_numa_config(&config(Some(nodes)), &machine(3, 384)).unwrap();
        assert_eq!(
            out.iter().map(|n| n.parent_numa).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn test_validate_numa_config_single_node_needs_no_section_align() {
        // A lone node is also the last node: its size ends the address space and
        // sets no other node's base, so section alignment does not apply.
        let nodes = vec![node(0, 2, 200)];
        assert_eq!(
            validate_numa_config(&config(Some(nodes)), &machine(2, 200)).unwrap(),
            vec![node(0, 2, 200)]
        );
    }
}
