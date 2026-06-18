// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Enclave build orchestrator.
//!
//! Loads a pre-built EIF image or builds one from kernel+initrd+boot_args,
//! then boots a Nitro Enclave from `VmResources`.

use std::sync::{Arc, Mutex};

use event_manager::SubscriberOps;

use crate::device_manager::DeviceManager;
use crate::logger::info;
use crate::nitro_enclave::eif;
use crate::nitro_enclave::enclave_vm::EnclaveVm;
use crate::nitro_enclave::ne_ioctl;
use crate::nitro_enclave::ne_ioctl::NitroEnclavesDevFd;
use crate::nitro_enclave::serial_console::ConsoleReader;
use crate::resources::VmResources;
use crate::utils::mib_to_bytes;
use crate::vmm_config::boot_source::{
    BootConfig, DEFAULT_ENCLAVE_KERNEL_CMDLINE, append_root_device_cmdline, build_cmdline,
};
use crate::vmm_config::enclave::EnclaveConfig;
use crate::vmm_config::instance_info::{InstanceInfo, VmState};
use crate::vstate::vm::Vm;
use crate::{EventManager, Vmm};

/// Errors from building and booting an enclave.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EnclaveBuilderError {
    /// Boot source not configured (kernel_image_path required)
    NoBootSource,
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
    AttachDevice(crate::device_manager::nitro_enclave::NeDeviceError),
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
) -> Result<Arc<Mutex<Vmm>>, EnclaveBuilderError> {
    let boot_config = vm_resources
        .boot_source
        .builder
        .as_ref()
        .ok_or(EnclaveBuilderError::NoBootSource)?;
    let kernel_path = &vm_resources.boot_source.config.kernel_image_path;

    let mut required_matched = ne_ioctl::start_flags::NE_ENCLAVE_PCIE_MODE
        | ne_ioctl::start_flags::NE_ENCLAVE_PCIE_VIRTIO_MODE;
    if enclave_config.cpu_overcommit {
        required_matched |= ne_ioctl::start_flags::NE_ENCLAVE_CPU_OVERCOMMIT_MODE;
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

    let mut enclave_vm = EnclaveVm::new(dev_fd, create_flags)?;
    info!(
        "Enclave VM created: slot_uid={}, direct_mode={}, cpu_overcommit={}, \
         create_flags=0x{:x}",
        enclave_vm.slot_uid(),
        enclave_config.direct_mode,
        enclave_config.cpu_overcommit,
        create_flags
    );

    let vcpu_count = vm_resources.machine_config.vcpu_count as u32;
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
        for _ in 0..vcpu_count {
            enclave_vm.add_any_vcpu(ne_ioctl::NE_NUMA_ANY)?;
        }
        info!("Added {} vCPUs via NE_ADD_ANY_VCPU", vcpu_count);
    }

    enclave_vm.install_info_page()?;
    info!("Info page installed");

    let mem_size = mib_to_bytes(vm_resources.machine_config.mem_size_mib);
    enclave_vm.load_and_add_memory(mem_size, &eif_data, enclave_config.direct_mode)?;
    info!(
        "Allocated {} MiB, loaded EIF, and donated memory to enclave",
        vm_resources.machine_config.mem_size_mib
    );

    // Device attachment must happen before the VM is started.
    // A DMB size selects confidential mode (per-device DMB); `None` selects
    // direct mode, where devices use the donated enclave RAM directly.
    let mut device_manager = DeviceManager::default();
    attach_enclave_devices(
        &mut device_manager,
        &enclave_vm,
        vm_resources,
        enclave_config.dmb_size_mib(),
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
        let console = ConsoleReader::new(info_page, vm_resources.serial_out_path.as_deref())
            .map_err(EnclaveBuilderError::Console)?;
        event_manager.add_subscriber(Arc::new(Mutex::new(console)));
        info!("Serial console reader started");
    }

    let vmm = Vmm {
        instance_info: instance_info.clone(),
        machine_config: vm_resources.machine_config.clone(),
        boot_source_config: vm_resources.boot_source.config.clone(),
        shutdown_exit_code: None,
        vm: Vm::Enclave(enclave_vm),
        device_manager,
        enclave_config: vm_resources.enclave.clone(),
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
            .ne_devices
            .attach_ne_virtio_device(entropy.clone(), enclave_vm, dmb_size_mib, event_manager)
            .map_err(EnclaveBuilderError::AttachDevice)?;
    }

    for block in &vm_resources.block.devices {
        info!("Attaching enclave block device");
        device_manager
            .ne_devices
            .attach_ne_virtio_device(block.clone(), enclave_vm, dmb_size_mib, event_manager)
            .map_err(EnclaveBuilderError::AttachDevice)?;
    }

    for net in vm_resources.net_builder.iter() {
        info!("Attaching enclave net device");
        device_manager
            .ne_devices
            .attach_ne_virtio_device(net.clone(), enclave_vm, dmb_size_mib, event_manager)
            .map_err(EnclaveBuilderError::AttachDevice)?;
    }

    if let Some(vsock) = vm_resources.vsock.get() {
        info!("Attaching enclave vsock device");
        device_manager
            .ne_devices
            .attach_ne_virtio_device(vsock.clone(), enclave_vm, dmb_size_mib, event_manager)
            .map_err(EnclaveBuilderError::AttachDevice)?;
    }

    Ok(())
}
