// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use std::sync::{Arc, Mutex};

use vm_memory::GuestAddress;
use vmm_sys_util::tempdir::TempDir;

use crate::builder::build_microvm_for_boot;
use crate::resources::VmResources;
use crate::seccomp::get_empty_filters;
use crate::test_utils::mock_resources::{MockBootSourceConfig, MockVmConfig, MockVmResources};
use crate::vmm_config::boot_source::BootSourceConfig;
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::HugePageConfig;
use crate::vstate::memory;
use crate::vstate::memory::{GuestMemoryMmap, GuestRegionMmap};
use crate::{EventManager, Vmm};

pub mod mock_resources;

/// Creates a [`GuestMemoryMmap`] with a single region of the given size starting at guest
/// physical address 0 and without dirty tracking.
pub fn single_region_mem(region_size: usize) -> GuestMemoryMmap {
    single_region_mem_at(0, region_size)
}

pub fn single_region_mem_raw(region_size: usize) -> Vec<GuestRegionMmap> {
    single_region_mem_at_raw(0, region_size)
}

/// Creates a [`GuestMemoryMmap`] with a single region of the given size starting at the given
/// guest physical address `at` and without dirty tracking.
pub fn single_region_mem_at(at: u64, size: usize) -> GuestMemoryMmap {
    multi_region_mem(&[(GuestAddress(at), size)])
}

pub fn single_region_mem_at_raw(at: u64, size: usize) -> Vec<GuestRegionMmap> {
    multi_region_mem_raw(&[(GuestAddress(at), size)])
}

/// Creates a [`GuestMemoryMmap`] with multiple regions and without dirty page tracking.
pub fn multi_region_mem(regions: &[(GuestAddress, usize)]) -> GuestMemoryMmap {
    GuestMemoryMmap::from_regions(
        memory::anonymous(regions.iter().copied(), false, HugePageConfig::None)
            .expect("Cannot initialize memory"),
    )
    .unwrap()
}

pub fn multi_region_mem_raw(regions: &[(GuestAddress, usize)]) -> Vec<GuestRegionMmap> {
    memory::anonymous(regions.iter().copied(), false, HugePageConfig::None)
        .expect("Cannot initialize memory")
}

/// Creates a [`GuestMemoryMmap`] of the given size with the contained regions laid out in
/// accordance with the requirements of the architecture on which the tests are being run.
pub fn arch_mem(mem_size_bytes: usize) -> GuestMemoryMmap {
    multi_region_mem(&crate::arch::arch_memory_regions(0, mem_size_bytes))
}

pub fn arch_mem_raw(mem_size_bytes: usize) -> Vec<GuestRegionMmap> {
    multi_region_mem_raw(&crate::arch::arch_memory_regions(0, mem_size_bytes))
}

pub fn create_vmm(
    _kernel_image: Option<&str>,
    is_diff: bool,
    boot_microvm: bool,
) -> (Arc<Mutex<Vmm>>, EventManager) {
    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();

    let boot_source_cfg = MockBootSourceConfig::new().with_default_boot_args();
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    let boot_source_cfg: BootSourceConfig = boot_source_cfg.into();
    #[cfg(target_arch = "x86_64")]
    let boot_source_cfg: BootSourceConfig = match _kernel_image {
        Some(kernel) => boot_source_cfg.with_kernel(kernel).into(),
        None => boot_source_cfg.into(),
    };
    let mock_vm_res = MockVmResources::new().with_boot_source(boot_source_cfg);
    let resources: VmResources = if is_diff {
        mock_vm_res
            .with_vm_config(MockVmConfig::new().with_dirty_page_tracking().into())
            .into()
    } else {
        mock_vm_res.into()
    };

    let vmm = build_microvm_for_boot(
        &InstanceInfo::default(),
        &resources,
        &mut event_manager,
        &empty_seccomp_filters,
    )
    .unwrap();

    if boot_microvm {
        vmm.lock().unwrap().resume_vm().unwrap();
    }

    (vmm, event_manager)
}

pub fn default_vmm(kernel_image: Option<&str>) -> (Arc<Mutex<Vmm>>, EventManager) {
    create_vmm(kernel_image, false, true)
}

pub fn default_vmm_no_boot(kernel_image: Option<&str>) -> (Arc<Mutex<Vmm>>, EventManager) {
    create_vmm(kernel_image, false, false)
}

#[cfg(target_arch = "x86_64")]
pub fn dirty_tracking_vmm(kernel_image: Option<&str>) -> (Arc<Mutex<Vmm>>, EventManager) {
    create_vmm(kernel_image, true, true)
}

#[allow(clippy::undocumented_unsafe_blocks)]
#[allow(clippy::cast_possible_truncation)]
pub fn create_tmp_socket() -> (TempDir, String) {
    let tmp_dir = TempDir::new().unwrap();
    let tmp_dir_path_str = tmp_dir.as_path().to_str().unwrap();
    let tmp_socket_path = format!("{tmp_dir_path_str}/tmp_socket");

    unsafe {
        let socketfd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if socketfd < 0 {
            panic!("Cannot create socket");
        }
        let mut socket_addr = libc::sockaddr_un {
            sun_family: libc::AF_UNIX as u16,
            sun_path: [0; 108],
        };

        std::ptr::copy(
            tmp_socket_path.as_ptr().cast(),
            socket_addr.sun_path.as_mut_ptr(),
            tmp_socket_path.len(),
        );

        let bind = libc::bind(
            socketfd,
            (&socket_addr as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as u32,
        );
        if bind < 0 {
            panic!("Cannot bind socket");
        }

        let listen = libc::listen(socketfd, 1);
        if listen < 0 {
            panic!("Cannot listen on socket");
        }
    }

    (tmp_dir, tmp_socket_path)
}
