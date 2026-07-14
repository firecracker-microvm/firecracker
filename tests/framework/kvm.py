# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""KVM-specific configuration helpers for the microVM test framework."""

from pathlib import Path

from framework.microvm import HugePagesConfig

KVM_PATH = Path("/dev/kvm")


def has_kvm():
    """Whether this host can run KVM microVMs (i.e. /dev/kvm exists)."""
    return KVM_PATH.exists()


def kvm_basic_config(
    vm,
    vcpu_count: int = 2,
    smt: bool = None,
    mem_size_mib: int = 256,
    add_root_device: bool = True,
    boot_args: str = None,
    use_initrd: bool = False,
    track_dirty_pages: bool = False,
    huge_pages: HugePagesConfig = HugePagesConfig.NONE,
    rootfs_io_engine=None,
    cpu_template=None,
    enable_entropy_device=False,
):
    """Shortcut for quickly configuring a microVM.

    It handles:
    - CPU and memory.
    - Kernel image (will load the one in the microVM allocated path).
    - Root File System (will use the one in the microVM allocated path).
    - Does not start the microvm.

    The function checks the response status code and asserts that
    the response is within the interval [200, 300).

    If boot_args is None, the default boot_args used in tests is
        reboot=k panic=1 nomodule swiotlb=noforce console=ttyS0 [pci=off]
    which differs from Firecracker's default only in the enabling of the serial console.
    Reference: file:../../src/vmm/src/vmm_config/boot_source.rs::DEFAULT_KERNEL_CMDLINE
    """
    vm.api.machine_config.put(
        vcpu_count=vcpu_count,
        smt=smt,
        mem_size_mib=mem_size_mib,
        track_dirty_pages=track_dirty_pages,
        huge_pages=huge_pages,
    )
    vm.huge_pages = huge_pages
    vm.vcpus_count = vcpu_count
    vm.mem_size_bytes = mem_size_mib * 2**20

    if vm.custom_cpu_template is not None:
        vm.set_cpu_template(vm.custom_cpu_template)

    if cpu_template is not None:
        vm.set_cpu_template(cpu_template)

    if vm.memory_monitor:
        vm.memory_monitor.start()

    if boot_args is not None:
        vm.boot_args = boot_args
    else:
        vm.boot_args = (
            "reboot=k panic=1 nomodule swiotlb=noforce console=ttyS0 cryptomgr.notests"
        )
        if not vm.pci_enabled:
            vm.boot_args += " pci=off"
    boot_source_args = {
        "kernel_image_path": vm.create_jailed_resource(vm.kernel_file),
        "boot_args": vm.boot_args,
    }

    if use_initrd and vm.initrd_file is not None:
        boot_source_args.update(initrd_path=vm.create_jailed_resource(vm.initrd_file))

    vm.api.boot.put(**boot_source_args)

    if add_root_device and vm.rootfs_file is not None:
        read_only = vm.rootfs_file.suffix == ".squashfs"

        # Add the root file system
        vm.add_drive(
            drive_id="rootfs",
            path_on_host=vm.rootfs_file,
            is_root_device=True,
            is_read_only=read_only,
            io_engine=rootfs_io_engine,
        )

    if enable_entropy_device:
        vm.enable_entropy_device()
