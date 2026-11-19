# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""KVM support for the microVM backend dimension.

``Microvm.basic_config`` delegates to this module via ``VmBackend.KVM``
(:mod:`framework.vm_backend`). Starting and spawning the Firecracker process
are backend-agnostic and live on ``Microvm`` itself.
"""

import os
import stat
from pathlib import Path

from framework.utils_hugepages import HugePagesConfig

KVM_PATH = Path("/dev/kvm")


def has_kvm():
    """Whether this host can run KVM microVMs (i.e. /dev/kvm exists)."""
    return KVM_PATH.exists()


def kvm_probe_details():
    """Return host KVM probe details for pytest diagnostics."""
    details = {
        "device": str(KVM_PATH),
        "exists": KVM_PATH.exists(),
        "readable": os.access(KVM_PATH, os.R_OK),
        "writable": os.access(KVM_PATH, os.W_OK),
    }
    try:
        details["mode"] = oct(stat.S_IMODE(KVM_PATH.stat().st_mode))
    except OSError as exc:
        details["stat_error"] = f"{type(exc).__name__}: {exc}"
    return details


# Guest kernel command line options shared by the tests' defaults: Firecracker's
# DEFAULT_KERNEL_CMDLINE (src/vmm/src/vmm_config/boot_source.rs) without
# `8250.nr_uarts=0`, plus `cryptomgr.notests`. The i8042 options stop the guest
# from probing the emulated keyboard controller for a mouse, a multiplexer and
# LED control, which otherwise stalls every boot by ~0.5 s; the AT keyboard is
# still registered, so SendCtrlAltDel keeps working. `i8042.nopnp` must not be
# added: without PNP the driver requests legacy IRQ 1, which fails, and the
# guest is left without a keyboard.
BASE_BOOT_ARGS = (
    "reboot=k panic=1 nomodule swiotlb=noforce cryptomgr.notests"
    " i8042.noaux i8042.nomux i8042.dumbkbd"
)


def default_boot_args(pci_enabled: bool) -> str:
    """Kernel command line used for a microVM whose test does not choose one."""
    args = BASE_BOOT_ARGS + " console=ttyS0"
    return args if pci_enabled else args + " pci=off"


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
    pcie_hotplug_ports: int = None,
):
    """Shortcut for quickly configuring a microVM.

    It handles:
    - CPU and memory.
    - Kernel image (will load the one in the microVM allocated path).
    - Root File System (will use the one in the microVM allocated path).
    - Does not start the microvm.

    The function checks the response status code and asserts that
    the response is within the interval [200, 300).

    If boot_args is None, `default_boot_args()` is used.
    """
    vm.api.machine_config.put(
        vcpu_count=vcpu_count,
        smt=smt,
        mem_size_mib=mem_size_mib,
        track_dirty_pages=track_dirty_pages,
        huge_pages=huge_pages,
        pcie_hotplug_ports=pcie_hotplug_ports,
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
        vm.boot_args = default_boot_args(vm.pci_enabled)
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
