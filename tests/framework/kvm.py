# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""KVM support for the microVM backend dimension.

``Microvm.basic_config`` delegates to this module via ``VmBackend.KVM``
(:mod:`framework.vm_backend`). Starting and spawning the Firecracker process
are backend-agnostic and live on ``Microvm`` itself.
"""

import fcntl
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from framework.utils_hugepages import HugePagesConfig

KVMIO = 0xAE
KVM_CHECK_EXTENSION = (KVMIO << 8) | 0x03

KVM_CAP_USER_MEMORY2 = 231
KVM_CAP_GUEST_MEMFD = 234
KVM_CAP_GUEST_MEMFD_FLAGS = 244
KVM_CAP_USERFAULT = 245

GUEST_MEMFD_FLAG_MMAP = 1 << 0
GUEST_MEMFD_FLAG_INIT_SHARED = 1 << 1
GUEST_MEMFD_FLAG_NO_DIRECT_MAP = 1 << 2
GUEST_MEMFD_FLAG_WRITE = 1 << 3

SECRET_FREE_BOOT_GUEST_MEMFD_FLAGS = (
    GUEST_MEMFD_FLAG_MMAP
    | GUEST_MEMFD_FLAG_INIT_SHARED
    | GUEST_MEMFD_FLAG_NO_DIRECT_MAP
)
SECRET_FREE_RESTORE_GUEST_MEMFD_FLAGS = (
    SECRET_FREE_BOOT_GUEST_MEMFD_FLAGS | GUEST_MEMFD_FLAG_WRITE
)


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
    secret_free=None,
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
    # Omit the field for A/B revisions that predate secret-free support.
    # TODO: Remove this workaround once all A/B baseline revisions support secret_free.
    kwargs = {"secret_free": True} if secret_free else {}
    vm.api.machine_config.put(
        vcpu_count=vcpu_count,
        smt=smt,
        mem_size_mib=mem_size_mib,
        track_dirty_pages=track_dirty_pages,
        huge_pages=huge_pages,
        **kwargs,
    )
    vm.huge_pages = huge_pages
    vm.vcpus_count = vcpu_count
    vm.mem_size_bytes = mem_size_mib * 2**20
    vm.secret_free = secret_free or False

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


@dataclass(frozen=True)
class KvmCapabilities:
    """Host KVM capabilities needed by secret_free tests."""

    user_memory2: int = 0
    guest_memfd: int = 0
    guest_memfd_flags: int = 0
    userfault: int = 0


def _supports_guest_memfd_flags(supported_flags: int, required_flags: int) -> bool:
    """Return True if all guest_memfd flags required by Firecracker are present."""
    return supported_flags & required_flags == required_flags


def _check_kvm_extension(kvm_fd: int, capability: int) -> int:
    """Query a single KVM capability via KVM_CHECK_EXTENSION."""
    return int(fcntl.ioctl(kvm_fd, KVM_CHECK_EXTENSION, capability))


def get_kvm_capabilities() -> KvmCapabilities:
    """Probe the host KVM capabilities needed by secret_free tests."""
    try:
        kvm_fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
    except OSError:
        return KvmCapabilities()

    try:
        return KvmCapabilities(
            user_memory2=_check_kvm_extension(kvm_fd, KVM_CAP_USER_MEMORY2),
            guest_memfd=_check_kvm_extension(kvm_fd, KVM_CAP_GUEST_MEMFD),
            guest_memfd_flags=_check_kvm_extension(kvm_fd, KVM_CAP_GUEST_MEMFD_FLAGS),
            userfault=_check_kvm_extension(kvm_fd, KVM_CAP_USERFAULT),
        )
    except OSError:
        return KvmCapabilities()
    finally:
        os.close(kvm_fd)


def supports_secret_free_boot(kvm_capabilities: KvmCapabilities) -> bool:
    """Return True if the host can boot secret_free microVMs."""
    return (
        kvm_capabilities.user_memory2 != 0
        and kvm_capabilities.guest_memfd != 0
        and _supports_guest_memfd_flags(
            kvm_capabilities.guest_memfd_flags,
            SECRET_FREE_BOOT_GUEST_MEMFD_FLAGS,
        )
    )


def supports_secret_free_restore(kvm_capabilities: KvmCapabilities) -> bool:
    """Return True if the host can restore secret_free snapshots via UFFD."""
    return (
        supports_secret_free_boot(kvm_capabilities)
        and kvm_capabilities.userfault != 0
        and _supports_guest_memfd_flags(
            kvm_capabilities.guest_memfd_flags,
            SECRET_FREE_RESTORE_GUEST_MEMFD_FLAGS,
        )
    )
