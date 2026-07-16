# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared utilities for Nitro Enclave testing."""

import dataclasses
import fcntl
import functools
import os
from enum import Enum
from pathlib import Path

import pytest

from framework.utils import parse_cpu_list
from framework.utils_hugepages import HugePagesConfig

NE_DEV_PATH = Path("/dev/nitro_enclaves")
NE_CPUS_PATH = Path("/sys/module/nitro_enclaves/parameters/ne_cpus")

NE_ENCLAVE_PCIE_MODE = 1 << 6
NE_ENCLAVE_PCIE_VIRTIO_MODE = 1 << 9
NE_REQUIRED_FLAGS = NE_ENCLAVE_PCIE_MODE | NE_ENCLAVE_PCIE_VIRTIO_MODE

# From include/uapi/linux/nitro_enclaves.h:
# #define NE_GET_SUPPORTED_FLAGS _IOR(0xAE, 0x29, __u32)
NE_GET_SUPPORTED_FLAGS = 0x8004AE29

# ---------------------------------------------------------------------------
# Hardware / feature detection
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class EnclaveInfo:
    """Point-in-time snapshot of the host's Nitro Enclaves driver state.

    Obtain via :meth:`probe`, which performs all reads in one pass so the
    fields are mutually consistent.
    """

    supported_flags: int
    """Flag mask reported by the NE_GET_SUPPORTED_FLAGS ioctl."""

    dynamic_cpu_pool: bool
    """Whether the NE CPU pool is in dynamic mode."""

    cpu_pool: tuple[int, ...]
    """CPUs in the static NE pool; empty when unset or dynamic."""

    @classmethod
    def probe(cls, cpus_path: Path = NE_CPUS_PATH):
        """Read the NE driver state, or return None if the device is unavailable.

        Opens /dev/nitro_enclaves (existence check and flags ioctl in one
        step), then reads the CPU pool sysfs file exactly once.
        """
        try:
            fd = os.open(NE_DEV_PATH, os.O_RDONLY | os.O_CLOEXEC)
        except OSError:
            return None
        try:
            buf = bytearray(4)
            fcntl.ioctl(fd, NE_GET_SUPPORTED_FLAGS, buf, True)
            supported_flags = int.from_bytes(buf, byteorder="little")
        except OSError:
            return None
        finally:
            os.close(fd)

        try:
            cpus = cpus_path.read_text(encoding="ascii").strip()
        except (FileNotFoundError, PermissionError):
            cpus = ""
        return cls(
            supported_flags=supported_flags,
            dynamic_cpu_pool=cpus == "dynamic",
            cpu_pool=(
                tuple(parse_cpu_list(cpus))
                if cpus not in ("", "(null)", "dynamic")
                else ()
            ),
        )

    @property
    def has_cpu_pool(self):
        """Whether a CPU pool is configured (static list or dynamic)."""
        return self.dynamic_cpu_pool or len(self.cpu_pool) > 0

    @property
    def has_required_flags(self):
        """Whether the driver supports the flags Firecracker requests."""
        return self.supported_flags & NE_REQUIRED_FLAGS == NE_REQUIRED_FLAGS


@functools.cache
def get_enclave_info():
    """The host's NE driver state, read once per test session.

    The driver state is host configuration; callers share this single
    consistent snapshot instead of re-probing.
    """
    return EnclaveInfo.probe()


def enclave_host_available():
    """Whether this host can run Nitro Enclave microVMs.

    Requires the NE device, a configured CPU pool, and the NE matched
    flags that Firecracker requests when creating enclaves.
    """
    info = get_enclave_info()
    return info is not None and info.has_cpu_pool and info.has_required_flags


# The functions below implement the basic_config / start verbs for the enclave
# backend, mirroring the KVM helpers in framework/kvm.py. Spawning the
# Firecracker process is backend-agnostic and stays on `Microvm`.


class EnclaveMode(str, Enum):
    """Memory-isolation mode of a Nitro Enclave microVM."""

    DIRECT = "direct"
    CONFIDENTIAL = "confidential"

    def __str__(self):
        return self.value


class EnclaveConfigError(AssertionError):
    """A test asked an enclave backend for a config it cannot express.

    Raised (not skipped) so a missing ``@pin_vm_backend(VM_BACKEND_KVM)`` on a
    KVM-only test surfaces as a failure rather than a silently dropped variant.
    """


def enclave_basic_config(
    vm,
    vcpu_count: int = 2,
    smt: bool = None,
    mem_size_mib: int = 256,
    add_root_device: bool = True,
    boot_args: str = None,
    use_initrd: bool = False,
    track_dirty_pages: bool = False,
    huge_pages=None,
    rootfs_io_engine=None,
    cpu_template=None,
    enable_entropy_device=False,
    cpu_ids: list[int] | None = None,
    *,
    enclave_mode: EnclaveMode = EnclaveMode.CONFIDENTIAL,
):
    """Configure an enclave microVM up to the pre-start state.

    Mirrors :meth:`Microvm.basic_config` so the same test code configures either
    backend. Configuration an enclave cannot express raises
    :class:`EnclaveConfigError`; see that class for why we raise rather than
    skip.

    A CPU template can arrive per-call (``cpu_template``) or session-wide
    (``vm.custom_cpu_template``, from ``--custom-cpu-template``); enclaves
    support neither.
    """
    if cpu_template is not None or vm.custom_cpu_template is not None:
        raise EnclaveConfigError(
            "Enclave backend cannot express CPU templates; pin this test "
            "to KVM with @pin_vm_backend(VM_BACKEND_KVM)."
        )
    if smt is not None:
        raise EnclaveConfigError(
            "Enclave backend cannot express a custom SMT setting; pin this "
            "test to KVM with @pin_vm_backend(VM_BACKEND_KVM)."
        )
    if track_dirty_pages:
        raise EnclaveConfigError(
            "Enclave backend cannot express dirty page tracking; pin this "
            "test to KVM with @pin_vm_backend(VM_BACKEND_KVM)."
        )
    if cpu_ids is not None and len(cpu_ids) != vcpu_count:
        raise EnclaveConfigError(
            f"Enclave backend got {len(cpu_ids)} explicit CPU IDs "
            f"for vcpu_count={vcpu_count}."
        )
    if huge_pages is None:
        huge_pages = HugePagesConfig.NONE
    if huge_pages != HugePagesConfig.NONE:
        raise EnclaveConfigError(
            f"Enclave backend cannot express huge-page mode {huge_pages!r}; "
            "pin this test to KVM with @pin_vm_backend(VM_BACKEND_KVM)."
        )

    # Enclaves can only run with PCI enabled. Skip MMIO variants
    if not vm.pci_enabled:
        pytest.skip("Enclave backend runs only in PCIe mode")

    vm.api.machine_config.put(
        vcpu_count=vcpu_count,
        mem_size_mib=mem_size_mib,
        huge_pages=HugePagesConfig.NONE,
    )

    vm.mem_size_bytes = mem_size_mib * 2**20

    vm.enclave_mode = enclave_mode
    # None means the NE kernel auto-selects CPUs; tests that explicitly cover
    # fixed allocation pass a full-core CPU ID list here.
    vm.enclave_cpu_ids = cpu_ids
    vm.vcpus_count = vcpu_count

    boot_kwargs = {
        "kernel_image_path": vm.create_jailed_resource(vm.kernel_file),
    }
    if boot_args is not None:
        vm.boot_args = boot_args
        boot_kwargs["boot_args"] = vm.boot_args
    if use_initrd and vm.initrd_file is not None:
        boot_kwargs["initrd_path"] = vm.create_jailed_resource(vm.initrd_file)
    vm.api.boot.put(**boot_kwargs)

    if add_root_device and vm.rootfs_file is not None:
        vm.add_drive(
            drive_id="rootfs",
            path_on_host=vm.rootfs_file,
            is_root_device=True,
            is_read_only=vm.rootfs_file.suffix == ".squashfs",
            io_engine=rootfs_io_engine,
        )

    if enable_entropy_device:
        vm.enable_entropy_device()

    return vm


def enclave_prepare_start(
    vm,
    *,
    debug_mode=True,
    cpu_overcommit=True,
    cpu_accounting=False,
    hotplug_mode=False,
):
    """Configure an enclave before starting its microVM.

    Tests run with CPU overcommit (floating vCPUs) by default so concurrent
    enclaves don't exhaust the NE CPU pool; pass ``cpu_overcommit=False`` to
    cover dedicated-core allocation specifically.
    """
    vm.api.enclave.put(
        debug_mode=debug_mode,
        direct_mode=vm.enclave_mode is EnclaveMode.DIRECT,
        cpu_ids=vm.enclave_cpu_ids,
        cpu_overcommit=cpu_overcommit,
        cpu_accounting=cpu_accounting,
        hotplug_mode=hotplug_mode,
    )
