# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared utilities for Nitro Enclave testing."""

import dataclasses
import fcntl
import functools
import os
import platform
from pathlib import Path

import pytest

from framework.utils import parse_cpu_list
from framework.utils_hugepages import HugePagesConfig
from framework.vm_lifecycle import VmLifecycle

NE_DEV_PATH = Path("/dev/nitro_enclaves")
NE_CPUS_PATH = Path("/sys/module/nitro_enclaves/parameters/ne_cpus")
CPU0_SIBLINGS_PATH = Path("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list")

NE_SYSFS_PATH = Path("/sys/class/misc/nitro_enclaves")
# Driver pools, mapped to the divisor for the unit we report: mem_pool is bytes
# (-> MiB), cpu_pool is a count.
NE_POOLS = {"mem_pool": 2**20, "cpu_pool": 1}

# DMB size the VMM allocates for a device that does not set dmb_size_mib;
# mirrors DEFAULT_DMB_SIZE_MIB in vmm_config/enclave.rs.
DEFAULT_DMB_SIZE_MIB = 16
NE_FLAT_COUNTERS = ("pcie_slots", "pcie_slots_total", "pcie_slots_in_use")

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


def _has_smt(path: Path = CPU0_SIBLINGS_PATH):
    """Check whether the host has SMT (hyperthreading) enabled."""
    try:
        return len(parse_cpu_list(path.read_text(encoding="ascii").strip())) >= 2
    except (FileNotFoundError, OSError, ValueError):
        return False


def enclave_host_available():
    """Whether this host can run Nitro Enclave microVMs.

    Return ``False`` when the NE device is absent. If the device is present,
    fail loudly when its driver state cannot support enclave tests.
    """
    info = get_enclave_info()
    if info is None:
        if NE_DEV_PATH.exists():
            raise EnclaveConfigError(
                f"Nitro Enclaves device {NE_DEV_PATH} could not be probed"
            )
        return False

    errors = []
    if not info.has_required_flags:
        missing_flags = NE_REQUIRED_FLAGS & ~info.supported_flags
        errors.append(
            "Nitro Enclaves driver is missing required flags: "
            f"missing=0x{missing_flags:04x}, "
            f"supported=0x{info.supported_flags:04x}, "
            f"required=0x{NE_REQUIRED_FLAGS:04x}"
        )
    if not info.has_cpu_pool:
        errors.append("Nitro Enclaves CPU pool is not configured")
    if errors:
        raise EnclaveConfigError("; ".join(errors))
    return True


def _read_int(path):
    """Read a single integer from sysfs, or ``None`` if unavailable."""
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def _pool_counters(base, scale=1):
    """Read a {total,in_use,free} triple, scaling values by `scale`."""
    out = {}
    for key in ("total", "in_use", "free"):
        val = _read_int(base / key)
        out[key] = val // scale if val is not None else None
    return out


def _pool_stats(name, scale=1):
    """One pool's counters, global and per NUMA node.

    ``None`` when the driver predates this pool's sysfs tree.
    """
    base = NE_SYSFS_PATH / name
    if not base.is_dir():
        return None
    stats = _pool_counters(base, scale)
    nodes = {
        d.name: _pool_counters(d, scale)
        for d in sorted(base.glob("node*"))
        if d.is_dir()
    }
    if nodes:
        stats["nodes"] = nodes
    return stats


def ne_sysfs_details():
    """Driver pool accounting for post-mortem diagnostics.

    The pools are NUMA-partitioned, so a request for one node can fail while
    another still has room; only the per-node breakdown distinguishes the two.
    Keys are omitted when the running driver does not expose them.
    """
    details = {}

    for name, scale in NE_POOLS.items():
        stats = _pool_stats(name, scale)
        if stats is not None:
            details[f"{name}_mib" if scale != 1 else name] = stats

    for counter in NE_FLAT_COUNTERS:
        val = _read_int(NE_SYSFS_PATH / counter)
        if val is not None:
            details[counter] = val

    return details


def enclave_probe_details():
    """Return Nitro Enclave probe details for pytest diagnostics."""
    info = get_enclave_info()
    return {
        "ne_device": NE_DEV_PATH.exists(),
        "ne_available": info is not None,
        "ne_cpus": list(info.cpu_pool) if info else None,
        "ne_dynamic": info.dynamic_cpu_pool if info else None,
        "ne_static_cpu_count": len(info.cpu_pool) if info else None,
        "kernel_release": platform.release(),
        "ne_supported_flags": f"0x{info.supported_flags:04x}" if info else None,
        "smt": _has_smt(),
        # A run that dies with NE_ERR_NO_MEM_SLOTS_ON_NODE needs the starting
        # budget to tell an undersized pool from an unevenly consumed one.
        **ne_sysfs_details(),
    }


# The functions below implement the basic_config / start verbs for the enclave
# backend, mirroring the KVM helpers in framework/kvm.py; `Microvm` delegates
# to them via `VmBackend` (framework.vm_backend). Spawning the Firecracker
# process is backend-agnostic and stays on `Microvm`; `spawn` honors the
# spawn-time API timing policy declared on `VmBackend`.


class EnclaveConfigError(AssertionError):
    """An enclave backend or host configuration cannot support an operation.

    Raised (not skipped) so a KVM-only test missing
    ``@pin_vm_backend(VM_BACKEND_KVM)`` and a misconfigured enclave host both
    surface as failures rather than silently dropping enclave variants.
    """


def enclave_deselect_reason(
    *, kernel, pci_enabled, huge_pages, lifecycle, cpu_template
):
    """Why an enclave backend cannot run a parametrisation, or ``None``.

    An enclave cannot restore snapshots, boots an EIF image over PCI, and
    donates its guest memory to the NE driver. It therefore cannot express
    MMIO, huge-page modes or CPU templates, and needs an ACPI guest kernel. A
    kernel whose EFI boot image is merely absent from the artifact set is not
    deselected: that artifact gap stays visible as a runtime skip (see
    ``VmBackend.kernel_image_for``).
    """
    if lifecycle is VmLifecycle.RESTORED:
        return "Enclave backend does not support snapshot restore"

    if pci_enabled is False:
        return "enclave backends boot EIF images over PCI only"
    if huge_pages is not None and huge_pages != HugePagesConfig.NONE:
        return "NE donated memory cannot express huge-page modes"
    if cpu_template is not None:
        return "enclave backends cannot express CPU templates"
    if kernel is not None and not kernel.acpi:
        return "enclave backends require an ACPI guest kernel"
    return None


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

    if vm.memory_monitor:
        vm.memory_monitor.start()

    return vm


def enclave_prepare_start(
    vm,
    *,
    direct_mode,
    debug_mode=True,
    cpu_overcommit=True,
    cpu_accounting=False,
    hotplug_mode=False,
    numa_nodes=None,
):
    """Configure an enclave before starting its microVM.

    Tests run with CPU overcommit (floating vCPUs) by default so concurrent
    enclaves don't exhaust the NE CPU pool; pass ``cpu_overcommit=False`` to
    cover dedicated-core allocation specifically.
    """
    # Omit numa_nodes unless a placement is requested, so tests that do not care
    # exercise the parent-node-0 default.
    other_kwargs = {} if numa_nodes is None else {"numa_nodes": numa_nodes}
    vm.api.enclave.put(
        debug_mode=debug_mode,
        direct_mode=direct_mode,
        cpu_ids=vm.enclave_cpu_ids,
        cpu_overcommit=cpu_overcommit,
        cpu_accounting=cpu_accounting,
        hotplug_mode=hotplug_mode,
        **other_kwargs,
    )
