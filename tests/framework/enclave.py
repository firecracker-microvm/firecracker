# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared utilities for Nitro Enclave testing."""

import dataclasses
import fcntl
import functools
import os
from pathlib import Path

from framework.utils import parse_cpu_list

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
