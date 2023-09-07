# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Define classes for interacting with CI artifacts"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest

import host_tools.network as net_tools
from framework.defs import ARTIFACT_DIR
from framework.properties import global_props
from framework.utils import get_firecracker_version_from_toml
from host_tools.cargo_build import get_binary


def select_supported_kernels():
    """Select guest kernels supported by the current combination of kernel and
    instance type.
    """
    supported_kernels = [r"vmlinux-4.14.\d+"]
    if (
        global_props.instance == "c7g.metal"
        and global_props.host_linux_version == "4.14"
    ):
        supported_kernels.append(r"vmlinux-5.10-no-sve.bin")
    else:
        supported_kernels.append(r"vmlinux-5.10.\d+")
    return supported_kernels


def kernels(glob) -> Iterator:
    """Return supported kernels as kernels supported by the current combination of kernel and
    instance type.
    """
    supported_kernels = select_supported_kernels()
    for kernel in sorted(ARTIFACT_DIR.rglob(glob)):
        for kernel_regex in supported_kernels:
            if re.fullmatch(kernel_regex, kernel.name):
                yield kernel
                break


def disks(glob) -> Iterator:
    """Return supported rootfs"""
    yield from sorted(ARTIFACT_DIR.glob(glob))


def kernel_params(glob="vmlinux-*") -> Iterator:
    """Return supported kernels"""
    for kernel in kernels(glob):
        yield pytest.param(kernel, id=kernel.name)


def rootfs_params(glob="ubuntu-*.squashfs") -> Iterator:
    """Return supported rootfs as pytest parameters"""
    for rootfs in disks(glob=glob):
        yield pytest.param(rootfs, id=rootfs.name)


@dataclass(frozen=True, repr=True)
class FirecrackerArtifact:
    """Utility class for Firecracker binary artifacts."""

    path: Path

    @property
    def name(self):
        """Get the Firecracker name."""
        return self.path.name

    @property
    def jailer(self):
        """Get the jailer with the same version."""
        return self.path.with_name(f"jailer-v{self.version}")

    @property
    def version(self):
        """Return Firecracker's version: `X.Y.Z`."""
        # Get the filename, split on '-' and trim the leading 'v'.
        # sample: firecracker-v1.2.0
        return self.path.name.split("-")[1][1:]

    @property
    def version_tuple(self):
        """Return the artifact's version as a tuple `(X, Y, Z)`."""
        return tuple(int(x) for x in self.version.split("."))

    @property
    def snapshot_version_tuple(self):
        """Return the artifact's snapshot version as a tuple: `X.Y.0`."""
        return self.version_tuple[:2] + (0,)

    @property
    def snapshot_version(self):
        """Return the artifact's snapshot version: `X.Y.0`.

        Due to how Firecracker maps release versions to snapshot versions, we
        have to request the minor version instead of the actual version.
        """
        return ".".join(str(x) for x in self.snapshot_version_tuple)


def current_release(version):
    """Massage this working copy Firecracker binary to look like a normal
    release, so it can run the same tests.
    """
    binaries = []
    for binary in ["firecracker", "jailer"]:
        bin_path1 = get_binary(binary)
        bin_path2 = bin_path1.with_name(f"{binary}-v{version}")
        bin_path2.unlink(missing_ok=True)
        bin_path2.hardlink_to(bin_path1)
        binaries.append(bin_path2)
    return binaries


def firecracker_artifacts():
    """Return all supported firecracker binaries."""
    cargo_version = get_firecracker_version_from_toml()
    # until the next minor version (but *not* including)
    max_version = (cargo_version.major, cargo_version.minor + 1, 0)
    min_version = (1, 3, 0)
    prefix = "firecracker/firecracker-*"
    for firecracker in sorted(ARTIFACT_DIR.glob(prefix)):
        match = re.match(r"firecracker-v(\d+)\.(\d+)\.(\d+)", firecracker.name)
        if not match:
            continue
        fc = FirecrackerArtifact(firecracker)
        version = fc.version_tuple
        if version < min_version:
            continue
        if version >= max_version:
            continue
        yield pytest.param(fc, id=fc.name)

    fc = FirecrackerArtifact(current_release(cargo_version.base_version)[0])
    yield pytest.param(fc, id=fc.name)


@dataclass(frozen=True, repr=True)
class NetIfaceConfig:
    """Defines a network interface configuration."""

    host_ip: str = "192.168.0.1"
    guest_ip: str = "192.168.0.2"
    tap_name: str = "tap0"
    dev_name: str = "eth0"
    netmask: int = 30

    @property
    def guest_mac(self):
        """Return the guest MAC address."""
        return net_tools.mac_from_ip(self.guest_ip)

    @staticmethod
    def with_id(i):
        """Define network iface with id `i`."""
        return NetIfaceConfig(
            host_ip=f"192.168.{i}.1",
            guest_ip=f"192.168.{i}.2",
            tap_name=f"tap{i}",
            dev_name=f"eth{i}",
        )
