# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Define classes for interacting with CI artifacts"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import packaging.version
import pytest

from framework.defs import ARTIFACT_DIR
from framework.properties import global_props
from framework.utils import check_output, get_firecracker_version_from_toml
from framework.with_filelock import with_filelock
from host_tools.cargo_build import get_binary


def select_supported_kernels():
    """Select guest kernels supported by the current combination of kernel and
    instance type.
    """
    hlv = packaging.version.parse(global_props.host_linux_version)
    supported_kernels = [r"vmlinux-4.14.\d+", r"vmlinux-5.10.\d+"]

    # Booting with MPTable is deprecated but we still want to test
    # for it. Until we drop support for it we will be building a 5.10 guest
    # kernel without ACPI support, so that we are able to test this use-case
    # as well.
    # TODO: remove this once we drop support for MPTable
    supported_kernels.append(r"vmlinux-5.10.\d+-no-acpi")

    # Support Linux 6.1 guest in a limited fashion
    if global_props.cpu_model == "ARM_NEOVERSE_V1" and (hlv.major, hlv.minor) >= (6, 1):
        supported_kernels.append(r"vmlinux-6.1.\d+")

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


def kernels_unfiltered(glob) -> Iterator:
    """Return kernels from the CI artifacts. This one does not filter for
    supported kernels. It will return any kernel in the CI artifacts folder
    that matches the 'glob'
    """
    all_kernels = [r"vmlinux-\d.\d+.\d+", r"vmlinux-5.10-no-sve-bin"]
    for kernel in sorted(ARTIFACT_DIR.rglob(glob)):
        for kernel_regex in all_kernels:
            if re.fullmatch(kernel_regex, kernel.name):
                yield kernel
                break


def disks(glob) -> Iterator:
    """Return supported rootfs"""
    yield from sorted(ARTIFACT_DIR.glob(glob))


def kernel_params(glob="vmlinux-*", select=kernels) -> Iterator:
    """Return supported kernels"""
    for kernel in select(glob):
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

        # Starting from Firecracker v1.7.0, snapshots have their own version that is
        # independent of Firecracker versions. For these Firecracker versions, use
        # the --snapshot-version Firecracker flag, to figure out which snapshot version
        # it supports.
        # TODO: remove this check once all version up to (and including) 1.6.0 go out of support.
        if packaging.version.parse(self.version) < packaging.version.parse("1.7.0"):
            return self.version_tuple[:2] + (0,)

        return (
            check_output([self.path, "--snapshot-version"])
            .stdout.strip()
            .split("\n")[0]
            .split(".")
        )

    @property
    def snapshot_version(self):
        """Return the artifact's snapshot version: `X.Y.0`.

        Due to how Firecracker maps release versions to snapshot versions, we
        have to request the minor version instead of the actual version.
        """
        return ".".join(str(x) for x in self.snapshot_version_tuple)


@with_filelock
def current_release(version):
    """Massage this working copy Firecracker binary to look like a normal
    release, so it can run the same tests.
    """
    binaries = []
    for binary in ["firecracker", "jailer"]:
        bin_path1 = get_binary(binary)
        bin_path2 = bin_path1.with_name(f"{binary}-v{version}")
        if not bin_path2.exists():
            bin_path2.unlink(missing_ok=True)
            bin_path2.hardlink_to(bin_path1)
        binaries.append(bin_path2)
    return binaries


def working_version_as_artifact():
    """
    Return working copy of Firecracker as a release artifact
    """
    cargo_version = get_firecracker_version_from_toml()
    return FirecrackerArtifact(current_release(cargo_version.base_version)[0])


def firecracker_artifacts():
    """Return all supported firecracker binaries."""
    cargo_version = get_firecracker_version_from_toml()
    # until the next minor version (but *not* including)
    max_version = (cargo_version.major, cargo_version.minor + 1, 0)
    prefix = "firecracker/firecracker-*"
    for firecracker in sorted(ARTIFACT_DIR.glob(prefix)):
        match = re.match(r"firecracker-v(\d+)\.(\d+)\.(\d+)", firecracker.name)
        if not match:
            continue
        fc = FirecrackerArtifact(firecracker)
        version = fc.version_tuple
        if version >= max_version:
            continue
        yield pytest.param(fc, id=fc.name)

    fc = working_version_as_artifact()
    yield pytest.param(fc, id=fc.name)
