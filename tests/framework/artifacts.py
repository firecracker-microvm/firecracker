# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Define classes for interacting with CI artifacts"""

import platform
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest

from framework.defs import ARTIFACT_DIR


@dataclass(frozen=True)
class GuestKernel:
    """Logical guest kernel variant and its concrete boot artifacts."""

    version: str
    acpi: bool
    vmlinux: Path
    efi_image: Path | None = None
    debug: bool = False

    @classmethod
    def from_vmlinux(cls, vmlinux: Path):
        """Build a logical guest kernel from a Firecracker `vmlinux-*` artifact."""
        vmlinux = Path(vmlinux)
        parsed = parse_vmlinux_name(vmlinux.name)
        if parsed is None:
            raise ValueError(f"Unsupported guest kernel artifact: {vmlinux}")
        version, acpi = parsed

        debug = vmlinux.parent.name == "debug"
        artifact_dir = vmlinux.parent.parent if debug else vmlinux.parent

        arch = platform.machine()
        if arch == "aarch64":
            # aarch64 uses Image format, which can boot both directly and via EFI
            efi_image = vmlinux
        elif arch == "x86_64":
            # x86_64 uses a separate EFI-enabled bzImage. The no-ACPI variant is
            # a legacy MPTable boot path and is never built as an EFI image, so
            # it has no bzImage sibling to pair with.
            path = artifact_dir / f"bzImage-{version}" if acpi else None
            efi_image = path if path is not None and path.exists() else None
        else:
            raise ValueError(f"Unsupported host architecture: {arch}")

        return cls(
            version=version,
            acpi=acpi,
            vmlinux=vmlinux,
            efi_image=efi_image,
            debug=debug,
        )

    @property
    def pytest_id(self):
        """Stable pytest id matching the canonical Firecracker kernel artifact."""
        return self.vmlinux.name

    @property
    def metric_id(self):
        """Kernel dimension value independent of the backend boot image.

        Deliberately ``linux-<major>.<minor>`` (the patch version is dropped) so
        the CloudWatch ``guest_kernel`` dimension stays stable across guest
        kernel patch bumps. This also preserves the historical behavior of
        reporting ACPI and no-ACPI variants under the same dimension.

        >>> GuestKernel("5.10.233", False, Path("vmlinux-5.10.233-no-acpi")).metric_id
        'linux-5.10'
        """
        major_minor = ".".join(self.version.split(".")[:2])
        return f"linux-{major_minor}"


# Guest kernel `<major>.<minor>` versions the suite supports.
SUPPORTED_KERNEL_VERSIONS = {"5.10", "6.1", "6.18"}
# Versions for which we also test the non-ACPI (MPTable) variant.
# Booting with MPTable is deprecated, so we only build a 5.10 no-ACPI kernel to
# keep covering it. TODO: remove this once we drop support for MPTable.
NO_ACPI_KERNEL_VERSIONS = {"5.10"}


# vmlinux-<major>.<minor>[.<patch>][-no-acpi]. The single place the artifact
# name format is parsed.
_VMLINUX_NAME_RE = re.compile(r"vmlinux-(\d+\.\d+(?:\.\d+)?)(-no-acpi)?")


def parse_vmlinux_name(name: str) -> tuple[str, bool] | None:
    """Parse a ``vmlinux-*`` artifact filename.

    Returns ``(version, acpi)`` where ``version`` is the dotted kernel version
    (e.g. ``"6.1.168"``) and ``acpi`` is ``False`` for a ``-no-acpi`` artifact,
    or ``None`` if `name` is not a recognised ``vmlinux-<version>`` artifact.

    >>> parse_vmlinux_name("vmlinux-6.1.168")
    ('6.1.168', True)
    >>> parse_vmlinux_name("vmlinux-5.10.233-no-acpi")
    ('5.10.233', False)
    >>> parse_vmlinux_name("bzImage-6.1.168") is None
    True
    """
    match = _VMLINUX_NAME_RE.fullmatch(name)
    if match is None:
        return None
    return match.group(1), match.group(2) != "-no-acpi"


def kernels(glob, artifact_dir: Path = ARTIFACT_DIR) -> Iterator:
    """Yield artifact paths for guest kernels the suite supports.

    Supported means: a parseable ``vmlinux-<version>`` artifact, with a patch
    version, whose ``<major>.<minor>`` is in `SUPPORTED_KERNEL_VERSIONS` (and,
    for ``-no-acpi`` artifacts, in `NO_ACPI_KERNEL_VERSIONS`).
    """
    for kernel in sorted(artifact_dir.glob(glob)):
        parsed = parse_vmlinux_name(kernel.name)
        if parsed is None:
            if kernel.suffix in {".config", ".debug"}:
                continue
            raise ValueError(f"Unsupported guest kernel artifact: {kernel}")
        version, acpi = parsed
        # Require a patch version (e.g. 6.1.168, not 6.1).
        if len(version.split(".")) != 3:
            raise ValueError(
                f"Guest kernel artifact must include a patch version: {kernel}"
            )
        major_minor = ".".join(version.split(".")[:2])
        if major_minor not in SUPPORTED_KERNEL_VERSIONS:
            raise ValueError(f"Unsupported guest kernel version {version}: {kernel}")
        if not acpi and major_minor not in NO_ACPI_KERNEL_VERSIONS:
            raise ValueError(
                f"Unsupported non-ACPI guest kernel version {version}: {kernel}"
            )
        yield kernel


def disks(glob) -> list:
    """Return supported rootfs"""
    return sorted(ARTIFACT_DIR.glob(glob))


def kernel_params(glob="vmlinux-*", select=kernels, artifact_dir=ARTIFACT_DIR) -> list:
    """Return supported kernels or a single None if no kernels are found"""
    return [
        pytest.param(kernel, id=kernel.pytest_id)
        for kernel in (
            GuestKernel.from_vmlinux(path) for path in select(glob, artifact_dir)
        )
    ] or [pytest.param(None, id="no-kernel-found")]


# Catalogues of guest kernel artifacts. Each entry is a `pytest.param` so test
# ids carry the kernel filename (e.g. "vmlinux-6.1.123") rather than "kernel0".
ALL_GUEST_KERNELS = list(kernel_params("vmlinux-*"))
ACPI_GUEST_KERNELS = [p for p in kernel_params("vmlinux-*") if "no-acpi" not in p.id]
GUEST_KERNELS_5_10 = list(kernel_params("vmlinux-5.10*"))
GUEST_KERNELS_6_1 = list(kernel_params("vmlinux-6.1*"))
GUEST_KERNELS_6_1_DEBUG = list(
    kernel_params("vmlinux-6.1*", artifact_dir=ARTIFACT_DIR / "debug")
)
# The single canonical kernel used when a test pins to one specific kernel
# (e.g. tests of Firecracker functionality that don't depend on guest kernel).
# Update here when the default version changes. Stored as a `pytest.param`
# so the test id carries the kernel filename (e.g. "vmlinux-6.1.168").
GUEST_KERNEL_DEFAULT = GUEST_KERNELS_6_1[0] if GUEST_KERNELS_6_1 else None
GUEST_KERNEL_DEFAULT_DEBUG = (
    GUEST_KERNELS_6_1_DEBUG[0] if GUEST_KERNELS_6_1_DEBUG else None
)


def pin_guest_kernel(kernels_or_param):
    """Convenience marker for pinning the `guest_kernel` dim.

    The default `guest_kernel` fixture parametrizes over ALL_GUEST_KERNELS;
    use this helper to restrict to a single kernel or a smaller subset.

    Usage at module level:
        pytestmark = pin_guest_kernel(ACPI_GUEST_KERNELS)

    Usage at test level:
        @pin_guest_kernel(GUEST_KERNEL_DEFAULT)
        def test_foo(uvm): ...

    Accepts a kernel catalogue (e.g. ACPI_GUEST_KERNELS) or a single
    `pytest.param`.
    """
    # Wrap a single pytest.param into a list. A bare ParameterSet passed to
    # `parametrize` would be treated as a sequence of args and produce broken
    # parameterizations.
    if not isinstance(kernels_or_param, list):
        kernels_or_param = [kernels_or_param]
    return pytest.mark.parametrize("guest_kernel", kernels_or_param, indirect=True)


def pin_rootfs_mode(mode):
    """Convenience marker for pinning the `rootfs_mode` dim ("ro" | "rw")."""
    return pytest.mark.parametrize("rootfs_mode", [mode], indirect=True)


def pin_pci(enabled):
    """Convenience marker for pinning the `pci_enabled` dim to a single value."""
    return pytest.mark.parametrize("pci_enabled", [enabled], indirect=True)
