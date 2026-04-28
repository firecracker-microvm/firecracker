# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Shared utilities for Nitro Enclave testing."""

import os

import pytest

from framework.defs import ARTIFACT_DIR

# ---------------------------------------------------------------------------
# Hardware / kernel detection
# ---------------------------------------------------------------------------


def _has_ne_device():
    """Check if /dev/nitro_enclaves exists."""
    return os.path.exists("/dev/nitro_enclaves")


def _is_ne_dynamic():
    """Check if the NE CPU pool is in dynamic mode."""
    try:
        with open(
            "/sys/module/nitro_enclaves/parameters/ne_cpus", encoding="ascii"
        ) as f:
            return f.read().strip() == "dynamic"
    except (FileNotFoundError, PermissionError):
        return False


def _get_ne_cpus():
    """Read and parse the NE CPU pool from sysfs. Returns list of CPU IDs or empty list."""
    try:
        with open(
            "/sys/module/nitro_enclaves/parameters/ne_cpus", encoding="ascii"
        ) as f:
            content = f.read().strip()
            if not content or content == "(null)" or content == "dynamic":
                return []
            cpus = []
            for part in content.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = part.split("-", 1)
                    cpus.extend(range(int(start), int(end) + 1))
                else:
                    cpus.append(int(part))
            return cpus
    except (FileNotFoundError, PermissionError, ValueError):
        return []


def _has_ne_cpus():
    """Check if NE CPU pool is configured (static list or dynamic)."""
    return _is_ne_dynamic() or len(_get_ne_cpus()) > 0


# ---------------------------------------------------------------------------
# Skip markers
# ---------------------------------------------------------------------------

requires_enclave = pytest.mark.skipif(
    not (_has_ne_device() and _has_ne_cpus()),
    reason="Requires NE hardware and CPU pool",
)


# ---------------------------------------------------------------------------
# Artifact finders
# ---------------------------------------------------------------------------


def _find_kernel():
    """Find a guest kernel for enclave boot.

    Prefers bzImage (has EFI stub, needed for EIF boot) over vmlinux.
    """
    # bzImage has an EFI stub and boots inside an EIF.
    candidates = sorted(ARTIFACT_DIR.glob("bzImage-6.1*"))
    if candidates:
        return candidates[0]
    # Fallback to vmlinux (won't boot in EIF without EFI stub).
    candidates = sorted(ARTIFACT_DIR.glob("vmlinux-6.1*"))
    candidates = [c for c in candidates if not c.name.endswith((".config", ".debug"))]
    return candidates[0] if candidates else None


def _find_initrd():
    """Find an initramfs for EIF building."""
    candidates = list(ARTIFACT_DIR.glob("initramfs.cpio"))
    return candidates[0] if candidates else None
