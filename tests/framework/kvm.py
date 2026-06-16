# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Helpers for probing host KVM capabilities used by tests."""

import fcntl
import os
from dataclasses import dataclass

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
