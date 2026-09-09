# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Backend dimension for pytest microVM fixtures.

A backend supplies the backend-specific parts of configuring and starting a
microVM. ``Microvm`` owns the lifecycle shared by every backend.
"""

from enum import Enum
from functools import lru_cache

import pytest

from framework.artifacts import GuestKernel
from framework.kvm import has_kvm, kvm_basic_config, kvm_probe_details


class VmBackend(str, Enum):
    """Backend values and lifecycle behavior for the ``vm_backend`` dimension."""

    KVM = "kvm"

    def __str__(self):
        """Return the stable value used in pytest IDs and reports."""
        return self.value

    def available(self):
        """Whether this host can run the backend."""
        match self:
            case VmBackend.KVM:
                return has_kvm()
            case _:
                raise AssertionError(f"Unhandled VM backend: {self!r}")

    def probe_details(self):
        """Host probe details for diagnostics."""
        match self:
            case VmBackend.KVM:
                return kvm_probe_details()
            case _:
                raise AssertionError(f"Unhandled VM backend: {self!r}")

    def kernel_image_for(self, guest_kernel: GuestKernel):
        """Return the concrete boot image required by the backend."""
        match self:
            case VmBackend.KVM:
                return guest_kernel.vmlinux
            case _:
                raise AssertionError(f"Unhandled VM backend: {self!r}")

    def basic_config(self, vm, *args, **kwargs):
        """Configure a microVM using this backend."""
        match self:
            case VmBackend.KVM:
                return kvm_basic_config(vm, *args, **kwargs)
            case _:
                raise AssertionError(f"Unhandled VM backend: {self!r}")

    def prepare_start(self, _vm, *args, **kwargs):
        """Perform backend-specific preparation before starting a microVM."""
        match self:
            case VmBackend.KVM:
                if args or kwargs:
                    raise TypeError("KVM backend does not accept start options")
                return
            case _:
                raise AssertionError(f"Unhandled VM backend: {self!r}")


VM_BACKEND_KVM = VmBackend.KVM
VM_BACKENDS_ALL = tuple(VmBackend)


@lru_cache(maxsize=1)
def available_vm_backends():
    """Return the backends this host can run, checked once per session."""
    return tuple(backend for backend in VmBackend if backend.available())


def available_vm_backend_params():
    """`pytest.param` list for the backends this host can run.

    Used as the default `params` of the `vm_backend` fixture so unpinned tests
    are auto-multiplied only over backends that actually exist on the host.
    """
    return [pytest.param(backend) for backend in available_vm_backends()]


def _format_probe_value(value):
    """Format backend probe values for pytest header output."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _format_probe_details(details):
    """Format a backend probe-details dict as a single line."""
    return ", ".join(
        f"{key}={_format_probe_value(value)}" for key, value in sorted(details.items())
    )


def vm_backend_probe_report():
    """Return human-readable backend probe lines for pytest logs."""
    available = available_vm_backends()
    lines = [
        "VM Backends Available: " + (", ".join(available) if available else "none")
    ]
    for backend in VmBackend:
        details = {
            "available": backend in available,
            **backend.probe_details(),
        }
        lines.append(f"VM Backend {backend}: {_format_probe_details(details)}")
    return lines


def get_vm_backend(backend):
    """Return the enum member for a backend dimension value."""
    try:
        return VmBackend(backend)
    except (TypeError, ValueError) as err:
        raise ValueError(f"Unknown VM backend: {backend}") from err
