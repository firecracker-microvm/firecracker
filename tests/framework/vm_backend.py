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
from framework.enclave import (
    EnclaveConfigError,
    enclave_basic_config,
    enclave_deselect_reason,
    enclave_host_available,
    enclave_prepare_start,
)
from framework.kvm import has_kvm, kvm_basic_config, kvm_probe_details


class VmBackend(str, Enum):
    """Backend values and lifecycle behavior for the ``vm_backend`` dimension."""

    KVM = "kvm"
    ENCLAVE_DIRECT = "enclave-direct"
    ENCLAVE_CONFIDENTIAL = "enclave-confidential"

    def __str__(self):
        """Return the stable value used in pytest IDs and reports."""
        return self.value

    @classmethod
    def enclaves(cls):
        """Return the Nitro Enclave backend values."""
        return (cls.ENCLAVE_DIRECT, cls.ENCLAVE_CONFIDENTIAL)

    @property
    def is_enclave(self):
        """Whether this value selects a Nitro Enclave backend."""
        return self in self.enclaves()

    @property
    def validates_api(self):
        """Whether API calls should be validated against the Swagger spec."""
        return not self.is_enclave

    @property
    def enforces_api_timing(self):
        """Whether API call durations are asserted against the timing budget.

        Enclave start (EIF build and guest-memory donation) has not been
        characterised against MAX_API_CALL_DURATION_MS, so exempt enclave VMs
        rather than assert an unvalidated bound - revisit with data, or drop
        the metric.
        """
        return not self.is_enclave

    @property
    def has_parent_vcpu_threads(self):
        """Whether guest vCPUs are threads of the parent Firecracker process.

        Enclave vCPUs are donated from the parent VM to the enclave, so they
        are not parent threads and there is nothing for pin_threads() to pin.
        Phrased as a capability rather than an is_enclave check at the call
        site, so `Microvm` never branches on which backend it is running.
        """
        return not self.is_enclave

    def available(self):
        """Whether this host can run the backend."""
        match self:
            case VmBackend.KVM:
                return has_kvm()
            case VmBackend.ENCLAVE_DIRECT | VmBackend.ENCLAVE_CONFIDENTIAL:
                return enclave_host_available()
            case _:
                raise AssertionError(f"Unhandled VM backend: {self!r}")

    def probe_details(self):
        """Host probe details for diagnostics."""
        match self:
            case VmBackend.KVM:
                return kvm_probe_details()
            case VmBackend.ENCLAVE_DIRECT | VmBackend.ENCLAVE_CONFIDENTIAL:
                return {}
            case _:
                raise AssertionError(f"Unhandled VM backend: {self!r}")

    def deselect_reason(self, *, kernel, pci_enabled, huge_pages, lifecycle):
        """Why this backend cannot run a parametrisation, or ``None``.

        Consulted at collection time so impossible variants are deselected
        instead of skipped during fixture setup.
        """
        match self:
            case VmBackend.KVM:
                return None
            case VmBackend.ENCLAVE_DIRECT | VmBackend.ENCLAVE_CONFIDENTIAL:
                return enclave_deselect_reason(
                    kernel=kernel,
                    pci_enabled=pci_enabled,
                    huge_pages=huge_pages,
                    lifecycle=lifecycle,
                )
            case _:
                raise AssertionError(f"Unhandled VM backend: {self!r}")

    def kernel_image_for(self, guest_kernel: GuestKernel):
        """Return the concrete boot image required by the backend."""
        match self:
            case VmBackend.KVM:
                return guest_kernel.vmlinux
            case VmBackend.ENCLAVE_DIRECT | VmBackend.ENCLAVE_CONFIDENTIAL:
                if not guest_kernel.acpi:
                    pytest.skip("Enclave backend requires an ACPI guest kernel")
                if guest_kernel.efi_image is None:
                    pytest.skip(
                        f"No enclave EFI boot image for {guest_kernel.pytest_id}"
                    )
                return guest_kernel.efi_image
            case _:
                raise AssertionError(f"Unhandled VM backend: {self!r}")

    def basic_config(self, vm, *args, **kwargs):
        """Configure a microVM using this backend."""
        match self:
            case VmBackend.KVM:
                return kvm_basic_config(vm, *args, **kwargs)
            case VmBackend.ENCLAVE_DIRECT | VmBackend.ENCLAVE_CONFIDENTIAL:
                return enclave_basic_config(vm, *args, **kwargs)
            case _:
                raise AssertionError(f"Unhandled VM backend: {self!r}")

    def prepare_start(self, vm, *args, **kwargs):
        """Perform backend-specific preparation before starting a microVM."""
        match self:
            case VmBackend.KVM:
                if args or kwargs:
                    raise TypeError("KVM backend does not accept start options")
                return
            case VmBackend.ENCLAVE_DIRECT | VmBackend.ENCLAVE_CONFIDENTIAL:
                enclave_prepare_start(
                    vm,
                    *args,
                    direct_mode=self is VmBackend.ENCLAVE_DIRECT,
                    **kwargs,
                )
            case _:
                raise AssertionError(f"Unhandled VM backend: {self!r}")

    def require_restore_support(self):
        """Raise if this backend cannot restore snapshots."""
        match self:
            case VmBackend.KVM:
                return
            case VmBackend.ENCLAVE_DIRECT | VmBackend.ENCLAVE_CONFIDENTIAL:
                raise EnclaveConfigError(
                    "Enclave backend does not support snapshot restore; pin this "
                    "test to KVM with @pin_vm_backend(VM_BACKEND_KVM)."
                )
            case _:
                raise AssertionError(f"Unhandled VM backend: {self!r}")


VM_BACKEND_KVM = VmBackend.KVM
VM_BACKEND_ENCLAVE_DIRECT = VmBackend.ENCLAVE_DIRECT
VM_BACKEND_ENCLAVE_CONFIDENTIAL = VmBackend.ENCLAVE_CONFIDENTIAL
VM_BACKENDS_ENCLAVE = VmBackend.enclaves()
VM_BACKENDS_ALL = tuple(VmBackend)


def pin_vm_backend(backends):
    """Convenience marker for pinning the `vm_backend` dimension."""
    if not isinstance(backends, (list, tuple)):
        backends = [backends]
    return pytest.mark.parametrize("vm_backend", list(backends), indirect=True)


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
