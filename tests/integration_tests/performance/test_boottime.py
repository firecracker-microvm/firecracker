# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that ensure the boot time to init process is within spec."""

import datetime
import re
import time

import pytest

from framework.artifacts import ACPI_GUEST_KERNELS, pin_guest_kernel, pin_rootfs_mode
from framework.kvm import BASE_BOOT_ARGS
from framework.utils_hugepages import HugePagesConfig
from framework.vm_backend import VM_BACKEND_KVM, pin_vm_backend

# Regex for obtaining boot time from some string.

# Boot time is measured without a serial console. `i8042.nopnp` keeps the
# measured configuration as it has always been, though it leaves the guest
# without a keyboard (see BASE_BOOT_ARGS).
DEFAULT_BOOT_ARGS = BASE_BOOT_ARGS + " 8250.nr_uarts=0 i8042.nopnp"

# Not pinned as a module: each test below states what it needs from the backend.
pytestmark = [pin_guest_kernel(ACPI_GUEST_KERNELS)]


def get_boottime_device_info(vm):
    """Auxiliary function for asserting the expected boot time."""
    boot_time_us = None
    boot_time_cpu_us = None
    timestamps = []

    timestamp_log_regex = (
        r"Guest-boot-time =\s+(\d+) us\s+(\d+) ms,\s+(\d+) CPU us\s+(\d+) CPU ms"
    )

    iterations = 50
    sleep_time_s = 0.1
    for _ in range(iterations):
        timestamps = re.findall(timestamp_log_regex, vm.log_data)
        if timestamps:
            break
        time.sleep(sleep_time_s)
    if timestamps:
        boot_time_us, _, boot_time_cpu_us, _ = timestamps[0]

    assert boot_time_us and boot_time_cpu_us, (
        f"MicroVM did not boot within {sleep_time_s * iterations}s\n"
        f"Firecracker logs:\n{vm.log_data}\n"
        f"Thread backtraces:\n{vm.thread_backtraces}"
    )
    return int(boot_time_us), int(boot_time_cpu_us)


def find_events(log_data):
    """
    Parse events in the Firecracker logs

    Events have this format:

        TIMESTAMP [LOGLEVEL] event_(start|end): EVENT
    """
    ts_fmt = "%Y-%m-%dT%H:%M:%S.%f"
    matches = re.findall(r"(.+) \[.+\] event_(start|end): (.*)", log_data)
    timestamps = {}
    for ts, when, what in matches:
        evt1 = timestamps.setdefault(what, {})
        evt1[when] = datetime.datetime.strptime(ts[:-3], ts_fmt)
    for _, val in timestamps.items():
        val["duration"] = val["end"] - val["start"]
    return timestamps


def get_systemd_analyze_times(microvm):
    """
    Parse systemd-analyze output
    """
    rc, stdout, stderr = microvm.ssh.run("systemd-analyze")
    assert rc == 0, stderr
    assert stderr == ""

    boot_line = stdout.splitlines()[0]
    # The line will look like this:
    # Startup finished in 79ms (kernel) + 231ms (userspace) = 310ms
    # In the regex we capture the time and the unit for kernel, userspace and total values
    pattern = r"Startup finished in ([\d.]*)(ms|s)\s+\(kernel\) \+ ([\d.]*)(ms|s)\s+\(userspace\) = ([\d.]*)(ms|s)\s*"
    kernel, kernel_unit, userspace, userspace_unit, total, total_unit = re.findall(
        pattern, boot_line
    )[0]

    def to_ms(v, unit):
        match unit:
            case "ms":
                return float(v)
            case "s":
                return float(v) * 1000

    kernel = to_ms(kernel, kernel_unit)
    userspace = to_ms(userspace, userspace_unit)
    total = to_ms(total, total_unit)

    return kernel, userspace, total


def launch_boottime_vm(
    microvm_factory,
    vm_backend,
    guest_kernel,
    rootfs,
    vcpu_count,
    mem_size_mib,
    pci_enabled,
    boot_from_pmem,
    huge_pages=HugePagesConfig.NONE,
):
    """Launch a microVM configured for boot-time measurement.

    Returns ``(vm, boot_time_us, cpu_boot_time_us)``, the latter two ``None`` on
    backends without a boot timer.
    """
    vm = microvm_factory.build(
        guest_kernel, rootfs, pci=pci_enabled, backend=vm_backend, monitor_memory=False
    )
    if vm_backend.has_boot_timer:
        vm.jailer.extra_args.update({"boot-timer": None})
    vm.spawn()
    # The entropy device is here to keep the guest from blocking on crng init,
    # not as a subject of the measurement, so drop it where it is unsupported.
    entropy = vm_backend.supports_entropy_device
    # /usr/local/bin/init pokes the boot timer through /dev/mem at a hardcoded
    # GPA, then execs /sbin/init. That GPA is arch::MMIO_MEM_START, which on
    # aarch64 is where an enclave puts the base of guest RAM, so without a boot
    # timer the poke corrupts the guest instead of signalling anything.
    boot_args = DEFAULT_BOOT_ARGS
    if vm_backend.is_enclave:
        # Enclaves have no i8042 device, skip its init to save 500ms of boot time.
        boot_args += " initcall_blacklist=i8042_init"
    if vm_backend.has_boot_timer:
        boot_args += " init=/usr/local/bin/init"
    if not boot_from_pmem:
        vm.basic_config(
            vcpu_count=vcpu_count,
            mem_size_mib=mem_size_mib,
            boot_args=boot_args,
            enable_entropy_device=entropy,
            huge_pages=huge_pages,
        )
    else:
        vm.basic_config(
            add_root_device=False,
            vcpu_count=vcpu_count,
            mem_size_mib=mem_size_mib,
            boot_args=boot_args + " rootflags=dax",
            enable_entropy_device=entropy,
            huge_pages=huge_pages,
        )
        vm.add_pmem("pmem", rootfs, True, True)

    vm.add_net_iface()
    vm.start()
    if vm.backend.has_parent_vcpu_threads:
        vm.pin_threads(0)

    if not vm_backend.has_boot_timer:
        return (vm, None, None)

    boot_time_us, cpu_boot_time_us = get_boottime_device_info(vm)

    return (vm, boot_time_us, cpu_boot_time_us)


# Asserts on measured boot times. KVM-only: without the boot timer device there
# is nothing to assert.
@pytest.mark.serial
@pin_vm_backend(VM_BACKEND_KVM)
def test_boot_timer(microvm_factory, vm_backend, guest_kernel, rootfs, pci_enabled):
    """Tests that the boot timer device works"""
    launch_boottime_vm(
        microvm_factory, vm_backend, guest_kernel, rootfs, 1, 128, pci_enabled, False
    )


@pytest.mark.parametrize(
    "vcpu_count,mem_size_mib",
    [(1, 1024), (2, 2048), (4, 4096)],
)
@pin_rootfs_mode("rw")
@pytest.mark.parametrize("boot_from_pmem", [True, False], ids=["PmemBoot", "BlockBoot"])
@pytest.mark.parametrize(
    "huge_pages", [HugePagesConfig.NONE, HugePagesConfig.TRANSPARENT], indirect=True
)
@pytest.mark.nonci
def test_boottime(
    microvm_factory,
    vm_backend,
    guest_kernel,
    rootfs,
    vcpu_count,
    mem_size_mib,
    boot_from_pmem,
    pci_enabled,
    huge_pages,
    metrics,
):
    """Test boot time with different guest configurations.

    Backends without a boot timer report time-to-ssh-up, the build and boot
    event durations and systemd-analyze, but no guest_boot_time.
    """
    if boot_from_pmem and vm_backend.is_enclave:
        pytest.skip("virtio-pmem has no Nitro Enclave transport")

    # An enclave guest also holds the EIF image in its RAM, so it needs more
    # than a KVM guest to boot at all. At 128 MiB it starts but dies before
    # even reaching crng init, on both arches.
    if vm_backend.is_enclave and mem_size_mib < 256:
        pytest.skip(f"{mem_size_mib} MiB is below the enclave memory floor")

    for i in range(10):
        vm, boot_time_us, cpu_boot_time_us = launch_boottime_vm(
            microvm_factory,
            vm_backend,
            guest_kernel,
            rootfs,
            vcpu_count,
            mem_size_mib,
            pci_enabled,
            boot_from_pmem,
            huge_pages,
        )

        if i == 0:
            metrics.set_dimensions(
                {
                    "performance_test": "test_boottime",
                    "boot_from_pmem": str(boot_from_pmem),
                    "huge_pages": str(huge_pages),
                    **vm.dimensions,
                }
            )

        metrics.put_metric(
            "time_to_ssh_up",
            vm.time_to_ssh_up_us,
            unit="Microseconds",
        )

        if boot_time_us is not None:
            metrics.put_metric(
                "guest_boot_time",
                boot_time_us,
                unit="Microseconds",
            )
            metrics.put_metric(
                "guest_cpu_boot_time",
                cpu_boot_time_us,
                unit="Microseconds",
            )

        events = find_events(vm.log_data)
        build_time = events["build microvm for boot"]["duration"]
        metrics.put_metric("build_time", build_time.microseconds, unit="Microseconds")
        resume_time = events["boot microvm"]["duration"]
        metrics.put_metric("resume_time", resume_time.microseconds, unit="Microseconds")

        kernel, userspace, total = get_systemd_analyze_times(vm)
        metrics.put_metric("systemd_kernel", kernel, unit="Milliseconds")
        metrics.put_metric("systemd_userspace", userspace, unit="Milliseconds")
        metrics.put_metric("systemd_total", total, unit="Milliseconds")

        vm.kill()
