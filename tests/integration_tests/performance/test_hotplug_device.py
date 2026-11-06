# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Performance test for PCIe device hot-plug.

Measures the guest-visible cost of hot-plugging a block device: from just
before the Firecracker API call until the device shows up on the guest's
PCI bus. Hot-unplug is measured the same way, until it disappears again.
"""

import os
import time

import pytest

import host_tools.drive as drive_tools
from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel
from framework.properties import global_props

pytestmark = pin_guest_kernel(GUEST_KERNEL_DEFAULT)

# Each iteration gets a fresh microVM so the samples are independent.
ITERATIONS = 20

# Hotplug and unplug timeout in seconds.
TIMEOUT = 10

DEVICE_TYPE = "block"
DRIVE_ID = "blk_hotplugged"

METRICS = {
    "auto": "plug_total_time",
    "rescan": "plug_rescan_total_time",
}


def pci_device_count():
    """Shell snippet echoing how many devices sit on the guest's PCI bus."""
    return (
        'set -- /sys/bus/pci/devices/*; if [ -e "$1" ]; then echo $#; else echo 0; fi'
    )


def pci_device_count_at_least(count):
    """Shell predicate, returns true once the PCI bus holds `count` devices."""
    return f'set -- /sys/bus/pci/devices/*; [ -e "$1" ] && [ "$#" -ge {count} ]'


def pci_device_count_at_most(count):
    """Shell predicate, returns true once the bus holds no more than `count`."""
    return f'set -- /sys/bus/pci/devices/*; [ ! -e "$1" ] || [ "$#" -le {count} ]'


def wait_for(probe, predicate, timeout, what):
    """Poll `predicate` over `probe` until it holds, or raise on timeout."""
    deadline = time.time() + timeout
    while not probe(predicate):
        if time.time() > deadline:
            raise TimeoutError(f"Guest did not {what} within {timeout}s")
        time.sleep(0.001)


def boot_microvm(microvm_factory, guest_kernel, rootfs):
    """Boot a microVM with one free root port to plug into."""
    vm = microvm_factory.build(guest_kernel, rootfs, pci=True)
    vm.spawn()
    vm.memory_monitor = None
    vm.basic_config(pcie_hotplug_ports=1)
    vm.add_net_iface()
    vm.start()
    return vm


def dimensions(vm, test_name):
    """The dimensions identifying one CloudWatch metric stream."""
    return {
        "instance": global_props.instance,
        "cpu_model": global_props.cpu_model,
        "host_kernel": f"linux-{global_props.host_linux_version}",
        "performance_test": test_name,
        "device_type": DEVICE_TYPE,
        **vm.dimensions,
    }


def stage_hotplug(vm):
    """Prepare host resources and return a callable issuing the hot-plug.

    Creating the backing file is host-side setup, not part of the hot-plug,
    so it has to happen before timing starts.
    """
    host_file = drive_tools.FilesystemFile(os.path.join(vm.fsfiles, DRIVE_ID), size=4)
    jailed = vm.create_jailed_resource(host_file.path)

    return lambda: vm.api.drive.put(
        drive_id=DRIVE_ID,
        path_on_host=jailed,
        is_root_device=False,
        is_read_only=False,
    )


def time_hotplug(vm, plug_mode):
    """Milliseconds from the hot-plug request until the guest sees it."""
    issue_hotplug = stage_hotplug(vm)

    with vm.ssh.probe_channel() as probe:
        # Poll for one more device than the bus already holds rather than
        # predicting the new device's address.
        _, stdout, _ = vm.ssh.check_output(pci_device_count())
        predicate = pci_device_count_at_least(int(stdout.strip()) + 1)

        start = time.time()
        issue_hotplug()

        if plug_mode == "rescan":
            assert probe("echo 1 > /sys/bus/pci/rescan"), "guest rescan failed"

        wait_for(probe, predicate, TIMEOUT, "see the plugged device")
        return (time.time() - start) * 1000


def time_hotunplug(vm):
    """Milliseconds from the unplug request until the guest drops it."""
    issue_hotplug = stage_hotplug(vm)

    with vm.ssh.probe_channel() as probe:
        _, stdout, _ = vm.ssh.check_output(pci_device_count())
        before = int(stdout.strip())

        # Getting a device onto the bus is setup, so it is not timed.
        issue_hotplug()
        wait_for(
            probe,
            pci_device_count_at_least(before + 1),
            TIMEOUT,
            "see the plugged device",
        )

        start = time.time()
        vm.api.drive.delete(DRIVE_ID)
        wait_for(
            probe,
            pci_device_count_at_most(before),
            TIMEOUT,
            "drop the unplugged device",
        )
        return (time.time() - start) * 1000


@pytest.mark.nonci
@pytest.mark.parametrize("plug_mode", sorted(METRICS))
def test_hotplug_device_latency(
    microvm_factory, guest_kernel, rootfs, plug_mode, metrics
):
    """Measure how long a hot-plugged device takes to reach the guest."""
    for i in range(ITERATIONS):
        vm = boot_microvm(microvm_factory, guest_kernel, rootfs)

        if i == 0:
            metrics.set_dimensions(dimensions(vm, "test_hotplug_device_latency"))

        metrics.put_metric(
            METRICS[plug_mode], time_hotplug(vm, plug_mode), unit="Milliseconds"
        )

        vm.kill()


@pytest.mark.nonci
def test_hotunplug_device_latency(microvm_factory, guest_kernel, rootfs, metrics):
    """Measure how long a hot-unplugged device takes to leave the guest."""
    for i in range(ITERATIONS):
        vm = boot_microvm(microvm_factory, guest_kernel, rootfs)

        if i == 0:
            metrics.set_dimensions(dimensions(vm, "test_hotunplug_device_latency"))

        metrics.put_metric("unplug_total_time", time_hotunplug(vm), unit="Milliseconds")

        vm.kill()
