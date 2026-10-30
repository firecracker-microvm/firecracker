# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Firecracker pvpanic MMIO device."""

from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel

# sysfs attribute the guest driver creates for each device it binds to. Its
# presence proves the driver bound and its value proves which events were
# negotiated. This cannot be checked through `dmesg`: the pvpanic driver logs
# nothing on a successful probe, and it binds successfully even when it reads
# back no supported events at all.
CAPABILITY_GLOB = "/sys/bus/platform/drivers/pvpanic-mmio/*/capability"

# What Firecracker advertises: PVPANIC_PANICKED | PVPANIC_CRASH_LOADED.
# PVPANIC_SHUTDOWN (bit 2) is intentionally not advertised, because it would
# make the guest expect the host to power the VM off.
EXPECTED_CAPABILITY = "3"

PANIC_LOG_MSG = "pvpanic: guest panicked"

# Logged by the VMM event loop, so it also proves the device handed the event
# over to it instead of only recording it on the vCPU thread.
VMM_HANDOVER_LOG_MSG = "pvpanic: guest panic handed over to the VMM"


def _trigger_guest_panic(vm):
    """Panic the guest via the magic SysRq interface.

    The guest pvpanic driver runs at the highest panic-notifier priority and
    writes the event to the device; with `panic=1` the guest then reboots, which
    makes Firecracker exit. Enabling sysrq first keeps this robust across guest
    kernel defaults.
    """
    vm.ssh.run("echo 1 > /proc/sys/kernel/sysrq")
    # SysRq 'c' panics the guest instantly, so a synchronous SSH command would
    # never return and would hang until the SSH timeout. Detach it (with a
    # small delay) so the call returns first, then wait for the panic to reboot
    # the guest and make Firecracker exit.
    vm.ssh.run("nohup sh -c 'sleep 1; echo c > /proc/sysrq-trigger' >/dev/null 2>&1 &")
    vm.mark_killed()


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_pvpanic_panic_event(uvm):
    """
    Verify that a guest kernel panic is surfaced to Firecracker via the
    pvpanic device when it is enabled with `--enable-pvpanic`.
    """
    vm = uvm
    # The guest will panic and reboot, so memory monitoring is not useful.
    vm.memory_monitor = None
    vm.jailer.extra_args.update({"enable-pvpanic": None})
    vm.spawn()
    vm.basic_config(vcpu_count=1, mem_size_mib=256)
    vm.add_net_iface()
    vm.start()

    # The driver must have bound to the device Firecracker described via ACPI
    # (x86_64) / device tree (aarch64), and must have negotiated exactly the
    # events we advertise. In particular PVPANIC_CRASH_LOADED has to be there:
    # a guest with a crash kernel armed reports that event instead of
    # PVPANIC_PANICKED and drops the notification entirely if the host did not
    # advertise it.
    _, capability, _ = vm.ssh.check_output(f"cat {CAPABILITY_GLOB}")
    assert capability.split() == [EXPECTED_CAPABILITY]

    _trigger_guest_panic(vm)

    # Firecracker must have logged the panic event received from the device.
    vm.check_log_message(PANIC_LOG_MSG)
    # And the device must have handed it over to the VMM event loop.
    vm.check_log_message(VMM_HANDOVER_LOG_MSG)


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_pvpanic_not_enabled(uvm):
    """
    Verify that without `--enable-pvpanic` no pvpanic device is exposed to the
    guest (the driver does not bind) and no panic event is logged.
    """
    vm = uvm
    vm.memory_monitor = None
    vm.spawn()
    vm.basic_config(vcpu_count=1, mem_size_mib=256)
    vm.add_net_iface()
    vm.start()

    # Nothing is described to the guest, so the driver binds to no device and
    # creates no sysfs attributes for it.
    _, stdout, _ = vm.ssh.run(f"ls {CAPABILITY_GLOB} 2>/dev/null")
    assert not stdout.split()

    # Panic anyway; Firecracker must not report a pvpanic event.
    _trigger_guest_panic(vm)

    assert PANIC_LOG_MSG not in vm.log_data
    assert VMM_HANDOVER_LOG_MSG not in vm.log_data


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_pvpanic_survives_snapshot_restore(uvm, microvm_factory):
    """
    Verify that a pvpanic device enabled with `--enable-pvpanic` comes back on
    restore.

    The device is part of the snapshot state, so it must be rebuilt purely from
    that state. `--enable-pvpanic` is a boot-path option: the restoring process
    is deliberately not given it, and the device must still be present and
    usable.
    """
    vm = uvm
    vm.memory_monitor = None
    vm.jailer.extra_args.update({"enable-pvpanic": None})
    vm.spawn()
    vm.basic_config(vcpu_count=1, mem_size_mib=256)
    vm.add_net_iface()
    vm.start()

    snapshot = vm.snapshot_full()

    # Restore in a brand new process that is NOT given `--enable-pvpanic`. If the
    # device came from the flag rather than the snapshot state, it would be
    # missing here.
    restored_vm = microvm_factory.build_from_snapshot(snapshot)
    restored_vm.memory_monitor = None

    # The device is back with the same negotiated events, and the guest driver
    # bound before the snapshot is still bound to the restored device.
    _, capability, _ = restored_vm.ssh.check_output(f"cat {CAPABILITY_GLOB}")
    assert capability.split() == [EXPECTED_CAPABILITY]

    # A panic in the restored guest must reach the restored Firecracker.
    _trigger_guest_panic(restored_vm)
    restored_vm.check_log_message(PANIC_LOG_MSG)
    # Including the VMM event loop: the notification eventfd is not part of the
    # snapshot state, so the restore path has to rebuild and re-register it.
    restored_vm.check_log_message(VMM_HANDOVER_LOG_MSG)
