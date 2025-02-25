# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import platform
import time
from subprocess import TimeoutExpired

import pytest


def verify_net_emulation_paused(metrics):
    """Verify net emulation is paused based on provided metrics."""
    net_metrics = metrics["net"]
    assert net_metrics["rx_queue_event_count"] == 0
    assert net_metrics["rx_partial_writes"] == 0
    assert net_metrics["rx_tap_event_count"] == 0
    assert net_metrics["rx_bytes_count"] == 0
    assert net_metrics["rx_packets_count"] == 0
    assert net_metrics["rx_fails"] == 0
    assert net_metrics["rx_count"] == 0
    assert net_metrics["tap_read_fails"] == 0
    assert net_metrics["tap_write_fails"] == 0
    assert net_metrics["tx_bytes_count"] == 0
    assert net_metrics["tx_fails"] == 0
    assert net_metrics["tx_count"] == 0
    assert net_metrics["tx_packets_count"] == 0
    assert net_metrics["tx_queue_event_count"] == 0
    print(net_metrics)


def test_pause_resume(uvm_nano):
    """
    Test scenario: boot/pause/resume.
    """
    microvm = uvm_nano
    microvm.add_net_iface()

    # Pausing the microVM before being started is not allowed.
    with pytest.raises(RuntimeError):
        microvm.api.vm.patch(state="Paused")

    # Resuming the microVM before being started is also not allowed.
    with pytest.raises(RuntimeError):
        microvm.api.vm.patch(state="Resumed")

    microvm.start()

    # Pausing the microVM after it's been started is successful.
    microvm.api.vm.patch(state="Paused")

    # Flush and reset metrics as they contain pre-pause data.
    microvm.flush_metrics()

    # Verify guest is no longer active.
    with pytest.raises(TimeoutExpired):
        microvm.ssh.check_output("true", timeout=1)

    # Verify emulation was indeed paused and no events from either
    # guest or host side were handled.
    verify_net_emulation_paused(microvm.flush_metrics())

    # Pausing the microVM when it is already `Paused` is allowed
    # (microVM remains in `Paused` state).
    microvm.api.vm.patch(state="Paused")

    # Resuming the microVM is successful.
    microvm.api.vm.patch(state="Resumed")

    # Verify guest is active again.
    microvm.ssh.check_output("true")

    # Resuming the microVM when it is already `Resumed` is allowed
    # (microVM remains in the running state).
    microvm.api.vm.patch(state="Resumed")

    # Verify guest is still active.

    microvm.kill()


def test_describe_instance(uvm_nano):
    """
    Test scenario: DescribeInstance different states.
    """
    microvm = uvm_nano

    # Check MicroVM state is "Not started"
    response = microvm.api.describe.get()
    assert "Not started" in response.text

    # Start MicroVM
    microvm.start()

    # Check MicroVM state is "Running"
    response = microvm.api.describe.get()
    assert "Running" in response.text

    # Pause MicroVM
    microvm.api.vm.patch(state="Paused")

    # Check MicroVM state is "Paused"
    response = microvm.api.describe.get()
    assert "Paused" in response.text

    # Resume MicroVM
    response = microvm.api.vm.patch(state="Resumed")

    # Check MicroVM state is "Running" after VM is resumed
    response = microvm.api.describe.get()
    assert "Running" in response.text

    microvm.kill()


def test_pause_resume_preboot(uvm_nano):
    """
    Test pause/resume operations are not allowed pre-boot.
    """
    basevm = uvm_nano

    expected_err = "not supported before starting the microVM"

    # Try to pause microvm when not running, it must fail.
    with pytest.raises(RuntimeError, match=expected_err):
        basevm.api.vm.patch(state="Paused")

    # Try to resume microvm when not running, it must fail.
    with pytest.raises(RuntimeError, match=expected_err):
        basevm.api.vm.patch(state="Resumed")


@pytest.mark.skipif(
    platform.machine() != "x86_64", reason="Only x86_64 supports pvclocks."
)
def test_kvmclock_ctrl(uvm_plain_any):
    """
    Test that pausing vCPUs does not trigger a soft lock-up
    """

    microvm = uvm_plain_any
    microvm.help.enable_console()
    microvm.spawn()

    # With 2 vCPUs under certain conditions soft lockup warnings can rarely be in dmesg causing this test to fail.
    # Example of the warning: `watchdog: BUG: soft lockup - CPU#0 stuck for (x)s! [(udev-worker):758]`
    # With 1 vCPU this intermittent issue doesn't occur. If the KVM_CLOCK_CTRL IOCTL is not made
    # the test will fail with 1 vCPU, so we can assert the call to the IOCTL is made.
    microvm.basic_config(vcpu_count=1)
    microvm.add_net_iface()
    microvm.start()

    # Launch reproducer in host
    # This launches `ls -R /` in a loop inside the guest. The command writes its output in the
    # console. This detail is important as it writing in the console seems to increase the probability
    # that we will pause the execution inside the kernel and cause a lock up. Setting KVM_CLOCK_CTRL
    # bit that informs the guest we're pausing the vCPUs, should avoid that lock up.
    microvm.ssh.check_output(
        "timeout 60 sh -c 'while true; do ls -R /; done' > /dev/ttyS0 2>&1 < /dev/null &"
    )

    for _ in range(12):
        microvm.api.vm.patch(state="Paused")
        time.sleep(5)
        microvm.api.vm.patch(state="Resumed")

    dmesg = microvm.ssh.check_output("dmesg").stdout
    assert "rcu_sched self-detected stall on CPU" not in dmesg
    assert "rcu_preempt detected stalls on CPUs/tasks" not in dmesg
    assert "BUG: soft lockup -" not in dmesg
