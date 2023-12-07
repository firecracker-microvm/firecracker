# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

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

    # Verify guest is active.
    exit_code, _, _ = microvm.ssh.run("ls")
    assert exit_code == 0

    # Pausing the microVM after it's been started is successful.
    microvm.api.vm.patch(state="Paused")

    # Flush and reset metrics as they contain pre-pause data.
    microvm.flush_metrics()

    # Verify guest is no longer active.
    exit_code, _, _ = microvm.ssh.run("ls")
    assert exit_code != 0

    # Verify emulation was indeed paused and no events from either
    # guest or host side were handled.
    verify_net_emulation_paused(microvm.flush_metrics())

    # Verify guest is no longer active.
    exit_code, _, _ = microvm.ssh.run("ls")
    assert exit_code != 0

    # Pausing the microVM when it is already `Paused` is allowed
    # (microVM remains in `Paused` state).
    microvm.api.vm.patch(state="Paused")

    # Resuming the microVM is successful.
    microvm.api.vm.patch(state="Resumed")

    # Verify guest is active again.
    exit_code, _, _ = microvm.ssh.run("ls")
    assert exit_code == 0

    # Resuming the microVM when it is already `Resumed` is allowed
    # (microVM remains in the running state).
    microvm.api.vm.patch(state="Resumed")

    # Verify guest is still active.
    exit_code, _, _ = microvm.ssh.run("ls")
    assert exit_code == 0

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
