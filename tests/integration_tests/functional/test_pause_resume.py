# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import os
from framework.builder import MicrovmBuilder
from framework.resources import DescribeInstance
import host_tools.logging as log_tools
import host_tools.network as net_tools  # pylint: disable=import-error


def verify_net_emulation_paused(metrics):
    """Verify net emulation is paused base on provided metrics."""
    net_metrics = metrics['net']
    assert net_metrics['rx_queue_event_count'] == 0
    assert net_metrics['rx_partial_writes'] == 0
    assert net_metrics['rx_tap_event_count'] == 0
    assert net_metrics['rx_bytes_count'] == 0
    assert net_metrics['rx_packets_count'] == 0
    assert net_metrics['rx_fails'] == 0
    assert net_metrics['rx_count'] == 0
    assert net_metrics['tap_read_fails'] == 0
    assert net_metrics['tap_write_fails'] == 0
    assert net_metrics['tx_bytes_count'] == 0
    assert net_metrics['tx_fails'] == 0
    assert net_metrics['tx_count'] == 0
    assert net_metrics['tx_packets_count'] == 0
    assert net_metrics['tx_queue_event_count'] == 0
    print(net_metrics)


def test_pause_resume(bin_cloner_path):
    """Test scenario: boot/pause/resume."""
    builder = MicrovmBuilder(bin_cloner_path)
    vm_instance = builder.build_vm_nano()
    microvm = vm_instance.vm

    # Pausing the microVM before being started is not allowed.
    response = microvm.vm.patch(state='Paused')
    assert microvm.api_session.is_status_bad_request(response.status_code)

    # Resuming the microVM before being started is also not allowed.
    response = microvm.vm.patch(state='Resumed')
    assert microvm.api_session.is_status_bad_request(response.status_code)

    # Configure metrics system and start microVM.
    metrics_fifo_path = os.path.join(microvm.path, 'metrics_fifo')
    metrics_fifo = log_tools.Fifo(metrics_fifo_path)
    response = microvm.metrics.put(
        metrics_path=microvm.create_jailed_resource(metrics_fifo.path)
    )
    assert microvm.api_session.is_status_no_content(response.status_code)
    microvm.start()

    ssh_connection = net_tools.SSHConnection(microvm.ssh_config)

    # Verify guest is active.
    exit_code, _, _ = ssh_connection.execute_command("ls")
    assert exit_code == 0

    # Pausing the microVM after it's been started is successful.
    response = microvm.vm.patch(state='Paused')
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Flush and reset metrics as they contain pre-pause data.
    microvm.flush_metrics(metrics_fifo)

    # Verify guest is no longer active.
    exit_code, _, _ = ssh_connection.execute_command("ls")
    assert exit_code != 0

    # Verify emulation was indeed paused and no events from either
    # guest or host side were handled.
    verify_net_emulation_paused(microvm.flush_metrics(metrics_fifo))

    # Verify guest is no longer active.
    exit_code, _, _ = ssh_connection.execute_command("ls")
    assert exit_code != 0

    # Pausing the microVM when it is already `Paused` is allowed
    # (microVM remains in `Paused` state).
    response = microvm.vm.patch(state='Paused')
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Resuming the microVM is successful.
    response = microvm.vm.patch(state='Resumed')
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Verify guest is active again.
    exit_code, _, _ = ssh_connection.execute_command("ls")
    assert exit_code == 0

    # Resuming the microVM when it is already `Resumed` is allowed
    # (microVM remains in the running state).
    response = microvm.vm.patch(state='Resumed')
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Verify guest is still active.
    exit_code, _, _ = ssh_connection.execute_command("ls")
    assert exit_code == 0

    microvm.kill()


def test_describe_instance(bin_cloner_path):
    """Test scenario: DescribeInstance different states."""
    builder = MicrovmBuilder(bin_cloner_path)
    vm_instance = builder.build_vm_nano()
    microvm = vm_instance.vm
    descr_inst = DescribeInstance(microvm.api_socket, microvm.api_session)

    # Check MicroVM state is "Not started"
    response = descr_inst.get()
    assert microvm.api_session.is_status_ok(response.status_code)
    assert "Not started" in response.text

    # Start MicroVM
    microvm.start()

    # Check MicroVM state is "Running"
    response = descr_inst.get()
    assert microvm.api_session.is_status_ok(response.status_code)
    assert "Running" in response.text

    # Pause MicroVM
    response = microvm.vm.patch(state='Paused')
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Check MicroVM state is "Paused"
    response = descr_inst.get()
    assert microvm.api_session.is_status_ok(response.status_code)
    assert "Paused" in response.text

    # Resume MicroVM
    response = microvm.vm.patch(state='Resumed')
    assert microvm.api_session.is_status_no_content(response.status_code)

    # Check MicroVM state is "Running" after VM is resumed
    response = descr_inst.get()
    assert microvm.api_session.is_status_ok(response.status_code)
    assert "Running" in response.text

    microvm.kill()
