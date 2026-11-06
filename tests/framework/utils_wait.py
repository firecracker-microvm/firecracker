# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helpers that wait for a process, port or socket to be ready."""

from tenacity import Retrying, stop_after_delay, wait_fixed

from framework.utils import run_cmd, wait_process_termination


def wait_for_tcp_port_on_host(network_prefix, port, timeout=5.0):
    """Poll until a TCP port is accepting connections on localhost."""
    for attempt in Retrying(
        wait=wait_fixed(0.1), stop=stop_after_delay(timeout), reraise=True
    ):
        with attempt:
            exit_code, _, _ = run_cmd(f"{network_prefix} ss -tln | grep -q ':{port} '")
            assert exit_code == 0, f"Port {port} not open on host"


def wait_for_tcp_port_on_guest(vm, port, timeout=5.0):
    """Poll via SSH until a TCP port is listening inside the guest."""
    for attempt in Retrying(
        wait=wait_fixed(0.1), stop=stop_after_delay(timeout), reraise=True
    ):
        with attempt:
            exit_code, _, _ = vm.ssh.run(f"ss -tln | grep -q ':{port} '")
            assert exit_code == 0, f"Port {port} not open on guest"


def kill_and_wait_on_host(process_name, timeout=5.0):
    """Kills the given process on the host, and waits for its termination via waitpid"""
    exit_code, pid, _ = run_cmd(["pgrep", process_name])
    if exit_code == 0:
        # Note: process might be spawned as a child, I need to explicitly
        # wait for it, otherwise it might remain a zombie
        run_cmd(f"kill {pid}")
        wait_process_termination(int(pid), timeout)


def kill_and_wait_on_guest(vm, process_name, timeout=5.0):
    """Kills the given process on the guest"""
    vm.ssh.run(f"pkill {process_name}")
    for attempt in Retrying(
        wait=wait_fixed(0.1), stop=stop_after_delay(timeout), reraise=True
    ):
        with attempt:
            exit_code, _, _ = vm.ssh.run(f"pgrep {process_name}")
            assert exit_code == 1, f"{process_name} is still running on guest"
