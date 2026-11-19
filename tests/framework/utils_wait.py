# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Helpers that wait for a process, port or socket to be ready."""

import uuid

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


def wait_for_guest_cmd(vm, cmd, timeout=5.0):
    """Poll via SSH until `cmd` succeeds inside the guest."""
    for attempt in Retrying(
        wait=wait_fixed(0.1), stop=stop_after_delay(timeout), reraise=True
    ):
        with attempt:
            # Not using check_output to not trigger the SSH error hook
            exit_code, stdout, stderr = vm.ssh.run(cmd)
            assert (
                exit_code == 0
            ), f"'{cmd}' did not succeed on guest:\n{stdout}{stderr}"


def wait_for_tcp_port_on_guest(vm, port, timeout=5.0):
    """Poll via SSH until a TCP port is listening inside the guest."""
    wait_for_guest_cmd(vm, f"ss -tln | grep -q ':{port} '", timeout)


def wait_for_unix_socket_on_host(network_prefix, path, timeout=5.0):
    """Poll until a Unix socket at `path` is listening on the host.

    The path exists from bind() on, so check the socket state instead.
    """
    for attempt in Retrying(
        wait=wait_fixed(0.1), stop=stop_after_delay(timeout), reraise=True
    ):
        with attempt:
            _, stdout, _ = run_cmd(
                f"{network_prefix} ss -xH state listening src {path}"
            )
            assert stdout.strip(), f"No Unix socket listening on {path}"


def start_guest_process(vm, cmd, ready_pattern, timeout=10.0):
    """Start `cmd` in the guest, detached, and return its log path.

    The ssh command returns as soon as the process is forked, so wait for
    `ready_pattern` in its output before returning. Use a line the program
    prints once it is ready, e.g. socat's "listening on" with `-d -d`.
    `cmd` must be a single command, as its output gets redirected.
    """
    log_path = f"/tmp/{uuid.uuid4()}.log"
    vm.ssh.check_output(f"nohup {cmd} > {log_path} 2>&1 &")
    try:
        wait_for_guest_cmd(vm, f"grep -q '{ready_pattern}' {log_path}", timeout)
    except AssertionError as err:
        output = vm.ssh.run(f"cat {log_path}").stdout
        raise AssertionError(
            f"'{cmd}' did not print '{ready_pattern}':\n{output}"
        ) from err
    return log_path


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
