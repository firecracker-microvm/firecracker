# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that the seccomp filters don't let blacklisted syscalls through."""

import os

import framework.utils as utils


def test_seccomp_ls(bin_seccomp_paths):
    """Assert that the seccomp filters deny a blacklisted syscall."""
    # pylint: disable=redefined-outer-name
    # pylint: disable=subprocess-run-check
    # The fixture pattern causes a pylint false positive for that rule.

    # Path to the `ls` binary, which attempts to execute the blacklisted
    # `SYS_access`.
    ls_command_path = '/bin/ls'
    demo_jailer = bin_seccomp_paths['demo_basic_jailer']

    assert os.path.exists(demo_jailer)

    # Compile the mini jailer.
    outcome = utils.run_cmd([demo_jailer, ls_command_path],
                            no_shell=True,
                            ignore_return_code=True)

    # The seccomp filters should send SIGSYS (31) to the binary. `ls` doesn't
    # handle it, so it will exit with error.
    assert outcome.returncode != 0


def test_advanced_seccomp_harmless(bin_seccomp_paths):
    """
    Test `demo_harmless`.

    Test that the advanced demo jailer allows the harmless demo binary.
    """
    # pylint: disable=redefined-outer-name
    # pylint: disable=subprocess-run-check
    # The fixture pattern causes a pylint false positive for that rule.

    demo_advanced_jailer = bin_seccomp_paths['demo_advanced_jailer']
    demo_harmless = bin_seccomp_paths['demo_harmless']

    assert os.path.exists(demo_advanced_jailer)
    assert os.path.exists(demo_harmless)

    outcome = utils.run_cmd([demo_advanced_jailer, demo_harmless],
                            no_shell=True,
                            ignore_return_code=True)

    # The demo harmless binary should have terminated gracefully.
    assert outcome.returncode == 0


def test_advanced_seccomp_malicious(bin_seccomp_paths):
    """
    Test `demo_malicious`.

    Test that the basic demo jailer denies the malicious demo binary.
    """
    # pylint: disable=redefined-outer-name
    # pylint: disable=subprocess-run-check
    # The fixture pattern causes a pylint false positive for that rule.

    demo_advanced_jailer = bin_seccomp_paths['demo_advanced_jailer']
    demo_malicious = bin_seccomp_paths['demo_malicious']

    assert os.path.exists(demo_advanced_jailer)
    assert os.path.exists(demo_malicious)

    outcome = utils.run_cmd([demo_advanced_jailer, demo_malicious],
                            no_shell=True,
                            ignore_return_code=True)

    # The demo malicious binary should have received `SIGSYS`.
    assert outcome.returncode == -31


def test_seccomp_applies_to_all_threads(test_microvm_with_api):
    """Test all Firecracker threads get default seccomp level 2."""
    test_microvm = test_microvm_with_api
    test_microvm.spawn()

    # Set up the microVM with 2 vCPUs, 256 MiB of RAM and
    # a root file system with the rw permission.
    test_microvm.basic_config()

    test_microvm.start()

    # Get Firecracker PID so we can count the number of threads.
    firecracker_pid = test_microvm.jailer_clone_pid

    # Get number of threads in Firecracker
    cmd = 'ps -T --no-headers -p {} | awk \'{{print $2}}\''.format(
        firecracker_pid
    )
    process = utils.run_cmd(cmd)
    threads_out_lines = process.stdout.splitlines()
    for tid in threads_out_lines:
        # Verify each Firecracker thread Seccomp status
        cmd = 'cat /proc/{}/status | grep Seccomp'.format(tid)
        process = utils.run_cmd(cmd)
        seccomp_line = ''.join(process.stdout.split())
        assert seccomp_line == "Seccomp:2"
