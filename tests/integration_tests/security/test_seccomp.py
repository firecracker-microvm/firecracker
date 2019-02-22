# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that the seccomp filters don't let blacklisted syscalls through."""

import os

from subprocess import run, PIPE

import pytest

import host_tools.cargo_build as host  # pylint:disable=import-error


@pytest.fixture(scope='session')
def seccomp_test_binaries(test_session_root_path):
    """Build the demo jailers and binaries required for the seccomp tests.

    :return: The paths of the built binaries.
    """
    binaries_srcdir = os.path.normpath(
        os.path.join(
            os.getcwd(),
            'integration_tests/security/demo_seccomp/'
        )
    )
    build_path = os.path.join(
        test_session_root_path,
        host.CARGO_RELEASE_REL_PATH
    )
    run("cd {} && CARGO_TARGET_DIR={} cargo build --release".format(
        binaries_srcdir, build_path), shell=True, check=True)

    release_binaries_path = os.path.join(
        host.CARGO_RELEASE_REL_PATH,
        host.RELEASE_BINARIES_REL_PATH
    )
    release_binaries_path = os.path.join(
        test_session_root_path,
        release_binaries_path
    )
    demo_basic_jailer = os.path.normpath(
        os.path.join(
            release_binaries_path,
            'demo_basic_jailer'
        )
    )
    demo_advanced_jailer = os.path.normpath(
        os.path.join(
            release_binaries_path,
            'demo_advanced_jailer'
        )
    )
    demo_harmless_firecracker = os.path.normpath(
        os.path.join(
            release_binaries_path,
            'demo_harmless_firecracker'
        )
    )
    demo_malicious_firecracker = os.path.normpath(
        os.path.join(
            release_binaries_path,
            'demo_malicious_firecracker'
        )
    )

    yield \
        demo_basic_jailer, \
        demo_advanced_jailer, \
        demo_harmless_firecracker, \
        demo_malicious_firecracker

    os.remove(demo_basic_jailer)
    os.remove(demo_advanced_jailer)
    os.remove(demo_harmless_firecracker)
    os.remove(demo_malicious_firecracker)


def test_seccomp_ls(seccomp_test_binaries):
    """Assert that the seccomp filters deny a blacklisted syscall."""
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.

    # Path to the `ls` binary, which attempts to execute `SYS_access`,
    # blacklisted for Firecracker.
    ls_command_path = '/bin/ls'
    demo_jailer, _, _, _ = seccomp_test_binaries

    assert os.path.exists(demo_jailer)

    # Compile the mini jailer.
    outcome = run([demo_jailer, ls_command_path])

    # The seccomp filters should send SIGSYS (31) to the binary. `ls` doesn't
    # handle it, so it will exit with error.
    assert outcome.returncode != 0


def test_advanced_seccomp_harmless(seccomp_test_binaries):
    """
    Test `demo_harmless_firecracker`.

    Test that the built demo jailer allows the built demo harmless firecracker.
    """
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.

    _, demo_advanced_jailer, demo_harmless_firecracker, _ = \
        seccomp_test_binaries

    assert os.path.exists(demo_advanced_jailer)
    assert os.path.exists(demo_harmless_firecracker)

    outcome = run([demo_advanced_jailer, demo_harmless_firecracker])

    # The demo harmless firecracker should have terminated gracefully.
    assert outcome.returncode == 0


def test_advanced_seccomp_malicious(seccomp_test_binaries):
    """
    Test `demo_malicious_firecracker`.

    Test that the built demo jailer denies the built demo malicious
    firecracker.
    """
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.

    _, demo_advanced_jailer, _, demo_malicious_firecracker = \
        seccomp_test_binaries

    assert os.path.exists(demo_advanced_jailer)
    assert os.path.exists(demo_malicious_firecracker)

    outcome = run([demo_advanced_jailer, demo_malicious_firecracker])

    # The demo malicious firecracker should have received `SIGSYS`.
    assert outcome.returncode != 0


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
    process = run(cmd, stdout=PIPE, stderr=PIPE, shell=True, check=True)
    threads_out_lines = process.stdout.decode('utf-8').splitlines()
    for tid in threads_out_lines:
        # Verify each Firecracker thread Seccomp status
        cmd = 'cat /proc/{}/status | grep Seccomp'.format(tid)
        process = run(cmd, stdout=PIPE, stderr=PIPE, shell=True, check=True)
        seccomp_line = ''.join(process.stdout.decode('utf-8').split())
        assert seccomp_line == "Seccomp:2"
