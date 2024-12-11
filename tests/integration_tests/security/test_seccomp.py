# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that the seccomp filters don't let denied syscalls through."""

import json
import os
import platform
from pathlib import Path

from framework import utils

ARCH = platform.machine()


def _get_basic_syscall_list():
    """Return the JSON list of syscalls that the demo jailer needs."""
    sys_list = [
        "rt_sigprocmask",
        "rt_sigaction",
        "execve",
        "mmap",
        "mprotect",
        "set_tid_address",
        "read",
        "close",
        "brk",
        "sched_getaffinity",
        "sigaltstack",
        "munmap",
        "exit_group",
    ]
    if ARCH == "x86_64":
        sys_list += [
            "arch_prctl",
            "readlink",
            "open",
            "poll",
        ]
    elif ARCH == "aarch64":
        sys_list += ["ppoll"]

    return sys_list


def test_seccomp_ls(bin_seccomp_paths, seccompiler):
    """
    Assert that the seccomp filter denies an unallowed syscall.
    """
    # pylint: disable=subprocess-run-check
    # The fixture pattern causes a pylint false positive for that rule.

    # Path to the `ls` binary, which attempts to execute the forbidden
    # `SYS_access`.
    ls_command_path = "/bin/ls"
    demo_jailer = bin_seccomp_paths["demo_jailer"]
    assert os.path.exists(demo_jailer)

    json_filter = {
        "main": {
            "default_action": "trap",
            "filter_action": "allow",
            "filter": [{"syscall": x} for x in _get_basic_syscall_list()],
        }
    }

    # Run seccompiler-bin.
    bpf_path = seccompiler.compile(json_filter)

    # Run the mini jailer.
    outcome = utils.run_cmd([demo_jailer, ls_command_path, bpf_path], shell=False)

    # The seccomp filters should send SIGSYS (31) to the binary. `ls` doesn't
    # handle it, so it will exit with error.
    assert outcome.returncode != 0


def test_advanced_seccomp(bin_seccomp_paths, seccompiler):
    """
    Test seccompiler-bin with `demo_jailer`.

    Test that the demo jailer (with advanced seccomp) allows the harmless demo
    binary, denies the malicious demo binary and that an empty allowlist
    denies everything.
    """
    # pylint: disable=subprocess-run-check
    # The fixture pattern causes a pylint false positive for that rule.

    demo_jailer = bin_seccomp_paths["demo_jailer"]
    demo_harmless = bin_seccomp_paths["demo_harmless"]
    demo_malicious = bin_seccomp_paths["demo_malicious"]

    assert os.path.exists(demo_jailer)
    assert os.path.exists(demo_harmless)
    assert os.path.exists(demo_malicious)

    json_filter = {
        "main": {
            "default_action": "trap",
            "filter_action": "allow",
            "filter": [
                *[{"syscall": x} for x in _get_basic_syscall_list()],
                {
                    "syscall": "write",
                    "args": [
                        {
                            "index": 0,
                            "type": "dword",
                            "op": "eq",
                            "val": 1,
                            "comment": "stdout fd",
                        },
                        {
                            "index": 2,
                            "type": "qword",
                            "op": "eq",
                            "val": 14,
                            "comment": "nr of bytes",
                        },
                    ],
                },
            ],
        }
    }

    # Run seccompiler-bin.
    bpf_path = seccompiler.compile(json_filter)

    # Run the mini jailer for harmless binary.
    outcome = utils.run_cmd([demo_jailer, demo_harmless, bpf_path], shell=False)

    # The demo harmless binary should have terminated gracefully.
    assert outcome.returncode == 0

    # Run the mini jailer for malicious binary.
    outcome = utils.run_cmd([demo_jailer, demo_malicious, bpf_path], shell=False)

    # The demo malicious binary should have received `SIGSYS`.
    assert outcome.returncode == -31

    # Run seccompiler-bin with `--basic` flag.
    bpf_path = seccompiler.compile(json_filter, basic=True)

    # Run the mini jailer for malicious binary.
    outcome = utils.run_cmd([demo_jailer, demo_malicious, bpf_path], shell=False)

    # The malicious binary also terminates gracefully, since the --basic option
    # disables all argument checks.
    assert outcome.returncode == 0

    # Run the mini jailer with an empty allowlist. It should trap on any
    # syscall.
    json_filter = {
        "main": {"default_action": "trap", "filter_action": "allow", "filter": []}
    }

    # Run seccompiler-bin.
    bpf_path = seccompiler.compile(json_filter)

    outcome = utils.run_cmd([demo_jailer, demo_harmless, bpf_path], shell=False)

    # The demo binary should have received `SIGSYS`.
    assert outcome.returncode == -31


def test_no_seccomp(uvm_plain):
    """
    Test that Firecracker --no-seccomp installs no filter.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.extra_args.update({"no-seccomp": None})
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.start()
    utils.assert_seccomp_level(test_microvm.firecracker_pid, "0")


def test_default_seccomp_level(uvm_plain):
    """
    Test that Firecracker installs a seccomp filter by default.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.start()
    utils.assert_seccomp_level(test_microvm.firecracker_pid, "2")


def test_seccomp_rust_panic(bin_seccomp_paths, seccompiler):
    """
    Test seccompiler-bin with `demo_panic`.

    Test that the Firecracker filters allow a Rust panic to run its
    course without triggering a seccomp violation.
    """
    # pylint: disable=subprocess-run-check
    # The fixture pattern causes a pylint false positive for that rule.

    demo_panic = bin_seccomp_paths["demo_panic"]
    assert os.path.exists(demo_panic)

    fc_filters = Path(f"../resources/seccomp/{ARCH}-unknown-linux-musl.json")
    fc_filters_data = json.loads(fc_filters.read_text(encoding="ascii"))
    filter_threads = list(fc_filters_data)

    bpf_path = seccompiler.compile(fc_filters_data)

    # Run the panic binary with all filters.
    for thread in filter_threads:
        code, _, _ = utils.run_cmd([demo_panic, str(bpf_path), thread], shell=False)
        # The demo panic binary should have terminated with SIGABRT
        # and not with a seccomp violation.
        # On a seccomp violation, the program exits with code -31 for
        # SIGSYS. Here, we make sure the program exits with -6, which
        # is for SIGABRT.
        assert (
            code == -6
        ), f"Panic binary failed with exit code {code} on {thread} filters."
