# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that the seccomp filters don't let denied syscalls through."""

import json as json_lib
import os
import platform
import tempfile

from framework import utils
from host_tools.cargo_build import run_seccompiler_bin


def _get_basic_syscall_list():
    """Return the JSON list of syscalls that the demo jailer needs."""
    if platform.machine() == "x86_64":
        sys_list = [
            "rt_sigprocmask",
            "rt_sigaction",
            "execve",
            "mmap",
            "mprotect",
            "arch_prctl",
            "set_tid_address",
            "readlink",
            "open",
            "read",
            "close",
            "brk",
            "sched_getaffinity",
            "sigaltstack",
            "munmap",
            "exit_group",
            "poll",
        ]
    else:
        # platform.machine() == "aarch64"
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
            "ppoll",
        ]

    json = ""
    for syscall in sys_list[0:-1]:
        json += """
            {{
                "syscall": \"{}\"
            }},
        """.format(
            syscall
        )

    json += """
        {{
            "syscall": \"{}\"
        }}
    """.format(
        sys_list[-1]
    )

    return json


def _run_seccompiler_bin(json_data, basic=False):
    json_temp = tempfile.NamedTemporaryFile(delete=False)
    json_temp.write(json_data.encode("utf-8"))
    json_temp.flush()

    bpf_temp = tempfile.NamedTemporaryFile(delete=False)

    run_seccompiler_bin(bpf_path=bpf_temp.name, json_path=json_temp.name, basic=basic)

    os.unlink(json_temp.name)
    return bpf_temp.name


def test_seccomp_ls(bin_seccomp_paths):
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

    json_filter = """{{
        "main": {{
            "default_action": "trap",
            "filter_action": "allow",
            "filter": [
                {}
            ]
        }}
    }}""".format(
        _get_basic_syscall_list()
    )

    # Run seccompiler-bin.
    bpf_path = _run_seccompiler_bin(json_filter)

    # Run the mini jailer.
    outcome = utils.run_cmd([demo_jailer, ls_command_path, bpf_path], shell=False)

    os.unlink(bpf_path)

    # The seccomp filters should send SIGSYS (31) to the binary. `ls` doesn't
    # handle it, so it will exit with error.
    assert outcome.returncode != 0


def test_advanced_seccomp(bin_seccomp_paths):
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

    json_filter = """{{
        "main": {{
            "default_action": "trap",
            "filter_action": "allow",
            "filter": [
                {},
                {{
                    "syscall": "write",
                    "args": [
                        {{
                            "index": 0,
                            "type": "dword",
                            "op": "eq",
                            "val": 1,
                            "comment": "stdout fd"
                        }},
                        {{
                            "index": 2,
                            "type": "qword",
                            "op": "eq",
                            "val": 14,
                            "comment": "nr of bytes"
                        }}
                    ]
                }}
            ]
        }}
    }}""".format(
        _get_basic_syscall_list()
    )

    # Run seccompiler-bin.
    bpf_path = _run_seccompiler_bin(json_filter)

    # Run the mini jailer for harmless binary.
    outcome = utils.run_cmd([demo_jailer, demo_harmless, bpf_path], shell=False)

    # The demo harmless binary should have terminated gracefully.
    assert outcome.returncode == 0

    # Run the mini jailer for malicious binary.
    outcome = utils.run_cmd([demo_jailer, demo_malicious, bpf_path], shell=False)

    # The demo malicious binary should have received `SIGSYS`.
    assert outcome.returncode == -31

    os.unlink(bpf_path)

    # Run seccompiler-bin with `--basic` flag.
    bpf_path = _run_seccompiler_bin(json_filter, basic=True)

    # Run the mini jailer for malicious binary.
    outcome = utils.run_cmd([demo_jailer, demo_malicious, bpf_path], shell=False)

    # The malicious binary also terminates gracefully, since the --basic option
    # disables all argument checks.
    assert outcome.returncode == 0

    os.unlink(bpf_path)

    # Run the mini jailer with an empty allowlist. It should trap on any
    # syscall.
    json_filter = """{
        "main": {
            "default_action": "trap",
            "filter_action": "allow",
            "filter": []
        }
    }"""

    # Run seccompiler-bin.
    bpf_path = _run_seccompiler_bin(json_filter)

    outcome = utils.run_cmd([demo_jailer, demo_harmless, bpf_path], shell=False)

    # The demo binary should have received `SIGSYS`.
    assert outcome.returncode == -31

    os.unlink(bpf_path)


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


def test_seccomp_rust_panic(bin_seccomp_paths):
    """
    Test seccompiler-bin with `demo_panic`.

    Test that the Firecracker filters allow a Rust panic to run its
    course without triggering a seccomp violation.
    """
    # pylint: disable=subprocess-run-check
    # The fixture pattern causes a pylint false positive for that rule.

    demo_panic = bin_seccomp_paths["demo_panic"]
    assert os.path.exists(demo_panic)

    fc_filters_path = "../resources/seccomp/{}-unknown-linux-musl.json".format(
        platform.machine()
    )
    with open(fc_filters_path, "r", encoding="utf-8") as fc_filters:
        filter_threads = list(json_lib.loads(fc_filters.read()))

    bpf_temp = tempfile.NamedTemporaryFile(delete=False)
    run_seccompiler_bin(bpf_path=bpf_temp.name, json_path=fc_filters_path)
    bpf_path = bpf_temp.name

    # Run the panic binary with all filters.
    for thread in filter_threads:
        code, _, _ = utils.run_cmd([demo_panic, bpf_path, thread], shell=False)
        # The demo panic binary should have terminated with SIGABRT
        # and not with a seccomp violation.
        # On a seccomp violation, the program exits with code -31 for
        # SIGSYS. Here, we make sure the program exits with -6, which
        # is for SIGABRT.
        assert (
            code == -6
        ), "Panic binary failed with exit code {} on {} " "filters.".format(
            code, thread
        )

    os.unlink(bpf_path)
