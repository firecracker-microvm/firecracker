# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that the seccomp filters don't let denied syscalls through."""

import json
import os
import platform
import time
from pathlib import Path

from framework import utils
from framework.artifacts import GUEST_KERNEL_DEFAULT, pin_guest_kernel

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


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_no_seccomp(uvm):
    """
    Test that Firecracker --no-seccomp installs no filter.
    """
    test_microvm = uvm
    test_microvm.jailer.extra_args.update({"no-seccomp": None})
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.start()
    utils.assert_seccomp_level(test_microvm.firecracker_pid, "0")


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_default_seccomp_level(uvm):
    """
    Test that Firecracker installs a seccomp filter by default.
    """
    test_microvm = uvm
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


ALL_SECCOMP_FEATURES = "api,pci,hotplug,block,async-io,net,vsock,pmem,memory-hotplug"


def _seccomp_features_log_line(features):
    """The log line reporting the seccomp features derived from the microVM."""
    return f"Seccomp features required by the microVM: [{features}]"


def _seccomp_filter_log_line(thread, features):
    """The log line reporting the filter a thread got, up to the feature set."""
    return f"Seccomp filter of the {thread} thread: ", f"features [{features}]"


def _check_filter_log_line(uvm, thread, features):
    """Check that `thread` got a filter composed with exactly `features`."""
    prefix, suffix = _seccomp_filter_log_line(thread, features)
    lines = [line for line in uvm.log_data.splitlines() if prefix in line]
    assert lines, f"no filter log line for the {thread} thread"
    assert all(line.endswith(suffix) for line in lines), lines


def _derived_features(uvm):
    """The features derived from the configuration `basic_config` sets up."""
    if uvm.pci_enabled:
        return "api,pci,hotplug,block,async-io,net,pmem"
    return "api,block"


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_seccomp_features_derived(uvm):
    """
    Test that Firecracker only enables the seccomp features a microVM uses.

    A microVM with just a root drive gets the API and block rules. With the
    PCI transport, devices can be hot-plugged, so every hot-pluggable device
    type is kept as well.
    """
    uvm.spawn()
    uvm.basic_config()
    uvm.start()
    expected = _derived_features(uvm)
    uvm.check_log_message(_seccomp_features_log_line(expected))
    assert "Seccomp features added by the command line" not in uvm.log_data
    for thread in ["vmm", "vcpu"]:
        _check_filter_log_line(uvm, thread, expected)
    # The API thread's filter is installed before the configuration is known.
    _check_filter_log_line(uvm, "api", "api")
    utils.assert_seccomp_level(uvm.firecracker_pid, "2")


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_seccomp_features_all(uvm):
    """
    Test that --seccomp-features all enables every feature on every thread.
    """
    uvm.jailer.extra_args.update({"seccomp-features": "all"})
    uvm.spawn()
    uvm.basic_config()
    uvm.start()
    uvm.check_log_message(_seccomp_features_log_line(_derived_features(uvm)))
    uvm.check_log_message(
        f"Seccomp features added by the command line: [{ALL_SECCOMP_FEATURES}]"
    )
    for thread in ["api", "vmm", "vcpu"]:
        _check_filter_log_line(uvm, thread, ALL_SECCOMP_FEATURES)
    utils.assert_seccomp_level(uvm.firecracker_pid, "2")


@pin_guest_kernel(GUEST_KERNEL_DEFAULT)
def test_seccomp_features_invalid(uvm):
    """
    Test that Firecracker refuses to start with an unknown seccomp feature.
    """
    uvm.jailer.extra_args.update({"seccomp-features": "net,warp-drive"})
    uvm.spawn(expect_failure=True)
    # give time for the process to exit
    time.sleep(1)
    assert (
        "Invalid value for seccomp-features: Unknown seccomp feature: warp-drive"
        in uvm.log_data
    )
    uvm.mark_killed()
