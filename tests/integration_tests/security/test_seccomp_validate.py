# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Test that validates that seccompiler filters work as expected"""

import json
import platform
import resource
from pathlib import Path

import pytest
import seccomp

from framework import utils

ARCH = platform.machine()

FC_FILTER_PATH = Path(f"../resources/seccomp/{ARCH}-unknown-linux-musl.json")
FILTER_THREADS = list(json.loads(FC_FILTER_PATH.read_text(encoding="ascii")))


@pytest.fixture
def bin_test_syscall(tmp_path):
    """Build the test_syscall binary."""
    test_syscall_bin = tmp_path / "test_syscall"
    compile_cmd = f"musl-gcc -static host_tools/test_syscalls.c -o {test_syscall_bin}"
    utils.check_output(compile_cmd)
    assert test_syscall_bin.exists()
    yield test_syscall_bin.resolve()


@pytest.mark.parametrize("thread", FILTER_THREADS)
def test_validate_filter(seccompiler, bin_test_syscall, monkeypatch, tmp_path, thread):
    """Assert that the seccomp filter for one thread matches the JSON description."""

    fc_filter = json.loads(FC_FILTER_PATH.read_text(encoding="ascii"))

    # cd to a tmp dir because we may generate a bunch of intermediate files
    monkeypatch.chdir(tmp_path)
    # prevent coredumps
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    seccompiler.compile(fc_filter, split_output=True)

    # With split_output=True, individual .bpf files are created for each thread
    arch = seccomp.Arch.X86_64 if ARCH == "x86_64" else seccomp.Arch.AARCH64
    filter_data = fc_filter[thread]
    filter_path = Path(f"{thread}.bpf")
    assert filter_path.exists(), f"Expected {filter_path} to be created by seccompiler"

    # for each rule, run the helper program and execute a syscall
    for rule in filter_data["filter"]:
        print(filter_path, rule)
        syscall = rule["syscall"]
        # this one cannot be called directly
        if syscall in ["rt_sigreturn"]:
            continue
        syscall_id = seccomp.resolve_syscall(arch, syscall)
        cmd = f"{bin_test_syscall} {filter_path} {syscall_id}"
        if "args" not in rule:
            # syscall should be allowed with any arguments and exit 0
            assert utils.run_cmd(cmd).returncode == 0
        else:
            allowed_args = [0] * 4
            # if we call it with allowed args, it should exit 0
            for arg in rule["args"]:
                allowed_args[arg["index"]] = arg["val"]
            allowed_str = " ".join(str(x) for x in allowed_args)
            assert utils.run_cmd(f"{cmd} {allowed_str}").returncode == 0
            # for each allowed arg try a different number
            for arg in rule["args"]:
                bad_args = allowed_args.copy()
                if isinstance(arg["op"], dict) and "masked_eq" in arg["op"]:
                    # For masked_eq, flip the mask bit to violate the check
                    bad_args[arg["index"]] = str(arg["val"] ^ arg["op"]["masked_eq"])
                else:
                    # We just add 1000000 to the allowed arg and assume it
                    # is not something we allow in another rule. While not
                    # perfect it works in practice.
                    bad_args[arg["index"]] = str(arg["val"] + 1_000_000)
                unallowed_str = " ".join(str(x) for x in bad_args)
                outcome = utils.run_cmd(f"{cmd} {unallowed_str}")
                # if we call it with unallowed args, it should exit 159
                # 159 = 128 (abnormal termination) + 31 (SIGSYS)
                assert outcome.returncode == 159


def _rule_features(rule):
    """The feature tags of a rule, empty for an always-on rule."""
    features = rule.get("features", rule.get("feature", []))
    return [features] if isinstance(features, str) else features


def _rule_args(rule):
    """Seed a syscall probe with the values mentioned by its argument conditions."""
    args = [0] * 4
    for arg in rule.get("args", []):
        args[arg["index"]] = arg["val"]
    return args


def _selected_rules(rules, enabled):
    """Select rules for a monolithic reference filter, removing their feature tags."""
    return [
        {
            key: value
            for key, value in rule.items()
            if key not in ("feature", "features")
        }
        for rule in rules
        if not _rule_features(rule) or enabled.intersection(_rule_features(rule))
    ]


@pytest.mark.parametrize("thread", [*FILTER_THREADS, "overlapping"])
def test_validate_feature_gating(
    seccompiler, bin_test_syscall, monkeypatch, tmp_path, thread
):
    """
    Compare composed filters with monolithic filters of the selected rules.

    The kernel evaluates argument conditions and overlapping rules in both
    programs, including rules enabled by different features.
    """

    fc_filter = json.loads(FC_FILTER_PATH.read_text(encoding="ascii"))
    fc_filter["overlapping"] = {
        "default_action": "trap",
        "filter_action": "allow",
        "filter": [
            {"syscall": "exit_group"},
            {"syscall": "write"},
            {"syscall": "getpid", "feature": "net"},
            {"syscall": "getpid", "features": ["block"]},
            {
                "syscall": "ioctl",
                "args": [
                    {
                        "index": 1,
                        "type": "dword",
                        "op": {"masked_eq": 0xFF},
                        "val": 0x12,
                    }
                ],
            },
            {
                "syscall": "ioctl",
                "feature": "pmem",
                "args": [{"index": 1, "type": "dword", "op": "eq", "val": 0x112}],
            },
        ],
    }
    filter_data = fc_filter[thread]
    fc_filter = {thread: filter_data}

    # cd to a tmp dir because we may generate a bunch of intermediate files
    monkeypatch.chdir(tmp_path)
    # prevent coredumps
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    arch = seccomp.Arch.X86_64 if ARCH == "x86_64" else seccomp.Arch.AARCH64
    # this one cannot be called directly
    rules = [
        rule
        for rule in filter_data["filter"]
        if rule["syscall"] not in ["rt_sigreturn"]
    ]
    features = sorted({feature for rule in rules for feature in _rule_features(rule)})
    filter_path = Path(f"{thread}.bpf")
    reference_path = tmp_path / f"{thread}-monolithic.bpf"

    def run(path, rule):
        syscall_id = seccomp.resolve_syscall(arch, rule["syscall"])
        args = " ".join(str(x) for x in _rule_args(rule))
        return utils.run_cmd(f"{bin_test_syscall} {path} {syscall_id} {args}")

    def check(enabled):
        reference = {
            **filter_data,
            "filter": _selected_rules(filter_data["filter"], enabled),
        }
        seccompiler.compile({thread: reference}, split_output=True)
        filter_path.rename(reference_path)
        selected = ",".join(sorted(enabled)) or "none"
        seccompiler.compile(fc_filter, split_output=True, features=selected)
        for rule in rules:
            expected = run(reference_path, rule).returncode
            # 159 = 128 (abnormal termination) + 31 (SIGSYS)
            assert expected in (0, 159), (selected, rule)
            assert run(filter_path, rule).returncode == expected, (selected, rule)

    check(set())
    for feature in features:
        check({feature})
    if len(features) > 1:
        check(set(features))
