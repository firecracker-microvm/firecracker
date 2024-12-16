# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Test that validates that seccompiler filters work as expected"""

import json
import platform
import resource
import struct
from pathlib import Path

import pytest
import seccomp

from framework import utils

ARCH = platform.machine()


@pytest.fixture
def bin_test_syscall(tmp_path):
    """Build the test_syscall binary."""
    test_syscall_bin = tmp_path / "test_syscall"
    compile_cmd = f"musl-gcc -static host_tools/test_syscalls.c -o {test_syscall_bin}"
    utils.check_output(compile_cmd)
    assert test_syscall_bin.exists()
    yield test_syscall_bin.resolve()


class BpfMapReader:
    """
    Simple reader for the files that seccompiler-bin produces

    The files are serialized with bincode[1] in format that is easy to parse.

        sock_filter = <ushort uchar uchar uint>
        BpfProgram = Vec<sock_filter>
        BpfMap = BTreeMap(str, BpfProgram)
        str = Vec<uchar>

    [1] https://github.com/bincode-org/bincode/blob/trunk/docs/spec.md
    """

    INSN_FMT = "<HBBI"
    INSN_SIZEOF = struct.calcsize(INSN_FMT)

    def __init__(self, buf):
        self.buf = buf
        self.offset = 0

    @classmethod
    def from_file(cls, file):
        """Initialize a buffer from a file"""
        return cls(Path(file).read_bytes())

    def read_format(self, fmt):
        """Read a struct format string from the buffer"""
        val = struct.unpack_from(fmt, self.buf, offset=self.offset)
        self.offset += struct.calcsize(fmt)
        if len(val) == 1:
            return val[0]
        return val

    def is_eof(self):
        """Are we at the end of the buffer?"""
        return self.offset == len(self.buf)

    def lookahead(self, size):
        """Look ahead `size` bytes"""
        return self.buf[self.offset : self.offset + size]

    def split(self):
        """Return separate filters"""
        threads = {}
        # how many entries in the map
        map_len = self.read_format("<Q")
        for _ in range(map_len):
            # read key
            key_str_len = self.read_format("<Q")
            key_str = self.read_format(f"{key_str_len}s").decode("ascii")
            # read value: vec of instructions
            insn_len = self.read_format("<Q")
            data = self.lookahead(insn_len * self.INSN_SIZEOF)
            threads[key_str] = data
            self.offset += len(data)

        assert self.is_eof()
        return threads


def test_validate_filter(seccompiler, bin_test_syscall, monkeypatch, tmp_path):
    """Assert that the seccomp filter matches the JSON description."""

    fc_filter_path = Path(f"../resources/seccomp/{ARCH}-unknown-linux-musl.json")
    fc_filter = json.loads(fc_filter_path.read_text(encoding="ascii"))

    # cd to a tmp dir because we may generate a bunch of intermediate files
    monkeypatch.chdir(tmp_path)
    # prevent coredumps
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    bpf_path = seccompiler.compile(fc_filter)
    filters = BpfMapReader.from_file(bpf_path).split()
    arch = seccomp.Arch.X86_64 if ARCH == "x86_64" else seccomp.Arch.AARCH64
    for thread, filter_data in fc_filter.items():
        filter_path = Path(f"{thread}.bpf")
        filter_path.write_bytes(filters[thread])
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
                    # We just add 1000000 to the allowed arg and assume it is
                    # not something we allow in another rule. While not perfect
                    # it works in practice.
                    bad_args = allowed_args.copy()
                    bad_args[arg["index"]] = str(arg["val"] + 1_000_000)
                    unallowed_str = " ".join(str(x) for x in bad_args)
                    outcome = utils.run_cmd(f"{cmd} {unallowed_str}")
                    # if we call it with unallowed args, it should exit 159
                    # 159 = 128 (abnormal termination) + 31 (SIGSYS)
                    assert outcome.returncode == 159
