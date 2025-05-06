# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests to check several aspects of the binaries"""

import re
import subprocess

import pytest

from framework import utils


@pytest.mark.timeout(500)
def test_firecracker_binary_static_linking(microvm_factory):
    """
    Test to make sure the firecracker binary is statically linked.
    """
    fc_binary_path = microvm_factory.fc_binary_path
    _, stdout, stderr = utils.check_output(f"file {fc_binary_path}")
    assert "" in stderr
    # expected "statically linked" for aarch64 and
    # "static-pie linked" for x86_64
    assert "statically linked" in stdout or "static-pie linked" in stdout


def test_release_debuginfo(microvm_factory):
    """Ensure the debuginfo file has the right ELF sections"""
    fc_binary = microvm_factory.fc_binary_path
    debuginfo = fc_binary.with_suffix(".debug")
    stdout = subprocess.check_output(
        ["readelf", "-S", str(debuginfo)],
        encoding="ascii",
    )
    matches = {
        match[0] for match in re.findall(r"\[..] (\.(\w|\.)+)", stdout, re.MULTILINE)
    }
    needed_sections = {
        ".debug_aranges",
        ".debug_info",
        ".debug_abbrev",
        ".debug_line",
        ".debug_frame",
        ".debug_str",
        ".debug_ranges",
    }
    missing_sections = needed_sections - matches
    assert missing_sections == set()


def test_release_no_gdb(microvm_factory):
    """Ensure the gdb feature is not enabled in releases"""
    fc_binary = microvm_factory.fc_binary_path
    # We use C++ demangle since there's no Rust support, but it's good enough
    # for our purposes.
    stdout = subprocess.check_output(
        ["readelf", "-W", "--demangle", "-s", str(fc_binary)],
        encoding="ascii",
    )
    gdb_symbols = []
    for line in stdout.splitlines():
        parts = line.split(maxsplit=7)
        if len(parts) == 8:
            symbol_name = parts[-1]
            if "gdb" in symbol_name:
                gdb_symbols.append(symbol_name)
    assert not gdb_symbols
