# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A test that fails if it can definitely prove a seccomp rule redundant
(although it passing does not guarantee the converse, that all rules are definitely needed).
"""
import platform
from pathlib import Path

from framework import utils
from framework.static_analysis import (
    determine_unneeded_seccomp_rules,
    find_syscalls_in_binary,
    load_seccomp_rules,
)


def test_redundant_seccomp_rules():
    """Test that fails if static analysis determines redundant seccomp rules"""
    arch = platform.processor()

    nightly_toolchain = utils.check_output(
        "rustup toolchain list | grep nightly"
    ).stdout.strip()
    target = f"{arch}-unknown-linux-musl"

    utils.check_output(
        f'RUSTFLAGS="-C relocation-model=static -C link-args=-no-pie" cargo +{nightly_toolchain} -Zbuild-std=panic_abort,std build --release --target {target} -p firecracker'
    )

    found_syscalls = find_syscalls_in_binary(
        Path(f"../build/cargo_target/{target}/release/firecracker")
    )

    seccomp_rules = load_seccomp_rules(Path(f"../resources/seccomp/{target}.json"))

    redundant_rules = determine_unneeded_seccomp_rules(seccomp_rules, found_syscalls)

    assert not redundant_rules, f"Found redundant seccomp rules! {redundant_rules}"
