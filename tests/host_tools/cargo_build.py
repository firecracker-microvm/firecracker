# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functionality for a shared binary build and release path for all tests."""

import os
import platform
from pathlib import Path

from framework import defs, utils
from framework.defs import (
    FC_BINARY_NAME,
    FC_WORKSPACE_DIR,
    FC_WORKSPACE_TARGET_DIR,
    JAILER_BINARY_NAME,
)
from framework.with_filelock import with_filelock

CARGO_BUILD_REL_PATH = "firecracker_binaries"
"""Keep a single build path across all build tests."""

CARGO_RELEASE_REL_PATH = os.path.join(CARGO_BUILD_REL_PATH, "release")
"""Keep a single Firecracker release binary path across all test types."""


DEFAULT_BUILD_TARGET = "{}-unknown-linux-musl".format(platform.machine())
RELEASE_BINARIES_REL_PATH = "{}/release/".format(DEFAULT_BUILD_TARGET)

CARGO_UNITTEST_REL_PATH = os.path.join(CARGO_BUILD_REL_PATH, "test")


def cargo(
    subcommand,
    cargo_args: str = "",
    subcommand_args: str = "",
    *,
    env: dict = None,
    cwd: str = None,
):
    """Executes the specified cargo subcommand"""
    env = env or {}

    env_string = " ".join(f'{key}="{str(value)}"' for key, value in env.items())

    cmd = f"{env_string} cargo {subcommand} {cargo_args} -- {subcommand_args}"

    return utils.run_cmd(cmd, cwd=cwd)


@with_filelock
def cargo_build(path, extra_args="", src_dir=""):
    """Trigger build depending on flags provided."""
    cargo("build", extra_args, env={"CARGO_TARGET_DIR": path}, cwd=src_dir)


def cargo_test(path, extra_args=""):
    """Trigger unit tests depending on flags provided."""
    env = {
        "CARGO_TARGET_DIR": os.path.join(path, CARGO_UNITTEST_REL_PATH),
        "RUST_TEST_THREADS": 1,
        "RUST_BACKTRACE": 1,
        "RUSTFLAGS": get_rustflags(),
    }
    cargo("test", extra_args + " --all --no-fail-fast", env=env)


@with_filelock
def get_firecracker_binaries():
    """Build the Firecracker and Jailer binaries if they don't exist.

    Returns the location of the firecracker related binaries eventually after
    building them in case they do not exist at the specified root_path.
    """
    target = DEFAULT_BUILD_TARGET
    target_dir = FC_WORKSPACE_TARGET_DIR
    out_dir = Path(f"{target_dir}/{target}/release")
    fc_bin_path = out_dir / FC_BINARY_NAME
    jailer_bin_path = out_dir / JAILER_BINARY_NAME

    if not fc_bin_path.exists():
        env = {"RUSTFLAGS": get_rustflags()}

        cargo("build", f"--release --target {target}", env=env, cwd=FC_WORKSPACE_DIR)
        cargo(
            "build",
            f"-p jailer --release --target {target}",
            env=env,
            cwd=FC_WORKSPACE_DIR,
        )

        utils.run_cmd(f"strip --strip-debug {fc_bin_path} {jailer_bin_path}")

    return fc_bin_path, jailer_bin_path


def get_rustflags():
    """Get the relevant rustflags for building/unit testing."""
    rustflags = "-D warnings"
    if platform.machine() == "aarch64":
        rustflags += " -C link-arg=-lgcc -C link-arg=-lfdt "
    return rustflags


@with_filelock
def run_seccompiler_bin(bpf_path, json_path=defs.SECCOMP_JSON_DIR, basic=False):
    """
    Run seccompiler-bin.

    :param bpf_path: path to the output file
    :param json_path: optional path to json file
    """
    cargo_target = "{}-unknown-linux-musl".format(platform.machine())

    # If no custom json filter, use the default one for the current target.
    if json_path == defs.SECCOMP_JSON_DIR:
        json_path = json_path / "{}.json".format(cargo_target)

    seccompiler_args = f"--input-file {json_path} --target-arch {platform.machine()} --output-file {bpf_path}"

    if basic:
        seccompiler_args += " --basic"

    rc, _, _ = cargo(
        "run",
        f"-p seccompiler --target-dir {defs.SECCOMPILER_TARGET_DIR} --target {cargo_target}",
        seccompiler_args,
    )

    assert rc == 0


@with_filelock
def run_rebase_snap_bin(base_snap, diff_snap):
    """
    Run apply_diff_snap.

    :param base_snap: path to the base snapshot mem file
    :param diff_snap: path to diff snapshot mem file
    """
    cargo_target = "{}-unknown-linux-musl".format(platform.machine())

    rc, _, _ = cargo(
        "run",
        f"-p rebase-snap --target {cargo_target}",
        f"--base-file {base_snap} --diff-file {diff_snap}",
    )

    assert rc == 0
