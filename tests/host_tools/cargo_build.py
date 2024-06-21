# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functionality for a shared binary build and release path for all tests."""

import os
import platform
from pathlib import Path

from framework import defs, utils
from framework.defs import FC_WORKSPACE_DIR
from framework.with_filelock import with_filelock

DEFAULT_TARGET = f"{platform.machine()}-unknown-linux-musl"
DEFAULT_TARGET_DIR = f"{DEFAULT_TARGET}/release/"


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
    return utils.check_output(cmd, cwd=cwd)


def get_rustflags():
    """Get the relevant rustflags for building/unit testing."""
    if platform.machine() == "aarch64":
        return "-C link-arg=-lgcc -C link-arg=-lfdt "
    return ""


def cargo_test(path, extra_args=""):
    """Trigger unit tests depending on flags provided."""
    env = {
        "CARGO_TARGET_DIR": os.path.join(path, "unit-tests"),
        "RUST_TEST_THREADS": 1,
        "RUST_BACKTRACE": 1,
        "RUSTFLAGS": get_rustflags(),
    }
    cargo("test", extra_args + " --all --no-fail-fast", env=env)


def get_binary(name, *, workspace_dir=FC_WORKSPACE_DIR, example=None):
    """Get a binary. The binaries are built before starting a testrun."""
    target_dir = workspace_dir / "build" / "cargo_target" / DEFAULT_TARGET_DIR
    bin_path = target_dir / name
    if example:
        bin_path = target_dir / "examples" / example
    return bin_path


def get_firecracker_binaries(*, workspace_dir=FC_WORKSPACE_DIR):
    """Build the Firecracker and Jailer binaries if they don't exist.

    Returns the location of the firecracker related binaries eventually after
    building them in case they do not exist at the specified root_path.
    """
    return get_binary("firecracker", workspace_dir=workspace_dir), get_binary(
        "jailer", workspace_dir=workspace_dir
    )


def get_example(name, *args, package="firecracker", **kwargs):
    """Build an example binary"""
    return get_binary(package, *args, **kwargs, example=name)


def run_seccompiler_bin(bpf_path, json_path=defs.SECCOMP_JSON_DIR, basic=False):
    """
    Run seccompiler-bin.

    :param bpf_path: path to the output file
    :param json_path: optional path to json file
    """
    # If no custom json filter, use the default one for the current target.
    if json_path == defs.SECCOMP_JSON_DIR:
        json_path = json_path / f"{DEFAULT_TARGET}.json"

    seccompiler_args = f"--input-file {json_path} --target-arch {platform.machine()} --output-file {bpf_path}"

    if basic:
        seccompiler_args += " --basic"

    seccompiler = get_binary("seccompiler-bin")
    utils.check_output(f"{seccompiler} {seccompiler_args}")


def run_snap_editor_rebase(base_snap, diff_snap):
    """
    Run apply_diff_snap.

    :param base_snap: path to the base snapshot mem file
    :param diff_snap: path to diff snapshot mem file
    """

    snap_ed = get_binary("snapshot-editor")
    utils.check_output(
        f"{snap_ed} edit-memory rebase --memory-path {base_snap} --diff-path {diff_snap}"
    )


def run_rebase_snap_bin(base_snap, diff_snap):
    """
    Run apply_diff_snap.

    :param base_snap: path to the base snapshot mem file
    :param diff_snap: path to diff snapshot mem file
    """
    rebase_snap = get_binary("rebase-snap")
    utils.check_output(f"{rebase_snap} --base-file {base_snap} --diff-file {diff_snap}")


@with_filelock
def gcc_compile(src_file, output_file, extra_flags="-static -O3"):
    """Build a source file with gcc."""
    output_file = Path(output_file)
    if not output_file.exists():
        compile_cmd = f"gcc {src_file} -o {output_file} {extra_flags}"
        utils.check_output(compile_cmd)
