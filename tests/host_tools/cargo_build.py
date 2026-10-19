# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Functionality for a shared binary build and release path for all tests."""

import platform
from pathlib import Path

from framework import defs, utils
from framework.defs import DEFAULT_BINARY_DIR, LOCAL_BUILD_PATH
from framework.with_filelock import with_filelock

DEFAULT_TARGET = f"{platform.machine()}-unknown-linux-musl"
DEFAULT_TARGET_DIR = f"{DEFAULT_TARGET}/release/"


def nightly_toolchain() -> str:
    """Receives the name of the installed nightly toolchain"""
    return utils.check_output("rustup toolchain list | grep nightly").stdout.strip()


def cargo(
    subcommand,
    cargo_args: str = "",
    subcommand_args: str = "",
    *,
    env: dict = None,
    cwd: str = None,
    nightly: bool = False,
    timeout: int = None,
):
    """Executes the specified cargo subcommand"""
    toolchain = f"+{nightly_toolchain()}" if nightly else ""
    env = env or {}
    env_string = " ".join(f'{key}="{str(value)}"' for key, value in env.items())
    cmd = (
        f"{env_string} cargo {toolchain} {subcommand} {cargo_args} -- {subcommand_args}"
    )
    return utils.check_output(cmd, cwd=cwd, timeout=timeout)


def get_rustflags():
    """Get the relevant rustflags for building/unit testing."""
    if platform.machine() == "aarch64":
        return "-C link-arg=-lgcc -C link-arg=-lfdt "
    return ""


def cargo_test(target_dir, extra_args="", env=None):
    """Run the unit, doc and example tests of all crates.

    `env` overrides the defaults below (e.g. RUSTFLAGS for coverage).
    """
    env = {
        "CARGO_TARGET_DIR": target_dir,
        "RUST_TEST_THREADS": 1,
        "RUST_BACKTRACE": "1",
        "RUSTFLAGS": get_rustflags(),
        **(env or {}),
    }
    # By default cargo only builds the examples, and selecting `--examples`
    # drops the doc tests, so the examples' tests need a second run.
    for targets in ("", " --examples"):
        cargo(
            "test",
            extra_args + " --profile ci --all --no-fail-fast" + targets,
            subcommand_args="--nocapture",
            env=env,
            # Kill cargo test 60s before pytest's 600s timeout, so pytest can report
            # the failure and upload artifacts cleanly instead of being killed itself.
            timeout=540,
        )


def get_binary(name, *, binary_dir=DEFAULT_BINARY_DIR, example=None):
    """Get a binary. The binaries are built before starting a testrun."""
    bin_path = binary_dir / name
    if example:
        bin_path = binary_dir / "examples" / example
    return bin_path


def get_example(name, *args, package="firecracker", **kwargs):
    """Build an example binary"""
    return get_binary(package, *args, **kwargs, example=name)


def run_seccompiler_bin(
    bpf_path,
    json_path=defs.SECCOMP_JSON_DIR,
    basic=False,
    split_output=False,
    binary_dir=DEFAULT_BINARY_DIR,
):
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

    if split_output:
        seccompiler_args += " --split-output"

    seccompiler = get_binary("seccompiler-bin", binary_dir=binary_dir)
    utils.check_output(f"{seccompiler} {seccompiler_args}")


def run_snap_editor_rebase(base_snap, diff_snap, binary_dir=DEFAULT_BINARY_DIR):
    """
    Run apply_diff_snap.

    :param base_snap: path to the base snapshot mem file
    :param diff_snap: path to diff snapshot mem file
    """

    snap_ed = get_binary("snapshot-editor", binary_dir=binary_dir)
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


def build_gdb(check_only=False):
    """Builds Firecracker with GDB feature enabled. Returns the binary dir.

    `check_only` runs `cargo check` instead: no binaries.
    """
    build_path = LOCAL_BUILD_PATH / "gdb"
    cargo(
        "check --profile ci" if check_only else "build",
        f"--features gdb --target {DEFAULT_TARGET} --all",
        env={"CARGO_TARGET_DIR": build_path},
    )

    return build_path / DEFAULT_TARGET / "debug"


def build_fuzzing(release=False, check_only=False):
    """Builds Firecracker with fuzzing feature enabled. Returns the binary dir.

    `check_only` runs `cargo check` instead: no binaries.
    """
    build_path = LOCAL_BUILD_PATH / "fuzzing"
    if release:
        # The `compile_error!` the release check looks for is gated on
        # `not(debug_assertions)`, so this stays on `release`.
        profile = "--release"
    else:
        profile = "--profile ci" if check_only else ""
    cargo(
        "check" if check_only else "build",
        f"{profile} --features fuzzing --target {DEFAULT_TARGET} --all",
        env={"CARGO_TARGET_DIR": build_path},
    )

    return build_path / DEFAULT_TARGET / ("release" if release else "debug")
