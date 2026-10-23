# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Integration test verifying that Firecracker builds and runs correctly when instrumented
with the `log_instrument::instrument` macro. Ensures that TRACE-level logs and entry/exit
markers (ThreadId(...) >> / <<) are emitted when the binary is built with the `tracing`
feature.
"""

import re
import shutil
from pathlib import Path

import pytest

from framework import utils
from framework.defs import FC_WORKSPACE_DIR, LOCAL_BUILD_PATH
from host_tools.cargo_build import DEFAULT_TARGET, cargo, get_binary

# Typical markers emitted by the `log_instrument` macro
TRACE_LEVEL_HINT = "TRACE"
MARKER_REGEX = re.compile(r"ThreadId\(\d+\).*?(?:>>|<<)")
PATHS_TO_INSTRUMENT = [
    "src/firecracker/src/main.rs",
    "src/firecracker/src/api_server",
    "src/vmm/src/lib.rs",
    "src/vmm/src/builder.rs",
]
# clippy-tracing rewrites sources in place, so we instrument a private copy
# of the workspace. Mutating the shared source tree would race with any
# concurrently running test that builds Firecracker (e.g. test_gdb), which
# then compiles half-written files.
WORKSPACE_COPY = LOCAL_BUILD_PATH / "instrumented_firecracker"
TARGET_DIR = LOCAL_BUILD_PATH / "instrumented_firecracker_target"
# Everything cargo needs to build the `firecracker` binary.
WORKSPACE_ENTRIES = [
    ".cargo",
    "Cargo.lock",
    "Cargo.toml",
    "resources/seccomp",
    "rust-toolchain.toml",
    "src",
]


def copy_workspace(dst: Path):
    """Makes a throwaway copy of the Firecracker sources at `dst`."""
    shutil.rmtree(dst, ignore_errors=True)
    for entry in WORKSPACE_ENTRIES:
        src = FC_WORKSPACE_DIR / entry
        (dst / entry).parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(
                src,
                dst / entry,
                symlinks=True,
                ignore=shutil.ignore_patterns("*.profraw"),
            )
        else:
            shutil.copy2(src, dst / entry)


def build_instrumented_binary(workspace: Path):
    """Builds an instrumented Firecracker binary with tracing instrumentation."""
    clippy_tracing = get_binary("clippy-tracing")
    for p in PATHS_TO_INSTRUMENT:
        utils.check_output(
            f"{clippy_tracing} --action fix --suffix log_instrument:: "
            f"--cfg-attr 'feature =\"tracing\"' --path {workspace / p}"
        )
    cargo(
        "build",
        f"--workspace --target {DEFAULT_TARGET} --release "
        f"--features tracing --bin firecracker",
        env={"CARGO_TARGET_DIR": TARGET_DIR},
        cwd=workspace,
    )
    return get_binary("firecracker", binary_dir=TARGET_DIR / DEFAULT_TARGET / "release")


@pytest.fixture(scope="module")
def instrumented_binary():
    """Build and provide the path to an instrumented Firecracker binary."""
    copy_workspace(WORKSPACE_COPY)
    yield build_instrumented_binary(WORKSPACE_COPY)


def test_log_instrument_firecracker_basic_functionality(
    instrumented_binary, microvm_factory
):
    """Test that instrumented Firecracker can start and handle basic API calls with trace logging."""
    vm = microvm_factory.build(fc_binary_path=instrumented_binary)
    vm.spawn(log_level="Info", log_show_level=True, log_show_origin=True)

    # Generate some log traffic
    _ = vm.api.describe.get()
    _ = vm.api.machine_config.get()

    pre_tracing_log_data = vm.log_data

    # Ensure TRACE logs are being captured
    logger_config = {
        "level": "Trace",
        "show_level": True,
        "show_log_origin": True,
    }
    _ = vm.api.logger.put(**logger_config)

    # Another API call after enabling TRACE
    _ = vm.api.describe.get()

    assert (
        TRACE_LEVEL_HINT not in pre_tracing_log_data
    ), "TRACE level logs were found before setting log level to TRACE. "

    pre_tracing_log_matches = re.findall(MARKER_REGEX, pre_tracing_log_data)

    assert (
        len(pre_tracing_log_matches) == 0
    ), f"Expected no log-instrument traces in logs before enabling TRACE, but found: {pre_tracing_log_matches}"

    post_tracing_log_data = vm.log_data

    assert (
        TRACE_LEVEL_HINT in post_tracing_log_data
    ), "Expected TRACE level logs in output"

    post_tracing_log_matches = re.findall(MARKER_REGEX, post_tracing_log_data)

    assert (
        len(post_tracing_log_matches) > 0
    ), f"Expected to find log-instrument traces in logs, but found none. Log data: {post_tracing_log_data[:1000]}..."

    entry_traces = [match for match in post_tracing_log_matches if ">>" in match]
    exit_traces = [match for match in post_tracing_log_matches if "<<" in match]

    assert len(entry_traces) > 0, "Expected to find function entry traces (>>)"
    assert len(exit_traces) > 0, "Expected to find function exit traces (<<)"

    meaningful_keywords = ["vmm", "request", "response"]

    # Ensure that each of the meaningful keywords is present in at least one trace
    # match from the post-tracing logs.
    assert all(
        any(keyword.lower() in trace.lower() for trace in post_tracing_log_matches)
        for keyword in meaningful_keywords
    ), (
        f"Expected to find traces from meaningful keywords {meaningful_keywords}, "
        f"but traces were: {post_tracing_log_matches[:10]}..."
    )
