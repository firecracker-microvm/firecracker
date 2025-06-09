# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Test that Firecracker works correctly when instrumented with tracing and trace level logs are enabled.

This test verifies that the log-instrument crate can successfully instrument the actual Firecracker
binary and that the instrumented Firecracker works correctly with trace-level logging.

Test Coverage:
1. Uses clippy-tracing tool to add instrumentation to Firecracker source files
2. Builds Firecracker with tracing features enabled
3. Verifies basic functionality (API calls, VM lifecycle) works with instrumentation
4. Confirms trace-level logs are generated and contain meaningful information
5. Checks performance impact is within acceptable bounds
"""

import re
import tempfile
import time
from pathlib import Path

import pytest

from framework import utils
from framework.microvm import MicroVMFactory
from host_tools.cargo_build import cargo, get_binary


def build_instrumented_firecracker():
    """Build Firecracker with tracing instrumentation enabled."""
    # First, add instrumentation using clippy-tracing
    clippy_tracing = get_binary("clippy-tracing")

    # Add instrumentation to a subset of files to avoid performance issues
    # We'll instrument just the API server and main entry points for meaningful traces
    cargo_args = [
        "--action",
        "fix",
        "--path",
        "./src/firecracker/src/main.rs",
        "--path",
        "./src/firecracker/src/api_server",
        "--path",
        "./src/vmm/src/lib.rs",
        "--path",
        "./src/vmm/src/builder.rs",
    ]

    utils.check_output(f"{clippy_tracing} {' '.join(cargo_args)}")

    # Build Firecracker with tracing feature enabled
    cargo("build", "--features tracing --bin firecracker")

    return get_binary("firecracker")


def cleanup_instrumentation():
    """Remove instrumentation from source files."""
    clippy_tracing = get_binary("clippy-tracing")

    # Strip instrumentation from the files we modified
    strip_args = [
        "--action",
        "strip",
        "--path",
        "./src/firecracker/src/main.rs",
        "--path",
        "./src/firecracker/src/api_server",
        "--path",
        "./src/vmm/src/lib.rs",
        "--path",
        "./src/vmm/src/builder.rs",
    ]

    utils.check_output(f"{clippy_tracing} {' '.join(strip_args)}")


@pytest.fixture(scope="module")
def instrumented_firecracker_binary():
    """Build instrumented Firecracker binary for testing."""
    binary = build_instrumented_firecracker()
    yield binary
    cleanup_instrumentation()


def test_firecracker_tracing_basic_functionality(instrumented_firecracker_binary):
    """Test that instrumented Firecracker can start and handle basic API calls with trace logging."""
    # Create a temporary directory for this test
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a MicroVM factory with the instrumented binary
        factory = MicroVMFactory(instrumented_firecracker_binary)

        # Build a microVM
        vm = factory.build()

        # Configure basic VM settings
        vm.basic_config(vcpu_count=1, mem_size_mib=128)

        # Spawn the VM with trace level logging
        vm.spawn(log_level="Trace", log_show_level=True, log_show_origin=True)

        try:
            # Wait for the API socket to be available
            vm._wait_for_api_socket()  # pylint: disable=protected-access

            # Make some basic API calls to generate trace logs
            # Get instance info
            response = vm.api.describe_instance.get()
            assert response.status_code == 200

            # Get machine config
            response = vm.api.machine_config.get()
            assert response.status_code == 200

            # Set logger to trace level to ensure we capture instrumentation logs
            logger_config = {"level": "Trace"}
            response = vm.api.logger.put(**logger_config)
            assert response.status_code == 204

            # Make another API call after setting trace level
            response = vm.api.describe_instance.get()
            assert response.status_code == 200

            # Verify that the VM is working correctly
            assert vm.state == "Not started"

        finally:
            vm.kill()

        # Check the logs for instrumentation traces
        log_data = vm.log_data

        # Verify that trace level logs are present
        assert "TRACE" in log_data, "Expected TRACE level logs in output"

        # Look for log-instrument traces (function entry/exit)
        # These should have the format: ThreadId(X)>>function_name or ThreadId(X)<<function_name
        trace_pattern = r"ThreadId\(\d+\)(?:::[^>]*)?(?:>>|<<)\w+"
        trace_matches = re.findall(trace_pattern, log_data)

        assert (
            len(trace_matches) > 0
        ), f"Expected to find log-instrument traces in logs, but found none. Log data: {log_data[:1000]}..."

        # Verify we see function entry and exit traces
        entry_traces = [match for match in trace_matches if ">>" in match]
        exit_traces = [match for match in trace_matches if "<<" in match]

        assert len(entry_traces) > 0, "Expected to find function entry traces (>>)"
        assert len(exit_traces) > 0, "Expected to find function exit traces (<<)"

        # Verify that meaningful functions are being traced
        # Look for traces from main, API handling, or VM management functions
        meaningful_functions = ["main", "api", "vmm", "request", "response"]
        found_meaningful = False

        for trace in trace_matches:
            for func in meaningful_functions:
                if func.lower() in trace.lower():
                    found_meaningful = True
                    break
            if found_meaningful:
                break

        assert (
            found_meaningful
        ), f"Expected to find traces from meaningful functions, but traces were: {trace_matches[:10]}"


def test_firecracker_tracing_performance_impact():
    """Test that instrumented Firecracker still performs reasonably (basic smoke test)."""
    # This is a basic performance smoke test to ensure tracing doesn't break functionality
    # We're not doing detailed performance analysis, just ensuring it doesn't hang or crash

    # Build instrumented binary
    instrumented_binary = build_instrumented_firecracker()

    try:
        factory = MicroVMFactory(instrumented_binary)
        vm = factory.build()

        # Time the basic configuration and startup
        start_time = time.time()

        vm.basic_config(vcpu_count=1, mem_size_mib=128, add_root_device=False)
        vm.spawn(log_level="Trace")

        # Make several API calls
        for _ in range(5):
            response = vm.api.describe_instance.get()
            assert response.status_code == 200

        elapsed = time.time() - start_time

        # Should complete within reasonable time (30 seconds is very generous)
        # This is just to catch major performance regressions or hangs
        assert (
            elapsed < 30
        ), f"Instrumented Firecracker took too long to start and handle API calls: {elapsed}s"

        vm.kill()

    finally:
        cleanup_instrumentation()


def test_trace_log_filtering():
    """Test that trace log filtering works correctly with instrumented Firecracker."""
    instrumented_binary = build_instrumented_firecracker()

    try:
        factory = MicroVMFactory(instrumented_binary)
        vm = factory.build()

        vm.basic_config(vcpu_count=1, mem_size_mib=128, add_root_device=False)
        vm.spawn(log_level="Info")  # Start with Info level

        try:
            # Initially should not have trace logs
            initial_log_data = vm.log_data

            # Set logger to trace level
            logger_config = {"level": "Trace"}
            response = vm.api.logger.put(**logger_config)
            assert response.status_code == 204

            # Make API calls to generate traces
            for _ in range(3):
                response = vm.api.describe_instance.get()
                assert response.status_code == 200

            # Now should have trace logs
            final_log_data = vm.log_data

            # Verify no TRACE logs were present initially
            assert (
                "TRACE" not in initial_log_data
            ), "Expected no TRACE logs before setting log level to Trace"

            # The new log data should contain trace information
            new_log_data = final_log_data[len(initial_log_data) :]
            assert (
                "TRACE" in new_log_data
            ), "Expected TRACE logs after setting log level to Trace"

        finally:
            vm.kill()

    finally:
        cleanup_instrumentation() 