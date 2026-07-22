# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the performance of MMDS token generation and verification."""

import re
import time

import pytest

from framework.utils import configure_mmds, populate_data_store

# Default IPv4 address for MMDS
DEFAULT_IPV4 = "169.254.169.254"

# Number of iterations (each iteration does multiple MMDS calls)
ITERATIONS = 100
MMDS_CALLS_PER_ITERATION = 10
# How frequently iterations start.
# Total time should be roughly ITERATIONS*ITERATION_PERIOD (unless each iteration takes longer than ITERATION_PERIOD)
# A longer interval helps de-correlate the system noise between iterations.
# The current target is approximately 10 seconds total (~=100ms per iteration)
ITERATION_PERIOD = 0.100


def parse_curl_timing(prefix: str, timing_line: str):
    """Parse curl timing output and extract timing information in milliseconds."""
    # curl -w format outputs timing in seconds, convert to milliseconds
    # Expected format: "<prefix>:0.123456"
    match = re.search(prefix + r":([\d.]+)", timing_line)
    if match:
        return float(match.group(1)) * 1000  # Convert to milliseconds

    raise ValueError(f"Could not parse timing from curl output: {timing_line}")


@pytest.fixture
def mmds_microvm(uvm):
    """Creates a microvm with MMDS configured for performance testing."""
    uvm.spawn(log_level="Info")
    uvm.basic_config()
    uvm.add_net_iface()

    # Configure MMDS V2 (requires tokens)
    configure_mmds(uvm, iface_ids=["eth0"], version="V2", ipv4_address=DEFAULT_IPV4)

    # Populate with minimal test data
    test_data = {"latest": {"meta-data": {"instance-id": "i-1234567890abcdef0"}}}
    populate_data_store(uvm, test_data)

    uvm.start()

    uvm.ssh.check_output(f"ip route add {DEFAULT_IPV4} dev eth0")

    return uvm


@pytest.mark.nonci
def test_mmds_token(mmds_microvm, metrics):
    """
    Test MMDS token generation performance using curl timing from within the guest.

    This test measures the time it takes to generate MMDS session tokens
    and perform data requests using curl's built-in timing capabilities.
    The outer iteration loop runs in Python with a sleep between iterations
    to decorrelate system noise, while the inner batch of curl calls is
    executed in a single SSH command for efficiency.
    """

    metrics.set_dimensions(
        {
            "performance_test": "test_mmds_performance",
            **mmds_microvm.dimensions,
        }
    )

    # Build the SSH command for a single iteration batch.
    # Each iteration does MMDS_CALLS_PER_ITERATION curl round-trips.
    # Output per curl pair (4 lines + delimiter):
    #   token_generation_time:<gen_seconds>
    #   <token>
    #   <response>
    #   request_time:<req_seconds>
    #   ---
    # noinspection HttpUrlsUsage
    cmd = (
        f"for i in $(seq 1 {MMDS_CALLS_PER_ITERATION}); do "
        f"curl -m 2 -s -w 'token_generation_time:%{{time_total}}\\n' "
        f"-X PUT -H 'X-metadata-token-ttl-seconds: 60' "
        f"-o /tmp/mmds_token "
        f"http://{DEFAULT_IPV4}/latest/api/token; "
        f"cat /tmp/mmds_token; echo; "
        f"curl -m 2 -s -w '\\nrequest_time:%{{time_total}}\\n' "
        f"-X GET "
        f'-H "X-metadata-token: $(cat /tmp/mmds_token)" '
        f"-H 'Accept: application/json' "
        f"http://{DEFAULT_IPV4}/latest/meta-data/instance-id; "
        f"echo '---'; "
        f"done"
    )

    next_iteration_time = time.monotonic()

    for iter_idx in range(ITERATIONS):
        _, stdout, stderr = mmds_microvm.ssh.check_output(cmd)
        assert stderr == "", f"Error calling MMDS at iteration {iter_idx}: {stderr}"

        # Parse output: split by "---\n"
        calls = stdout.split("---\n")
        if calls and calls[-1].strip() == "":
            calls = calls[:-1]
        assert len(calls) == MMDS_CALLS_PER_ITERATION, (
            f"Iteration {iter_idx}: expected {MMDS_CALLS_PER_ITERATION} "
            f"calls, got {len(calls)}"
        )

        batch_token_sum = 0.0
        batch_request_sum = 0.0

        for call_idx in range(MMDS_CALLS_PER_ITERATION):
            block = calls[call_idx]
            lines = block.strip().split("\n")
            assert len(lines) == 4, f"Unexpected output block: {block}"

            # Line 0: time_total from token generation (body went to file)
            batch_token_sum += parse_curl_timing("token_generation_time", lines[0])

            # Line 1: token value (from cat)
            token = lines[1].strip()
            assert len(token) > 0, f"Token generation failed. Block: {block}"

            # Line 2: response body from GET request
            response = lines[2].strip()
            assert (
                response == '"i-1234567890abcdef0"'
            ), f"MMDS request failed. Response: {response}"

            # Line 3: time_total from GET request
            batch_request_sum += parse_curl_timing("request_time", lines[3])

        # Emit one averaged datapoint per iteration
        metrics.put_metric(
            "token_generation_time",
            batch_token_sum / MMDS_CALLS_PER_ITERATION,
            "Milliseconds",
        )
        metrics.put_metric(
            "request_time",
            batch_request_sum / MMDS_CALLS_PER_ITERATION,
            "Milliseconds",
        )

        next_iteration_time += ITERATION_PERIOD
        time.sleep(max(0, next_iteration_time - time.monotonic()))
