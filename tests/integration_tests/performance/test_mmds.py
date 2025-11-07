# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the performance of MMDS token generation and verification."""

import re

import pytest

from framework.utils import configure_mmds, populate_data_store

# Default IPv4 address for MMDS
DEFAULT_IPV4 = "169.254.169.254"

# Number of iterations for performance measurements
ITERATIONS = 500


def parse_curl_timing(timing_line):
    """Parse curl timing output and extract timing information in milliseconds."""
    # curl -w format outputs timing in seconds, convert to milliseconds
    # Expected format: "time_total:0.123456"
    match = re.search(r"time_total:([\d.]+)", timing_line)
    if match:
        return float(match.group(1)) * 1000  # Convert to milliseconds

    raise ValueError(f"Could not parse timing from curl output: {timing_line}")


@pytest.fixture
def mmds_microvm(uvm_plain_any):
    """Creates a microvm with MMDS configured for performance testing."""
    uvm = uvm_plain_any
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
    using curl's built-in timing capabilities.
    """

    metrics.set_dimensions(
        {
            "performance_test": "test_mmds_performance",
            **mmds_microvm.dimensions,
        }
    )

    # Measure token generation performance
    for _ in range(ITERATIONS):
        # Curl command to generate token with timing
        token_cmd = (
            f'curl -m 2 -s -w "\\ntime_total:%{{time_total}}" '
            f'-X PUT -H "X-metadata-token-ttl-seconds: 60" '
            f"http://{DEFAULT_IPV4}/latest/api/token"
        )
        _, stdout, stderr = mmds_microvm.ssh.check_output(token_cmd)
        assert stderr == "", "Error generating token"

        # Parse timing and token from output
        lines = stdout.strip().split("\n")
        token = lines[0].strip()  # First line is the token

        # Verify token was generated successfully
        assert len(token) > 0, f"Token generation failed. Output: {stdout}"

        generation_time_ms = parse_curl_timing(lines[-1])
        metrics.put_metric("token_generation_time", generation_time_ms, "Milliseconds")

        # Curl command to verify token with timing
        request_cmd = (
            f'curl -m 2 -s -w "\\ntime_total:%{{time_total}}" '
            f'-X GET -H "X-metadata-token: {token}" -H "Accept: application/json" '
            f"http://{DEFAULT_IPV4}/latest/meta-data/instance-id"
        )
        _, stdout, stderr = mmds_microvm.ssh.check_output(request_cmd)
        assert stderr == "", "MMDS request failed"

        # Parse response and timing
        lines = stdout.strip().split("\n")
        response = lines[0].strip()  # First line is the response

        # Verify request was successful
        assert (
            "i-1234567890abcdef0" in response
        ), f"MMDS request failed. Response: {response}"

        request_time_ms = parse_curl_timing(lines[-1])
        metrics.put_metric("request_time", request_time_ms, "Milliseconds")
