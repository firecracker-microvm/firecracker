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
    Curl invocations are batched into single SSH calls for efficiency.
    """

    metrics.set_dimensions(
        {
            "performance_test": "test_mmds_performance",
            **mmds_microvm.dimensions,
        }
    )

    # Batch all curl invocations in a single SSH call using a shell loop.
    # Each iteration generates a token (PUT) then uses it to fetch data (GET).
    # We use -o /tmp/mmds_token so curl writes the token body to file and only
    # outputs the -w timing string to stdout. Then we cat the token and run the
    # GET request. Output per iteration (4 lines + delimiter):
    #   token_generation_time:<gen_seconds>
    #   <token>
    #   <response>
    #   request_time:<req_seconds>
    #   ---
    # noinspection HttpUrlsUsage
    batch_cmd = (
        f"for i in $(seq 1 {ITERATIONS}); do "
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

    _, stdout, stderr = mmds_microvm.ssh.check_output(batch_cmd)
    assert stderr == "", "Error calling MMDS"

    # Parse batched output (splitting by '---', and removing last empty token)
    iterations = stdout.split("---\n")
    assert iterations[-1] == ""
    iterations = iterations[:-1]
    assert len(iterations) == ITERATIONS

    for block in iterations:
        lines = block.strip().split("\n")
        assert len(lines) == 4, f"Unexpected output block: {block}"

        # Line 0: time_total from token generation (body went to file)
        generation_time_ms = parse_curl_timing("token_generation_time", lines[0])
        metrics.put_metric("token_generation_time", generation_time_ms, "Milliseconds")

        # Line 1: token value (from cat)
        token = lines[1].strip()
        assert len(token) > 0, f"Token generation failed. Block: {block}"

        # Line 2: response body from GET request
        response = lines[2].strip()
        assert (
            response == '"i-1234567890abcdef0"'
        ), f"MMDS request failed. Response: {response}"

        # Line 3: time_total from GET request
        request_time_ms = parse_curl_timing("request_time", lines[3])
        metrics.put_metric("request_time", request_time_ms, "Milliseconds")
