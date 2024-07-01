# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for checking the rate limiter on /drives resources."""

import os

import host_tools.drive as drive_tools

MB = 2**20


def check_iops_limit(ssh_connection, block_size, count, min_time, max_time):
    """Verify if the rate limiter throttles block iops using dd."""
    obs = block_size
    byte_count = block_size * count
    dd = "dd if=/dev/zero of=/dev/vdb ibs={} obs={} count={} oflag=direct".format(
        block_size, obs, count
    )
    print("Running cmd {}".format(dd))
    # Check write iops (writing with oflag=direct is more reliable).
    _, _, stderr = ssh_connection.check_output(dd)

    # "dd" writes to stderr by design. We drop first lines
    lines = stderr.split("\n")
    dd_result = lines[2].strip()

    # Interesting output looks like this:
    # 4194304 bytes (4.2 MB, 4.0 MiB) copied, 0.0528524 s, 79.4 MB/s
    tokens = dd_result.split()

    # Check total read bytes.
    assert int(tokens[0]) == byte_count
    # Check duration.
    assert float(tokens[7]) > min_time
    assert float(tokens[7]) < max_time


def test_patch_drive_limiter(uvm_plain):
    """
    Test replacing the drive rate-limiter after guest boot works.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()
    # Set up the microVM with 2 vCPUs, 512 MiB of RAM, 1 network iface, a root
    # file system, and a scratch drive.
    test_microvm.basic_config(vcpu_count=2, mem_size_mib=512)
    test_microvm.add_net_iface()

    fs1 = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch"), size=512
    )
    test_microvm.api.drive.put(
        drive_id="scratch",
        path_on_host=test_microvm.create_jailed_resource(fs1.path),
        is_root_device=False,
        is_read_only=False,
        rate_limiter={
            "bandwidth": {"size": 10 * MB, "refill_time": 100},
            "ops": {"size": 100, "refill_time": 100},
        },
    )
    test_microvm.start()

    # Validate IOPS stays within above configured limits.
    # For example, the below call will validate that reading 1000 blocks
    # of 512b will complete in at 0.8-1.2 seconds ('dd' is not very accurate,
    # so we target to stay within 30% error).
    check_iops_limit(test_microvm.ssh, 512, 1000, 0.7, 1.3)
    check_iops_limit(test_microvm.ssh, 4096, 1000, 0.7, 1.3)

    # Patch ratelimiter
    test_microvm.api.drive.patch(
        drive_id="scratch",
        rate_limiter={
            "bandwidth": {"size": 100 * MB, "refill_time": 100},
            "ops": {"size": 200, "refill_time": 100},
        },
    )

    check_iops_limit(test_microvm.ssh, 512, 2000, 0.7, 1.3)
    check_iops_limit(test_microvm.ssh, 4096, 2000, 0.7, 1.3)

    # Patch ratelimiter
    test_microvm.api.drive.patch(
        drive_id="scratch", rate_limiter={"ops": {"size": 1000, "refill_time": 100}}
    )

    check_iops_limit(test_microvm.ssh, 512, 10000, 0.7, 1.3)
    check_iops_limit(test_microvm.ssh, 4096, 10000, 0.7, 1.3)
