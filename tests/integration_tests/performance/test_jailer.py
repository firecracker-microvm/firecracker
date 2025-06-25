# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for the jailer."""

import os
import shutil
import subprocess

import pytest

from framework.jailer import DEFAULT_CHROOT_PATH, JailerContext


@pytest.mark.nonci
@pytest.mark.parametrize("jailers", [1, 100, 300, 500])
@pytest.mark.parametrize("mounts", [0, 100, 300, 500])
def test_jailer_startup(jailer_time_bin, microvm_factory, jailers, mounts, metrics):
    """
    Test the overhead of jailer startup without and with bind mounts
    """

    jailer_binary = microvm_factory.jailer_binary_path

    # Create bind mount points. The exact location of them
    # does not matter, they just need to exist.
    mounts_paths = "/tmp/mounts"
    os.makedirs(mounts_paths)
    for m in range(mounts):
        mount_path = f"{mounts_paths}/mount{m}"
        os.makedirs(mount_path)
        subprocess.run(
            ["mount", "--bind", f"{mount_path}", f"{mount_path}"], check=True
        )

    metrics.set_dimensions(
        {
            "performance_test": "test_boottime",
            "jailers": jailers,
            "mounts": mounts,
        }
    )

    # Testing 1 jailer will give 1 data point which is not enough,
    # so do 100 runs in this case.
    if jailers == 1:
        iterations = 100
    else:
        iterations = 1

    for i in range(iterations):
        processes = []
        for j in range(jailers):
            jailer = JailerContext(
                jailer_id=f"fakefc{i}{j}",
                exec_file=jailer_time_bin,
                # Don't deamonize to get the stdout
                daemonize=False,
            )
            jailer.setup()

            cmd = [str(jailer_binary), *jailer.construct_param_list()]
            processes.append(
                subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False
                )
            )

        for p in processes:
            r = p.communicate()[0]
            e, s = r.split()
            metrics.put_metric(
                "startup",
                int(e) - int(s),
                unit="Microseconds",
            )

    # Cleanup mounts and jailer dirs
    for d in os.listdir(mounts_paths):
        subprocess.run(["umount", f"{mounts_paths}/{d}"], check=True)
    shutil.rmtree(mounts_paths)
    shutil.rmtree(DEFAULT_CHROOT_PATH)
