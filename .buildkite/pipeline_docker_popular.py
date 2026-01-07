#!/usr/bin/env python3
# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Buildkite pipeline for testing popular Docker containers
"""

from common import BKPipeline, random_str

pipeline = BKPipeline()

ROOTFS_TAR = f"rootfs_$(uname -m)_{random_str(k=8)}.tar.gz"

pipeline.build_group_per_arch(
    "rootfs-build",
    [
        "sudo yum install -y systemd-container",
        "cd tools/test-popular-containers",
        "sudo ./build_rootfs.sh",
        f'tar czf "{ROOTFS_TAR}" *.ext4 *.id_rsa',
        f'buildkite-agent artifact upload "{ROOTFS_TAR}"',
    ],
    depends_on_build=False,
    set_key=ROOTFS_TAR,
)

pipeline.build_group(
    "docker-popular-containers",
    [
        "./tools/devtool ensure_current_artifacts",
        f'buildkite-agent artifact download "{ROOTFS_TAR}" .',
        f'tar xzf "{ROOTFS_TAR}" -C tools/test-popular-containers',
        './tools/devtool sh "cd ./tools/test-popular-containers; PYTHONPATH=../../tests ./test-docker-rootfs.py"',
    ],
    depends_on=ROOTFS_TAR,
)

print(pipeline.to_json())
