# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define classes for interacting with CI artifacts in s3."""

import os
import platform
import re

from shutil import copyfile
from typing import List
from os import path
from pathlib import Path

import boto3
import botocore.client


MICROVM_CONFIG_EXTENSION = ".json"
MICROVM_KERNEL_EXTENSION = ".bin"
MICROVM_DISK_EXTENSION = ".ext4"


class Artifact:
    """A generic artifact manipulation class."""

    bucket = None
    key = None
    local_folder = None

    def __init__(self, bucket, key, type="misc"):
        """Initialize bucket, key and type."""
        self.bucket = bucket
        self.key = key
        self.type = type

    def name(self):
        """Return the artifact name."""
        return self.key.rsplit("/", 1)[1]

    def local_dir(self):
        """Return the directory containing the downloaded artifact."""
        return "{}/{}/{}".format(
            self.local_folder,
            self.type,
            platform.machine(),
        )

    def download(self, target_folder, force=False):
        """Save the artifact in the folder specified target_path."""
        self.local_folder = target_folder
        Path(self.local_dir()).mkdir(parents=True, exist_ok=True)
        if force or not os.path.exists(self.local_path()):
            self.bucket.download_file(self.key, self.local_path())

    def local_path(self):
        """Return the local path where the file was downloaded."""
        # The file path format: <target_folder>/<type>/<platform>/<name>
        return "{}/{}".format(
            self.local_dir(),
            self.name()
        )


class DiskArtifact(Artifact):
    """Specializes the generic artifact."""

    def ssh_key(self):
        """Return a ssh key artifact."""
        key_file_path = self.key.rsplit(".", 1)[0] + '.id_rsa'
        return Artifact(self.bucket, key_file_path, type="ssh_key")


class ArtifactCollection:
    """Provides easy access to different artifact types."""

    # S3 bucket structure.
    ARTIFACTS_ROOT = 'ci-artifacts'
    ARTIFACTS_DISKS = '/disks/' + platform.machine()
    ARTIFACTS_KERNELS = '/kernels/' + platform.machine()
    ARTIFACTS_MICROVMS = '/microvms'
    ARTIFACTS_SNAPSHOTS = '/snapshots/' + platform.machine()

    s3 = None
    artifacts_bucket = None

    def __init__(
        self,
        artifacts_bucket
    ):
        """Initialize S3 client."""
        config = botocore.client.Config(signature_version=botocore.UNSIGNED)
        self.s3 = boto3.resource('s3', config=config)
        self.artifacts_bucket = artifacts_bucket

    def microvms(self):
        """Return all microvms artifacts for the current arch."""
        bucket = self.s3.Bucket(self.artifacts_bucket)
        microvm_artifacts = []
        microvm_prefix = self.ARTIFACTS_ROOT + self.ARTIFACTS_MICROVMS
        microvms = bucket.objects.filter(Prefix=microvm_prefix)
        for microvm in microvms:
            if microvm.key.endswith(MICROVM_CONFIG_EXTENSION):
                microvm_artifacts.append(Artifact(bucket,
                                                  microvm.key,
                                                  type="microvm"))

        return microvm_artifacts

    def kernels(self):
        """Return all microvms kernels for the current arch."""
        bucket = self.s3.Bucket(self.artifacts_bucket)
        kernel_artifacts = []
        kernel_prefix = self.ARTIFACTS_ROOT + self.ARTIFACTS_KERNELS
        kernels = bucket.objects.filter(Prefix=kernel_prefix)
        for kernel in kernels:
            if kernel.key.endswith(MICROVM_KERNEL_EXTENSION):
                kernel_artifacts.append(Artifact(bucket,
                                                 kernel.key,
                                                 type="kernel"))

        return kernel_artifacts

    def disks(self):
        """Return all disk artifacts for the current arch."""
        bucket = self.s3.Bucket(self.artifacts_bucket)
        disk_artifacts = []
        disk_prefix = self.ARTIFACTS_ROOT + self.ARTIFACTS_DISKS
        disks = bucket.objects.filter(Prefix=disk_prefix)
        for disk in disks:
            if disk.key.endswith(MICROVM_DISK_EXTENSION):
                disk_artifacts.append(DiskArtifact(bucket,
                                                   disk.key,
                                                   type="disk"))

        return disk_artifacts
