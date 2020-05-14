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

    def __init__(
        self,
        artifacts_bucket
    ):
        """Initialize S3 client."""
        config = botocore.client.Config(signature_version=botocore.UNSIGNED)
        self.s3 = boto3.resource('s3', config=config)
        self.artifacts_bucket = artifacts_bucket

    def _fetch_artifacts(self,
                         artifact_root,
                         artifact_dir,
                         artifact_ext,
                         artifact_type,
                         artifact_class,
                         keyword=None):
        bucket = self.s3.Bucket(self.artifacts_bucket)
        artifacts = []
        prefix = artifact_root + artifact_dir
        files = bucket.objects.filter(Prefix=prefix)
        for file in files:
            if (
                # Filter by extensions.
                file.key.endswith(artifact_ext)
                # Filter by userprovided keyword if any.
                and (keyword is None or keyword in file.key)
            ):
                artifacts.append(artifact_class(bucket,
                                                file.key,
                                                type=artifact_type))
        return artifacts

    def microvms(self, keyword=None):
        """Return all microvms artifacts for the current arch."""
        return self._fetch_artifacts(
            self.ARTIFACTS_ROOT,
            self.ARTIFACTS_MICROVMS,
            MICROVM_CONFIG_EXTENSION,
            "microvm",
            Artifact,
            keyword=keyword
        )

    def kernels(self, keyword=None):
        """Return all microvms kernels for the current arch."""
        return self._fetch_artifacts(
            self.ARTIFACTS_ROOT,
            self.ARTIFACTS_KERNELS,
            MICROVM_KERNEL_EXTENSION,
            "kernel",
            Artifact,
            keyword=keyword
        )

    def disks(self, keyword=None):
        """Return all disk artifacts for the current arch."""
        return self._fetch_artifacts(
            self.ARTIFACTS_ROOT,
            self.ARTIFACTS_DISKS,
            MICROVM_DISK_EXTENSION,
            "disk",
            DiskArtifact,
            keyword=keyword
        )
