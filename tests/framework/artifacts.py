# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define classes for interacting with CI artifacts in s3."""

import os
import platform
import tempfile
from enum import Enum
from pathlib import Path
from stat import S_IREAD, S_IWRITE
from shutil import copyfile
import boto3
import botocore.client
from host_tools.snapshot_helper import merge_memory_bitmaps


class ArtifactType(Enum):
    """Supported artifact types."""

    MICROVM = "microvm"
    KERNEL = "kernel"
    DISK = "disk"
    SSH_KEY = "ssh_key"
    MEM = "mem"
    VMSTATE = "vmstate"
    MISC = "misc"


class Artifact:
    """A generic read-only artifact manipulation class."""

    LOCAL_ARTIFACT_DIR = "/tmp/local-artifacts"

    def __init__(self,
                 bucket,
                 key,
                 artifact_type=ArtifactType.MISC,
                 local_folder=None):
        """Initialize bucket, key and type."""
        self._bucket = bucket
        self._key = key
        self._local_folder = local_folder
        self._type = artifact_type

    @property
    def type(self):
        """Return the artifact type."""
        return self._type

    @property
    def key(self):
        """Return the artifact key."""
        return self._key

    @property
    def bucket(self):
        """Return the artifact bucket."""
        return self._bucket

    def name(self):
        """Return the artifact name."""
        return Path(self.key).name

    def local_dir(self):
        """Return the directory containing the downloaded artifact."""
        assert self._local_folder is not None
        return "{}/{}/{}".format(
            self._local_folder,
            self.type.value,
            platform.machine(),
        )

    def download(self, target_folder, force=False):
        """Save the artifact in the folder specified target_path."""
        assert self.bucket is not None
        self._local_folder = target_folder
        Path(self.local_dir()).mkdir(parents=True, exist_ok=True)
        if force or not os.path.exists(self.local_path()):
            self._bucket.download_file(self._key, self.local_path())
            # Artifacts are read only by design.
            os.chmod(self.local_path(), S_IREAD)

    def local_path(self):
        """Return the local path where the file was downloaded."""
        # The file path format: <target_folder>/<type>/<platform>/<name>
        return "{}/{}".format(
            self.local_dir(),
            self.name()
        )

    def copy(self):
        """Create a writeable copy of the artifact."""
        assert os.path.exists(self.local_path()), """File {} not found.
        call download() first.""".format(self.local_path())

        # The file path for this artifact copy.
        new_dir = "{}/{}/{}".format(
            Artifact.LOCAL_ARTIFACT_DIR,
            self.type.value,
            platform.machine()
        )
        # The temp file suffix is the artifact type.
        suffix = "-{}".format(self.type.value)
        # The key for the new artifact is the full path to the file.
        new_key = tempfile.mktemp(dir=new_dir, suffix=suffix)
        # Create directories if needed.
        Path(new_dir).mkdir(parents=True, exist_ok=True)
        # Copy to local artifact.
        copyfile(self.local_path(), new_key)
        # Make it writeable.
        os.chmod(new_key, S_IREAD | S_IWRITE)
        # Local folder of the new artifact.
        local_folder = Artifact.LOCAL_ARTIFACT_DIR
        # Calls to download() on the new Artifact are guarded by a
        # bucket assert.
        return Artifact(None, new_key,
                        artifact_type=self.type,
                        local_folder=local_folder)


class DiskArtifact(Artifact):
    """Specializes the generic artifact."""

    def ssh_key(self):
        """Return a ssh key artifact."""
        # Replace extension.
        key_file_path = str(Path(self.key).with_suffix('.id_rsa'))
        return Artifact(self.bucket,
                        key_file_path,
                        artifact_type=ArtifactType.SSH_KEY)


class ArtifactCollection:
    """Provides easy access to different artifact types."""

    MICROVM_CONFIG_EXTENSION = ".json"
    MICROVM_KERNEL_EXTENSION = ".bin"
    MICROVM_DISK_EXTENSION = ".ext4"
    MICROVM_VMSTATE_EXTENSION = ".vmstate"
    MICROVM_MEM_EXTENSION = ".mem"
    PLATFORM = platform.machine()

    # S3 bucket structure.
    ARTIFACTS_ROOT = 'ci-artifacts'
    ARTIFACTS_DISKS = '/disks/' + PLATFORM
    ARTIFACTS_KERNELS = '/kernels/' + PLATFORM
    ARTIFACTS_MICROVMS = '/microvms'
    ARTIFACTS_SNAPSHOTS = '/snapshots/' + PLATFORM

    def __init__(
        self,
        bucket
    ):
        """Initialize S3 client."""
        config = botocore.client.Config(signature_version=botocore.UNSIGNED)
        # pylint: disable=E1101
        # fixes "E1101: Instance of '' has no 'Bucket' member (no-member)""
        self.bucket = boto3.resource('s3', config=config).Bucket(bucket)

    def _fetch_artifacts(self,
                         artifact_dir,
                         artifact_ext,
                         artifact_type,
                         artifact_class,
                         keyword=None):
        artifacts = []
        prefix = ArtifactCollection.ARTIFACTS_ROOT + artifact_dir
        files = self.bucket.objects.filter(Prefix=prefix)
        for file in files:
            if (
                # Filter by extensions.
                file.key.endswith(artifact_ext)
                # Filter by userprovided keyword if any.
                and (keyword is None or keyword in file.key)
            ):
                artifacts.append(artifact_class(self.bucket,
                                                file.key,
                                                artifact_type=artifact_type))
        return artifacts

    def microvms(self, keyword=None):
        """Return microvms artifacts for the current arch."""
        return self._fetch_artifacts(
            ArtifactCollection.ARTIFACTS_MICROVMS,
            ArtifactCollection.MICROVM_CONFIG_EXTENSION,
            ArtifactType.MICROVM,
            Artifact,
            keyword=keyword
        )

    def kernels(self, keyword=None):
        """Return kernel artifacts for the current arch."""
        return self._fetch_artifacts(
            ArtifactCollection.ARTIFACTS_KERNELS,
            ArtifactCollection.MICROVM_KERNEL_EXTENSION,
            ArtifactType.KERNEL,
            Artifact,
            keyword=keyword
        )

    def disks(self, keyword=None):
        """Return disk artifacts for the current arch."""
        return self._fetch_artifacts(
            ArtifactCollection.ARTIFACTS_DISKS,
            ArtifactCollection.MICROVM_DISK_EXTENSION,
            ArtifactType.DISK,
            DiskArtifact,
            keyword=keyword
        )


class ArtifactSet:
    """Manages a set of artifacts with the same type."""

    def __init__(self, artifacts):
        """Initialize type and artifact array."""
        self._type = None
        self._artifacts = []
        self.insert(artifacts)

    def insert(self, artifacts):
        """Add artifacts to set."""
        if artifacts is not None and len(artifacts) > 0:
            self._type = self._type or artifacts[0].type
        for artifact in artifacts:
            assert artifact.type == self._type
            self._artifacts.append(artifact)

    @property
    def artifacts(self):
        """Return the artifacts array."""
        return self._artifacts

    def __len__(self):
        """Return the artifacts array len."""
        return len(self._artifacts)


class SnapshotType(Enum):
    """Supported snapshot types."""

    FULL = 0
    DIFF = 1


class Snapshot:
    """Manages Firecracker snapshots."""

    def __init__(self, mem, vmstate, disks, ssh_key):
        """Initialize mem, vmstate, disks, key."""
        assert mem is not None
        assert vmstate is not None
        assert disks is not None
        assert ssh_key is not None
        self._mem = mem
        self._vmstate = vmstate
        self._disks = disks
        self._ssh_key = ssh_key

    def rebase_snapshot(self, base):
        """Rebases current incremental snapshot onto a specified base layer."""
        merge_memory_bitmaps(base.mem, self.mem)
        self._mem = base.mem

    @property
    def mem(self):
        """Return the mem file path."""
        return self._mem

    @property
    def vmstate(self):
        """Return the vmstate file path."""
        return self._vmstate

    @property
    def disks(self):
        """Return the disk file paths."""
        return self._disks

    @property
    def ssh_key(self):
        """Return the ssh key file path."""
        return self._ssh_key
