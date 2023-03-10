# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define classes for interacting with CI artifacts in s3."""

import functools
import os
import platform
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from shutil import copyfile
from stat import S_IREAD, S_IWRITE

import boto3
import botocore.client

import host_tools.network as net_tools
from framework.defs import (
    DEFAULT_TEST_SESSION_ROOT_PATH,
    SUPPORTED_KERNELS,
    SUPPORTED_KERNELS_NO_SVE,
)
from framework.utils import compare_versions, get_kernel_version
from framework.utils_cpuid import get_instance_type
from host_tools.cargo_build import run_rebase_snap_bin

ARTIFACTS_LOCAL_ROOT = f"{DEFAULT_TEST_SESSION_ROOT_PATH}/ci-artifacts"


def select_supported_kernels():
    """Select guest kernels supported by the current combination of kernel and instance type."""
    supported_kernels = SUPPORTED_KERNELS
    host_kernel_version = get_kernel_version(level=1)
    try:
        instance_type = get_instance_type()
    # in case we are not in EC2, return the default
    # pylint: disable=broad-except
    except Exception:
        return supported_kernels

    if instance_type == "c7g.metal" and host_kernel_version == "4.14":
        supported_kernels = SUPPORTED_KERNELS_NO_SVE

    return supported_kernels


class ArtifactType(Enum):
    """Supported artifact types."""

    MICROVM = "microvm"
    KERNEL = "kernel"
    DISK = "disk"
    SSH_KEY = "ssh_key"
    MEM = "mem"
    VMSTATE = "vmstate"
    MISC = "misc"
    SNAPSHOT = "snapshot"
    FC = "firecracker"
    JAILER = "jailer"


class Artifact:
    """A generic read-only artifact manipulation class."""

    LOCAL_ARTIFACT_DIR = f"{DEFAULT_TEST_SESSION_ROOT_PATH}/local-artifacts"

    def __init__(
        self,
        bucket,
        key,
        artifact_type=ArtifactType.MISC,
        local_folder=None,
        is_copy=False,
    ):
        """Initialize bucket, key and type."""
        self._bucket = bucket
        self._key = key
        self._local_folder = local_folder
        self._type = artifact_type
        self._is_copy = is_copy

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

    def base_name(self):
        """Return the base name (without extension)."""
        return Path(self.key).stem

    def local_dir(self):
        """Return the directory containing the downloaded artifact."""
        assert self._local_folder is not None
        return "{}/{}/{}".format(
            self._local_folder,
            self.type.value,
            platform.machine(),
        )

    def download(self, target_folder=ARTIFACTS_LOCAL_ROOT, force=False, perms=None):
        """Save the artifact in the folder specified target_path."""
        assert self.bucket is not None
        self._local_folder = target_folder
        local_path = Path(self.local_path())
        local_path.parent.mkdir(parents=True, exist_ok=True)
        if force or not local_path.exists():
            self._bucket.download_file(self._key, local_path)
            # Artifacts are read-only by design.
            if perms is None:
                perms = 0o400
            local_path.chmod(perms)

    def local_path(self):
        """Return the local path where the file was downloaded."""
        # The file path format: <target_folder>/<type>/<platform>/<name>
        return "{}/{}".format(self.local_dir(), self.name())

    def copy(self, file_name=None):
        """Create a writeable copy of the artifact."""
        assert os.path.exists(
            self.local_path()
        ), """File {} not found.
        call download() first.""".format(
            self.local_path()
        )

        # The file path for this artifact copy.
        new_dir = "{}/{}/{}".format(
            Artifact.LOCAL_ARTIFACT_DIR, self.type.value, platform.machine()
        )

        if file_name is None:
            # The temp file suffix is the artifact type.
            suffix = "-{}".format(self.type.value)
            # The key for the new artifact is the full path to the file.
            new_key = tempfile.mktemp(dir=new_dir, suffix=suffix)
        else:
            # Caller specified new name.
            new_key = os.path.join(new_dir, file_name)

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
        return Artifact(
            None,
            new_key,
            artifact_type=self.type,
            local_folder=local_folder,
            is_copy=True,
        )

    def cleanup(self):
        """Delete the backing files from disk."""
        if os.path.exists(self._key):
            os.remove(self._key)

    def __del__(self):
        """Teardown the object."""
        if self._is_copy:
            self.cleanup()


class DiskArtifact(Artifact):
    """Provides access to associated ssh key artifact."""

    def ssh_key(self):
        """Return a ssh key artifact."""
        # Replace extension.
        key_file_path = str(Path(self.key).with_suffix(".id_rsa"))
        return Artifact(
            self.bucket,
            key_file_path,
            artifact_type=ArtifactType.SSH_KEY,
            local_folder=self._local_folder,
        )


class FirecrackerArtifact(Artifact):
    """Provides access to associated jailer artifact."""

    @functools.lru_cache
    def jailer(self):
        """Return a jailer binary artifact."""
        # Jailer and FC binaries have different extensions and share
        # file name when stored in S3:
        # Firecracker binary: v0.22.firecracker
        # Jailer binary: v0.23.0.jailer
        jailer_path = str(Path(self.key).with_suffix(".jailer"))
        return Artifact(self.bucket, jailer_path, artifact_type=ArtifactType.JAILER)

    @property
    def version(self):
        """Return the artifact's version: `X.Y.Z`."""
        # Get the filename, remove the extension and trim the leading 'v'.
        return os.path.splitext(os.path.basename(self.key))[0][1:]

    @property
    def version_tuple(self):
        """Return the artifact's version as a tuple `(X, Y, Z)`."""
        return tuple(int(x) for x in self.version.split("."))

    @property
    def snapshot_version_tuple(self):
        """Return the artifact's snapshot version as a tuple: `X.Y.0`."""
        return self.version_tuple[:2] + (0,)

    @property
    def snapshot_version(self):
        """Return the artifact's snapshot version: `X.Y.0`.

        Due to how Firecracker maps release versions to snapshot versions, we
        have to request the minor version instead of the actual version.
        """
        return ".".join(str(x) for x in self.snapshot_version_tuple)


class ArtifactCollection:
    """Provides easy access to different artifact types."""

    MICROVM_CONFIG_EXTENSION = ".json"
    MICROVM_KERNEL_EXTENSION = ".bin"
    MICROVM_DISK_EXTENSION = ".ext4"
    MICROVM_VMSTATE_EXTENSION = ".vmstate"
    MICROVM_MEM_EXTENSION = ".mem"
    FC_EXTENSION = ".firecracker"
    JAILER_EXTENSION = ".jailer"

    PLATFORM = platform.machine()

    # S3 bucket structure.
    ARTIFACTS_ROOT = "ci-artifacts"
    ARTIFACTS_DISKS = "/disks/" + PLATFORM + "/"
    ARTIFACTS_KERNELS = "/kernels/" + PLATFORM + "/"
    ARTIFACTS_MICROVMS = "/microvms/"
    ARTIFACTS_SNAPSHOTS = "/snapshots/" + PLATFORM + "/"
    ARTIFACTS_BINARIES = "/binaries/" + PLATFORM + "/"

    def __init__(self, bucket):
        """Initialize S3 client."""
        config = botocore.client.Config(signature_version=botocore.UNSIGNED)
        # pylint: disable=E1101
        # fixes "E1101: Instance of '' has no 'Bucket' member (no-member)""
        self.bucket = boto3.resource("s3", config=config).Bucket(bucket)

    def _fetch_artifacts(
        self, artifact_dir, artifact_ext, artifact_type, artifact_class, keyword=None
    ):
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
                artifacts.append(
                    artifact_class(self.bucket, file.key, artifact_type=artifact_type)
                )
        return artifacts

    def microvms(self, keyword=None):
        """Return microvms artifacts for the current arch."""
        return self._fetch_artifacts(
            ArtifactCollection.ARTIFACTS_MICROVMS,
            ArtifactCollection.MICROVM_CONFIG_EXTENSION,
            ArtifactType.MICROVM,
            Artifact,
            keyword=keyword,
        )

    def firecrackers(
        self, keyword=None, min_version=None, max_version=None, max_version_open=None
    ):
        """Return fc/jailer artifacts for the current arch."""
        firecrackers = self._fetch_artifacts(
            ArtifactCollection.ARTIFACTS_BINARIES,
            ArtifactCollection.FC_EXTENSION,
            ArtifactType.FC,
            FirecrackerArtifact,
            keyword=keyword,
        )

        res = []
        for fc in firecrackers:
            # Filter out binaries with versions older than `min_version`
            if (
                min_version is not None
                and compare_versions(fc.version, min_version) < 0
            ):
                continue
            # Filter out binaries with versions newer than `max_version`
            if (
                max_version is not None
                and compare_versions(fc.version, max_version) > 0
            ):
                continue

            if (
                max_version_open is not None
                and compare_versions(fc.version, max_version_open) >= 0
            ):
                continue
            res.append(fc)

        return res

    def firecracker_versions(self, min_version=None, max_version=None):
        """Return fc/jailer artifacts' versions for the current arch."""
        return [
            fc.base_name()[1:]
            for fc in self.firecrackers(
                min_version=min_version, max_version=max_version
            )
        ]

    def kernels(self, keyword=None):
        """Return guest kernel artifacts for the current arch."""
        kernels = self._fetch_artifacts(
            ArtifactCollection.ARTIFACTS_KERNELS,
            ArtifactCollection.MICROVM_KERNEL_EXTENSION,
            ArtifactType.KERNEL,
            Artifact,
            keyword=keyword,
        )

        supported_kernels = {f"vmlinux-{sup}.bin" for sup in select_supported_kernels()}
        valid_kernels = [
            kernel for kernel in kernels if Path(kernel.key).name in supported_kernels
        ]

        return valid_kernels

    def disks(self, keyword=None):
        """Return disk artifacts for the current arch."""
        return self._fetch_artifacts(
            ArtifactCollection.ARTIFACTS_DISKS,
            ArtifactCollection.MICROVM_DISK_EXTENSION,
            ArtifactType.DISK,
            DiskArtifact,
            keyword=keyword,
        )


class SnapshotType(Enum):
    """Supported snapshot types."""

    FULL = 0
    DIFF = 1


class SnapshotMemBackendType(Enum):
    """
    Supported guest memory backend types used for snapshot load.

    - `FILE`: establishes if the guest memory is backed by a file.
    - `UFFD`: indicates that the guest memory page faults are handled by
              a dedicated UFFD page-fault handler process.
    """

    FILE = "File"
    UFFD = "Uffd"


class Snapshot:
    """Manages Firecracker snapshots."""

    def __init__(self, mem, vmstate, disks, net_ifaces, ssh_key):
        """Initialize mem, vmstate, disks, key."""
        assert mem is not None
        assert vmstate is not None
        assert disks is not None
        assert ssh_key is not None
        self._mem = mem
        self._vmstate = vmstate
        self._disks = disks
        self._ssh_key = ssh_key
        self._net_ifaces = net_ifaces

    def rebase_snapshot(self, base):
        """Rebases current incremental snapshot onto a specified base layer."""
        run_rebase_snap_bin(base.mem, self.mem)
        self._mem = base.mem

    def cleanup(self):
        """Delete the backing files from disk."""
        os.remove(self._mem)
        os.remove(self._vmstate)

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

    @property
    def net_ifaces(self):
        """Return the list of net interface configs."""
        return self._net_ifaces


# Default configuration values for network interfaces.
DEFAULT_HOST_IP = "192.168.0.1"
DEFAULT_GUEST_IP = "192.168.0.2"
DEFAULT_TAP_NAME = "tap0"
DEFAULT_DEV_NAME = "eth0"
DEFAULT_NETMASK = 30


def create_net_devices_configuration(num):
    """Define configuration for the requested number of net devices."""
    return [NetIfaceConfig.with_id(i) for i in range(num)]


@dataclass(frozen=True, repr=True)
class NetIfaceConfig:
    """Defines a network interface configuration."""

    host_ip: str = DEFAULT_HOST_IP
    guest_ip: str = DEFAULT_GUEST_IP
    tap_name: str = DEFAULT_TAP_NAME
    dev_name: str = DEFAULT_DEV_NAME
    netmask: int = DEFAULT_NETMASK

    @property
    def guest_mac(self):
        """Return the guest MAC address."""
        return net_tools.mac_from_ip(self.guest_ip)

    @staticmethod
    def with_id(i):
        """Define network iface with id `i`."""
        return NetIfaceConfig(
            host_ip=f"192.168.{i}.1",
            guest_ip=f"192.168.{i}.2",
            tap_name=f"tap{i}",
            dev_name=f"eth{i}",
        )
