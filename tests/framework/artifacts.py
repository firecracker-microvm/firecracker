# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define classes for interacting with CI artifacts in s3."""

import os
import platform
import tempfile
from shutil import copyfile
from enum import Enum
from stat import S_IREAD, S_IWRITE
from pathlib import Path
import boto3
import botocore.client
from framework.defs import DEFAULT_TEST_SESSION_ROOT_PATH
from framework.utils import compare_versions
from host_tools.snapshot_helper import merge_memory_bitmaps


ARTIFACTS_LOCAL_ROOT = f"{DEFAULT_TEST_SESSION_ROOT_PATH}/ci-artifacts"


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

    def __init__(self,
                 bucket,
                 key,
                 artifact_type=ArtifactType.MISC,
                 local_folder=None,
                 is_copy=False):
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

    def download(self, target_folder=ARTIFACTS_LOCAL_ROOT, force=False):
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

    def copy(self, file_name=None):
        """Create a writeable copy of the artifact."""
        assert os.path.exists(self.local_path()), """File {} not found.
        call download() first.""".format(self.local_path())

        # The file path for this artifact copy.
        new_dir = "{}/{}/{}".format(
            Artifact.LOCAL_ARTIFACT_DIR,
            self.type.value,
            platform.machine()
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
        return Artifact(None, new_key,
                        artifact_type=self.type,
                        local_folder=local_folder, is_copy=True)

    def __del__(self):
        """Teardown the object."""
        if self._is_copy and os.path.exists(self._key):
            os.remove(self._key)


class SnapshotArtifact:
    """Manages snapshot S3 artifact objects."""

    def __init__(self,
                 bucket,
                 key,
                 artifact_type=ArtifactType.SNAPSHOT):
        """Initialize bucket, key and type."""
        self._bucket = bucket
        self._type = artifact_type
        self._key = key

        self._mem = Artifact(self._bucket, "{}vm.mem".format(key),
                             artifact_type=ArtifactType.MISC)
        self._vmstate = Artifact(self._bucket, "{}vm.vmstate".format(key),
                                 artifact_type=ArtifactType.MISC)
        self._ssh_key = Artifact(self._bucket, "{}ssh_key".format(key),
                                 artifact_type=ArtifactType.SSH_KEY)
        self._disks = []

        disk_prefix = "{}disk".format(key)
        snaphot_disks = self._bucket.objects.filter(Prefix=disk_prefix)

        for disk in snaphot_disks:
            artifact = Artifact(self._bucket, disk.key,
                                artifact_type=ArtifactType.DISK)
            self._disks.append(artifact)

        # Get the name of the snapshot folder.
        snapshot_name = self.name
        self._local_folder = os.path.join(ARTIFACTS_LOCAL_ROOT,
                                          self.type.value,
                                          snapshot_name)

    @property
    def type(self):
        """Return the artifact type."""
        return self._type

    @property
    def key(self):
        """Return the artifact key."""
        return self._key

    @property
    def mem(self):
        """Return the memory artifact."""
        return self._mem

    @property
    def vmstate(self):
        """Return the vmstate artifact."""
        return self._vmstate

    @property
    def ssh_key(self):
        """Return the vmstate artifact."""
        return self._ssh_key

    @property
    def disks(self):
        """Return the disk artifacts."""
        return self._disks

    @property
    def name(self):
        """Return the name of the artifact."""
        return self._key.strip('/').split('/')[-1]

    def download(self):
        """Download artifacts and return a Snapshot object."""
        self.mem.download(self._local_folder)
        self.vmstate.download(self._local_folder)
        # SSH key is not needed by microvm, it is needed only by
        # test functions.
        self.ssh_key.download(self._local_folder)

        for disk in self.disks:
            disk.download(self._local_folder)
            os.chmod(disk.local_path(), 0o700)

    def copy(self, vm_root_folder):
        """Copy artifacts and return a Snapshot object."""
        assert self._local_folder is not None

        dst_mem_path = os.path.join(vm_root_folder, self.mem.name())
        dst_state_file = os.path.join(vm_root_folder, self.vmstate.name())
        dst_ssh_key = os.path.join(vm_root_folder, self.ssh_key.name())

        # Copy mem, state & ssh_key.
        copyfile(self.mem.local_path(), dst_mem_path)
        copyfile(self.vmstate.local_path(), dst_state_file)
        copyfile(self.ssh_key.local_path(), dst_ssh_key)
        # Set proper permissions for ssh key.
        os.chmod(dst_ssh_key, 0o400)

        disk_paths = []
        for disk in self.disks:
            dst_disk_path = os.path.join(vm_root_folder, disk.name())
            copyfile(disk.local_path(), dst_disk_path)
            disk_paths.append(dst_disk_path)

        return Snapshot(dst_mem_path,
                        dst_state_file,
                        disks=disk_paths,
                        net_ifaces=None,
                        ssh_key=dst_ssh_key)


class DiskArtifact(Artifact):
    """Provides access to associated ssh key artifact."""

    def ssh_key(self):
        """Return a ssh key artifact."""
        # Replace extension.
        key_file_path = str(Path(self.key).with_suffix('.id_rsa'))
        return Artifact(self.bucket,
                        key_file_path,
                        artifact_type=ArtifactType.SSH_KEY)


class FirecrackerArtifact(Artifact):
    """Provides access to associated jailer artifact."""

    def jailer(self):
        """Return a jailer binary artifact."""
        # Jailer and FC binaries have different extensions and share
        # file name when stored in S3:
        # Firecracker binary: v0.22.firecrcker
        # Jailer binary: v0.23.0.jailer
        jailer_path = str(Path(self.key).with_suffix('.jailer'))
        return Artifact(self.bucket,
                        jailer_path,
                        artifact_type=ArtifactType.JAILER)

    @property
    def version(self):
        """Return the artifact's version: `X.Y.Z`."""
        # Get the filename, remove the extension and trim the leading 'v'.
        return os.path.splitext(os.path.basename(self.key))[0][1:]


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
    ARTIFACTS_ROOT = 'ci-artifacts-io-uring'
    ARTIFACTS_DISKS = '/disks/' + PLATFORM + "/"
    ARTIFACTS_KERNELS = '/kernels/' + PLATFORM + "/"
    ARTIFACTS_MICROVMS = '/microvms/'
    ARTIFACTS_SNAPSHOTS = '/snapshots/' + PLATFORM + "/"
    ARTIFACTS_BINARIES = '/binaries/' + PLATFORM + "/"

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

    def snapshots(self, keyword=None):
        """Return snapshot artifacts for the current arch."""
        # Snapshot artifacts are special since they need to contain
        # a variable number of files: mem, state, disks, ssh key.
        # To simplify the way we retrieve and store snapshot artifacts
        # we are going to group all snapshot file in a folder and the
        # "keyword" parameter will filter this folder name.
        #
        # Naming convention for files within the snapshot below.
        # Snapshot folder /ci-artifacts/snapshots/x86_64/fc_snapshot_v0.22:
        # - vm.mem
        # - vm.vmstate
        # - disk0 <---- this is the root disk
        # - disk1
        # - diskN
        # - ssh_key

        artifacts = []
        prefix = ArtifactCollection.ARTIFACTS_ROOT
        prefix += ArtifactCollection.ARTIFACTS_SNAPSHOTS
        snaphot_dirs = self.bucket.objects.filter(Prefix=prefix)
        for snapshot_dir in snaphot_dirs:
            key = snapshot_dir.key
            # Filter out the snapshot artifacts root folder.
            # Select only files with specified keyword.
            if (key[-1] == "/" and key != prefix and
                    (keyword is None or keyword in snapshot_dir.key)):
                artifact_type = ArtifactType.SNAPSHOT
                artifacts.append(SnapshotArtifact(self.bucket,
                                                  key,
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

    def firecrackers(self, keyword=None, min_version=None, max_version=None):
        """Return fc/jailer artifacts for the current arch."""
        firecrackers = self._fetch_artifacts(
            ArtifactCollection.ARTIFACTS_BINARIES,
            ArtifactCollection.FC_EXTENSION,
            ArtifactType.FC,
            FirecrackerArtifact,
            keyword=keyword
        )

        # Filter out binaries with versions older than the `min_version` arg.
        if min_version is not None:
            return list(filter(
                lambda fc: compare_versions(fc.version, min_version) >= 0,
                firecrackers
            ))

        # Filter out binaries with versions newer than the `max_version` arg.
        if max_version is not None:
            return list(filter(
                lambda fc: compare_versions(fc.version, max_version) <= 0,
                firecrackers
            ))

        return firecrackers

    def firecracker_versions(self, min_version=None, max_version=None):
        """Return fc/jailer artifacts' versions for the current arch."""
        return [fc.base_name()[1:]
                for fc in self.firecrackers(min_version=min_version,
                                            max_version=max_version)]

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
        merge_memory_bitmaps(base.mem, self.mem)
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


class NetIfaceConfig:
    """Defines a network interface configuration."""

    def __init__(self,
                 host_ip=DEFAULT_HOST_IP,
                 guest_ip=DEFAULT_GUEST_IP,
                 tap_name=DEFAULT_TAP_NAME,
                 dev_name=DEFAULT_DEV_NAME,
                 netmask=DEFAULT_NETMASK):
        """Initialize object."""
        self._host_ip = host_ip
        self._guest_ip = guest_ip
        self._tap_name = tap_name
        self._dev_name = dev_name
        self._netmask = netmask

    @property
    def host_ip(self):
        """Return the host IP."""
        return self._host_ip

    @property
    def guest_ip(self):
        """Return the guest IP."""
        return self._guest_ip

    @property
    def tap_name(self):
        """Return the tap device name."""
        return self._tap_name

    @property
    def dev_name(self):
        """Return the guest device name."""
        return self._dev_name

    @property
    def netmask(self):
        """Return the netmask."""
        return self._netmask
