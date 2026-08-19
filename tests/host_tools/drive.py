# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for creating filesystems on the host."""

import os
import tempfile

from framework import utils


class FilesystemFile:
    """Facility for creating and working with filesystems."""

    KNOWN_FILEFS_FORMATS = {"ext4"}
    path = None

    def __init__(self, path: str = None, size: int = 256, fs_format: str = "ext4"):
        """Create a new file system in a file.

        Raises if the file system format is not supported, if the file already
        exists, or if it ends in '/'.
        """

        # If no path is supplied, use a temporary file.
        # This is useful to force placing the file on disk, not in memory,
        # because qemu vhost-user-blk backend always uses O_DIRECT,
        # but O_DIRECT is not supported by tmpfs.
        if path is None:
            _, path = tempfile.mkstemp(suffix=f".{fs_format}", dir="/tmp")

        if fs_format not in self.KNOWN_FILEFS_FORMATS:
            raise ValueError("Format not in: + " + str(self.KNOWN_FILEFS_FORMATS))
        # Here we append the format as a
        path = os.path.join(path + "." + fs_format)

        if os.path.isfile(path):
            raise FileExistsError("File already exists: " + path)

        utils.check_output(
            "dd status=none if=/dev/zero"
            "    of=" + path + "    bs=1M count=" + str(size)
        )
        utils.check_output("mkfs.ext4 -qF " + path)
        self.path = path

    def __repr__(self):
        return f"<FilesystemFile path={self.path} size={self.size()}>"

    def resize(self, new_size):
        """Resize the filesystem."""
        utils.check_output("truncate --size " + str(new_size) + "M " + self.path)
        utils.check_output("resize2fs " + self.path)

    def size(self):
        """Return the size of the filesystem."""
        return os.stat(self.path).st_size

    def __del__(self):
        """Destructor cleaning up filesystem from where it was created."""
        if self.path:
            try:
                os.remove(self.path)
            except OSError:
                pass


class VmdkFile:
    """Build a read-only ``monolithicFlat`` VMDK image (descriptor + FLAT extent).

    Firecracker only supports read-only VMDK images backed by a single flat
    extent (``monolithicFlat``). This helper writes a plain-text VMDK descriptor
    alongside a flat extent file that is filled with a recognizable byte pattern,
    so the image can be attached as a read-only ``virtio`` block device and the
    data can be verified from inside the guest.

    The descriptor and the extent are placed in the same directory; the extent is
    referenced from the descriptor by its base name only, which is what lets
    Firecracker open it once both files are jailed into the microVM root.
    """

    def __init__(
        self, path=None, size=16, pattern=b"FIRECRACKER VMDK INTEGRATION TEST"
    ):
        """Create a ``size`` MiB VMDK with ``pattern`` repeated to fill the extent.

        :param path: path of the descriptor file; if ``None`` a temp file is used.
        :param size: size of the image, in MiB.
        :param pattern: byte pattern used to fill the flat extent.
        """
        if path is None:
            path = os.path.join(tempfile.mkdtemp(prefix="vmdk"), "disk.vmdk")
        self.path = path
        self.size = size
        self.pattern = pattern
        self._build()

    @property
    def descriptor_path(self):
        """Path of the VMDK descriptor file (passed to Firecracker)."""
        return self.path

    @property
    def extent_path(self):
        """Path of the flat extent file backing the descriptor."""
        stem, _ = os.path.splitext(self.path)
        return stem + "-flat.vmdk"

    def _build(self):
        """Write the descriptor and the flat extent with the byte pattern."""
        total_bytes = self.size * 1024 * 1024
        sectors = total_bytes // 512

        # Fill the flat extent with the repeated pattern so that reading the
        # device back yields deterministic, verifiable data.
        repeated = (self.pattern * (total_bytes // len(self.pattern) + 1))[:total_bytes]
        with open(self.extent_path, "wb") as extent:
            extent.write(repeated)

        extent_name = os.path.basename(self.extent_path)
        descriptor = (
            "# Disk DescriptorFile\n"
            "version=1\n"
            "CID=ffffffff\n"
            "parentCID=ffffffff\n"
            'createType="monolithicFlat"\n'
            "\n"
            "# Extent description\n"
            f'RW {sectors} FLAT "{extent_name}" 0\n'
            "\n"
            "# The disk Data Base\n"
            "#DDB\n"
        )
        with open(self.path, "w", encoding="utf-8") as desc:
            desc.write(descriptor)

    def __del__(self):
        """Remove the descriptor and the flat extent."""
        for pth in (self.path, self.extent_path):
            try:
                os.remove(pth)
            except OSError:
                pass
