# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for creating filesystems on the host."""

import os
import tempfile
from pathlib import Path

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
    """Create a ``monolithicFlat`` VMDK from an offline descriptor fixture."""

    def __init__(self, path=None, size=16, *, pattern):
        """Create a 16 or 2048 MiB VMDK with a patterned extent."""
        if not pattern:
            raise ValueError("VMDK pattern must not be empty")
        if path is None:
            path = os.path.join(tempfile.mkdtemp(prefix="vmdk"), "disk.vmdk")
        self.path = path
        self.size = size

        # Fixtures generated with qemu-img 8.2.2 (Ubuntu 1:8.2.2+ds-0ubuntu1.17):
        # qemu-img create -f vmdk -o subformat=monolithicFlat 16m.vmdk 16M
        # qemu-img create -f vmdk -o subformat=monolithicFlat 2048m.vmdk 2048M
        # CID is random; the flat extent is headerless raw data.
        fixture_dir = Path(__file__).resolve().parents[1] / "data" / "vmdk"
        descriptor = (fixture_dir / f"{size}m.vmdk").read_text(encoding="utf-8")
        with open(self.descriptor_path, "w", encoding="utf-8") as output:
            output.write(
                descriptor.replace(
                    f'"{size}m-flat.vmdk"', f'"{os.path.basename(self.extent_path)}"'
                )
            )

        chunk = pattern * max(1, (64 * 1024) // len(pattern))
        remaining = size * 1024 * 1024
        with open(self.extent_path, "wb") as extent:
            while remaining:
                count = min(remaining, len(chunk))
                extent.write(chunk[:count])
                remaining -= count

    @property
    def descriptor_path(self):
        """Path of the VMDK descriptor file (passed to Firecracker)."""
        return self.path

    @property
    def extent_path(self):
        """Path of the flat extent file backing the descriptor."""
        return os.path.splitext(self.path)[0] + "-flat.vmdk"

    def __del__(self):
        """Remove the descriptor and the flat extent."""
        if not getattr(self, "path", None):
            return
        for pth in (self.path, self.extent_path):
            try:
                os.remove(pth)
            except OSError:
                pass
