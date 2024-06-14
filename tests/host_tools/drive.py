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
