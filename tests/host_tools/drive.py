"""Utilities for creating filesystems on the host."""

import os

from subprocess import run


class FilesystemFile:
    """Facility for creating and working with filesystem files."""

    KNOWN_FILEFS_FORMATS = {'ext4'}
    path = None

    def __init__(self, path: str, size: int = 256, fs_format: str = 'ext4'):
        """Create a new file system in a file.

        Raises if the file system format is not supported, if the file already
        exists, or if it ends in '/'.
        """
        if fs_format not in self.KNOWN_FILEFS_FORMATS:
            raise ValueError(
                'Format not in: + ' + str(self.KNOWN_FILEFS_FORMATS)
            )
        # Here we append the format as a
        path = os.path.join(path + '.' + fs_format)

        if os.path.isfile(path):
            raise FileExistsError("File already exists: " + path)

        run(
            'dd status=none if=/dev/zero'
            '    of=' + path +
            '    bs=1M count=' + str(size),
            shell=True,
            check=True
        )
        run('mkfs.ext4 -qF ' + path, shell=True, check=True)
        self.path = path

    def resize(self, new_size):
        """Resize the filesystem file."""
        run(
            'truncate --size ' + str(new_size) + 'M ' + self.path,
            shell=True,
            check=True
        )
        run('resize2fs ' + self.path, shell=True, check=True)

    def size(self):
        """Return the size of the filesystem file."""
        return os.stat(self.path).st_size

    def __del__(self):
        """Destructor cleaning up filesystem from where it was created."""
        if self.path:
            try:
                os.remove(self.path)
            except OSError:
                pass
