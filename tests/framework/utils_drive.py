# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Utilities for vhost-user-blk backend."""

import os
import subprocess
import time
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from subprocess import check_output

from framework import utils

MB = 1024 * 1024


class VhostUserBlkBackendType(Enum):
    """vhost-user-blk backend type"""

    QEMU = "Qemu"
    CROSVM = "Crosvm"


def partuuid_and_disk_path(rootfs_ubuntu_22, disk_path):
    """
    We create a new file with specified path, get its partuuid and use it as a rootfs.
    """
    initial_size = rootfs_ubuntu_22.stat().st_size + 50 * MB
    disk_path.touch()
    os.truncate(disk_path, initial_size)
    check_output(f"echo type=83 | sfdisk --no-tell-kernel {str(disk_path)}", shell=True)
    check_output(
        f"dd bs=1M seek=1 if={str(rootfs_ubuntu_22)} of={disk_path}", shell=True
    )
    ptuuid = check_output(
        f"blkid -s PTUUID -o value {disk_path}", shell=True, encoding="ascii"
    ).strip()
    # PARTUUID for an msdos partition table is PTUUID-<PART NUMBER>
    partuuid = ptuuid + "-01"

    return (partuuid, disk_path)


class VhostUserBlkBackend(ABC):
    """vhost-user-blk backend base class"""

    @classmethod
    def get_all_subclasses(cls):
        """Get all subclasses of the class."""
        subclasses = {}
        for subclass in cls.__subclasses__():
            subclasses[subclass.__name__] = subclass
            subclasses.update(subclass.get_all_subclasses())
        return subclasses

    @classmethod
    def with_backend(cls, backend: VhostUserBlkBackendType, *args, **kwargs):
        """Get a backend of a specific type."""
        subclasses = cls.get_all_subclasses()
        return subclasses[backend.value + cls.__name__](*args, **kwargs)

    def __init__(
        self,
        host_mem_path,
        chroot,
        backend_id,
        readonly,
    ):
        self.host_mem_path = host_mem_path
        self.socket_path = Path(chroot) / f"{backend_id}_vhost_user.sock"
        self.readonly = readonly
        self.proc = None

    def spawn(self, uid, gid):
        """
        Spawn a backend.

        Return socket path in the jail that can be used with FC API.
        """
        assert not self.proc, "backend already spawned"
        args = self._spawn_cmd()
        proc = subprocess.Popen(args)

        # Give the backend time to initialise.
        time.sleep(1)

        assert proc is not None and proc.poll() is None, "backend is not up"
        assert self.socket_path.exists()

        os.chown(self.socket_path, uid, gid)

        self.proc = proc

        return str(Path("/") / os.path.basename(self.socket_path))

    @abstractmethod
    def _spawn_cmd(self):
        """Return a spawn command for the backend"""
        return ""

    @abstractmethod
    def resize(self, new_size):
        """Resize the vhost-user-backed drive"""

    def pin(self, cpu_id: int):
        """Pin the vhost-user backend to a CPU list."""
        return utils.set_cpu_affinity(self.proc.pid, [cpu_id])

    def kill(self):
        """Kill the backend"""
        if self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait()
            os.remove(self.socket_path)
        assert not os.path.exists(self.socket_path)


class QemuVhostUserBlkBackend(VhostUserBlkBackend):
    """vhost-user-blk backend implementaiton for Qemu backend"""

    def _spawn_cmd(self):
        args = [
            "vhost-user-blk",
            "--socket-path",
            self.socket_path,
            "--blk-file",
            self.host_mem_path,
        ]
        if self.readonly:
            args.append("--read-only")
        return args

    def resize(self, new_size):
        raise NotImplementedError("not supported for Qemu backend")


class CrosvmVhostUserBlkBackend(VhostUserBlkBackend):
    """vhost-user-blk backend implementaiton for crosvm backend"""

    def __init__(
        self,
        host_mem_path,
        chroot,
        backend_id,
        readonly=False,
    ):
        super().__init__(
            host_mem_path,
            chroot,
            backend_id,
            readonly,
        )
        self.ctr_socket_path = Path(chroot) / f"{backend_id}_ctr.sock"

    def _spawn_cmd(self):
        ro = ",ro" if self.readonly else ""
        args = [
            "crosvm",
            "--log-level",
            "off",
            "devices",
            "--disable-sandbox",
            "--control-socket",
            self.ctr_socket_path,
            "--block",
            f"vhost={self.socket_path},path={self.host_mem_path}{ro}",
        ]
        return args

    def resize(self, new_size):
        assert self.proc, "backend is not spawned"
        assert self.ctr_socket_path.exists()

        utils.check_output(
            f"crosvm disk resize 0 {new_size * 1024 * 1024} {self.ctr_socket_path}"
        )

    def kill(self):
        super().kill()
        assert self.proc.poll() is not None
        os.remove(self.ctr_socket_path)
        assert not os.path.exists(self.ctr_socket_path)
