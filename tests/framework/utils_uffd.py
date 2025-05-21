# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""UFFD related utility functions"""

import os
import stat
import subprocess
import time
from pathlib import Path

from framework.utils import chroot
from host_tools import cargo_build

SOCKET_PATH = "/firecracker-uffd.sock"


class UffdHandler:
    """Describe the UFFD page fault handler process."""

    def __init__(
        self, name, socket_path, snapshot: "Snapshot", chroot_path, log_file_name
    ):
        """Instantiate the handler process with arguments."""
        self._proc = None
        self._handler_name = name
        self.socket_path = socket_path
        self.snapshot = snapshot
        self._chroot = chroot_path
        self._log_file = log_file_name

    def spawn(self, uid, gid):
        """Spawn handler process using arguments provided."""

        with chroot(self._chroot):
            st = os.stat(self._handler_name)
            os.chmod(self._handler_name, st.st_mode | stat.S_IEXEC)

            chroot_log_file = Path("/") / self._log_file
            with open(chroot_log_file, "w", encoding="utf-8") as logfile:
                args = [
                    f"/{self._handler_name}",
                    self.socket_path,
                    self.snapshot.mem.name,
                ]
                self._proc = subprocess.Popen(
                    args, stdout=logfile, stderr=subprocess.STDOUT
                )

            # Give it time start and fail, if it really has too (bad things happen).
            time.sleep(1)
            if not self.is_running():
                print(chroot_log_file.read_text(encoding="utf-8"))
                assert False, "Could not start PF handler!"

            # The page fault handler will create the socket path with root rights.
            # Change rights to the jailer's.
            os.chown(self.socket_path, uid, gid)

    @property
    def proc(self):
        """Return UFFD handler process."""
        return self._proc

    def is_running(self):
        """Check if UFFD process is running"""
        return self.proc is not None and self.proc.poll() is None

    @property
    def log_file(self):
        """Return the path to the UFFD handler's log file"""
        return Path(self._chroot) / Path(self._log_file)

    @property
    def log_data(self):
        """Return the log data of the UFFD handler"""
        if self.log_file is None:
            return ""
        return self.log_file.read_text(encoding="utf-8")

    def kill(self):
        """Kills the uffd handler process"""
        assert self.is_running()

        self.proc.kill()

    def mark_killed(self):
        """Marks the uffd handler as already dead"""
        assert not self.is_running()

        self._proc = None

    def __del__(self):
        """Tear down the UFFD handler process."""
        if self.is_running():
            self.kill()


def spawn_pf_handler(vm, handler_path, jailed_snapshot):
    """Spawn page fault handler process."""
    # Copy snapshot memory file into chroot of microVM.
    # Copy the valid page fault binary into chroot of microVM.
    jailed_handler = vm.create_jailed_resource(handler_path)
    handler_name = os.path.basename(jailed_handler)

    uffd_handler = UffdHandler(
        handler_name, SOCKET_PATH, jailed_snapshot, vm.chroot(), "uffd.log"
    )
    uffd_handler.spawn(vm.jailer.uid, vm.jailer.gid)

    return uffd_handler


def uffd_handler(handler_name, **kwargs):
    """Retrieves the uffd handler with the given name"""
    return cargo_build.get_example(f"uffd_{handler_name}_handler", **kwargs)
