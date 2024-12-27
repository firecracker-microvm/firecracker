# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define a class for creating the jailed context."""

import os
import shutil
import signal
import stat
from pathlib import Path

from tenacity import Retrying, retry_if_exception_type, stop_after_delay

from framework import defs, utils
from framework.defs import FC_BINARY_NAME

# Default name for the socket used for API calls.
DEFAULT_USOCKET_NAME = "run/firecracker.socket"
# The default location for the chroot.
DEFAULT_CHROOT_PATH = f"{defs.DEFAULT_TEST_SESSION_ROOT_PATH}/jailer"


class JailerContext:
    """Represents jailer configuration and contains jailer helper functions.

    Each microvm will have a jailer configuration associated with it.
    """

    def __init__(
        self,
        jailer_id,
        jailer_binary_path,
        exec_file,
        uid=1234,
        gid=1234,
        chroot_base=DEFAULT_CHROOT_PATH,
        netns=None,
        daemonize=True,
        new_pid_ns=False,
        cgroups=None,
        resource_limits=None,
        cgroup_ver=None,
        parent_cgroup=None,
        **extra_args,
    ):
        """Set up jailer fields.

        This plays the role of a default constructor as it populates
        the jailer's fields with some default values. Each field can be
        further adjusted by each test even with None values.
        """
        self.jailer_id = jailer_id
        assert jailer_id
        self.jailer_bin_path = jailer_binary_path
        self.exec_file = exec_file
        self.uid = uid
        self.gid = gid
        assert chroot_base is not None
        self.chroot_base = Path(chroot_base)
        self.netns = netns
        self.daemonize = daemonize
        self.new_pid_ns = new_pid_ns
        self.extra_args = extra_args
        self.api_socket_name = DEFAULT_USOCKET_NAME
        self.cgroups = cgroups or []
        self.resource_limits = resource_limits
        self.cgroup_ver = cgroup_ver
        self.parent_cgroup = parent_cgroup

    # Disabling 'too-many-branches' warning for this function as it needs to
    # check every argument, so the number of branches will increase
    # with every new argument.
    # pylint: disable=too-many-branches
    def construct_param_list(self):
        """Create the list of parameters we want the jailer to start with.

        We want to be able to vary any parameter even the required ones as we
        might want to add integration tests that validate the enforcement of
        mandatory arguments.
        """
        jailer_param_list = [str(self.jailer_bin_path)]

        # Pretty please, try to keep the same order as in the code base.
        jailer_param_list.extend(["--id", str(self.jailer_id)])
        if self.exec_file is not None:
            jailer_param_list.extend(["--exec-file", str(self.exec_file)])
        if self.uid is not None:
            jailer_param_list.extend(["--uid", str(self.uid)])
        if self.gid is not None:
            jailer_param_list.extend(["--gid", str(self.gid)])
        if self.chroot_base is not None:
            jailer_param_list.extend(["--chroot-base-dir", str(self.chroot_base)])
        if self.netns is not None:
            jailer_param_list.extend(["--netns", str(self.netns.path)])
        if self.daemonize:
            jailer_param_list.append("--daemonize")
        if self.new_pid_ns:
            jailer_param_list.append("--new-pid-ns")
        if self.parent_cgroup:
            jailer_param_list.extend(["--parent-cgroup", str(self.parent_cgroup)])
        if self.cgroup_ver:
            jailer_param_list.extend(["--cgroup-version", str(self.cgroup_ver)])
        if self.cgroups:
            for cgroup in self.cgroups:
                jailer_param_list.extend(["--cgroup", str(cgroup)])
        if self.resource_limits is not None:
            for limit in self.resource_limits:
                jailer_param_list.extend(["--resource-limit", str(limit)])
        # applying necessary extra args if needed
        if len(self.extra_args) > 0:
            jailer_param_list.append("--")
            for key, value in self.extra_args.items():
                jailer_param_list.append("--{}".format(key))
                if value is not None:
                    jailer_param_list.append(value)
                    if key == "api-sock":
                        self.api_socket_name = value
        return jailer_param_list

    # pylint: enable=too-many-branches

    @property
    def chroot(self):
        """Return where the jailer will place the chroot"""
        return self.chroot_base / self.exec_file.name / self.jailer_id / "root"

    def api_socket_path(self):
        """Return the MicroVM API socket path."""
        return self.chroot / self.api_socket_name

    def jailed_path(self, file_path, subdir="."):
        """Create a hard link or block special device owned by uid:gid.

        Create a hard link or block special device from the specified file,
        changes the owner to uid:gid, and returns a path to the file which is
        valid within the jail.
        """
        file_path = Path(file_path)
        global_p = self.chroot / subdir / file_path.name
        global_p.parent.mkdir(parents=True, exist_ok=True)
        jailed_p = Path("/") / subdir / file_path.name
        if not global_p.exists():
            stat_src = file_path.stat()
            if file_path.is_block_device():
                perms = stat.S_IRUSR | stat.S_IWUSR
                os.mknod(global_p, mode=stat.S_IFBLK | perms, device=stat_src.st_rdev)
            else:
                stat_dst = self.chroot.stat()
                if stat_src.st_dev == stat_dst.st_dev:
                    # if they are in the same device, hardlink
                    global_p.unlink(missing_ok=True)
                    global_p.hardlink_to(file_path)
                else:
                    # otherwise, copy
                    shutil.copyfile(file_path, global_p)

        os.chown(global_p, self.uid, self.gid)
        return str(jailed_p)

    def setup(self):
        """Set up this jailer context."""
        os.makedirs(self.chroot, exist_ok=True)
        # Copy the /etc/localtime file in the jailer root
        self.jailed_path("/etc/localtime", subdir="etc")

    def cleanup(self):
        """Clean up this jailer context."""

        # Remove the cgroup folders associated with this microvm.
        # The base /sys/fs/cgroup/<controller>/firecracker folder will remain,
        # because we can't remove it unless we're sure there's no other running
        # microVM.

        if self.cgroups:
            controllers = set()

            # Extract the controller for every cgroup that needs to be set.
            for cgroup in self.cgroups:
                controllers.add(cgroup.split(".")[0])

            for controller in controllers:
                # Obtain the tasks from each cgroup and wait on them before
                # removing the microvm's associated cgroup folder.
                try:
                    for attempt in Retrying(
                        retry=retry_if_exception_type(TimeoutError),
                        stop=stop_after_delay(5),
                        reraise=True,
                    ):
                        with attempt:
                            self._kill_cgroup_tasks(controller)
                except TimeoutError:
                    pass

                # Remove cgroups and sub cgroups.
                back_cmd = r"-depth -type d -exec rmdir {} \;"
                cmd = "find /sys/fs/cgroup/{}/{}/{} {}".format(
                    controller, FC_BINARY_NAME, self.jailer_id, back_cmd
                )
                # We do not need to know if it succeeded or not; afterall,
                # we are trying to clean up resources created by the jailer
                # itself not the testing system.
                utils.run_cmd(cmd)

    def _kill_cgroup_tasks(self, controller):
        """Simulate wait on pid.

        Read the tasks file and stay there until /proc/{pid}
        disappears. The retry function that calls this code makes
        sure we do not timeout.
        """
        tasks_file = Path(
            f"/sys/fs/cgroup/{controller}/{FC_BINARY_NAME}/{self.jailer_id}/tasks"
        )

        # If tests do not call start on machines, the cgroups will not be
        # created.
        if not tasks_file.exists():
            return True

        for task in tasks_file.read_text(encoding="ascii").splitlines():
            if Path(f"/proc/{task}").exists():
                raise TimeoutError
        return True

    @property
    def pid(self):
        """Return the PID of the jailed process"""
        # Read the PID stored inside the file.
        pid_file = self.chroot / (self.exec_file.name + ".pid")
        if not pid_file.exists():
            return None
        return int(pid_file.read_text(encoding="ascii"))

    def spawn(self, pre_cmd):
        """Spawn Firecracker and daemonize via the Jailer"""
        cmd = pre_cmd or []
        cmd += self.construct_param_list()
        if not self.daemonize:
            raise RuntimeError("Use a different jailer")
        return utils.check_output(cmd, shell=False)

    def kill(self):
        """Kill the Firecracker process"""
        if self.pid is not None:
            os.kill(self.pid, signal.SIGKILL)
