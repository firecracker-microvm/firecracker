# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define a class for creating the jailed context."""

import os
import shutil
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

    # Keep in sync with parameters from code base.
    jailer_id = None
    exec_file = None
    uid = None
    gid = None
    chroot_base = None
    daemonize = None
    new_pid_ns = None
    extra_args = None
    api_socket_name = None
    cgroups = None
    resource_limits = None
    cgroup_ver = None
    parent_cgroup = None

    def __init__(
        self,
        jailer_id,
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
        assert jailer_id is not None
        self.exec_file = exec_file
        self.uid = uid
        self.gid = gid
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
        assert chroot_base is not None

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
        jailer_param_list = []

        # Pretty please, try to keep the same order as in the code base.
        if self.jailer_id is not None:
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

    def chroot_base_with_id(self):
        """Return the MicroVM chroot base + MicroVM ID."""
        return self.chroot_base / Path(self.exec_file).name / self.jailer_id

    def api_socket_path(self):
        """Return the MicroVM API socket path."""
        return os.path.join(self.chroot_path(), self.api_socket_name)

    def chroot_path(self):
        """Return the MicroVM chroot path."""
        return os.path.join(self.chroot_base_with_id(), "root")

    def jailed_path(self, file_path, create=False, subdir="."):
        """Create a hard link or block special device owned by uid:gid.

        Create a hard link or block special device from the specified file,
        changes the owner to uid:gid, and returns a path to the file which is
        valid within the jail.
        """
        file_path = Path(file_path)
        chroot_path = Path(self.chroot_path())
        global_p = chroot_path / subdir / file_path.name
        global_p.parent.mkdir(parents=True, exist_ok=True)
        jailed_p = Path("/") / subdir / file_path.name
        if create:
            stat_src = file_path.stat()
            if file_path.is_block_device():
                perms = stat.S_IRUSR | stat.S_IWUSR
                os.mknod(global_p, mode=stat.S_IFBLK | perms, device=stat_src.st_rdev)
            else:
                stat_dst = chroot_path.stat()
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
        os.makedirs(self.chroot_base, exist_ok=True)

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
        # pylint: disable=subprocess-run-check
        tasks_file = "/sys/fs/cgroup/{}/{}/{}/tasks".format(
            controller, FC_BINARY_NAME, self.jailer_id
        )

        # If tests do not call start on machines, the cgroups will not be
        # created.
        if not os.path.exists(tasks_file):
            return True

        cmd = "cat {}".format(tasks_file)
        result = utils.check_output(cmd)

        tasks_split = result.stdout.splitlines()
        for task in tasks_split:
            if os.path.exists("/proc/{}".format(task)):
                raise TimeoutError
        return True

    @property
    def pid_file(self):
        """Return the PID file of the jailed process"""
        return Path(self.chroot_path()) / (self.exec_file.name + ".pid")
