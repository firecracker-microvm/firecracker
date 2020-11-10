# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define a class for creating the jailed context."""

import os
import shutil
import stat
from pathlib import Path
from retry.api import retry_call
import framework.utils as utils
from framework.defs import FC_BINARY_NAME

# Default name for the socket used for API calls.
DEFAULT_USOCKET_NAME = 'run/firecracker.socket'
# The default location for the chroot.
DEFAULT_CHROOT_PATH = '/srv/jailer'


class JailerContext:
    """Represents jailer configuration and contains jailer helper functions.

    Each microvm will have a jailer configuration associated with it.
    """

    # Keep in sync with parameters from code base.
    jailer_id = None
    exec_file = None
    numa_node = None
    uid = None
    gid = None
    chroot_base = None
    netns = None
    daemonize = None
    extra_args = None
    api_socket_name = None
    cgroups = None

    def __init__(
            self,
            jailer_id,
            exec_file,
            numa_node=None,
            uid=1234,
            gid=1234,
            chroot_base=DEFAULT_CHROOT_PATH,
            netns=None,
            daemonize=True,
            cgroups=None,
            **extra_args
    ):
        """Set up jailer fields.

        This plays the role of a default constructor as it populates
        the jailer's fields with some default values. Each field can be
        further adjusted by each test even with None values.
        """
        self.jailer_id = jailer_id
        self.exec_file = exec_file
        self.numa_node = numa_node
        self.uid = uid
        self.gid = gid
        self.chroot_base = chroot_base
        self.netns = netns if netns is not None else jailer_id
        self.daemonize = daemonize
        self.extra_args = extra_args
        self.api_socket_name = DEFAULT_USOCKET_NAME
        self.cgroups = cgroups

    def __del__(self):
        """Cleanup this jailer context."""
        self.cleanup()

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
            jailer_param_list.extend(['--id', str(self.jailer_id)])
        if self.exec_file is not None:
            jailer_param_list.extend(['--exec-file', str(self.exec_file)])
        if self.numa_node is not None:
            jailer_param_list.extend(['--node', str(self.numa_node)])
        if self.uid is not None:
            jailer_param_list.extend(['--uid', str(self.uid)])
        if self.gid is not None:
            jailer_param_list.extend(['--gid', str(self.gid)])
        if self.chroot_base is not None:
            jailer_param_list.extend(
                ['--chroot-base-dir', str(self.chroot_base)]
            )
        if self.netns is not None:
            jailer_param_list.extend(['--netns', str(self.netns_file_path())])
        if self.daemonize:
            jailer_param_list.append('--daemonize')
        if self.cgroups is not None:
            for cgroup in self.cgroups:
                jailer_param_list.extend(['--cgroup', str(cgroup)])
        # applying neccessory extra args if needed
        if len(self.extra_args) > 0:
            jailer_param_list.append('--')
            for key, value in self.extra_args.items():
                jailer_param_list.append('--{}'.format(key))
                if value is not None:
                    jailer_param_list.append(value)
                    if key == "api-sock":
                        self.api_socket_name = value
        return jailer_param_list
    # pylint: enable=too-many-branches

    def chroot_base_with_id(self):
        """Return the MicroVM chroot base + MicroVM ID."""
        return os.path.join(
            self.chroot_base if self.chroot_base is not None
            else DEFAULT_CHROOT_PATH,
            Path(self.exec_file).name,
            self.jailer_id
        )

    def api_socket_path(self):
        """Return the MicroVM API socket path."""
        return os.path.join(self.chroot_path(), self.api_socket_name)

    def chroot_path(self):
        """Return the MicroVM chroot path."""
        return os.path.join(self.chroot_base_with_id(), 'root')

    def jailed_path(self, file_path, create=False, create_jail=False):
        """Create a hard link or block special device owned by uid:gid.

        Create a hard link or block special device from the specified file,
        changes the owner to uid:gid, and returns a path to the file which is
        valid within the jail.
        """
        file_name = os.path.basename(file_path)
        global_p = os.path.join(self.chroot_path(), file_name)
        if create_jail:
            os.makedirs(self.chroot_path(), exist_ok=True)
        jailed_p = os.path.join("/", file_name)
        if create:
            stat_result = os.stat(file_path)
            if stat.S_ISBLK(stat_result.st_mode):
                cmd = [
                    'mknod', global_p, 'b',
                    str(os.major(stat_result.st_rdev)),
                    str(os.minor(stat_result.st_rdev))
                ]
                utils.run_cmd(cmd)
            else:
                cmd = 'ln -f {} {}'.format(file_path, global_p)
                utils.run_cmd(cmd)
            cmd = 'chown {}:{} {}'.format(self.uid, self.gid, global_p)
            utils.run_cmd(cmd)
        return jailed_p

    def copy_into_root(self, file_path, create_jail=False):
        """Copy a file in the jail root, owned by uid:gid.

        Copy a file in the jail root, creating the folder path if
        not existent, then change their owner to uid:gid.
        """
        global_path = os.path.join(
            self.chroot_path(), file_path.strip(os.path.sep))
        if create_jail:
            os.makedirs(self.chroot_path(), exist_ok=True)

        os.makedirs(os.path.dirname(global_path), exist_ok=True)

        shutil.copy(file_path, global_path)

        cmd = 'chown {}:{} {}'.format(
            self.uid, self.gid, global_path)
        utils.run_cmd(cmd)

    def netns_file_path(self):
        """Get the host netns file path for a jailer context.

        Returns the path on the host to the file which represents the netns,
        and which must be passed to the jailer as the value of the --netns
        parameter, when in use.
        """
        if self.netns:
            return '/var/run/netns/{}'.format(self.netns)
        return None

    def netns_cmd_prefix(self):
        """Return the jailer context netns file prefix."""
        if self.netns:
            return 'ip netns exec {} '.format(self.netns)
        return ''

    def setup(self):
        """Set up this jailer context."""
        os.makedirs(
            self.chroot_base if self.chroot_base is not None
            else DEFAULT_CHROOT_PATH,
            exist_ok=True
        )
        if self.netns:
            utils.run_cmd('ip netns add {}'.format(self.netns))

    def cleanup(self):
        """Clean up this jailer context."""
        # pylint: disable=subprocess-run-check
        if self.jailer_id:
            shutil.rmtree(self.chroot_base_with_id(), ignore_errors=True)

        if self.netns:
            utils.run_cmd('ip netns del {}'.format(self.netns))

        # Remove the cgroup folders associated with this microvm.
        # The base /sys/fs/cgroup/<controller>/firecracker folder will remain,
        # because we can't remove it unless we're sure there's no other running
        # microVM.

        if self.cgroups:
            controllers = set()

            # Extract the controller for every cgroup that needs to be set.
            for cgroup in self.cgroups:
                controllers.add(cgroup.split('.')[0])

            for controller in controllers:
                # Obtain the tasks from each cgroup and wait on them before
                # removing the microvm's associated cgroup folder.
                try:
                    retry_call(
                        f=self._kill_cgroup_tasks,
                        fargs=[controller],
                        exceptions=TimeoutError,
                        max_delay=5
                    )
                except TimeoutError:
                    pass

                # Remove cgroups and sub cgroups.
                back_cmd = r'-depth -type d -exec rmdir {} \;'
                cmd = 'find /sys/fs/cgroup/{}/{}/{} {}'.format(
                    controller,
                    FC_BINARY_NAME,
                    self.jailer_id,
                    back_cmd
                )
                # We do not need to know if it succeeded or not; afterall,
                # we are trying to clean up resources created by the jailer
                # itself not the testing system.
                utils.run_cmd(cmd, ignore_return_code=True)

    def _kill_cgroup_tasks(self, controller):
        """Simulate wait on pid.

        Read the tasks file and stay there until /proc/{pid}
        disappears. The retry function that calls this code makes
        sure we do not timeout.
        """
        # pylint: disable=subprocess-run-check
        tasks_file = '/sys/fs/cgroup/{}/{}/{}/tasks'.format(
            controller,
            FC_BINARY_NAME,
            self.jailer_id
        )

        # If tests do not call start on machines, the cgroups will not be
        # created.
        if not os.path.exists(tasks_file):
            return True

        cmd = 'cat {}'.format(tasks_file)
        result = utils.run_cmd(cmd)

        tasks_split = result.stdout.splitlines()
        for task in tasks_split:
            if os.path.exists("/proc/{}".format(task)):
                raise TimeoutError
        return True
