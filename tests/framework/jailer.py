# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define a class for creating the jailed context."""

import os
import shutil
import stat

from subprocess import run, PIPE

from retry.api import retry_call

from framework.defs import API_USOCKET_NAME, FC_BINARY_NAME, \
    JAILER_DEFAULT_CHROOT


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

    def __init__(
            self,
            jailer_id,
            exec_file,
            numa_node=0,
            uid=1234,
            gid=1234,
            chroot_base=JAILER_DEFAULT_CHROOT,
            netns=None,
            daemonize=True,
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

    def __del__(self):
        """Cleanup this jailer context."""
        self.cleanup()

    def construct_param_list(self, config_file, no_api):
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
        if config_file is not None:
            jailer_param_list.extend(['--'])
            jailer_param_list.extend(['--config-file', str(config_file)])
        if no_api:
            jailer_param_list.append('--no-api')
        return jailer_param_list

    def chroot_base_with_id(self):
        """Return the MicroVM chroot base + MicroVM ID."""
        return os.path.join(
            self.chroot_base if self.chroot_base is not None
            else JAILER_DEFAULT_CHROOT,
            FC_BINARY_NAME,
            self.jailer_id
        )

    def api_socket_path(self):
        """Return the MicroVM API socket path."""
        return os.path.join(self.chroot_path(), API_USOCKET_NAME)

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
                run(cmd, check=True)
            else:
                cmd = 'ln -f {} {}'.format(file_path, global_p)
                run(cmd, shell=True, check=True)
            cmd = 'chown {}:{} {}'.format(self.uid, self.gid, global_p)
            run(cmd, shell=True, check=True)
        return jailed_p

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
            else JAILER_DEFAULT_CHROOT,
            exist_ok=True
        )
        if self.netns:
            run('ip netns add {}'.format(self.netns), shell=True, check=True)

    def cleanup(self):
        """Clean up this jailer context."""
        # pylint: disable=subprocess-run-check
        shutil.rmtree(self.chroot_base_with_id(), ignore_errors=True)

        if self.netns:
            _ = run(
                'ip netns del {}'.format(self.netns),
                shell=True,
                stderr=PIPE
            )

        # Remove the cgroup folders associated with this microvm.
        # The base /sys/fs/cgroup/<controller>/firecracker folder will remain,
        # because we can't remove it unless we're sure there's no other running
        # microVM.

        # Firecracker is interested in these 3 cgroups for the moment.
        controllers = ('cpu', 'cpuset', 'pids')
        for controller in controllers:
            # Obtain the tasks from each cgroup and wait on them before
            # removing the microvm's associated cgroup folder.
            try:
                retry_call(
                    f=self._kill_crgoup_tasks,
                    fargs=[controller],
                    exceptions=TimeoutError,
                    max_delay=5
                )
            except TimeoutError:
                pass

            # As the files inside a cgroup aren't real, they can't need
            # to be removed, that is why 'rm -rf' and 'rmdir' fail.
            # We only need to remove the cgroup directories. The "-depth"
            # argument tells find to do a depth first recursion, so that
            # we remove any sub cgroups first if they are there.
            back_cmd = r'-depth -type d -exec rmdir {} \;'
            cmd = 'find /sys/fs/cgroup/{}/{}/{} {}'.format(
                controller,
                FC_BINARY_NAME,
                self.jailer_id,
                back_cmd
            )
            # We do not need to know if it succeeded or not; afterall, we are
            # trying to clean up resources created by the jailer itself not
            # the testing system.
            _ = run(cmd, shell=True, stderr=PIPE)

    def _kill_crgoup_tasks(self, controller):
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
        tasks = run(cmd, shell=True, stdout=PIPE).stdout.decode('utf-8')

        tasks_split = tasks.splitlines()
        for task in tasks_split:
            if os.path.exists("/proc/{}".format(task)):
                raise TimeoutError
        return True
