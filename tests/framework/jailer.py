"""Define a class for creating the jailed context."""

import os
import shutil

from subprocess import run, PIPE
from time import sleep

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
    seccomp_level = None

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
            seccomp_level=0
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
        self.seccomp_level = seccomp_level

    def __del__(self):
        """Cleanup this jailer context."""
        self.cleanup()

    def construct_param_list(self):
        """Create the list of parameters we want the jailer to start with.

        We want to be able to vary any parameter even the required ones as we
        might want to add integration tests that validate the enforcement of
        mandatory arguments.
        """
        jailer_params_list = []

        # Pretty please, try to keep the same order as in the code base.
        if self.jailer_id is not None:
            jailer_params_list.extend(['--id', str(self.jailer_id)])
        if self.exec_file is not None:
            jailer_params_list.extend(['--exec-file', str(self.exec_file)])
        if self.numa_node is not None:
            jailer_params_list.extend(['--node', str(self.numa_node)])
        if self.uid is not None:
            jailer_params_list.extend(['--uid', str(self.uid)])
        if self.gid is not None:
            jailer_params_list.extend(['--gid', str(self.gid)])
        if self.chroot_base is not None:
            jailer_params_list.extend(
                ['--chroot-base-dir', str(self.chroot_base)]
            )
        if self.netns is not None:
            jailer_params_list.extend(['--netns', str(self.netns_file_path())])
        if self.daemonize:
            jailer_params_list = ['jailer'] + jailer_params_list
            jailer_params_list.append('--daemonize')
        if self.seccomp_level is not None:
            jailer_params_list.extend(
                ['--seccomp-level', str(self.seccomp_level)]
            )
        return jailer_params_list

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
        return os.path.join(self.chroot_base_with_id(), API_USOCKET_NAME)

    def chroot_path(self):
        """Return the MicroVM chroot path."""
        return os.path.join(self.chroot_base_with_id(), 'root')

    def jailed_path(self, file_path, create=False):
        """Create a hard link owned by uid:gid.

        Create a hard link to the specified file, changes the owner to
        uid:gid, and returns a path to the link which is valid within the jail.
        """
        file_name = os.path.basename(file_path)
        global_p = os.path.join(self.chroot_path(), file_name)
        jailed_p = os.path.join("/", file_name)

        if create:
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
        sleep(1)

        shutil.rmtree(self.chroot_base_with_id(), ignore_errors=True)

        if self.netns:
            _ = run(
                'ip netns del {}'.format(self.netns),
                shell=True,
                stderr=PIPE
            )

        # Remove the cgroup folders. This is a hacky solution, which assumes
        # cgroup controllers are mounted as they are right now in AL2.
        # TODO: better solution at some point?
        # The base /sys/fs/cgroup/<controller>/firecracker folder will remain,
        # because we can't remove it unless we're sure there's no other running
        # microVM.
        # TODO: better solution at some point?
        controllers = ('cpu', 'cpuset', 'pids')
        for controller in controllers:
            run_command = 'rmdir /sys/fs/cgroup/{}/{}/{}'.format(
                controller,
                FC_BINARY_NAME,
                self.jailer_id
            )
            # TODO: temporary solution; read tasks file and kill the tasks
            _ = run(run_command, shell=True, stderr=PIPE)
