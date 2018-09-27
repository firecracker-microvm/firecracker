"""Define a class for creating the jailed context."""

import os
import shutil

from subprocess import run, PIPE
from time import sleep

from framework.defs import FC_BINARY_NAME


class JailerContext:
    """Represents jailer configuration and contains jailer helper functions.

    Each microvm will have a jailer configuration associated with it.
    """

    def __init__(
            self,
            microvm_slot_id: str,
            numa_node: int,
            uid: int,
            gid: int,
            chroot_base: str,
            netns: str,
            daemonize: bool
    ):
        """Set up jailer fields."""
        self.microvm_slot_id = microvm_slot_id
        self.numa_node = numa_node
        self.uid = uid
        self.gid = gid
        self.chroot_base = chroot_base
        self.netns = netns
        self.daemonize = daemonize

    @staticmethod
    def default_with_id(slot_id: str):
        """Create a default jailer with a given ID."""
        return JailerContext(
            microvm_slot_id=slot_id,
            numa_node=0,
            uid=1234,
            gid=1234,
            chroot_base='/srv/jailer',
            netns=slot_id,
            daemonize=True
        )

    def chroot_base_with_id(self):
        """Return the MicroVM chroot base + MicroVM ID."""
        return os.path.join(
            self.chroot_base,
            FC_BINARY_NAME,
            self.microvm_slot_id
        )

    def api_socket_path(self):
        """Return the MicroVM API socket path."""
        return os.path.join(self.chroot_base_with_id(), 'api.socket')

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

    def setup(self):
        """Set up this jailer context."""
        run('mkdir -p {}'.format(self.chroot_base), shell=True, check=True)
        if self.netns:
            run('ip netns add {}'.format(self.netns), shell=True, check=True)

    def cleanup(self):
        """Clean up this jailer context."""
        # We can't delete the entire folder tree here, because other slots
        # might still be running ?!
        shutil.rmtree(self.chroot_base_with_id(), ignore_errors=True)

        # Remove the cgroup folders. This is a hacky solution, which assumes
        # cgroup controllers are mounted as they are right now in AL2.
        # TODO: better solution at some point?
        # The base /sys/fs/cgroup/<controller>/firecracker folder will remain,
        # because we can't remove it unless we're sure there's no other running
        # slot/microVM.
        # TODO: better solution at some point?
        sleep(1)
        controllers = ('cpu', 'cpuset', 'pids')
        for controller in controllers:
            run_command = 'rmdir /sys/fs/cgroup/{}/{}/{}'.format(
                controller,
                FC_BINARY_NAME,
                self.microvm_slot_id
            )
            # TODO: temporary solution; read tasks file and kill the tasks
            _ = run(run_command, shell=True, stderr=PIPE)

        if self.netns:
            _ = run(
                'ip netns del {}'.format(self.netns),
                shell=True,
                stderr=PIPE
            )
