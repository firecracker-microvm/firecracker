"""
This module defines `MicrovmSlot` and `Microvm`, which can be used together
to create, test drive, and destroy microvms (based on microvm images).

# Notes

- Programming here is not defensive, since tests systems turn false negatives
  into a quality-improving positive feedback loop.
"""

import os
import shutil
import urllib
import uuid

from subprocess import run


class MicrovmSlot:
    """
    A microvm slot with everything that's needed for a Firecracker microvm:
    - A location for kernel, rootfs, and other fsfiles.
    - The ability to create and keep track of additional fsfiles.
    - The ability to create and keep track of tap devices.

    `setup()` and `teardown()` handle the lifecycle of these resources.

    Microvm Slot Layout
    -------------------

    There is a fixed tree layout for a microvm slot:

    ``` file_tree
    <microvm_slot_name>/
        kernel/
            <kernel_file_n>
            ....
        fsfiles/
            <fsfile_n>
            ...
    ```

    Creating a microvm slot does *not* make a microvm image available, or any
    other microvm resources. A microvm image must be added to the microvm slot.
    MicrovmSlot methods can be used to create tap devices and fsfiles.
    """

    DEFAULT_MICROVM_ROOT_PATH = '/tmp/firecracker/'
    """ Default path on the system where microvm slots will be created. """

    MICROVM_SLOT_DIR_PREFIX = 'microvm_slot_'

    MICROVM_SLOT_KERNEL_RELPATH = 'kernel/'
    """ Relative path to the root of a slot for kernel files. """

    MICROVM_SLOT_FSFILES_RELPATH = 'fsfiles/'
    """ Relative path to the root of a slot for filesystem files. """

    KNOWN_FILEFS_FORMATS = {'ext4'}

    created_microvm_root_path = False
    """
    Class variable to keep track if the root path was created by an object of
    this class, since we need to clean up if that is the case.
    """

    def __init__(
        self, id: str="firecracker_slot",
        microvm_root_path=DEFAULT_MICROVM_ROOT_PATH
    ):
        self.id = id
        self.microvm_root_path = microvm_root_path
        self.path = microvm_root_path + self.MICROVM_SLOT_DIR_PREFIX + id + '/'
        self.kernel_path = self.path + self.MICROVM_SLOT_KERNEL_RELPATH
        self.fsfiles_path = self.path + self.MICROVM_SLOT_FSFILES_RELPATH

        self.kernel_file = ''
        """ Assigned once an microvm image populates this slot. """
        self.rootfs_file = ''
        """ Assigned once an microvm image populates this slot. """

        self.fsfiles = set()
        """ A set of file systems for this microvm slot. """
        self.taps = set()
        """ A set of tap devices for this microvm slot. """

    def say(self, message: str):
        return "Microvm slot " + self.id + ": " + message

    def setup(self):
        """
        Creates a local microvm slot under
        `[self.microvm_root_path]/[self.path]/`. Also creates
        `self.microvm_root_path` if it does not exist.
        """

        if not os.path.exists(self.microvm_root_path):
            os.makedirs(self.microvm_root_path)
            self.created_microvm_root_path = True

        os.makedirs(self.path)
        os.makedirs(self.kernel_path)
        os.makedirs(self.fsfiles_path)

    def make_fsfile(self, name: str=None, size: int=256, fmt: str='ext4'):
        """
        Creates an new file system in a file. `size` is in MiB. Raises if the
        file system format is not supported, of if the file already exists.
        """

        if fmt not in self.KNOWN_FILEFS_FORMATS:
            raise ValueError(
                self.say('Format not in: + ' + str(self.KNOWN_FILEFS_FORMATS))
            )

        if name is None:
            name = 'fsfile' + str(len(self.fsfiles) + 1)

        if os.path.isfile(self.fsfiles_path + name):
            raise ValueError(self.say('File already exists: ' + name))

        path = self.fsfiles_path + name + '.' + fmt

        run(
            'dd status=none if=/dev/zero'
            '    of=' + path +
            '    bs=1M count=' + str(size),
            shell=True,
            check=True
        )
        run('mkfs.ext4 -qF ' + path, shell=True, check=True)

        self.fsfiles.add(path)
        return path

    def make_tap(self, name: str=None):
        """ Creates a new tap device, and brings it up. """

        if name is None:
            name = self.id[:8] + '_tap' + str(len(self.taps) + 1)

        if os.path.isfile('/dev/tap/' + name):
            raise ValueError(self.say("Tap already exists: " + name))

        run('ip tuntap add mode tap name ' + name, shell=True, check=True)
        run('ip link set ' + name + ' up', shell=True, check=True)

        self.taps.add(name)
        return name

    def teardown(self):
        """
        Deletes a local microvm slot. Also deletes `[self.microvm_root_path]`
        if it has no other subdirectories, and it was created by this class.
        """

        shutil.rmtree(self.path)
        if (
            not os.listdir(self.microvm_root_path) and
            self.created_microvm_root_path
        ):
            os.rmdir(self.microvm_root_path)

        for tap in self.taps:
            run('ip link set ' + tap + ' down', shell=True, check=True)
            run('ip link delete ' + tap, shell=True, check=True)
            run('ip tuntap del mode tap name ' + tap, shell=True, check=True)


class Microvm:
    """
    A Firecracker microvm. It goes into a microvm slot.

    Besides keeping track of microvm resources and exposing microvm API
    methods, `spawn()` and `kill()` can be used to start/end the microvm
    process.

    TODO
    ====
    - Use the Firecracker Open API spec to populate Microvm API resource URLs.
    """

    FC_BINARY_PATH = '../target/x86_64-unknown-linux-musl/release/'
    FC_BINARY_NAME = 'firecracker'

    fc_start_cmd = 'screen -dmS {session} {fc_binary} --api-sock {fc_usock}'
    fc_stop_cmd = 'screen -XS {session} kill'

    api_usocket_name = 'api.socket'
    api_usocket_url_prefix = 'http+unix://'

    microvm_cfg_resource = 'machine-config'
    net_cfg_resource = 'network-interfaces'
    blk_cfg_resource = 'drives'
    vsock_cfg_resource = 'vsocks'
    boot_cfg_resource = 'boot-source'
    actions_resource = 'actions'
    # TODO: Get the API paths from the Firecracker API definition.

    def __init__(
        self,
        microvm_slot: MicrovmSlot,
        id: str="firecracker_microvm",
        fc_binary_path=FC_BINARY_PATH,
        fc_binary_name=FC_BINARY_NAME
    ):
        self.slot = microvm_slot
        self.id = id
        self.fc_binary_path = fc_binary_path
        self.fc_binary_name = fc_binary_name

        self.session_name = self.fc_binary_name + '-' + self.id

        api_usocket_full_name = self.slot.path + self.api_usocket_name
        url_encoded_path = urllib.parse.quote_plus(api_usocket_full_name)
        self.api_url = self.api_usocket_url_prefix + url_encoded_path + '/'

    def say(self, message: str):
        return "Microvm " + self.id + ": " + message

    def spawn(self):
        """
        Start a microVM in a screen session, using an existing microVM slot.
        Returns the API socket URL.
        """

        self.microvm_cfg_url = self.api_url + self.microvm_cfg_resource
        self.net_cfg_url = self.api_url + self.net_cfg_resource
        self.blk_cfg_url = self.api_url + self.blk_cfg_resource
        self.vsock_cfg_url = self.api_url + self.vsock_cfg_resource
        self.boot_cfg_url = self.api_url + self.boot_cfg_resource
        self.actions_url = self.api_url + self.actions_resource

        self.ensure_firecracker_binary()

        start_fc_session_cmd = self.fc_start_cmd.format(
            session=self.session_name,
            fc_binary=self.fc_binary_path + self.fc_binary_name,
            fc_usock=self.slot.path + self.api_usocket_name
        )
        run(start_fc_session_cmd, shell=True, check=True)

        return self.api_url

    def kill(self):
        """
        Kills a Firecracker microVM process. Does not issue a stop command to
        the guest.
        """
        run(
            self.fc_stop_cmd.format(session=self.session_name),
            shell=True,
            check=True
        )

    def ensure_firecracker_binary(self):
        """ If no firecracker binary exists in the repo, build it. """
        if not os.path.isfile(self.FC_BINARY_PATH + self.FC_BINARY_NAME):
            run(
                'cargo build --quiet --release >/dev/null 2>&1',
                shell=True,
                check=True
            )
