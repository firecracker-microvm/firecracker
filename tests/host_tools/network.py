# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for test host microVM network setup."""

import os
import random
import string
from io import StringIO
from nsenter import Namespace
from retry import retry

from framework import utils


class SSHConnection:
    """SSHConnection encapsulates functionality for microVM SSH interaction.

    This class should be instantiated as part of the ssh fixture with the
    the hostname obtained from the MAC address, the username for logging into
    the image and the path of the ssh key.

    The ssh config dictionary contains the following fields:
    * hostname
    * username
    * ssh_key_path

    This translates into an SSH connection as follows:
    ssh -i ssh_key_path username@hostname
    """

    def __init__(self, ssh_config):
        """Instantiate a SSH client and connect to a microVM."""
        self.netns_file_path = ssh_config["netns_file_path"]
        self.ssh_config = ssh_config
        assert os.path.exists(ssh_config["ssh_key_path"])

        self._init_connection()

    def execute_command(self, cmd_string):
        """Execute the command passed as a string in the ssh context."""
        exit_code, stdout, stderr = self._exec(cmd_string)
        return exit_code, StringIO(stdout), StringIO(stderr)

    run = execute_command

    def scp_file(self, local_path, remote_path):
        """Copy a files to the VM using scp."""
        cmd = (
            "scp -o StrictHostKeyChecking=no"
            " -o UserKnownHostsFile=/dev/null"
            " -i {} {} {}@{}:{}"
        ).format(
            self.ssh_config["ssh_key_path"],
            local_path,
            self.ssh_config["username"],
            self.ssh_config["hostname"],
            remote_path,
        )
        if self.netns_file_path:
            with Namespace(self.netns_file_path, "net"):
                utils.run_cmd(cmd)
        else:
            utils.run_cmd(cmd)

    def scp_get_file(self, remote_path, local_path):
        """Copy files from the VM using scp."""
        cmd = (
            "scp -o StrictHostKeyChecking=no"
            " -o UserKnownHostsFile=/dev/null"
            " -i {} {}@{}:{} {}"
        ).format(
            self.ssh_config["ssh_key_path"],
            self.ssh_config["username"],
            self.ssh_config["hostname"],
            remote_path,
            local_path,
        )
        if self.netns_file_path:
            with Namespace(self.netns_file_path, "net"):
                utils.run_cmd(cmd)
        else:
            utils.run_cmd(cmd)

    @retry(ConnectionError, delay=0.1, tries=20)
    def _init_connection(self):
        """Create an initial SSH client connection (retry until it works).

        Since we're connecting to a microVM we just started, we'll probably
        have to wait for it to boot up and start the SSH server.
        We'll keep trying to execute a remote command that can't fail
        (`/bin/true`), until we get a successful (0) exit code.
        """
        ecode, _, _ = self._exec("true")
        if ecode != 0:
            raise ConnectionError

    def _exec(self, cmd):
        """Private function that handles the ssh client invocation."""

        def _exec_raw(_cmd):
            # pylint: disable=subprocess-run-check
            cp = utils.run_cmd(
                [
                    "ssh",
                    "-q",
                    "-o",
                    "ConnectTimeout=1",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-i",
                    self.ssh_config["ssh_key_path"],
                    "{}@{}".format(
                        self.ssh_config["username"], self.ssh_config["hostname"]
                    ),
                    _cmd,
                ],
                ignore_return_code=True,
            )

            _res = (cp.returncode, cp.stdout, cp.stderr)
            return _res

        # TODO: If a microvm runs in a particular network namespace, we have to
        # temporarily switch to that namespace when doing something that routes
        # packets over the network, otherwise the destination will not be
        # reachable. Use a better setup/solution at some point!
        if self.netns_file_path:
            with Namespace(self.netns_file_path, "net"):
                res = _exec_raw(cmd)
        else:
            res = _exec_raw(cmd)
        return res


def mac_from_ip(ip_address):
    """Create a MAC address based on the provided IP.

    Algorithm:
    - the first 2 bytes are fixed to 06:00
    - the next 4 bytes are the IP address

    Example of function call:
    mac_from_ip("192.168.241.2") -> 06:00:C0:A8:F1:02
    C0 = 192, A8 = 168, F1 = 241 and  02 = 2
    :param ip_address: IP address as string
    :return: MAC address from IP
    """
    mac_as_list = ["06", "00"]
    mac_as_list.extend(
        list(map(lambda val: "{0:02x}".format(int(val)), ip_address.split(".")))
    )

    return "{}:{}:{}:{}:{}:{}".format(*mac_as_list)


def get_guest_net_if_name(ssh_connection, guest_ip):
    """Get network interface name based on its IPv4 address."""
    cmd = "ip a s | grep '{}' | tr -s ' ' | cut -d' ' -f6".format(guest_ip)
    _, guest_if_name, _ = ssh_connection.execute_command(cmd)
    if_name = guest_if_name.read().strip()
    return if_name if if_name != "" else None


def random_str(k):
    """Create a random string of length `k`."""
    symbols = string.ascii_lowercase + string.digits
    return "".join(random.choices(symbols, k=k))


class Tap:
    """Functionality for creating a tap and cleaning up after it."""

    def __init__(self, name, netns, ip=None):
        """Set up the name and network namespace for this tap interface.

        It also creates a new tap device, and brings it up. The tap will
        stay on the host as long as the object obtained by instantiating this
        class will be in scope. Once it goes out of scope, its destructor will
        get called and the tap interface will get removed.
        The function also moves the interface to the specified namespace.
        """
        # Avoid a conflict if two tests want to create the same tap device tap0
        # in the host before moving it into its own netns
        temp_name = "tap" + random_str(k=8)
        utils.run_cmd(f"ip tuntap add mode tap name {temp_name}")
        utils.run_cmd(f"ip link set {temp_name} name {name} netns {netns}")
        if ip:
            utils.run_cmd(f"ip netns exec {netns} ifconfig {name} {ip} up")
        self._name = name
        self._netns = netns

    @property
    def name(self):
        """Return the name of this tap interface."""
        return self._name

    @property
    def netns(self):
        """Return the network namespace of this tap."""
        return self._netns

    def set_tx_queue_len(self, tx_queue_len):
        """Set the length of the tap's TX queue."""
        utils.run_cmd(
            "ip netns exec {} ip link set {} txqueuelen {}".format(
                self.netns, self.name, tx_queue_len
            )
        )

    def __repr__(self):
        return f"<Tap name={self.name} netns={self.netns}>"
