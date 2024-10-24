# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for test host microVM network setup."""

import ipaddress
import random
import string
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_fixed

from framework import utils


class SSHConnection:
    """
    SSHConnection encapsulates functionality for microVM SSH interaction.

    This class should be instantiated as part of the ssh fixture with the
    the hostname obtained from the MAC address, the username for logging into
    the image and the path of the ssh key.

    This translates into an SSH connection as follows:
    ssh -i ssh_key_path username@hostname
    """

    def __init__(self, netns, ssh_key: Path, host, user, *, on_error=None):
        """Instantiate a SSH client and connect to a microVM."""
        self.netns = netns
        self.ssh_key = ssh_key
        # check that the key exists and the permissions are 0o400
        # This saves a lot of debugging time.
        assert ssh_key.exists()
        ssh_key.chmod(0o400)
        assert (ssh_key.stat().st_mode & 0o777) == 0o400
        self.host = host
        self.user = user

        self._on_error = None

        self.options = [
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=1",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "PreferredAuthentications=publickey",
            "-i",
            str(self.ssh_key),
        ]

        # _init_connection loops until it can connect to the guest
        # dumping debug state on every iteration is not useful or wanted, so
        # only dump it once if _all_ iterations fail.
        try:
            self._init_connection()
        except Exception as exc:
            if on_error:
                on_error(exc)

            raise

        self._on_error = on_error

    @property
    def user_host(self):
        """remote address for in SSH format <user>@<IP>"""
        return f"{self.user}@{self.host}"

    def remote_path(self, path):
        """Convert a path to remote"""
        return f"{self.user_host}:{path}"

    def _scp(self, path1, path2, options):
        """Copy files to/from the VM using scp."""
        self._exec(["scp", *options, path1, path2], check=True)

    def scp_put(self, local_path, remote_path, recursive=False):
        """Copy files to the VM using scp."""
        opts = self.options.copy()
        if recursive:
            opts.append("-r")
        self._scp(local_path, self.remote_path(remote_path), opts)

    def scp_get(self, remote_path, local_path, recursive=False):
        """Copy files from the VM using scp."""
        opts = self.options.copy()
        if recursive:
            opts.append("-r")
        self._scp(self.remote_path(remote_path), local_path, opts)

    @retry(
        retry=retry_if_exception_type(ChildProcessError),
        wait=wait_fixed(0.5),
        stop=stop_after_attempt(20),
        reraise=True,
    )
    def _init_connection(self):
        """Create an initial SSH client connection (retry until it works).

        Since we're connecting to a microVM we just started, we'll probably
        have to wait for it to boot up and start the SSH server.
        We'll keep trying to execute a remote command that can't fail
        (`/bin/true`), until we get a successful (0) exit code.
        """
        self.check_output("true", timeout=100, debug=True)

    def run(self, cmd_string, timeout=None, *, check=False, debug=False):
        """
        Execute the command passed as a string in the ssh context.

        If `debug` is set, pass `-vvv` to `ssh`. Note that this will clobber stderr.
        """
        command = ["ssh", *self.options, self.user_host, cmd_string]

        if debug:
            command.insert(1, "-vvv")

        return self._exec(command, timeout, check=check)

    def check_output(self, cmd_string, timeout=None, *, debug=False):
        """Same as `run`, but raises an exception on non-zero return code of remote command"""
        return self.run(cmd_string, timeout, check=True, debug=debug)

    def _exec(self, cmd, timeout=None, check=False):
        """Private function that handles the ssh client invocation."""
        if self.netns is not None:
            cmd = ["ip", "netns", "exec", self.netns] + cmd

        try:
            return utils.run_cmd(cmd, check=check, timeout=timeout)
        except Exception as exc:
            if self._on_error:
                self._on_error(exc)

            raise

    # pylint:disable=invalid-name
    def Popen(
        self,
        cmd: str,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,
    ) -> subprocess.Popen:
        """Execute the command in the guest and return a Popen object.

        pop = uvm.ssh.Popen("while true; do echo $(date -Is) $RANDOM; sleep 1; done")
        pop.stdout.read(16)
        """
        cmd = ["ssh", *self.options, self.user_host, cmd]
        if self.netns is not None:
            cmd = ["ip", "netns", "exec", self.netns] + cmd
        return subprocess.Popen(
            cmd, stdin=stdin, stdout=stdout, stderr=stderr, **kwargs
        )


def mac_from_ip(ip_address):
    """Create a MAC address based on the provided IP.

    Algorithm:
    - the first 2 bytes are fixed to 06:00, which is in an LAA range
      - https://en.wikipedia.org/wiki/MAC_address#Ranges_of_group_and_locally_administered_addresses
    - the next 4 bytes are the IP address

    Example of function call:
    mac_from_ip("192.168.241.2") -> 06:00:C0:A8:F1:02
    C0 = 192, A8 = 168, F1 = 241 and  02 = 2
    :param ip_address: IP address as string
    :return: MAC address from IP
    """
    mac_as_list = ["06", "00"]
    mac_as_list.extend(f"{int(octet):02x}" for octet in ip_address.split("."))
    return ":".join(mac_as_list)


def get_guest_net_if_name(ssh_connection, guest_ip):
    """Get network interface name based on its IPv4 address."""
    cmd = "ip a s | grep '{}' | tr -s ' ' | cut -d' ' -f6".format(guest_ip)
    _, guest_if_name, _ = ssh_connection.run(cmd)
    if_name = guest_if_name.strip()
    return if_name if if_name != "" else None


def random_str(k):
    """Create a random string of length `k`."""
    symbols = string.ascii_lowercase + string.digits
    return "".join(random.choices(symbols, k=k))


class Tap:
    """Functionality for creating a tap and cleaning up after it."""

    def __init__(self, name, netns, ip=None):
        """Set up the name and network namespace for this tap interface.

        It also creates a new tap device, brings it up and moves the interface
        to the specified namespace.
        """
        # Avoid a conflict if two tests want to create the same tap device tap0
        # in the host before moving it into its own netns
        temp_name = "tap" + random_str(k=8)
        utils.check_output(f"ip tuntap add mode tap name {temp_name}")
        utils.check_output(f"ip link set {temp_name} name {name} netns {netns}")
        if ip:
            utils.check_output(f"ip netns exec {netns} ifconfig {name} {ip} up")
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
        utils.check_output(
            "ip netns exec {} ip link set {} txqueuelen {}".format(
                self.netns, self.name, tx_queue_len
            )
        )

    def __repr__(self):
        return f"<Tap name={self.name} netns={self.netns}>"


@dataclass(frozen=True, repr=True)
class NetIfaceConfig:
    """Defines a network interface configuration."""

    host_ip: str
    guest_ip: str
    tap_name: str
    dev_name: str
    netmask_len: int

    @property
    def guest_mac(self):
        """Return the guest MAC address."""
        return mac_from_ip(self.guest_ip)

    @property
    def network(self):
        """Return the guest network"""
        return ipaddress.IPv4Interface(f"{self.host_ip}/{self.netmask_len}").network

    @staticmethod
    def with_id(i, netmask_len=30):
        """Define network iface with id `i`."""
        return NetIfaceConfig(
            host_ip=f"192.168.{i}.1",
            guest_ip=f"192.168.{i}.2",
            tap_name=f"tap{i}",
            dev_name=f"eth{i}",
            netmask_len=netmask_len,
        )


@dataclass(frozen=True, repr=True)
class NetNs:
    """Defines a network namespace."""

    id: str
    taps: dict[str, Tap] = field(init=False, default_factory=dict)

    @property
    def path(self):
        """Get the host netns file path.

        Returns the path on the host to the file which represents the netns.
        """
        return Path("/var/run/netns") / self.id

    def cmd_prefix(self):
        """Return the jailer context netns file prefix."""
        return f"ip netns exec {self.id}"

    def setup(self):
        """Set up this network namespace."""
        if not self.path.exists():
            utils.check_output(f"ip netns add {self.id}")

    def cleanup(self):
        """Clean up this network namespace."""
        if self.path.exists():
            utils.check_output(f"ip netns del {self.id}")

    def add_tap(self, name, ip):
        """Add a TAP device to the namespace

        We assume that a Tap is always configured with the same IP.
        """
        if name not in self.taps:
            tap = Tap(name, self.id, ip)
            self.taps[name] = tap
        return self.taps[name]
