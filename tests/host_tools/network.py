# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utilities for test host microVM network setup."""

import ipaddress
import os
import random
import re
import signal
import string
from dataclasses import dataclass, field
from pathlib import Path

from tenacity import retry, stop_after_attempt, wait_fixed

from framework import utils
from framework.utils import Timeout


class SSHConnection:
    """
    SSHConnection encapsulates functionality for microVM SSH interaction.

    This class should be instantiated as part of the ssh fixture with
    the hostname obtained from the MAC address, the username for logging into
    the image and the path of the ssh key.

    Establishes a ControlMaster upon construction, which is then re-used
    for all subsequent SSH interactions.
    """

    def __init__(
        self, netns, ssh_key: Path, control_path: Path, host, user, *, on_error=None
    ):
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
        self._control_path = control_path

        self._on_error = None

        self.options = [
            "-o",
            f"ControlPath={self._control_path}",
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
        wait=wait_fixed(1),
        stop=stop_after_attempt(20),
        reraise=True,
    )
    def _init_connection(self):
        """Initialize the persistent background connection which will be used
        to execute all commands sent via this `SSHConnection` object.

        Since we're connecting to a microVM we just started, we'll probably
        have to wait for it to boot up and start the SSH server.
        We'll keep trying to execute a remote command that can't fail
        (`/bin/true`), until we get a successful (0) exit code.
        """
        assert not self._control_path.exists()

        # Sadly, we cannot get debug output from this command (e.g. `-vvv`),
        # because passing -vvv causes the daemonized ssh to hold on to stderr,
        # and inside utils.run_cmd we're using subprocess.communicate, which
        # only returns once stderr gets closed (which would thus result in an
        # indefinite hang).
        establish_cmd = [
            "ssh",
            # Only need to pass the ssh key here, as all multiplexed
            # connections won't have to re-authenticate
            "-i",
            str(self.ssh_key),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=2",
            # Set up a persistent background connection
            "-o",
            "ControlMaster=auto",
            "-o",
            "ControlPersist=yes",
            *self.options,
            self.user_host,
            "true",
        ]

        try:
            # don't set a low timeout here, because otherwise we might get into a race condition
            # where ssh already forked off the persisted connection daemon, but gets killed here
            # before exiting itself. In that case, self._control_path will exist, and the retry
            # will hit the assert at the start of this function.
            self._exec(establish_cmd, check=True)
        except Exception:
            # if the control socket is present, then the daemon is running, and we should stop it
            # before retrying again
            if self._control_path.exists():
                self.close()
            raise

    def _check_liveness(self) -> int:
        """Checks whether the ControlPersist connection is still alive"""
        check_cmd = ["ssh", "-O", "check", *self.options, self.user_host]

        _, _, stderr = self._exec(check_cmd, check=True)

        pid_match = re.match(r"Master running \(pid=(\d+)\)", stderr)

        assert pid_match, f"SSH ControlMaster connection not alive anymore: {stderr}"

        return int(pid_match.group(1))

    def close(self):
        """Closes the ControlPersist connection"""
        master_pid = self._check_liveness()

        stop_cmd = ["ssh", "-O", "stop", *self.options, self.user_host]

        _, _, stderr = self._exec(stop_cmd, check=True)

        assert "Stop listening request sent" in stderr

        try:
            with Timeout(5):
                utils.wait_process_termination(master_pid)
        except TimeoutError:
            # for some reason it won't exit, let's force it...
            # if this also fails, when during teardown we'll get an error about
            # "found a process with supposedly dead Firecracker's jailer ID"
            os.kill(master_pid, signal.SIGKILL)

    def run(self, cmd_string, timeout=100, *, check=False, debug=False):
        """
        Execute the command passed as a string in the ssh context.

        If `debug` is set, pass `-vvv` to `ssh`. Note that this will clobber stderr.
        """
        self._check_liveness()

        command = ["ssh", *self.options, self.user_host, cmd_string]

        if debug:
            command.insert(1, "-vvv")

        return self._exec(command, timeout, check=check)

    def check_output(self, cmd_string, timeout=100, *, debug=False):
        """Same as `run`, but raises an exception on non-zero return code of remote command"""
        return self.run(cmd_string, timeout, check=True, debug=debug)

    def _exec(self, cmd, timeout=100, check=False):
        """Private function that handles the ssh client invocation."""
        if self.netns is not None:
            cmd = ["ip", "netns", "exec", self.netns] + cmd

        try:
            return utils.run_cmd(cmd, check=check, timeout=timeout)
        except Exception as exc:
            if self._on_error:
                self._on_error(exc)

            raise


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
        self._name = name
        self._netns = netns
        # Create the tap device tap0 directly in the network namespace to avoid
        # conflicts
        self.netns.check_output(f"ip tuntap add mode tap name {name}")
        if ip:
            self.netns.check_output(f"ifconfig {name} {ip} up")

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
        self.netns.check_output(f"ip link set {self.name} txqueuelen {tx_queue_len}")

    def __repr__(self):
        return f"<Tap name={self.name} netns={self.netns.id}>"


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


@dataclass(repr=True)
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

    def check_output(self, cmd: str):
        """Run a command inside the netns."""
        return utils.check_output(f"{self.cmd_prefix()} {cmd}")

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
            tap = Tap(name, self, ip)
            self.taps[name] = tap
        return self.taps[name]

    def is_used(self):
        """Are any of the TAPs still in use

        Waits until there's no carrier signal.
        Otherwise trying to reuse the TAP may return
            `Resource busy (os error 16)`
        """
        for tap in self.taps:
            _, stdout, _ = self.check_output(f"cat /sys/class/net/{tap}/carrier")
            if stdout.strip() != "0":
                return True
        return False
