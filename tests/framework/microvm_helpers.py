# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Microvm helper functions for interactive use"""

import os
import platform
import subprocess
from pathlib import Path


def docker_apt_install(packages: str | list[str]):
    """Install a package in the Docker devctr"""
    apt_lists = Path("/var/lib/apt/lists/")
    if len(list(apt_lists.iterdir())) == 0:
        subprocess.run(["apt", "update"], check=True)
    if isinstance(packages, str):
        packages = [packages]
    subprocess.run(["apt", "install", "-y", *packages], check=True)


class DockerInfo:
    """Class to extract information from the Docker environment"""

    @property
    def ip(self):
        """Return this container's IP address"""
        return (
            subprocess.check_output(
                "ip -j address show eth0 |jq -r '.[].addr_info[].local'",
                shell=True,
            )
            .decode("ascii")
            .strip()
        )

    @property
    def id(self):
        """Return this container's id"""
        return platform.node()


DOCKER = DockerInfo()


class MicrovmHelpers:
    """Microvm helper functions for interactive use"""

    def __init__(self, vm):
        self.vm = vm

    def print_log(self):
        """Print Firecracker's log"""
        print(self.vm.log_data)

    def resize_disk(self, disk, size: int = 2**30):
        """Resize a filesystem

        The filesystem should be unmounted for this to work
        """
        os.truncate(disk, size)
        subprocess.check_output(["resize2fs", disk])

    def gdbserver(self, port=2000):
        """Attach gdbserver to the FC process

        See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Debugging.html#Remote-Debugging
        """
        comm = f"localhost:{port}"
        subprocess.Popen(["gdbserver", "--attach", comm, str(self.vm.jailer_clone_pid)])
        print(f"Connect gdb with:\n\tgdb --ex 'target remote {DOCKER.ip}:{port}'")

    def lldbserver(self, port=2001):
        """Attach lldb-server to the FC process

        See https://lldb.llvm.org/use/remote.html

        TBD does not work. Fails with
          error: attach failed: lost connection
        """
        # Unlike gdbserver, lldb-server is not a separate package, but is part
        # of lldb and it's about ~400MB to install, so we don't include it in
        # the devctr
        docker_apt_install("lldb")
        subprocess.Popen(["lldb-server", "p", "--listen", f"*:{port}", "--server"])
        print(
            f"Connect lldb with\n\tlldb -o 'platform select remote-linux' -o 'platform connect connect://{DOCKER.ip}:{port}' -o 'attach {self.vm.jailer_clone_pid}'"
        )

    def tmux_neww(self, cmd: str):
        """Open a window in the local tmux"""
        return subprocess.run(["tmux", "neww", cmd], check=True)

    def how_to_ssh(self):
        """Print how to SSH to the microvm

        This may be useful for example to get a terminal
        """
        ip = self.vm.iface["eth0"]["iface"].guest_ip
        return f"ip netns exec {self.vm.jailer.netns} ssh -o StrictHostKeyChecking=no -i {self.vm.ssh_key} root@{ip}"

    def tmux_ssh(self):
        """Open a tmux window with an SSH session to the VM"""
        return self.tmux_neww(self.how_to_ssh())

    def enable_console(self):
        """Helper method to attach a console, before the machine boots"""
        if self.vm.api is not None:
            raise RuntimeError(".spawn already called, too late to enable the console")
        if self.vm.boot_args is None:
            self.vm.boot_args = ""
        self.vm.boot_args += "console=ttyS0 reboot=k panic=1"
        self.vm.jailer.daemonize = False

    def how_to_console(self):
        """Print how to connect to the VM console"""
        return f"screen -dR {self.vm.screen_session}"

    def tmux_console(self):
        """Open a tmux window with the console"""
        return self.tmux_neww(self.how_to_console())

    def how_to_docker(self):
        """How to get into this container from outside"""
        return f"docker exec -it {DOCKER.id}"

    def enable_ip_forwarding(self):
        """
        Enables IP forwarding

        TBD this only works for a single microvm. allow several microvms.
          we need to make the veth network smaller and **allocate** them
          accordingly
        """
        docker_apt_install("iptables")
        netns = self.vm.jailer.netns
        vethhost = "vethhost0"
        vethhost_ip = "10.0.0.1"
        veth_net = "10.0.0.0/255.255.255.0"
        tap_net = "192.168.0.0/255.255.255.0"
        tap_host_ip = self.vm.iface["eth0"]["iface"].host_ip

        def run(cmd):
            return subprocess.run(cmd, shell=True, check=True)

        def run_in_netns(cmd):
            return run(f"ip netns exec {netns} " + cmd)

        # outside netns
        # iptables -L -v -n
        run(f"ip link add name {vethhost} type veth peer name vethvpn0 netns {netns}")
        run(f"ip addr add {vethhost_ip}/24 dev {vethhost}")
        run_in_netns("ip addr add 10.0.0.2/24 dev vethvpn0")
        run(f"ip link set {vethhost} up")
        run_in_netns("ip link set vethvpn0 up")

        run("iptables -P FORWARD DROP")
        # iptables -L FORWARD
        # iptables -t nat -L
        run(f"iptables -t nat -A POSTROUTING -s {veth_net} -o eth0 -j MASQUERADE")
        run("iptables -A FORWARD -i eth0 -o vethhost0 -j ACCEPT")
        run("iptables -A FORWARD -i vethhost0 -o eth0 -j ACCEPT")

        # in the netns
        run_in_netns(f"ip route add default via {vethhost_ip}")
        # tap_ip = ipaddress.ip_network("192.168.0.1/30", False)
        run_in_netns("iptables -A FORWARD -i tap0 -o vethvpn0 -j ACCEPT")
        run_in_netns("iptables -A FORWARD -i vethvpn0 -o tap0  -j ACCEPT")
        run_in_netns(
            f"iptables -t nat -A POSTROUTING -s {tap_net} -o vethvpn0 -j MASQUERADE"
        )

        self.vm.ssh.run(f"ip route add default via {tap_host_ip}")
        self.vm.ssh.run("echo nameserver 8.8.8.8 >/etc/resolv.conf")
