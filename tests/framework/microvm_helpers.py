# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Microvm helper functions for interactive use"""

import ipaddress
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

    @property
    def in_docker(self):
        """Are we running inside a Docker container?"""
        return Path("/.dockerenv").exists()


DOCKER = DockerInfo()


class MicrovmHelpers:
    """Microvm helper functions for interactive use"""

    # keep track of assigned subnets
    shared_subnet_ctr = 0
    # Try not to collide with anything by using the last /16 of the 10.x.x.x
    # private block
    _supernet = ipaddress.IPv4Network("10.255.0.0/16")
    _subnets_gen = _supernet.subnets(new_prefix=30)
    # Addresses that can be used outside the netns. Could be public IPv4 blocks
    _ingress_net = ipaddress.IPv4Network("172.16.0.0/12")
    _ingress_gen = _ingress_net.hosts()

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
        subprocess.check_output(["resize2fs", "-f", str(disk)])

    def gdbserver(self, port=2000):
        """Attach gdbserver to the FC process

        See https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Debugging.html#Remote-Debugging
        """
        comm = f"localhost:{port}"
        subprocess.Popen(["gdbserver", "--attach", comm, str(self.vm.firecracker_pid)])
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
            f"Connect lldb with\n\tlldb -o 'platform select remote-linux' -o 'platform connect connect://{DOCKER.ip}:{port}' -o 'attach {self.vm.firecracker_pid}'"
        )

    def tmux_neww(self, cmd: str):
        """Open a window in the local tmux"""
        return subprocess.run(["tmux", "neww", cmd], check=True)

    def how_to_ssh(self):
        """Print how to SSH to the microvm

        This may be useful for example to get a terminal
        """
        ip = self.vm.iface["eth0"]["iface"].guest_ip
        return f"{self.vm.netns.cmd_prefix()} ssh -o StrictHostKeyChecking=no -i {self.vm.ssh_key} root@{ip}"

    def tmux_ssh(self, cmd=""):
        """Open a tmux window with an SSH session to the VM"""
        if len(cmd) > 0:
            cmd = f" {cmd}"
        return self.tmux_neww(self.how_to_ssh() + cmd)

    def enable_console(self):
        """Helper method to attach a console, before the machine boots"""
        if self.vm.api is not None:
            raise RuntimeError(".spawn already called, too late to enable the console")
        if self.vm.boot_args is None:
            self.vm.boot_args = ""
        self.vm.boot_args += "console=ttyS0 reboot=k panic=1"
        self.vm.jailer.daemonize = False
        self.vm.jailer.new_pid_ns = False

    def how_to_console(self):
        """Print how to connect to the VM console"""
        return f"screen -dR {self.vm.screen_session}"

    def tmux_console(self):
        """Open a tmux window with the console"""
        return self.tmux_neww(self.how_to_console())

    def how_to_docker(self):
        """How to get into this container from outside"""
        return f"docker exec -it {DOCKER.id}"

    def enable_ip_forwarding(self, iface="eth0", ingress_ipv4=None):
        """Enables IP forwarding in the guest"""
        i = MicrovmHelpers.shared_subnet_ctr
        MicrovmHelpers.shared_subnet_ctr += 1
        netns = self.vm.netns.id
        veth_host = f"vethhost{i}"
        veth_guest = f"vethguest{i}"
        veth_net = next(self._subnets_gen)
        veth_host_ip, veth_guest_ip = list(veth_net.hosts())
        iface = self.vm.iface[iface]["iface"]
        tap_host_ip = iface.host_ip
        tap_net = iface.network.with_netmask  # i.e. 192.168.7.0/255.255.255.0
        # get the device associated with the default route
        upstream_dev = (
            subprocess.check_output(
                "ip -j route list default |jq -r '.[0].dev'",
                shell=True,
            )
            .decode("ascii")
            .strip()
        )

        def run(cmd):
            return subprocess.run(cmd, shell=True, check=True)

        def run_in_netns(cmd):
            return run(f"ip netns exec {netns} " + cmd)

        # outside netns
        # iptables -L -v -n --line-numbers
        run(
            f"ip link add name {veth_host} type veth peer name {veth_guest} netns {netns}"
        )
        run(f"ip addr add {veth_host_ip}/{veth_net.prefixlen} dev {veth_host}")
        run_in_netns(
            f"ip addr add {veth_guest_ip}/{veth_net.prefixlen} dev {veth_guest}"
        )
        run(f"ip link set {veth_host} up")
        run_in_netns(f"ip link set {veth_guest} up")

        run("iptables -P FORWARD ACCEPT")
        # iptables -L FORWARD
        # iptables -t nat -L
        run(
            f"iptables -t nat -A POSTROUTING -s {veth_net} -o {upstream_dev} -j MASQUERADE"
        )
        run_in_netns(f"ip route add default via {veth_host_ip}")
        run_in_netns(
            f"iptables -t nat -A POSTROUTING -s {tap_net} -o {veth_guest} -j MASQUERADE"
        )

        # Configure the guest
        self.vm.ssh.run(f"ip route add default via {tap_host_ip}")
        # Copy the nameserver from the host
        nameserver = (
            subprocess.check_output(
                r"grep -oP 'nameserver\s+\K.+' /etc/resolv.conf", shell=True
            )
            .decode("ascii")
            .strip()
        )
        self.vm.ssh.run(f"echo nameserver {nameserver} >/etc/resolv.conf")

        # only configure ingress if we get an IP
        if not ingress_ipv4:
            return

        if not isinstance(ingress_ipv4, ipaddress.IPv4Address):
            ingress_ipv4 = next(self._ingress_gen)

        guest_ip = iface.guest_ip

        # packets heading towards the clone address are rewritten to the guest ip
        run_in_netns(
            f"iptables -t nat -A PREROUTING -i {veth_guest} -d {ingress_ipv4} -j DNAT --to {guest_ip}"
        )

        # add a route on the host for the clone address
        run(f"ip route add {ingress_ipv4} via {veth_guest_ip}")

    def trace_cmd_guest(self, fns, cmd, port=4321):
        """Run trace-cmd on the guest, but transfer the data directly to the host."""
        docker_apt_install("trace-cmd")
        print("host> trace-cmd listen")
        _proc = subprocess.Popen(
            [
                "ip",
                "netns",
                "exec",
                self.vm.netns.id,
                "trace-cmd",
                "listen",
                "-p",
                str(port),
            ]
        )
        print("guest> trace-cmd record")
        host_ip = self.vm.iface["eth0"]["iface"].host_ip
        _guest_ps = self.vm.ssh.run(
            f"trace-cmd record -N {host_ip}:{port} -p function {' '.join(fns)} {cmd}"
        )
        return list(Path(".").glob("trace.*.dat"))
