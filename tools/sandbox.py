#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Run Firecracker in an IPython REPL
"""

import argparse
import re

from framework.artifacts import disks, kernels
from framework.microvm import MicroVMFactory
from host_tools.cargo_build import get_firecracker_binaries

kernels = list(kernels("vmlinux-*"))
rootfs = list(disks("ubuntu*ext4"))


def parse_byte_size(param):
    """
    >>> parse_byte_size("1MB")
    1048576
    """
    unit = {
        "MB": 2**20,
        "GB": 2**30,
    }
    match = re.match(r"(?P<val>\d+)(?P<unit>[MG]B)", param.upper())
    return int(match.group("val")) * unit[match.group("unit")]


parser = argparse.ArgumentParser()
parser.add_argument(
    "--kernel",
    choices=kernels,
    default=kernels[-1],
    help=f"Kernel to use. [{kernels[-1]}]",
)
parser.add_argument(
    "--rootfs",
    choices=rootfs,
    default=rootfs[-1],
    help=f"Rootfs to use. [{rootfs[-1]}]",
)
parser.add_argument("--vcpus", type=int, default=2)
parser.add_argument(
    "--guest-mem-size",
    type=parse_byte_size,
    default=128 * 2**20,  # 128MB
)
parser.add_argument("--rootfs-size", type=parse_byte_size, default=1 * 2**30)  # 1GB
args = parser.parse_args()
print(args)


print("This step may take a while to compile Firecracker ...")
vmfcty = MicroVMFactory("/srv", None, *get_firecracker_binaries())
uvm = vmfcty.build(args.kernel, args.rootfs)
uvm.help.enable_console()
uvm.help.resize_disk(uvm.rootfs_file, args.rootfs_size)
uvm.spawn()
uvm.help.print_log()
uvm.add_net_iface()
uvm.basic_config(vcpu_count=args.vcpus, mem_size_mib=args.guest_mem_size // 2**20)
uvm.start()
uvm.get_all_metrics()
