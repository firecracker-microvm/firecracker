#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# pylint:disable=invalid-name

"""
Run Firecracker in an IPython REPL
"""

import argparse
import json
import re
from pathlib import Path

from framework.artifacts import disks, kernels
from framework.defs import DEFAULT_BINARY_DIR
from framework.microvm import MicroVMFactory

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
    type=Path,
    choices=kernels,
    default=kernels[-1],
    help=f"Kernel to use. [{kernels[-1]}]",
)
parser.add_argument(
    "--rootfs",
    type=Path,
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
parser.add_argument("--binary-dir", help="Path to the firecracker binaries")
parser.add_argument("--cpu-template-path", help="CPU template to use", type=Path)
args = parser.parse_args()
print(args)

binary_dir = None
if args.binary_dir:
    binary_dir = Path(args.binary_dir).resolve()
else:
    binary_dir = DEFAULT_BINARY_DIR

cpu_template = None
if args.cpu_template_path is not None:
    cpu_template = json.loads(args.cpu_template_path.read_text())
vmfcty = MicroVMFactory(binary_dir)

print(f"uvm with kernel {args.kernel} ...")
uvm = vmfcty.build(args.kernel, args.rootfs)
uvm.help.enable_console()
uvm.help.resize_disk(uvm.rootfs_file, args.rootfs_size)
uvm.spawn(log_show_level=True)
uvm.help.print_log()
uvm.add_net_iface()
uvm.basic_config(vcpu_count=args.vcpus, mem_size_mib=args.guest_mem_size // 2**20)
if cpu_template is not None:
    uvm.api.cpu_config.put(**cpu_template)
    print(cpu_template)
uvm.start()
uvm.get_all_metrics()

kernel_dbg_dir = args.kernel.parent / "debug"
kernel_dbg = kernel_dbg_dir / args.kernel.name
print(f"uvm2 with kernel {kernel_dbg} ...")
uvm2 = vmfcty.build(kernel_dbg, args.rootfs)
uvm2.spawn()
uvm2.add_net_iface()
uvm2.basic_config(vcpu_count=args.vcpus, mem_size_mib=args.guest_mem_size // 2**20)
uvm2.start()
# trace-cmd needs this (DNS resolution?)
uvm2.help.enable_ip_forwarding()
files = uvm2.help.trace_cmd_guest(["-l", "read_msr"], cmd="sleep 5")
