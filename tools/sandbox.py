#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# pylint:disable=invalid-name

"""
Run Firecracker in an IPython REPL
"""

import argparse
import json
import os
import re
from pathlib import Path

import host_tools.cargo_build as build_tools
from framework.artifacts import disks, kernels
from framework.defs import DEFAULT_BINARY_DIR, FC_WORKSPACE_DIR
from framework.microvm import MicroVMFactory

kernels = list(kernels("vmlinux-*"))
rootfs = list(disks("*.ext4"))


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


def translate_host_path(p):
    """Rewrite a host path under HOST_FC_ROOT_DIR to its /firecracker/... equivalent."""
    if p is None:
        return None
    host_root = os.environ.get("HOST_FC_ROOT_DIR")
    if not host_root:
        return Path(p)
    p = Path(p).resolve()
    if p.is_relative_to(host_root):
        return FC_WORKSPACE_DIR / p.relative_to(host_root)
    if p.exists():
        return p
    raise SystemExit(
        f"{p} not found in container and not under host workspace {host_root}."
    )


def pick_default_rootfs(candidates):
    """Default to AL2023, falling back to Ubuntu, then any rootfs available."""
    if not candidates:
        return None
    for prefix in ("amazonlinux-", "ubuntu-"):
        matches = [c for c in candidates if c.name.startswith(prefix)]
        if matches:
            return matches[-1]
    return candidates[-1]


default_rootfs = pick_default_rootfs(rootfs)
default_kernel = kernels[-1] if kernels else None

parser = argparse.ArgumentParser()
parser.add_argument(
    "--kernel",
    type=Path,
    default=default_kernel,
    help=f"Kernel to use. Default: {default_kernel}. "
    f"Available: {[k.name for k in kernels]}",
)
parser.add_argument(
    "--rootfs",
    type=Path,
    default=default_rootfs,
    help=f"Rootfs to use. Default: {default_rootfs}. "
    f"Available: {[r.name for r in rootfs]}",
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
parser.add_argument(
    "--boot-args", help="Kernel boot arguments", type=str, default=None, nargs="+"
)
parser.add_argument(
    "--debug", action="store_true", default=False, help="Use debug kernel"
)
parser.add_argument(
    "--gdb", action="store_true", default=False, help="Connect to Firecracker guest GDB"
)
args = parser.parse_args()
args.kernel = translate_host_path(args.kernel)
args.rootfs = translate_host_path(args.rootfs)
args.binary_dir = translate_host_path(args.binary_dir)
args.cpu_template_path = translate_host_path(args.cpu_template_path)
print(args)

if args.kernel is None:
    raise SystemExit("No kernel found and --kernel was not provided.")
if args.rootfs is None:
    raise SystemExit("No rootfs found and --rootfs was not provided.")

binary_dir = None
if args.binary_dir:
    binary_dir = Path(args.binary_dir).resolve()
elif args.gdb:
    # Build Firecracker with GDB feature if needed
    print("Building Firecracker with GDB feature...")
    binary_dir = build_tools.build_gdb()
    print("Build complete!")
else:
    binary_dir = DEFAULT_BINARY_DIR

cpu_template = None
if args.cpu_template_path is not None:
    cpu_template = json.loads(args.cpu_template_path.read_text("utf-8"))
vmfcty = MicroVMFactory(binary_dir)

if args.debug or args.gdb:
    kernel = args.kernel.parent / "debug" / args.kernel.name
else:
    kernel = args.kernel

print(f"uvm with kernel {kernel} ...")
uvm = vmfcty.build(kernel, args.rootfs)
uvm.help.enable_console()
uvm.help.resize_disk(uvm.rootfs_file, args.rootfs_size)
uvm.spawn(log_show_level=True, validate_api=False)
uvm.help.print_log()
uvm.add_net_iface()
uvm.basic_config(
    vcpu_count=args.vcpus,
    mem_size_mib=args.guest_mem_size // 2**20,
    boot_args=" ".join(args.boot_args) if args.boot_args else None,
)
if cpu_template is not None:
    uvm.api.cpu_config.put(**cpu_template)
    print(cpu_template)

if args.gdb:
    uvm.enable_gdb()
    uvm.help.tmux_gdb()

uvm.start()
uvm.get_all_metrics()
