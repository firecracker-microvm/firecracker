#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# pylint:disable=invalid-name

"""
Test all the ext4 rootfs in the current directory
"""

import os
import sys
from pathlib import Path

# Hack to be able to import testing framework functions.
sys.path.append(os.path.join(os.getcwd(), "tests"))

# pylint: disable=wrong-import-position
from framework.artifacts import kernels
from framework.microvm import MicroVMFactory
from host_tools.cargo_build import get_firecracker_binaries

# pylint: enable=wrong-import-position

kernels = list(kernels("vmlinux-*"))
# Use the latest guest kernel
kernel = kernels[-1]

vmfcty = MicroVMFactory("/srv", None, *get_firecracker_binaries())
# (may take a while to compile Firecracker...)

for rootfs in Path(".").glob("*.ext4"):
    print(f">>>> Testing {rootfs}")
    uvm = vmfcty.build(kernel, rootfs)
    uvm.spawn()
    uvm.add_net_iface()
    uvm.basic_config()
    uvm.start()
    rc, stdout, stderr = uvm.ssh.run("cat /etc/issue")
    print(rc, stdout, stderr)
