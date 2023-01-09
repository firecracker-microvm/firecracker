# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Metadata we want to attach to tests for further analysis and troubleshooting
"""

import platform
import subprocess

from framework.utils_cpuid import get_cpu_model_name


def run_cmd(cmd):
    """Return the stdout of a command"""
    stdout = subprocess.check_output(cmd, shell=True).decode().strip()
    return stdout


GLOBAL_PROPS = {
    "architecture": platform.machine(),
    "host_linux_kernel": platform.release(),
    "libc_ver": "-".join(platform.libc_ver()),
    "cpu_model": get_cpu_model_name(),
    "commit_id": run_cmd("git rev-parse HEAD"),
}
