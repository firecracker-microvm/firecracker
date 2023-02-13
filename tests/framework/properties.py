# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# pylint:disable=broad-except
# pylint:disable=too-few-public-methods

"""
Metadata we want to attach to tests for further analysis and troubleshooting
"""

import platform
import re
import subprocess
from pathlib import Path

from framework.utils_imdsv2 import imdsv2_get
from framework.utils_cpuid import get_cpu_model_name, get_cpu_vendor


def run_cmd(cmd):
    """Return the stdout of a command"""
    return subprocess.check_output(cmd, shell=True).decode().strip()


def get_kernel_version(level):
    """Return the current kernel version in format `major.minor.patch`."""
    linux_version = platform.release()
    # 5.15.0-56-generic
    # major, minor, patch
    mmp = linux_version.split("-")[0].split(".")
    return ".".join(mmp[:level])


def get_os_version():
    """Get the OS version

    >>> get_os_version()
    Ubuntu 18.04.6 LTS
    """

    os_release = Path("/etc/os-release").read_text(encoding="ascii")
    match = re.search('PRETTY_NAME="(.*)"', os_release)
    return match.group(1)


class GlobalProps:
    """Class to hold metadata about the testrun environment"""

    def __init__(self):
        self.cpu_architecture: str = platform.machine()
        self.cpu_model = get_cpu_model_name()
        self.cpu_vendor = get_cpu_vendor().name.lower()
        self.cpu_microcode = run_cmd(
            "grep microcode /proc/cpuinfo |head -1 |awk '{print $3}'"
        )
        self.host_linux_full_version = platform.release()
        # major.minor
        self.host_linux_version = get_kernel_version(2)
        # major.minor.patch
        self.host_linux_patch = get_kernel_version(3)
        self.os = get_os_version()
        self.libc_ver = "-".join(platform.libc_ver())
        self.git_commit_id = run_cmd("git rev-parse HEAD")
        self.git_branch = run_cmd("git show -s --pretty=%D HEAD")
        self.git_origin_url = run_cmd("git config --get remote.origin.url")
        self.rust_version = run_cmd("rustc --version |awk '{print $2}'")

        self.environment = self._detect_environment()
        if self.is_ec2:
            self.instance = imdsv2_get("/meta-data/instance-type")
            self.ami = imdsv2_get("/meta-data/ami-id")
        else:
            self.instance = "NA"
            self.ami = "NA"

    @property
    def is_ec2(self):
        """Are we running on an EC2 instance?"""
        return self.environment == "ec2"

    def _detect_environment(self):
        """Detect what kind of environment we are running under

        The most reliable way is to just query IMDSv2
        https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/identify_ec2_instances.html
        """

        try:
            imdsv2_get("/meta-data/instance-type")
            return "ec2"
        except Exception:
            return "local"


global_props = GlobalProps()
# TBD could do a props fixture for tests to use...
