# Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# pylint:disable=broad-except

"""
Metadata we want to attach to tests for further analysis and troubleshooting
"""
import os
import platform
import re
import subprocess
from pathlib import Path

from framework.utils import get_kernel_version
from framework.utils_cpuid import get_cpu_codename, get_cpu_model_name, get_cpu_vendor
from framework.utils_imdsv2 import imdsv2_get


def run_cmd(cmd):
    """Return the stdout of a command"""
    return subprocess.check_output(cmd, shell=True).decode().strip()


def get_os_version():
    """Get the OS version

    >>> get_os_version()
    'Ubuntu 24.04.1 LTS'
    """

    os_release = Path("/etc/os-release").read_text(encoding="ascii")
    match = re.search('PRETTY_NAME="(.*)"', os_release)
    return match.group(1)


def get_host_os(kv: str = None):
    """
    Extract OS information from the kernel if it's there.

    This only works for AL2 and AL2023

    >>> get_host_os("6.1.41-63.118.amzn2023.x86_64")
    'amzn2023'
    """
    if kv is None:
        kv = platform.release()
    parts = kv.split("-")
    if len(parts) < 2:
        return kv
    misc = parts[1].split(".")
    if len(misc) > 2 and misc[2] in {"amzn2", "amzn2023"}:
        return misc[2]
    return kv


class GlobalProps:
    """Class to hold metadata about the testrun environment"""

    def __init__(self):
        self.cpu_architecture: str = platform.machine()
        self.cpu_model = get_cpu_model_name()
        self.cpu_codename = get_cpu_codename()
        self.cpu_vendor = get_cpu_vendor().name.lower()
        self.cpu_microcode = run_cmd(
            "grep microcode /proc/cpuinfo |head -1 |awk '{print $3}'"
        )
        self.host_linux_full_version = platform.release()
        # major.minor
        self.host_linux_version = get_kernel_version(1)
        # major.minor.patch
        self.host_linux_patch = get_kernel_version(2)
        self.os = get_os_version()
        self.host_os = get_host_os() or "NA"
        self.libc_ver = "-".join(platform.libc_ver())
        self.rust_version = run_cmd("rustc --version |awk '{print $2}'")
        # Buildkite/PR information
        self.buildkite_pipeline_slug = os.environ.get("BUILDKITE_PIPELINE_SLUG")
        self.buildkite_build_number = os.environ.get("BUILDKITE_BUILD_NUMBER")
        self.buildkite_pr = os.environ.get("BUILDKITE_PULL_REQUEST", "false") != "false"
        self.buildkite_revision_a = os.environ.get("BUILDKITE_PULL_REQUEST_BASE_BRANCH")

        if self._in_git_repo():
            self.git_commit_id = run_cmd("git rev-parse HEAD")
            self.git_branch = run_cmd("git show -s --pretty=%D HEAD")
            self.git_origin_url = run_cmd("git config --get remote.origin.url")
        else:
            self.git_commit_id = None
            self.git_branch = None
            self.git_origin_url = None

        self.environment = self._detect_environment()
        if self.is_ec2:
            self.instance = imdsv2_get("/meta-data/instance-type")
            self.ami = imdsv2_get("/meta-data/ami-id")
        else:
            self.instance = "NA"
            self.ami = "NA"

    @property
    def host_linux_version_tpl(self):
        """Host Linux version major.minor, as a tuple for easy comparison"""
        return tuple(int(x) for x in self.host_linux_version.split("."))

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

    def _in_git_repo(self):
        try:
            run_cmd("git rev-parse --show-toplevel")
        except subprocess.CalledProcessError:
            return False
        return True


global_props = GlobalProps()
