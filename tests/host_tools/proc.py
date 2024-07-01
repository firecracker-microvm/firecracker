# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utility functions for interacting with the processor."""
import re

from framework import utils


def proc_type():
    """Obtain the model processor on a Linux system."""
    cmd = "cat /proc/cpuinfo"
    result = utils.check_output(cmd)
    lines = result.stdout.strip().splitlines()
    for line in lines:
        if "model name" in line:
            return re.sub(".*model name.*:", "", line, 1)

    cmd = "uname -m"
    result = utils.check_output(cmd).stdout.strip()
    if "aarch64" in result:
        return "ARM"
    return ""
