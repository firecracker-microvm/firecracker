# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Utilities to deal with the git repo."""

import subprocess
from fnmatch import fnmatch
from pathlib import Path


def git_repo_files(root: str = ".", glob: str = "*"):
    """
    Return a list of files in the git repo from a given path

    :param root: path where to look for files, defaults to the current dir
    :param glob: what pattern to apply to file names
    :return: list of found files
    """
    files = subprocess.check_output(
        ["git", "ls-files", root],
        encoding="ascii",
    ).splitlines()
    for file in files:
        if fnmatch(file, glob):
            yield Path(file)
