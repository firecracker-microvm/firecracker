#!/usr/bin/env python3
# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# pylint:disable=invalid-name

"""Print changelog of specified version with markdown stripped"""

import sys
from pathlib import Path

if __name__ == "__main__":
    cur_version = sys.argv[1]

    with Path(__file__).parent.joinpath("../CHANGELOG.md").open(encoding="UTF-8") as f:
        changelog_lines = f.readlines()

    # Skip first 7 lines because they contain the "keep a changelog" metadata
    changelog_lines = changelog_lines[7:]

    iterator = iter(changelog_lines)

    for line in iterator:
        if line.startswith(f"## [{cur_version}]"):
            break
    else:
        print(f"Could not find changelog entry for version {cur_version}!")
        sys.exit(1)

    for line in iterator:
        if line.startswith("## ["):
            break

        if line.startswith("#"):
            line = line.lstrip("#").lstrip()

        if line.startswith("-"):
            line = line.replace("-", "*", 1)

        print(line, end="")
