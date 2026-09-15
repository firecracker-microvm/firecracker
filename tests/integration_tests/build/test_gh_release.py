# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the GitHub release helper."""

import importlib
import sys
import tarfile
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[3] / "tools"
sys.path.insert(0, str(TOOLS_DIR))

gh_release = importlib.import_module("gh_release")


def test_build_tarball_excludes_custom_cpu_templates(tmp_path):
    """Custom CPU templates are already available in the repository."""
    tag_version = "v1.15.0"
    release_dir = tmp_path / f"release-{tag_version}-x86_64"
    release_dir.mkdir()
    included_assets = [
        f"firecracker-{tag_version}-x86_64",
        f"firecracker_spec-{tag_version}.yaml",
        f"seccomp-filter-{tag_version}-x86_64.json",
    ]
    excluded_assets = [
        f"C3-{tag_version}.json",
        f"GNR_TO_T2_5.10-{tag_version}.json",
        "RELEASE_NOTES",
        "SHA256SUMS.sig",
    ]
    for asset in included_assets + excluded_assets:
        (release_dir / asset).write_text("test asset", encoding="utf-8")

    release_tgz = tmp_path / f"firecracker-{tag_version}-x86_64.tgz"
    gh_release.build_tarball(release_dir, release_tgz, "x86_64", tag_version)

    with tarfile.open(release_tgz) as tar:
        tar_assets = {Path(member.name).name for member in tar.getmembers()}

    assert tar_assets == set(included_assets)
