# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the GitHub release helper."""

import tarfile
from pathlib import Path

import gh_release


def test_build_tarball_excludes_custom_cpu_templates(tmp_path):
    """Custom CPU templates are already available in the repository."""
    release_dir = tmp_path / "release-v1.15.0-x86_64"
    release_dir.mkdir()
    included_assets = [
        "firecracker-v1.15.0-x86_64",
        "firecracker_spec-v1.15.0.yaml",
        "seccomp-filter-v1.15.0-x86_64.json",
    ]
    excluded_assets = [
        "C3-v1.15.0.json",
        "GNR_TO_T2_5.10-v1.15.0.json",
        "RELEASE_NOTES",
        "SHA256SUMS.sig",
    ]
    for asset in included_assets + excluded_assets:
        (release_dir / asset).write_text("test asset", encoding="utf-8")

    release_tgz = tmp_path / "firecracker-v1.15.0-x86_64.tgz"
    gh_release.build_tarball(release_dir, release_tgz, "x86_64")

    with tarfile.open(release_tgz) as tar:
        tar_assets = {Path(member.name).name for member in tar.getmembers()}

    assert tar_assets == set(included_assets)
