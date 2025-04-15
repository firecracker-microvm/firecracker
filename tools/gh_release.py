#!/usr/bin/env python3
# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Draft a release in GitHub by calling into its API.

Assumes all the releases are in the current path.
"""

import argparse
import re
import subprocess
import tarfile
from pathlib import Path

from github import Github


def build_tarball(release_dir, release_tgz, arch):
    """Build a release tarball with local assets"""
    # Do not include signatures in GitHub release since we aren't
    # making those keys public.
    # Exclude CPU templates in GitHub release as they are already
    # available on GitHub without any action (like building a binary).
    exclude_files = {
        "RELEASE_NOTES",
        "SHA256SUMS.sig",
        *[f.stem for f in Path("tests/data/custom_cpu_templates").glob("*.json")],
    }
    with tarfile.open(release_tgz, "w:gz") as tar:
        files = [x for x in release_dir.rglob("*") if x.is_file()]
        for asset in files:
            if asset.name in exclude_files:
                print(f"Skipping file {asset}")
                continue
            if asset.name.endswith(arch):
                print(f"Setting +x bit for {asset}")
                asset.chmod(0o755)
            print(f"Adding {asset} to {release_tgz}")
            tar.add(asset)


def github_release(tag_version, repo, github_token):
    """Create a draft release in GitHub"""
    prerelease = False
    assets = []
    for arch in ["x86_64", "aarch64"]:
        release_dir = Path(f"release-{tag_version}-{arch}")
        # Build tarball
        release_tgz = Path(f"firecracker-{tag_version}-{arch}.tgz")
        print(f"Creating release archive {release_tgz} ...")
        build_tarball(release_dir, release_tgz, arch)
        print("Done. Archive successfully created. sha256sum result:")
        sha256sums = release_tgz.with_suffix(release_tgz.suffix + ".sha256.txt")
        subprocess.run(
            f"sha256sum {release_tgz} > {sha256sums}",
            check=True,
            shell=True,
        )
        print(sha256sums.read_text("utf-8"))
        assets.append(release_tgz)
        assets.append(sha256sums)

    assets.append(Path("test_results.tar.gz"))

    message_file = Path(f"release-{tag_version}-x86_64") / "RELEASE_NOTES"
    message = message_file.read_text()

    # Create release
    print("Creating GitHub release draft")
    gh_client = Github(github_token)
    gh_repo = gh_client.get_repo(repo)
    gh_release = gh_repo.create_git_release(
        tag_version,
        f"Firecracker {tag_version}",
        message,
        draft=True,
        prerelease=prerelease,
    )

    # Upload assets
    for asset in assets:
        content_type = "application/octet-stream"
        if asset.suffix == ".txt":
            content_type = "text/plain"
        elif asset.suffix in {".tgz", ".gz"}:
            content_type = "application/gzip"
        print(f"Uploading asset {asset} with content-type={content_type}")
        gh_release.upload_asset(str(asset), label=asset.name, content_type=content_type)

    release_url = gh_release.html_url
    print(f"Draft release created successful. Check it out at {release_url}")


def version(version_str: str):
    """Validate version parameter"""
    if not re.fullmatch(r"v\d+\.\d+\.\d+", version_str):
        raise ValueError("version does not match vX.Y.Z")
    return version_str


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--version",
        required=True,
        metavar="vX.Y.Z",
        help="Firecracker version.",
        type=version,
    )
    parser.add_argument(
        "--repository", required=False, default="firecracker-microvm/firecracker"
    )
    parser.add_argument("--github-token", required=True)
    args = parser.parse_args()
    github_release(
        tag_version=args.version,
        repo=args.repository,
        github_token=args.github_token,
    )
