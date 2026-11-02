# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exercise rootfs SSH-key injection with real filesystem image tools."""

import gzip
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REQUIRED_TOOLS = (
    "bash",
    "debugfs",
    "gunzip",
    "mkfs.ext4",
    "mksquashfs",
    "ssh-keygen",
    "unsquashfs",
)


@unittest.skipUnless(
    all(shutil.which(tool) for tool in REQUIRED_TOOLS),
    "Filesystem image tools and OpenSSH are required",
)
class ArtifactStagingTests(unittest.TestCase):
    """Check staged rootfs images against their corresponding SSH keys."""

    def setUp(self):
        """Create temporary source and artefact directories; return None."""

        directory = tempfile.TemporaryDirectory(prefix="fc-artifact-staging-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / "source"
        ssh_dir = self.source / "root/.ssh"
        ssh_dir.mkdir(parents=True)
        (ssh_dir / "authorized_keys").write_text("original-image-key\n")
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.image = self.artifacts / "amazonlinux-2023.squashfs"
        self.create_image()

    def run_command(self, *command):
        """Run command arguments and return CompletedProcess[str]."""

        result = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=30
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def create_image(self):
        """Pack self.source into self.image; return None."""

        self.run_command(
            "mksquashfs",
            str(self.source),
            str(self.image),
            "-noappend",
            "-processors",
            "1",
            "-quiet",
        )

    def stage(self):
        """Stage self.artifacts with a debug fixture; return None."""

        # Supply "gunzip" input even before empty-input handling is fixed.
        (self.artifacts / "test.debug").unlink(missing_ok=True)
        (self.artifacts / "test.debug.gz").write_bytes(gzip.compress(b"debug"))
        self.run_command(
            "bash", str(REPO / "tools/setup-ci-artifacts.sh"), str(self.artifacts)
        )

    def check_image_keys(self):
        """Assert both rootfs images match their private key; return None."""

        key = self.run_command(
            "ssh-keygen",
            "-y",
            "-P",
            "",
            "-f",
            str(self.image.with_suffix(".id_rsa")),
        ).stdout.split()[:2]
        squashfs_key = self.run_command(
            "unsquashfs", "-cat", str(self.image), "root/.ssh/authorized_keys"
        ).stdout.split()[:2]
        ext4_key = self.run_command(
            "debugfs",
            "-R",
            "cat /root/.ssh/authorized_keys",
            str(self.image.with_suffix(".ext4")),
        ).stdout.split()[:2]
        self.assertEqual(squashfs_key, key)
        self.assertEqual(ext4_key, key)

    def test_fresh_staging_injects_matching_keys(self):
        """Check initial SSH-key injection in both image formats; return None."""

        self.stage()
        self.check_image_keys()
