# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exercise kernel build selection without cloning or compiling Linux."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Run the real build scheduler, replacing cloning, compilation and debug-info
# splitting with stubs. Each build prints a JSON array containing its output
# directory and arguments; debug-info splitting prints a DEBUGINFO line.
# Source rebuild.sh without its final main invocation to avoid setup side effects.
# Parameters passed after the bash -c command string:
#   $0: Diagnostic script name (kernel-build-test).
#   $1: Path to resources/rebuild.sh.
#   $2: Target architecture (aarch64 or x86_64).
#   $3: Temporary working directory, also used as the output directory.
#   $4 onwards: Optional arguments forwarded to build_al_kernels.
BUILD_SELECTION = r"""
source <(sed '$d' "$1")
ARCH="$2"
OUTPUT_DIR="$3"
cd "$3"
clone_amazon_linux_repo() { :; }
build_al_kernel()
{
    local version
    version=$(basename "${1:-}" .config)
    version="${version##*-$ARCH-}"
    OUTPUT_FILE="$OUTPUT_DIR/vmlinux-$version.168"
    python3 -c 'import json, sys; print(json.dumps(sys.argv[1:]))' \
        "$OUTPUT_DIR" "$@"
}
vmlinux_split_debuginfo()
{
    echo "DEBUGINFO: ${1:-}"
}
shift 3
build_al_kernels "$@"
"""

# Run the real ARM64 image builder against a fake Linux tree. Stub Git, tag
# lookup, architecture detection and make, retaining config merging and image
# copies so tests can inspect the output without cloning or compiling Linux.
# As above, omit rebuild.sh's final main invocation when sourcing it.
# Parameters passed after the bash -c command string:
#   $0: Diagnostic script name (kernel-image-test).
#   $1: Path to resources/rebuild.sh.
#   $2: Temporary working directory containing linux/ and output/ fixtures.
#   $3: Repository resources directory containing guest_configs/.
#   $4: Kernel version (defaults to 6.1).
BUILD_IMAGE = r"""
source <(sed '$d' "$1")
ARCH="aarch64"
OUTPUT_DIR="$2/output"
cd "$2"
git() { :; }
get_tag() { echo test-kernel-tag; }
uname() { echo aarch64; }
make()
{
    return 0
}
version="${4:-6.1}"
build_al_kernel "$3/guest_configs/microvm-kernel-ci-aarch64-$version.config"
"""


class KernelBuildTests(unittest.TestCase):
    """Check existing build selection and kernel image output."""

    def run_build(self, arch, *versions):
        """Record the real scheduler's kernel build invocations."""

        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    BUILD_SELECTION,
                    "kernel-build-test",
                    str(REPO / "resources/rebuild.sh"),
                    arch,
                    directory,
                    *versions,
                ],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        calls = [
            json.loads(line)
            for line in result.stdout.splitlines()
            if line.startswith("[")
        ]
        return result, calls

    def test_arm64_all_builds_existing_variants(self):
        """Check that the default ARM64 build includes existing variants."""

        result, calls = self.run_build("aarch64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 6)

    def test_x86_all_keeps_existing_variants(self):
        """Check that the default x86 build includes existing variants."""

        result, calls = self.run_build("x86_64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 7)

    def test_explicit_4k_build_is_unchanged(self):
        """Check explicit version selection for normal and debug kernels."""

        for version in ("6.1", "6.18"):
            with self.subTest(version=version):
                result, calls = self.run_build("aarch64", version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 2)

    def test_invalid_requests_fail_before_build(self):
        """Reject unsupported versions and excess arguments before building."""

        for arch, versions in (
            ("aarch64", ("6.1-16k",)),
            ("aarch64", ("6.1", "6.18")),
        ):
            with self.subTest(arch=arch, versions=versions):
                result, calls = self.run_build(arch, *versions)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_image_names(self):
        """Check image filenames and saved configurations for each version."""

        for version in ("6.1", "6.18"):
            with self.subTest(version=version):
                self.check_image_build(version)

    def check_image_build(self, version):
        """Run the real image builder with a fake compiler and Git backend."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "output").mkdir()
            linux = root / "linux"
            (linux / "include/config").mkdir(parents=True)
            (linux / "arch/arm64/boot").mkdir(parents=True)
            (linux / "arch/arm64/boot/Image").write_bytes(b"test image")
            (linux / "include/config/kernel.release").write_text(f"{version}.168\n")
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    BUILD_IMAGE,
                    "kernel-image-test",
                    str(REPO / "resources/rebuild.sh"),
                    directory,
                    str(REPO / "resources"),
                    version,
                ],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertTrue((root / f"output/vmlinux-{version}.168").is_file())
            self.assertEqual(result.returncode, 0, result.stderr)
            image = root / f"output/vmlinux-{version}.168"
            self.assertEqual(image.read_bytes(), b"test image")
            self.assertTrue(image.with_name(image.name + ".config").is_file())
