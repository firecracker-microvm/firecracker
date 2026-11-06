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
# Source "rebuild.sh" without its final main invocation to avoid side effects.
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
    version=$(basename "${2:-}" .config)
    version="${version##*-$ARCH-}"
    OUTPUT_FILE="$OUTPUT_DIR/vmlinux-$version.168${1:-}"
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
# Build both normal and 64 KiB images; optionally simulate olddefconfig rejecting
# the 64 KiB selection to exercise the resolved-config guard.
# As above, omit rebuild.sh's final main invocation when sourcing it.
# Parameters passed after the bash -c command string:
#   $0: Diagnostic script name (kernel-image-test).
#   $1: Path to resources/rebuild.sh.
#   $2: Temporary working directory containing linux/ and output/ fixtures.
#   $3: Repository resources directory containing guest_configs/.
#   $4: Whether to reject the 64 KiB selection (yes or no; defaults to no).
#   $5: Kernel version (defaults to 6.1).
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
    if [ "${1:-}" = "olddefconfig" ] && [ "$reject_config" = "yes" ]
    then
        sed -i '/CONFIG_ARM64_64K_PAGES=y/d' .config
    fi
    [ "${1:-}" != "-j" ] || touch compiled
    return 0
}
reject_config="${4:-no}"
version="${5:-6.1}"
build_al_kernel "" "$3/guest_configs/microvm-kernel-ci-aarch64-$version.config"
build_al_kernel "-64k" \
    "$3/guest_configs/microvm-kernel-ci-aarch64-$version.config" \
    "$3/guest_configs/64k-aarch64.config"
"""


class KernelBuildTests(unittest.TestCase):
    """Check architecture gating and normal/debug variant isolation."""

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
            json.loads(line.partition("] ")[2])
            for line in result.stdout.splitlines()
            if line.partition("] ")[2].startswith("[")
        ]
        return result, calls

    def test_arm64_builds_normal_and_debug_64k(self):
        """Build both 64 KiB kernel versions with normal and debug configs."""

        for version in ("6.1", "6.18"):
            with self.subTest(version=version):
                self.check_64k_build(version)

    def check_64k_build(self, version):
        """Both versions must merge the page-size fragment last."""

        result, calls = self.run_build("aarch64", f"{version}-64k")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertEqual(call[1], "-64k")
            self.assertTrue(call[2].endswith(f"aarch64-{version}.config"))
            self.assertTrue(call[-1].endswith("/64k-aarch64.config"))
        self.assertEqual(Path(calls[1][0]).name, "debug")
        self.assertTrue(any(p.endswith("/debug.config") for p in calls[1]))
        self.assertIn(f"vmlinux-{version}.168-64k", result.stdout)

    def test_arm64_all_builds_existing_variants(self):
        """Check that the default ARM64 build includes existing variants."""

        result, calls = self.run_build("aarch64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 10)
        variants = [call for call in calls if call[1] == "-64k"]
        self.assertEqual(len(variants), 4)
        for version in ("6.1", "6.18"):
            self.assertEqual(
                sum(call[2].endswith(f"-{version}.config") for call in variants),
                2,
            )

    def test_x86_all_keeps_existing_variants(self):
        """Check that the default x86 build includes existing variants."""

        result, calls = self.run_build("x86_64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 7)
        self.assertTrue(all(call[1] == "" for call in calls))

    def test_efi_config_is_included_for_acpi_kernels(self):
        """Keep EFI in normal and debug builds, including 64 KiB variants."""

        for arch in ("aarch64", "x86_64"):
            with self.subTest(arch=arch):
                result, calls = self.run_build(arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(calls)
                for call in calls:
                    has_efi = any(p.endswith("/efi.config") for p in call[3:])
                    self.assertEqual(has_efi, "no-acpi" not in call[2], call)

    def test_explicit_4k_build_is_unchanged(self):
        """Check explicit version selection for normal and debug kernels."""

        for version in ("6.1", "6.18"):
            with self.subTest(version=version):
                result, calls = self.run_build("aarch64", version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(calls), 2)
                self.assertTrue(all(call[1] == "" for call in calls))

    def test_invalid_requests_fail_before_build(self):
        """Reject unsupported versions and excess arguments before building."""

        for arch, versions in (
            ("x86_64", ("6.1-64k",)),
            ("x86_64", ("6.18-64k",)),
            ("aarch64", ("6.1-16k",)),
            ("aarch64", ("6.1", "6.18")),
        ):
            with self.subTest(arch=arch, versions=versions):
                result, calls = self.run_build(arch, *versions)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_image_names_and_resolved_config_guard(self):
        """Check image names and require the resolved 64 KiB configuration."""

        for version in ("6.1", "6.18"):
            for reject_config in ("no", "yes"):
                with self.subTest(version=version, reject_config=reject_config):
                    self.check_image_build(version, reject_config)

    def check_image_build(self, version, reject_config="no"):
        """Run the real image builder with a fake compiler and Git backend."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "output").mkdir()
            linux = root / f"linux-{version}"
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
                    reject_config,
                    version,
                ],
                cwd=REPO,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            self.assertTrue((root / f"output/vmlinux-{version}.168").is_file())
            image = root / f"output/vmlinux-{version}.168-64k"
            if reject_config == "yes":
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("did not enable 64 KiB", result.stderr)
                self.assertFalse(image.exists())
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(image.read_bytes(), b"test image")
                config = image.with_name(image.name + ".config").read_text()
                self.assertIn("CONFIG_ARM64_64K_PAGES=y", config)

    def test_image_names(self):
        """Check image filenames and saved configurations for each version."""

        for version in ("6.1", "6.18"):
            with self.subTest(version=version):
                self.check_image_build(version)
