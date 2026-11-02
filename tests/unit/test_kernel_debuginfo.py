# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check debug-info splitting with real compiler and binutils output."""

import gzip
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REQUIRED_TOOLS = ("bash", "cc", "gzip", "objcopy", "readelf")
SPLIT_DEBUGINFO = r"""
source <(sed '$d' "$1")
ARCH="$2"
cd "$3"
vmlinux_split_debuginfo "$4" "linux-6.1"
"""


@unittest.skipUnless(
    all(shutil.which(tool) for tool in REQUIRED_TOOLS),
    "A C compiler and binutils are required",
)
class KernelDebuginfoTests(unittest.TestCase):
    """Preserve ARM64 images while retaining x86 ELF debug links."""

    def setUp(self):
        """Create an ELF debug source and output directory; return None."""

        directory = tempfile.TemporaryDirectory(prefix="fc-kernel-debug-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "linux-6.1").mkdir()
        (self.root / "output with spaces").mkdir()
        self.elf = self.root / "linux-6.1/vmlinux"
        self.image = self.root / "output with spaces/vmlinux-test"
        subprocess.run(
            ["cc", "-g", "-c", "-x", "c", "-o", str(self.elf), "-"],
            input="int main(void) { return 0; }\n",
            text=True,
            capture_output=True,
            check=True,
            timeout=30,
        )

    def run_split(self, arch):
        """Run the real helper for arch; return its completed process."""

        return subprocess.run(
            [
                "bash",
                "-c",
                SPLIT_DEBUGINFO,
                "kernel-debuginfo-test",
                str(REPO / "resources/rebuild.sh"),
                arch,
                str(self.root),
                str(self.image),
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )

    def check_debug_info(self):
        """Check compressed ELF debug sections; return None."""

        debug = self.image.with_suffix(".debug")
        compressed = self.image.with_suffix(".debug.gz")
        self.assertTrue(compressed.is_file())
        self.assertFalse(debug.exists())
        debug.write_bytes(gzip.decompress(compressed.read_bytes()))
        sections = subprocess.check_output(
            ["readelf", "-S", str(debug)], text=True, timeout=10
        )
        self.assertIn(".debug_info", sections)
        self.assertIn(".debug_line", sections)

    def test_arm64_boot_image_is_unchanged(self):
        """Preserve ARM64 boot bytes and extract ELF symbols; return None."""

        self.image = self.root / "vmlinux-arm64"
        image = bytearray(4096)
        image[:2] = b"MZ"
        image[56:60] = b"ARMd"
        self.image.write_bytes(image)
        original_elf = self.elf.read_bytes()
        result = self.run_split("aarch64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.image.read_bytes(), image)
        self.assertEqual(self.elf.read_bytes(), original_elf)
        self.check_debug_info()

    def test_x86_elf_is_stripped_and_linked(self):
        """Strip x86 debug sections and keep the debug link; return None."""

        shutil.copyfile(self.elf, self.image)
        result = self.run_split("x86_64")
        self.assertEqual(result.returncode, 0, result.stderr)
        sections = subprocess.check_output(
            ["readelf", "-S", str(self.image)], text=True, timeout=10
        )
        self.assertNotIn(".debug_info", sections)
        link = subprocess.check_output(
            ["readelf", "--string-dump=.gnu_debuglink", str(self.image)],
            timeout=10,
        )
        self.assertIn((self.image.name + ".debug").encode("ascii"), link)
        self.check_debug_info()

    def test_invalid_debug_source_preserves_boot_image(self):
        """Preserve the image when ELF extraction fails; return None."""

        image = b"boot image must remain intact"
        self.image.write_bytes(image)
        self.elf.write_bytes(b"invalid ELF")
        result = self.run_split("aarch64")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.image.read_bytes(), image)
        self.assertFalse(self.image.with_suffix(".debug.gz").exists())
