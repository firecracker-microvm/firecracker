# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check kernel discovery without loading privileged integration fixtures."""

import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]


def load_artifacts(directory, arch="aarch64"):
    """Load the real catalogues against an isolated artefact directory."""

    definitions = types.ModuleType("framework.defs")
    definitions.ARTIFACT_DIR = directory
    spec = importlib.util.spec_from_file_location(
        "kernel_artifacts_test", REPO / "tests/framework/artifacts.py"
    )
    module = importlib.util.module_from_spec(spec)
    with (
        patch.dict(
            sys.modules,
            {"framework.defs": definitions, spec.name: module},
        ),
        patch("platform.machine", return_value=arch),
    ):
        spec.loader.exec_module(module)
    return module


class KernelArtifactsTests(unittest.TestCase):
    """Check supported kernels, metadata and catalogue selection."""

    def setUp(self):
        """Create temporary kernel artefacts and load their catalogues."""

        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "debug").mkdir()
        for name in (
            "vmlinux-5.10.233-no-acpi",
            "vmlinux-6.1.168",
            "vmlinux-6.1.168.config",
            "vmlinux-6.18.1",
            "debug/vmlinux-6.1.168",
            "debug/vmlinux-6.1.168.debug",
            "debug/vmlinux-6.18.1",
        ):
            (self.root / name).touch()
        self.artifacts = load_artifacts(self.root)

    def test_default_catalogues(self):
        """Check the default catalogues and supported kernel metadata."""

        self.assertEqual(len(self.artifacts.ALL_GUEST_KERNELS), 3)
        self.assertEqual(len(self.artifacts.ACPI_GUEST_KERNELS), 2)
        for catalogue, debug in (
            (self.artifacts.GUEST_KERNELS_6_1, False),
            (self.artifacts.GUEST_KERNELS_6_1_DEBUG, True),
        ):
            self.assertEqual(len(catalogue), 2)
            for param in catalogue:
                kernel = param.values[0]
                self.assertEqual(kernel.debug, debug)
                self.assertTrue(kernel.acpi)
                self.assertEqual(kernel.efi_image, kernel.vmlinux)
                self.assertEqual(kernel.pytest_id, f"vmlinux-{kernel.version}")
                major_minor = ".".join(kernel.version.split(".")[:2])
                self.assertEqual(kernel.metric_id, f"linux-{major_minor}")
        self.assertEqual(self.artifacts.GUEST_KERNEL_DEFAULT.id, "vmlinux-6.1.168")

    def test_filename_validation(self):
        """Accept supported kernel names and reject malformed variants."""

        parse = self.artifacts.parse_vmlinux_name
        self.assertEqual(parse("vmlinux-6.1.168"), ("6.1.168", True))
        self.assertEqual(parse("vmlinux-5.10.233-no-acpi"), ("5.10.233", False))
        for name in (
            "vmlinux-6.1.168-16k",
            "vmlinux-6.1.168.config",
            "../vmlinux-6.1.168",
            "bzImage-6.1.168",
        ):
            with self.subTest(name=name):
                self.assertIsNone(parse(name))

    def test_unsupported_versions_fail(self):
        """Reject unsupported versions and no-ACPI kernel combinations."""

        for name in ("vmlinux-6.1", "vmlinux-6.2.1", "vmlinux-6.1.168-no-acpi"):
            path = self.root / name
            path.touch()
            with self.subTest(name=name), self.assertRaises(ValueError):
                list(self.artifacts.kernels(name, self.root))
            path.unlink()
