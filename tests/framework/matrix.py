# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Generate multiple microvm configurations and run tests.

Implements a component that can run a specific test through a matrix of
microvm kernel, disk, cpu and ram configurations.
The matrix is computed as the cartesian product of all artifacts.
"""

import json
import os
from framework.microvm import Microvm
import host_tools.cargo_build as build_tools
import uuid


ARTIFACTS_LOCAL_ROOT = "/tmp/ci-artifacts/"


class TestContext:
    """Define a context for running test fns by TestMatrix."""

    __test__ = False

    def __init__(self):
        """Initialize the test context."""
        self._kernel = None
        self._disk = None
        self._microvm = None
        self._snapshot = None
        # User defined context.
        self._custom = None

    @property
    def kernel(self):
        """Return the kernel artifact."""
        return self._kernel

    @kernel.setter
    def kernel(self, kernel):
        """Setter for kernel artifact."""
        self._kernel = kernel

    @property
    def disk(self):
        """Return the disk artifact."""
        return self._disk

    @disk.setter
    def disk(self, disk):
        """Setter for disk artifact."""
        self._disk = disk

    @property
    def microvm(self):
        """Return the microvm artifact."""
        return self._microvm

    @microvm.setter
    def microvm(self, microvm):
        """Setter for kernel artifact."""
        self._microvm = microvm

    @property
    def snapshot(self):
        """Return the snapshot artifact."""
        return self._snapshot

    @snapshot.setter
    def snapshot(self, snapshot):
        """Setter for snapshot artifact."""
        self._snapshot = snapshot

    @property
    def custom(self):
        """Return the custom context."""
        return self._custom

    @custom.setter
    def custom(self, custom):
        """Setter for custom context."""
        self._custom = custom


class TestMatrix:
    """Computes the cartesian product of artifacts."""

    __test__ = False
    _kernels = []
    _disks = []
    _microvms = []
    _cache_dir = None
    _microvm = None
    _context = None

    def __init__(self, context=TestContext(), cache_dir=ARTIFACTS_LOCAL_ROOT):
        """Initialize the cache directory."""
        self._cache_dir = cache_dir
        self._context = context

        if not os.path.exists(cache_dir):
            os.mkdir(cache_dir)

    @property
    def disks(self):
        """Return the disk artifacts."""
        return self._disks

    @disks.setter
    def disks(self, disks):
        """Setter for disk artifacts."""
        self._disks = disks

    @property
    def kernels(self):
        """Return the kernel artifacts."""
        return self._kernels

    @kernels.setter
    def kernels(self, kernels):
        """Setter for kernel artifacts."""
        self._kernels = kernels

    @property
    def microvms(self):
        """Return the microvm artifacts."""
        return self._microvms

    @microvms.setter
    def microvms(self, microvms):
        """Setter for microvm artifacts."""
        self._microvms = microvms

    def download_artifacts(self):
        """Download all configured artifacts."""
        for disk in self.disks:
            disk.download(self._cache_dir)

        for kernel in self.kernels:
            kernel.download(self._cache_dir)

        for microvm in self.microvms:
            microvm.download(self._cache_dir)

    def run_test(self, test_fn):
        """Run a test function.

        The function will be called through the configuration matrix
        in the context of a TestMicrovm
        """
        self.download_artifacts()

        assert len(self.microvms) > 0
        assert len(self.kernels) > 0
        assert len(self.disks) > 0

        for microvm_config in self.microvms:
            for kernel in self.kernels:
                for disk in self.disks:
                    self._context.kernel = kernel
                    self._context.disk = disk
                    self._context.microvm = microvm_config
                    test_fn(self._context)
