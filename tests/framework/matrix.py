# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Generate multiple microvm configurations and run tests.

Implements a component that calls a specific function in the context
of the cartesian product of all artifact sets.
"""

import os
from framework.artifacts import ARTIFACTS_LOCAL_ROOT


class TestContext:
    """Define a context for running test fns by TestMatrix."""

    __test__ = False

    def __init__(self):
        """Initialize the test context."""
        self._context = {}

    def set_any(self, key, value):
        """Set any key value in the context."""
        self._context[key] = value

    @property
    def kernel(self):
        """Return the kernel artifact."""
        return self._context.get('kernel', None)

    @kernel.setter
    def kernel(self, kernel):
        """Setter for kernel artifact."""
        self._context['kernel'] = kernel

    @property
    def disk(self):
        """Return the disk artifact."""
        return self._context.get('disk', None)

    @disk.setter
    def disk(self, disk):
        """Setter for disk artifact."""
        self._context['disk'] = disk

    @property
    def microvm(self):
        """Return the microvm artifact."""
        return self._context.get('microvm', None)

    @microvm.setter
    def microvm(self, microvm):
        """Setter for kernel artifact."""
        self._context['microvm'] = microvm

    @property
    def snapshot(self):
        """Return the snapshot artifact."""
        return self._context.get('snapshot', None)

    @snapshot.setter
    def snapshot(self, snapshot):
        """Setter for snapshot artifact."""
        self._context['snapshot'] = snapshot

    @property
    def custom(self):
        """Return the custom context."""
        return self._context.get('custom', None)

    @custom.setter
    def custom(self, custom):
        """Setter for custom context."""
        self._context['custom'] = custom


class TestMatrix:
    """Computes the cartesian product of artifacts."""

    __test__ = False

    def __init__(self,
                 artifact_sets,
                 context=TestContext(),
                 cache_dir=ARTIFACTS_LOCAL_ROOT):
        """Initialize context, cache dir, and artifact_sets."""
        self._context = context
        # Stores the artifact sets array.
        self._sets = artifact_sets
        # ArtifactSet stack pointer.
        self._set_index = 0
        if not os.path.exists(cache_dir):
            os.mkdir(cache_dir)
        self._cache_dir = cache_dir

    @property
    def sets(self):
        """Return the artifact sets."""
        return self._sets

    def download_artifacts(self):
        """Download all configured artifacts."""
        for artifact_set in self._sets:
            for artifact in artifact_set.artifacts:
                artifact.download(self._cache_dir)

    def _backtrack(self, test_fn, cartesian_product):
        if len(self._sets) < self._set_index:
            return

        # Validate solution: tuple element count is equal to
        # set stack size.
        if len(self._sets) == len(cartesian_product):
            self._run_test_fn(cartesian_product, test_fn)
            return

        current_set = self._sets[self._set_index]
        for _artifact in current_set.artifacts:
            # Prepare for recursive call.
            # Push the current Artifact in the solution.
            cartesian_product.append(_artifact)
            # Go 1 level up the ArtifactSet stack.
            self._set_index += 1

            self._backtrack(test_fn, cartesian_product)

            # Pop the previous artifact from solution.
            cartesian_product.pop()
            # Walk down 1 level.
            self._set_index -= 1

    def _run_test_fn(self, artifacts, test_fn):
        """Patch context and call test_fn."""
        for artifact in artifacts:
            self._context.set_any(artifact.type.value, artifact)
        test_fn(self._context)

    def run_test(self, test_fn):
        """Run a test function.

        Iterates over the cartesian product of artifact sets and
        calls `test_fn` for each element.
        """
        self.download_artifacts()
        # Reset artifact stack pointer.
        self._set_index = 0

        # Recursive backtracking will generate the cartesian product of
        # the artifact sets.
        self._backtrack(test_fn, [])
