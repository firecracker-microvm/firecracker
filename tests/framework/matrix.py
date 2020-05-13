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


class TestMatrix:
    """Computes the cartesian product of artifacts."""

    __test__ = False
    _kernels = []
    _disks = []
    _microvms = []
    _cache_dir = None
    _microvm = None
    _context = None

    def __init__(self, context=dict(), cache_dir=ARTIFACTS_LOCAL_ROOT):
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

    def configure_microvm(self, microvm_config, kernel, disk):
        """Link the microvm to kernel, rootfs, ssh_key artifacts."""
        self._microvm.kernel_file = kernel.local_path()
        self._microvm.rootfs_file = disk.local_path()
        ssh_key = disk.ssh_key()
        ssh_key.download(self._cache_dir)
        self._microvm.ssh_config['ssh_key_path'] = ssh_key.local_path()
        os.chmod(self._microvm.ssh_config['ssh_key_path'], 0o400)

        # Start firecracker.
        self._microvm.spawn()

        # Apply the microvm artifact configuration.
        self._microvm.apply_microvm_config(microvm_config)

    def run_test(self, test_fn, test_session_root_path, bin_cloner_path):
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
                    self._microvm = init_microvm(test_session_root_path,
                                                 bin_cloner_path)
                    self.configure_microvm(microvm_config, kernel, disk)
                    self._context.update({
                        'microvm': microvm_config,
                        'kernel': kernel,
                        'disk': disk
                    })
                    test_fn(self._context, self._microvm)


def init_microvm(root_path, bin_cloner_path):
    """Auxiliary function for instantiating a microvm and setting it up."""
    # pylint: disable=redefined-outer-name
    # The fixture pattern causes a pylint false positive for that rule.
    microvm_id = str(uuid.uuid4())
    fc_binary, jailer_binary = build_tools.get_firecracker_binaries()

    vm = TestMicrovm(
        resource_path=root_path,
        fc_binary_path=fc_binary,
        jailer_binary_path=jailer_binary,
        microvm_id=microvm_id,
        bin_cloner_path=bin_cloner_path
    )
    vm.setup()
    return vm


class TestMicrovm(Microvm):
    """Specializes the configuration using a microvm artifact."""

    def apply_microvm_config(self, microvm_artifact):
        """Configure vCPUs, RAM and HT."""
        with open(microvm_artifact.local_path()) as microvm_config_file:
            microvm_config = json.load(microvm_config_file)

        self.basic_config(vcpu_count=int(microvm_config['vcpu_count']),
                          mem_size_mib=int(microvm_config['mem_size_mib']),
                          ht_enabled=bool(microvm_config['ht_enabled']))
