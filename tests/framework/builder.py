# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define some helpers methods to create microvms from artifacts."""

import json
import os
from conftest import init_microvm
from framework.artifacts import Artifact, DiskArtifact


class MicrovmBuilder:
    """Build fresh microvms or restore from snapshot."""

    def __init__(self, root_path, bin_cloner_path):
        """Initialize microvm root and cloning binary."""
        self.root_path = root_path
        self.bin_cloner_path = bin_cloner_path

    def build(self, kernel: Artifact, disks: [DiskArtifact], config: Artifact):
        """Build a fresh microvm."""
        vm = init_microvm(self.root_path, self.bin_cloner_path)
        vm.setup()

        # Link the microvm to kernel, rootfs, ssh_key artifacts.
        vm.kernel_file = kernel.local_path()
        vm.rootfs_file = disks[0].local_path()
        ssh_key = disks[0].ssh_key()

        # Download ssh key into microvm root.
        ssh_key.download(self.root_path)
        vm.ssh_config['ssh_key_path'] = ssh_key.local_path()
        os.chmod(vm.ssh_config['ssh_key_path'], 0o400)

        # Start firecracker.
        vm.spawn()

        with open(config.local_path()) as microvm_config_file:
            microvm_config = json.load(microvm_config_file)

        # Apply the microvm artifact configuration
        vm.basic_config(vcpu_count=int(microvm_config['vcpu_count']),
                        mem_size_mib=int(microvm_config['mem_size_mib']),
                        ht_enabled=bool(microvm_config['ht_enabled']))

        return vm

    # TBD: Snapshot support is not fully merged. Once that is read
    # this function will provide a way to spin up clones.
    def build_from_snapshot(self, snapshot: Artifact):
        """Build a microvm from a snapshot artifact."""
