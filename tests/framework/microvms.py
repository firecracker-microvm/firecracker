# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define helper functions that create predefined type of resources."""

from framework.artifacts import ArtifactCollection
from framework.builder import MicrovmBuilder
import host_tools.network as net_tools
from conftest import _test_images_s3_bucket


class VmInstance:
    """A class that describes a microvm instance resources."""

    def __init__(self, config, kernel, disks, ssh_key, vm):
        """Initialize a Vm configuration based on artifacts."""
        self._config = config
        self._kernel = kernel
        self._disks = disks
        self._ssh_key = ssh_key
        self._vm = vm

    @property
    def config(self):
        """Return machine config artifact."""
        return self._config

    @property
    def kernel(self):
        """Return the kernel artifact."""
        return self._kernel

    @property
    def disks(self):
        """Return an array of block file paths."""
        return self._disks

    @property
    def ssh_key(self):
        """Return ssh key artifact linked to the root block device."""
        return self._ssh_key

    @property
    def vm(self):
        """Return the Microvm object intsance."""
        return self._vm


# VM base class to abstract away the s3 artifacts we are using
# to specify the configuration
# Too few public methods (1/2) (too-few-public-methods)
# pylint: disable=R0903
class VMBase:
    """Base class for constructing microvms."""

    @classmethod
    def from_artifacts(cls, bin_cloner_path, config,
                       kernel, disks, cpu_template, start=False,
                       fc_binary=None, jailer_binary=None):
        """Spawns a new Firecracker and applies specified config."""
        artifacts = ArtifactCollection(_test_images_s3_bucket())
        # Pick the first artifact in the set.
        config = artifacts.microvms(keyword=config)[0]
        kernel = artifacts.kernels(keyword=kernel)[0]
        disks = artifacts.disks(keyword=disks)
        config.download()
        kernel.download()
        attached_disks = []
        for disk in disks:
            disk.download()
            attached_disks.append(disk.copy())

        vm_builder = MicrovmBuilder(bin_cloner_path,
                                    fc_binary,
                                    jailer_binary)

        # SSH key is attached to root disk artifact.
        # Builder will download ssh key in the VM root.
        ssh_key = disks[0].ssh_key()

        # Create a fresh microvm from aftifacts.
        basevm = vm_builder.build(kernel=kernel,
                                  disks=attached_disks,
                                  ssh_key=ssh_key,
                                  config=config,
                                  cpu_template=cpu_template)

        if start:
            basevm.start()
            ssh_connection = net_tools.SSHConnection(basevm.ssh_config)

            # Verify if we can run commands in guest via ssh.
            exit_code, _, _ = ssh_connection.execute_command("sync")
            assert exit_code == 0

        return VmInstance(config, kernel, attached_disks, ssh_key, basevm)


class C3nano(VMBase):
    """Create VMs with 2vCPUs and 256 MB RAM."""

    @classmethod
    def spawn(cls, bin_cloner_path, start=False,
              fc_binary=None, jailer_binary=None):
        """Spawns and optionally starts the vm."""
        return VMBase.from_artifacts(bin_cloner_path,
                                     "2vcpu_256mb",
                                     "vmlinux-4.14",
                                     "ubuntu-18.04",
                                     "C3",
                                     start,
                                     fc_binary,
                                     jailer_binary)


class C3micro(VMBase):
    """Create VMs with 2vCPUs and 512 MB RAM."""

    @classmethod
    def spawn(cls, bin_cloner_path, start=False,
              fc_binary=None, jailer_binary=None):
        """Spawns and optionally starts the vm."""
        return VMBase.from_artifacts(bin_cloner_path,
                                     "2vcpu_512mb",
                                     "vmlinux-4.14",
                                     "ubuntu-18.04",
                                     "C3",
                                     start,
                                     fc_binary,
                                     jailer_binary)
