# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define some helpers methods to create microvms from artifacts."""

import json
import os
import shutil
import tempfile
from pathlib import Path
from conftest import init_microvm, _test_images_s3_bucket
from framework.defs import DEFAULT_TEST_SESSION_ROOT_PATH
from framework.artifacts import (
    ArtifactCollection, Artifact, DiskArtifact, Snapshot,
    SnapshotType, NetIfaceConfig
)
import framework.utils as utils
import host_tools.logging as log_tools
import host_tools.network as net_tools


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
        """Return the Microvm object instance."""
        return self._vm


class MicrovmBuilder:
    """Build fresh microvms or restore from snapshot."""

    ROOT_PREFIX = "fctest-"

    _root_path = None

    def __init__(self, bin_cloner_path):
        """Initialize microvm root and cloning binary."""
        self.bin_cloner_path = bin_cloner_path
        self.init_root_path()

    @property
    def root_path(self):
        """Return the root path of the microvm."""
        return self._root_path

    def init_root_path(self):
        """Initialize microvm root path."""
        self._root_path = tempfile.mkdtemp(
            prefix=MicrovmBuilder.ROOT_PREFIX,
            dir=f"{DEFAULT_TEST_SESSION_ROOT_PATH}")

    def build(self,
              kernel: Artifact,
              disks: [DiskArtifact],
              ssh_key: Artifact,
              config: Artifact,
              net_ifaces=None,
              diff_snapshots=False,
              cpu_template=None,
              fc_binary=None,
              jailer_binary=None,
              use_ramdisk=False):
        """Build a fresh microvm."""
        vm = init_microvm(self.root_path, self.bin_cloner_path,
                          fc_binary, jailer_binary)

        # Start firecracker.
        vm.spawn(use_ramdisk=use_ramdisk)

        # Link the microvm to kernel, rootfs, ssh_key artifacts.
        vm.kernel_file = kernel.local_path()
        vm.rootfs_file = disks[0].local_path()
        # copy rootfs to ramdisk if needed
        jailed_rootfs_path = vm.copy_to_jail_ramfs(vm.rootfs_file) if \
            use_ramdisk else vm.create_jailed_resource(vm.rootfs_file)

        # Download ssh key into the microvm root.
        ssh_key.download(vm.path)
        vm.ssh_config['ssh_key_path'] = ssh_key.local_path()
        os.chmod(vm.ssh_config['ssh_key_path'], 0o400)

        # Provide a default network configuration.
        if net_ifaces is None or len(net_ifaces) == 0:
            ifaces = [NetIfaceConfig()]
        else:
            ifaces = net_ifaces

        # Configure network interfaces using artifacts.
        for iface in ifaces:
            vm.create_tap_and_ssh_config(host_ip=iface.host_ip,
                                         guest_ip=iface.guest_ip,
                                         netmask_len=iface.netmask,
                                         tapname=iface.tap_name)
            guest_mac = net_tools.mac_from_ip(iface.guest_ip)
            response = vm.network.put(
                iface_id=iface.dev_name,
                host_dev_name=iface.tap_name,
                guest_mac=guest_mac,
                allow_mmds_requests=True,
            )
            assert vm.api_session.is_status_no_content(response.status_code)

        with open(config.local_path()) as microvm_config_file:
            microvm_config = json.load(microvm_config_file)

        response = vm.basic_config(
            add_root_device=False,
            boot_args='console=ttyS0 reboot=k panic=1'
        )

        # Add the root file system with rw permissions.
        response = vm.drive.put(
            drive_id='rootfs',
            path_on_host=jailed_rootfs_path,
            is_root_device=True,
            is_read_only=False
        )
        assert vm.api_session \
            .is_status_no_content(response.status_code), \
            response.text

        # Apply the microvm artifact configuration and template.
        response = vm.machine_cfg.put(
            vcpu_count=int(microvm_config['vcpu_count']),
            mem_size_mib=int(microvm_config['mem_size_mib']),
            ht_enabled=bool(microvm_config['ht_enabled']),
            track_dirty_pages=diff_snapshots,
            cpu_template=cpu_template,
        )
        assert vm.api_session.is_status_no_content(response.status_code)

        vm.vcpus_count = int(microvm_config['vcpu_count'])

        return VmInstance(config, kernel, disks, ssh_key, vm)

    # This function currently returns the vm and a metrics_fifo which
    # is needed by the performance integration tests.
    # TODO: Move all metrics functionality to microvm (encapsulating the fifo)
    # so we do not need to move it around polluting the code.
    def build_from_snapshot(self,
                            snapshot: Snapshot,
                            resume=False,
                            # Enable incremental snapshot capability.
                            diff_snapshots=False,
                            use_ramdisk=False,
                            fc_binary=None, jailer_binary=None):
        """Build a microvm from a snapshot artifact."""
        vm = init_microvm(self.root_path, self.bin_cloner_path,
                          fc_binary, jailer_binary,)
        vm.spawn(log_level='Error', use_ramdisk=use_ramdisk)
        vm.api_session.untime()

        metrics_file_path = os.path.join(vm.path, 'metrics.log')
        metrics_fifo = log_tools.Fifo(metrics_file_path)
        response = vm.metrics.put(
            metrics_path=vm.create_jailed_resource(metrics_fifo.path)
        )
        assert vm.api_session.is_status_no_content(response.status_code)

        # Hardlink all the snapshot files into the microvm jail.
        jailed_mem = vm.copy_to_jail_ramfs(snapshot.mem) if use_ramdisk else \
            vm.create_jailed_resource(snapshot.mem)
        jailed_vmstate = vm.copy_to_jail_ramfs(snapshot.vmstate) \
            if use_ramdisk else vm.create_jailed_resource(snapshot.vmstate)

        assert len(snapshot.disks) > 0, "Snapshot requires at least one disk."
        _jailed_disks = []
        for disk in snapshot.disks:
            _jailed_disks.append(vm.copy_to_jail_ramfs(disk) if use_ramdisk
                                 else vm.create_jailed_resource(disk))

        vm.ssh_config['ssh_key_path'] = snapshot.ssh_key.local_path()

        # Create network interfaces.
        for iface in snapshot.net_ifaces:
            vm.create_tap_and_ssh_config(host_ip=iface.host_ip,
                                         guest_ip=iface.guest_ip,
                                         netmask_len=iface.netmask,
                                         tapname=iface.tap_name)
        response = vm.snapshot.load(mem_file_path=jailed_mem,
                                    snapshot_path=jailed_vmstate,
                                    diff=diff_snapshots,
                                    resume=resume)
        status_ok = vm.api_session.is_status_no_content(response.status_code)

        # Verify response status and cleanup if needed before assert.
        if not status_ok:
            # Destroy VM here before we assert.
            vm.kill()
            del vm

        assert status_ok, response.text

        # Return a resumed microvm.
        return vm, metrics_fifo

    def build_from_artifacts(self, config,
                             kernel, disks, cpu_template,
                             net_ifaces=None, diff_snapshots=False,
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

        # SSH key is attached to root disk artifact.
        # Builder will download ssh key in the VM root.
        ssh_key = disks[0].ssh_key()
        # Create a fresh microvm from artifacts.
        return self.build(kernel=kernel,
                          disks=attached_disks,
                          ssh_key=ssh_key,
                          config=config,
                          net_ifaces=net_ifaces,
                          diff_snapshots=diff_snapshots,
                          cpu_template=cpu_template,
                          fc_binary=fc_binary,
                          jailer_binary=jailer_binary)

    def build_vm_nano(self, fc_binary=None, jailer_binary=None,
                      net_ifaces=None, diff_snapshots=False):
        """Create a clean VM in an initial state."""
        return self.build_from_artifacts("2vcpu_256mb",
                                         "vmlinux-4.14",
                                         "ubuntu-18.04",
                                         None,
                                         net_ifaces=net_ifaces,
                                         diff_snapshots=diff_snapshots,
                                         fc_binary=fc_binary,
                                         jailer_binary=jailer_binary)

    def build_vm_micro(self, fc_binary=None, jailer_binary=None,
                       net_ifaces=None, diff_snapshots=False):
        """Create a clean VM in an initial state."""
        return self.build_from_artifacts("2vcpu_512mb",
                                         "vmlinux-4.14",
                                         "ubuntu-18.04",
                                         None,
                                         net_ifaces=net_ifaces,
                                         diff_snapshots=diff_snapshots,
                                         fc_binary=fc_binary,
                                         jailer_binary=jailer_binary)

    def cleanup(self):
        """Clean up this builder context."""
        if self._root_path:
            shutil.rmtree(self._root_path, ignore_errors=True)

    def __del__(self):
        """Teardown the object."""
        self.cleanup()


class SnapshotBuilder:  # pylint: disable=too-few-public-methods
    """Create a snapshot from a running microvm."""

    def __init__(self, microvm):
        """Initialize the snapshot builder."""
        self._microvm = microvm

    def create_snapshot_dir(self):
        """Create dir and files for saving snapshot state and memory."""
        chroot_path = self._microvm.jailer.chroot_path()
        snapshot_dir = os.path.join(chroot_path, "snapshot")
        Path(snapshot_dir).mkdir(parents=True, exist_ok=True)
        cmd = 'chown {}:{} {}'.format(self._microvm.jailer.uid,
                                      self._microvm.jailer.gid,
                                      snapshot_dir)
        utils.run_cmd(cmd)
        return snapshot_dir

    def create(self,
               disks,
               ssh_key: Artifact,
               snapshot_type: SnapshotType = SnapshotType.FULL,
               target_version: str = None,
               mem_file_name: str = "vm.mem",
               snapshot_name: str = "vm.vmstate",
               net_ifaces=None,
               use_ramdisk=False):
        """Create a Snapshot object from a microvm and artifacts."""
        if use_ramdisk:
            snaps_dir = self._microvm.jailer.chroot_ramfs_path()
            mem_full_path = os.path.join(snaps_dir, mem_file_name)
            vmstate_full_path = os.path.join(snaps_dir, snapshot_name)

            memsize = self._microvm.machine_cfg.configuration['mem_size_mib']
            # Pre-allocate ram for memfile to eliminate allocation variability.
            utils.run_cmd('dd if=/dev/zero of={} bs=1M count={}'.format(
                mem_full_path, memsize
            ))
            cmd = 'chown {}:{} {}'.format(
                self._microvm.jailer.uid,
                self._microvm.jailer.gid,
                mem_full_path
            )
            utils.run_cmd(cmd)
        else:
            snaps_dir = self.create_snapshot_dir()
            mem_full_path = os.path.join(snaps_dir, mem_file_name)
            vmstate_full_path = os.path.join(snaps_dir, snapshot_name)

        snaps_dir_name = os.path.basename(snaps_dir)
        self._microvm.pause_to_snapshot(
            mem_file_path=os.path.join('/', snaps_dir_name, mem_file_name),
            snapshot_path=os.path.join('/', snaps_dir_name, snapshot_name),
            diff=snapshot_type == SnapshotType.DIFF,
            version=target_version)

        # Create a copy of the ssh_key artifact.
        ssh_key_copy = ssh_key.copy()
        return Snapshot(mem=mem_full_path,
                        vmstate=vmstate_full_path,
                        # TODO: To support more disks we need to figure out a
                        # simple and flexible way to store snapshot artifacts
                        # in S3. This should be done in a PR where we add tests
                        # that resume from S3 snapshot artifacts.
                        disks=disks,
                        net_ifaces=net_ifaces or [NetIfaceConfig()],
                        ssh_key=ssh_key_copy)
