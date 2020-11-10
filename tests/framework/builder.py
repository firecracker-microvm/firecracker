# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define some helpers methods to create microvms from artifacts."""

import json
import os
import tempfile
from pathlib import Path
from conftest import init_microvm
from framework.artifacts import Artifact, DiskArtifact, Snapshot, SnapshotType
import framework.utils as utils
import host_tools.logging as log_tools
import host_tools.network as net_tools


DEFAULT_HOST_IP = "192.168.0.1"
DEFAULT_GUEST_IP = "192.168.0.2"
DEFAULT_TAP_NAME = "tap0"
DEFAULT_DEV_NAME = "eth0"
DEFAULT_NETMASK = 30


class MicrovmBuilder:
    """Build fresh microvms or restore from snapshot."""

    ROOT_PREFIX = "fctest-"

    def __init__(self, bin_cloner_path,
                 fc_binary=None,
                 jailer_binary=None):
        """Initialize microvm root and cloning binary."""
        self.bin_cloner_path = bin_cloner_path
        self.init_root_path()

        # Update permissions for custom binaries.
        if fc_binary is not None:
            os.chmod(fc_binary, 0o555)
        if jailer_binary is not None:
            os.chmod(jailer_binary, 0o555)

        self._fc_binary = fc_binary
        self._jailer_binary = jailer_binary

    @property
    def root_path(self):
        """Return the root path of the microvm."""
        return self._root_path

    def init_root_path(self):
        """Initialize microvm root path."""
        self._root_path = tempfile.mkdtemp(MicrovmBuilder.ROOT_PREFIX)

    def build(self,
              kernel: Artifact,
              disks: [DiskArtifact],
              ssh_key: Artifact,
              config: Artifact,
              network_config: net_tools.UniqueIPv4Generator = None,
              enable_diff_snapshots=False,
              cpu_template=None):
        """Build a fresh microvm."""
        vm = init_microvm(self.root_path, self.bin_cloner_path,
                          self._fc_binary, self._jailer_binary)

        # Link the microvm to kernel, rootfs, ssh_key artifacts.
        vm.kernel_file = kernel.local_path()
        vm.rootfs_file = disks[0].local_path()

        # Start firecracker.
        vm.spawn()

        # Download ssh key into the microvm root.
        ssh_key.download(self.root_path)
        vm.ssh_config['ssh_key_path'] = ssh_key.local_path()
        os.chmod(vm.ssh_config['ssh_key_path'], 0o400)
        if network_config:
            (host_ip, guest_ip) = network_config.get_next_available_ips(2)
        else:
            host_ip, guest_ip = DEFAULT_HOST_IP, DEFAULT_GUEST_IP
        vm.create_tap_and_ssh_config(host_ip=host_ip,
                                     guest_ip=guest_ip,
                                     netmask_len=DEFAULT_NETMASK,
                                     tapname=DEFAULT_TAP_NAME)

        # TODO: propper network configuraiton with artifacts.
        guest_mac = net_tools.mac_from_ip(guest_ip)
        response = vm.network.put(
            iface_id=DEFAULT_DEV_NAME,
            host_dev_name=DEFAULT_TAP_NAME,
            guest_mac=guest_mac,
            allow_mmds_requests=True,
        )

        assert vm.api_session.is_status_no_content(response.status_code)

        with open(config.local_path()) as microvm_config_file:
            microvm_config = json.load(microvm_config_file)

        response = vm.basic_config(boot_args='console=ttyS0 reboot=k panic=1')

        # Apply the microvm artifact configuration and template.
        response = vm.machine_cfg.put(
            vcpu_count=int(microvm_config['vcpu_count']),
            mem_size_mib=int(microvm_config['mem_size_mib']),
            ht_enabled=bool(microvm_config['ht_enabled']),
            track_dirty_pages=enable_diff_snapshots,
            cpu_template=cpu_template,
        )
        assert vm.api_session.is_status_no_content(response.status_code)

        vm.vcpus_count = int(microvm_config['vcpu_count'])

        # Reset root path so next microvm is built some place else.
        self.init_root_path()
        return vm

    # This function currently returns the vm and a metrics_fifo which
    # is needed by the performance integration tests.
    # TODO: Move all metrics functionality to microvm (encapsulating the fifo)
    # so we do not need to move it around polluting the code.
    def build_from_snapshot(self,
                            snapshot: Snapshot,
                            resume=False,
                            # Enable incremental snapshot capability.
                            enable_diff_snapshots=False):
        """Build a microvm from a snapshot artifact."""
        vm = init_microvm(self.root_path, self.bin_cloner_path,
                          self._fc_binary, self._jailer_binary)
        vm.spawn(log_level='Info')

        metrics_file_path = os.path.join(vm.path, 'metrics.log')
        metrics_fifo = log_tools.Fifo(metrics_file_path)
        response = vm.metrics.put(
            metrics_path=vm.create_jailed_resource(metrics_fifo.path)
        )
        assert vm.api_session.is_status_no_content(response.status_code)

        # Hardlink all the snapshot files into the microvm jail.
        jailed_mem = vm.create_jailed_resource(snapshot.mem)
        jailed_vmstate = vm.create_jailed_resource(snapshot.vmstate)
        assert len(snapshot.disks) > 0, "Snapshot requiures at least one disk."
        _jailed_disks = []
        for disk in snapshot.disks:
            _jailed_disks.append(vm.create_jailed_resource(disk))
        vm.ssh_config['ssh_key_path'] = snapshot.ssh_key

        vm.create_tap_and_ssh_config(host_ip=DEFAULT_HOST_IP,
                                     guest_ip=DEFAULT_GUEST_IP,
                                     netmask_len=DEFAULT_NETMASK,
                                     tapname=DEFAULT_TAP_NAME)

        response = vm.snapshot_load.put(mem_file_path=jailed_mem,
                                        snapshot_path=jailed_vmstate,
                                        diff=enable_diff_snapshots)

        assert vm.api_session.is_status_no_content(response.status_code)

        if resume:
            # Resume microvm
            response = vm.vm.patch(state='Resumed')
            assert vm.api_session.is_status_no_content(response.status_code)

        # Reset root path so next microvm is built some place else.
        self.init_root_path()

        # Return a resumed microvm.
        return vm, metrics_fifo


class SnapshotBuilder:  # pylint: disable=too-few-public-methods
    """Create a snapshot from a running microvm."""

    def __init__(self, microvm):
        """Initialize the snapshot builder."""
        self._microvm = microvm

    def create(self,
               disks,
               ssh_key: Artifact,
               snapshot_type: SnapshotType = SnapshotType.FULL,
               target_version: str = None,
               mem_file_name: str = "vm.mem",
               snapshot_name: str = "vm.vmstate"):
        """Create a Snapshot object from a microvm and artifacts."""
        # Disable API timeout as the APIs for snapshot related procedures
        # take longer.
        self._microvm.api_session.untime()
        chroot_path = self._microvm.jailer.chroot_path()
        snapshot_dir = os.path.join(chroot_path, "snapshot")
        Path(snapshot_dir).mkdir(parents=True, exist_ok=True)
        cmd = 'chown {}:{} {}'.format(self._microvm.jailer.uid,
                                      self._microvm.jailer.gid,
                                      snapshot_dir)
        utils.run_cmd(cmd)
        self._microvm.pause_to_snapshot(
            mem_file_path="/snapshot/"+mem_file_name,
            snapshot_path="/snapshot/"+snapshot_name,
            diff=snapshot_type == SnapshotType.DIFF,
            version=target_version)

        # Create a copy of the ssh_key artifact.
        ssh_key_copy = ssh_key.copy()
        mem_path = os.path.join(snapshot_dir, mem_file_name)
        vmstate_path = os.path.join(snapshot_dir, snapshot_name)
        return Snapshot(mem=mem_path,
                        vmstate=vmstate_path,
                        # TODO: To support more disks we need to figure out a
                        # simple and flexible way to store snapshot artifacts
                        # in S3. This should be done in a PR where we add tests
                        # that resume from S3 snapshot artifacts.
                        disks=disks,
                        ssh_key=ssh_key_copy.local_path())
