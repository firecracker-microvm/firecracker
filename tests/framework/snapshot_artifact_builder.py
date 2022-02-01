# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Create snapshot artifact of complex microVM."""

import json
import logging
import tempfile
from framework.artifacts import NetIfaceConfig
from framework.builder import MicrovmBuilder, SnapshotBuilder, SnapshotType
from framework.utils import generate_mmds_session_token,\
    generate_mmds_v2_get_request
import host_tools.network as net_tools  # pylint: disable=import-error
import host_tools.drive as drive_tools


# Define 4 net device configurations.
net_ifaces = [NetIfaceConfig(),
              NetIfaceConfig(host_ip="192.168.1.1",
                             guest_ip="192.168.1.2",
                             tap_name="tap1",
                             dev_name="eth1"),
              NetIfaceConfig(host_ip="192.168.2.1",
                             guest_ip="192.168.2.2",
                             tap_name="tap2",
                             dev_name="eth2"),
              NetIfaceConfig(host_ip="192.168.3.1",
                             guest_ip="192.168.3.2",
                             tap_name="tap3",
                             dev_name="eth3")]
# Define 4 scratch drives.
scratch_drives = ["vdb", "vdc", "vdd", "vde", "vdf"]


def test_create_snapshot_supported_versions(bin_cloner_path):
    """
    Create snapshot artifact from the supported fc versions.

    The microVMs to be snapshotted contain as much of firecracker's
    functionality as possible: balloon device, disks, network devices,
    MMDS, vsock.

    @type: functional
    """
    # Microvm: 2vCPU 256MB RAM.
    logger = logging.getLogger("snapshot_full_functionality")
    builder = MicrovmBuilder(bin_cloner_path)

    # Build a nano VM with 4 network devices attacked.
    vm_instance = builder.build_vm_nano(net_ifaces=net_ifaces,
                                        diff_snapshots=True)
    vm = vm_instance.vm

    # Add a memory balloon with stats enabled.
    response = vm.balloon.put(
        amount_mib=0,
        deflate_on_oom=True,
        stats_polling_interval_s=1
    )
    assert vm.api_session.is_status_no_content(response.status_code)

    # Configure MMDS version 2.
    response = vm.mmds.put_config(json={
        'version': 'V2',
        'network_interfaces': [f'{net_ifaces[2].dev_name}']
    })
    assert vm.api_session.is_status_no_content(response.status_code)

    # Populate MMDS with data.
    data_store = {
        'latest': {
            'meta-data': {
                'ami-id': 'ami-12345678',
                'reservation-id': 'r-fea54097',
                'local-hostname': 'ip-10-251-50-12.ec2.internal',
                'public-hostname': 'ec2-203-0-113-25.compute-1.amazonaws.com'
            }
        }
    }
    response = vm.mmds.put(data_store)
    assert vm.api_session.is_status_no_content(response.status_code)

    # Disk path array needed when creating the snapshot later.
    disks = [vm_instance.disks[0].local_path()]
    test_drives = [] if scratch_drives is None else scratch_drives

    # Add disks.
    for scratch in test_drives:
        # Add a scratch 64MB RW non-root block device.
        scratchdisk = drive_tools.FilesystemFile(tempfile.mktemp(), size=64)
        vm.add_drive(scratch, scratchdisk.path)
        disks.append(scratchdisk.path)

        # Workaround FilesystemFile destructor removal of file.
        scratchdisk.path = None

    vm.start()

    # Iterate and validate connectivity on all ifaces after boot.
    for iface in net_ifaces:
        vm.ssh_config['hostname'] = iface.guest_ip
        ssh_connection = net_tools.SSHConnection(vm.ssh_config)
        exit_code, _, _ = ssh_connection.execute_command("sync")
        assert exit_code == 0

    # Mount scratch drives in guest.
    for blk in test_drives:
        # Create mount point and mount each device.
        cmd = "mkdir -p /mnt/{blk} && mount /dev/{blk} /mnt/{blk}".format(
            blk=blk
        )
        exit_code, _, _ = ssh_connection.execute_command(cmd)
        assert exit_code == 0

        # Create file using dd using O_DIRECT.
        # After resume we will compute md5sum on these files.
        dd = "dd if=/dev/zero of=/mnt/{}/test bs=4096 count=10 oflag=direct"
        exit_code, _, _ = ssh_connection.execute_command(dd.format(blk))
        assert exit_code == 0

        # Unmount the device.
        cmd = "umount /dev/{}".format(blk)
        exit_code, _, _ = ssh_connection.execute_command(cmd)
        assert exit_code == 0

    # Fetch metadata to ensure MMDS is accessible.
    token = generate_mmds_session_token(
        ssh_connection,
        ipv4_address='169.254.169.254',
        token_ttl=60
    )
    cmd = generate_mmds_v2_get_request(
        ipv4_address='169.254.169.254',
        token=token
    )
    _, stdout, _ = ssh_connection.execute_command(cmd)
    assert json.load(stdout) == data_store

    # Create a snapshot builder from a microvm.
    snapshot_builder = SnapshotBuilder(vm)

    snapshot = snapshot_builder.create(disks,
                                       vm_instance.ssh_key,
                                       snapshot_type=SnapshotType.DIFF,
                                       net_ifaces=net_ifaces)
    logger.debug("========== Firecracker create snapshot log ==========")
    logger.debug(vm.log_data)
    vm.kill()

    assert 1 == 2