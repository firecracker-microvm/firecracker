# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import platform
import pytest
from framework.artifacts import NetIfaceConfig
from framework.builder import SnapshotBuilder, MicrovmBuilder

import host_tools.network as net_tools  # pylint: disable=import-error

# Firecracker v0.23 used 16 IRQ lines. For virtio devices,
# IRQs are available from 5 to 23, so the maximum number
# of devices allowed at the same time was 11.
FC_V0_23_MAX_DEVICES_ATTACHED = 11


def _create_and_start_microvm_with_net_devices(test_microvm,
                                               network_config=None,
                                               devices_no=0):
    test_microvm.spawn()
    # Set up a basic microVM: configure the boot source and
    # add a root device.
    test_microvm.basic_config(track_dirty_pages=True)

    # Add network devices on top of the already configured rootfs for a
    # total of (`devices_no` + 1) devices.
    for i in range(devices_no):
        # Create tap before configuring interface.
        _tap, _host_ip, _guest_ip = test_microvm.ssh_network_config(
            network_config,
            str(i)
        )
    test_microvm.start()

    if network_config is not None:
        ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)
        # Verify if guest can run commands.
        exit_code, _, _ = ssh_connection.execute_command("sync")
        assert exit_code == 0


@pytest.mark.skipif(
    platform.machine() != "aarch64",
    reason="Exercises specific x86_64 functionality."
)
def test_create_v0_23_snapshot(test_microvm_with_api):
    """
    Exercise creating a snapshot targeting v0.23 on aarch64.

    @type: functional
    """
    test_microvm = test_microvm_with_api

    _create_and_start_microvm_with_net_devices(test_microvm)

    snapshot_builder = SnapshotBuilder(test_microvm)
    # Create directory and files for saving snapshot state and memory.
    _snapshot_dir = snapshot_builder.create_snapshot_dir()

    # Pause microVM for snapshot.
    response = test_microvm.vm.patch(state='Paused')
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    response = test_microvm.snapshot.create(
        mem_file_path="/snapshot/vm.mem",
        snapshot_path="/snapshot/vm.vmstate",
        diff=True,
        version="0.23.0"
    )

    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Cannot translate microVM version to snapshot data version"\
           in response.text


@pytest.mark.skipif(
    platform.machine() != "x86_64",
    reason="Exercises specific x86_64 functionality."
)
def test_create_with_too_many_devices(test_microvm_with_api, network_config):
    """
    Create snapshot with unexpected device count for previous versions.

    @type: negative
    """
    test_microvm = test_microvm_with_api

    # Create and start a microVM with `FC_V0_23_MAX_DEVICES_ATTACHED`
    # network devices.
    devices_no = FC_V0_23_MAX_DEVICES_ATTACHED
    _create_and_start_microvm_with_net_devices(test_microvm,
                                               network_config,
                                               devices_no)

    snapshot_builder = SnapshotBuilder(test_microvm)
    # Create directory and files for saving snapshot state and memory.
    _snapshot_dir = snapshot_builder.create_snapshot_dir()

    # Pause microVM for snapshot.
    response = test_microvm.vm.patch(state='Paused')
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Attempt to create a snapshot with version: `0.23.0`. Firecracker
    # v0.23 allowed a maximum of `FC_V0_23_MAX_DEVICES_ATTACHED` virtio
    # devices at a time. This microVM has `FC_V0_23_MAX_DEVICES_ATTACHED`
    # network devices on top of the rootfs, so the limit is exceeded.
    response = test_microvm.snapshot.create(
        mem_file_path="/snapshot/vm.mem",
        snapshot_path="/snapshot/vm.vmstate",
        diff=True,
        version="0.23.0"
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Too many devices attached" in response.text


def test_create_invalid_version(bin_cloner_path):
    """
    Test scenario: create snapshot targeting invalid version.

    @type: functional
    """
    # Use a predefined vm instance.
    builder = MicrovmBuilder(bin_cloner_path)
    test_microvm = builder.build_vm_nano().vm
    test_microvm.start()

    try:
        # Target an invalid Firecracker version string.
        test_microvm.pause_to_snapshot(
            mem_file_path="/vm.mem",
            snapshot_path="/vm.vmstate",
            diff=False,
            version="invalid")
    except AssertionError as error:
        # Check if proper error is returned.
        assert "Invalid microVM version format" in \
            str(error)
    else:
        assert False, "Negative test failed"

    try:
        # Target a valid version string but with no snapshot support.
        test_microvm.pause_to_snapshot(
            mem_file_path="/vm.mem",
            snapshot_path="/vm.vmstate",
            diff=False,
            version="0.22.0")
    except AssertionError as error:
        # Check if proper error is returned.
        assert "Cannot translate microVM version to snapshot data version" in \
            str(error)
    else:
        assert False, "Negative test failed"


def test_create_with_newer_virtio_features(bin_cloner_path):
    """
    Attempt to create a snapshot with newer virtio features.

    @type: functional
    """
    builder = MicrovmBuilder(bin_cloner_path)
    test_microvm = builder.build_vm_nano().vm
    test_microvm.start()

    # Init a ssh connection in order to wait for the VM to boot. This way
    # we can be sure that the block device was activated.
    iface = NetIfaceConfig()
    test_microvm.ssh_config['hostname'] = iface.guest_ip
    _ssh_connection = net_tools.SSHConnection(test_microvm.ssh_config)

    # Create directory and files for saving snapshot state and memory.
    snapshot_builder = SnapshotBuilder(test_microvm)
    _snapshot_dir = snapshot_builder.create_snapshot_dir()

    # Pause microVM for snapshot.
    response = test_microvm.vm.patch(state='Paused')
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # We try to create a snapshot to a target version < 0.26.0.
    # This should fail because Fc versions < 0.26.0 don't support
    # virtio notification suppression.
    target_fc_versions = ["0.24.0", "0.25.0"]
    if platform.machine() == "x86_64":
        target_fc_versions.insert(0, "0.23.0")
    for target_fc_version in target_fc_versions:
        response = test_microvm.snapshot.create(
            mem_file_path="/snapshot/vm.mem",
            snapshot_path="/snapshot/vm.vmstate",
            version=target_fc_version
        )
        assert test_microvm.api_session.is_status_bad_request(
            response.status_code
        )
        assert "The virtio devices use a features that is incompatible " \
               "with older versions of Firecracker: notification suppression" \
               in response.text

        # It should work when we target a version >= 0.26.0
        response = test_microvm.snapshot.create(
            mem_file_path="/snapshot/vm.mem",
            snapshot_path="/snapshot/vm.vmstate",
            version="0.26.0"
        )
        assert test_microvm.api_session.is_status_no_content(
            response.status_code
        )
