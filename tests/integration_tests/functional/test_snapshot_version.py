# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Basic tests scenarios for snapshot save/restore."""

import platform

import pytest

from framework.utils import get_firecracker_version_from_toml, run_cmd
from host_tools.cargo_build import get_firecracker_binaries

# Firecracker v0.23 used 16 IRQ lines. For virtio devices,
# IRQs are available from 5 to 23, so the maximum number
# of devices allowed at the same time was 11.
FC_V0_23_MAX_DEVICES_ATTACHED = 11


def _create_and_start_microvm_with_net_devices(test_microvm, devices_no=0):
    test_microvm.spawn()
    # Set up a basic microVM: configure the boot source and
    # add a root device.
    test_microvm.basic_config(track_dirty_pages=True)

    # Add network devices on top of the already configured rootfs for a
    # total of (`devices_no` + 1) devices.
    for _ in range(devices_no):
        # Create tap before configuring interface.
        test_microvm.add_net_iface()

    test_microvm.start()

    if devices_no > 0:
        # Verify if guest can run commands.
        exit_code, _, _ = test_microvm.ssh.execute_command("sync")
        assert exit_code == 0


@pytest.mark.skipif(
    platform.machine() != "x86_64", reason="Exercises specific x86_64 functionality."
)
def test_create_with_too_many_devices(test_microvm_with_api):
    """
    Create snapshot with unexpected device count for previous versions.
    """
    test_microvm = test_microvm_with_api

    # Create and start a microVM with `FC_V0_23_MAX_DEVICES_ATTACHED`
    # network devices.
    devices_no = FC_V0_23_MAX_DEVICES_ATTACHED
    _create_and_start_microvm_with_net_devices(test_microvm, devices_no)

    # Pause microVM for snapshot.
    response = test_microvm.vm.patch(state="Paused")
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # Attempt to create a snapshot with version: `0.23.0`. Firecracker
    # v0.23 allowed a maximum of `FC_V0_23_MAX_DEVICES_ATTACHED` virtio
    # devices at a time. This microVM has `FC_V0_23_MAX_DEVICES_ATTACHED`
    # network devices on top of the rootfs, so the limit is exceeded.
    response = test_microvm.snapshot.create(
        mem_file_path="/vm.mem",
        snapshot_path="/vm.vmstate",
        diff=True,
        version="0.23.0",
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert "Too many devices attached" in response.text


def test_create_invalid_version(uvm_nano):
    """
    Test scenario: create snapshot targeting invalid version.
    """
    # Use a predefined vm instance.
    test_microvm = uvm_nano
    test_microvm.start()

    try:
        # Target an invalid Firecracker version string.
        test_microvm.pause_to_snapshot(
            mem_file_path="/vm.mem",
            snapshot_path="/vm.vmstate",
            diff=False,
            version="invalid",
        )
    except AssertionError as error:
        # Check if proper error is returned.
        assert "unexpected character 'i' while parsing major version" in str(error)
    else:
        assert False, "Negative test failed"

    try:
        # Target a valid version string but with no snapshot support.
        test_microvm.pause_to_snapshot(
            mem_file_path="/vm.mem",
            snapshot_path="/vm.vmstate",
            diff=False,
            version="0.22.0",
        )
    except AssertionError as error:
        # Check if proper error is returned.
        assert "Cannot translate microVM version to snapshot data version" in str(error)
    else:
        assert False, "Negative test failed"


def test_snapshot_current_version(uvm_nano):
    """Tests taking a snapshot at the version specified in Cargo.toml

    Check that it is possible to take a snapshot at the version of the upcoming
    release (during the release process this ensures that if we release version
    x.y, then taking a snapshot at version x.y works - something we'd otherwise
    only be able to test once the x.y binary has been uploaded to S3, at which
    point it is too late, see also the 1.3 release).
    """
    vm = uvm_nano
    vm.start()

    version = get_firecracker_version_from_toml()
    # normalize to a snapshot version
    target_version = f"{version.major}.{version.minor}.0"
    snapshot = vm.snapshot_full(target_version=target_version)

    # Fetch Firecracker binary for the latest version
    fc_binary, _ = get_firecracker_binaries()
    # Verify the output of `--describe-snapshot` command line parameter
    cmd = [str(fc_binary)] + ["--describe-snapshot", str(snapshot.vmstate)]

    code, stdout, stderr = run_cmd(cmd)
    assert code == 0, stderr
    assert stderr == ""
    assert target_version in stdout


def test_create_with_newer_virtio_features(uvm_nano):
    """
    Attempt to create a snapshot with newer virtio features.
    """
    test_microvm = uvm_nano
    test_microvm.add_net_iface()
    test_microvm.start()

    # Init a ssh connection in order to wait for the VM to boot. This way
    # we can be sure that the block device was activated.
    test_microvm.ssh.run("true")

    # Pause microVM for snapshot.
    response = test_microvm.vm.patch(state="Paused")
    assert test_microvm.api_session.is_status_no_content(response.status_code)

    # We try to create a snapshot to a target version < 1.0.0.
    # This should fail because Fc versions < 1.0.0 don't support
    # virtio notification suppression.
    target_fc_versions = ["0.24.0", "0.25.0"]
    if platform.machine() == "x86_64":
        target_fc_versions.insert(0, "0.23.0")
    for target_fc_version in target_fc_versions:
        response = test_microvm.snapshot.create(
            mem_file_path="/vm.mem",
            snapshot_path="/vm.vmstate",
            version=target_fc_version,
        )
        assert test_microvm.api_session.is_status_bad_request(response.status_code)
        assert (
            "The virtio devices use a features that is incompatible "
            "with older versions of Firecracker: notification suppression"
            in response.text
        )

    # We try to create a snapshot for target version 1.0.0. This should
    # fail because in 1.0.0 we do not support notification suppression for Net.
    response = test_microvm.snapshot.create(
        mem_file_path="/vm.mem",
        snapshot_path="/vm.vmstate",
        version="1.0.0",
    )
    assert test_microvm.api_session.is_status_bad_request(response.status_code)
    assert (
        "The virtio devices use a features that is incompatible "
        "with older versions of Firecracker: notification suppression" in response.text
    )

    # It should work when we target a version >= 1.1.0
    response = test_microvm.snapshot.create(
        mem_file_path="/vm.mem",
        snapshot_path="/vm.vmstate",
        version="1.1.0",
    )
    assert test_microvm.api_session.is_status_no_content(response.status_code)
