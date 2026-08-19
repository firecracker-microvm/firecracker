# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for read-only VMDK disk image support."""

import hashlib
import os

import pytest

import host_tools.drive as drive_tools

MB = 1024 * 1024


def _check_vmdk_data(ssh, dev_path, extent_path):
    """Verify the guest reads back exactly the data written to the flat extent.

    Mirrors the read-back / ``cmp`` step used by other block integration tests:
    the full device is checksummed from inside the guest and compared against the
    checksum of the flat extent written on the host.
    """
    _, stdout, stderr = ssh.run("md5sum {}".format(dev_path))
    assert stderr == "", stderr
    guest_md5 = stdout.split()[0]

    with open(extent_path, "rb") as extent:
        host_md5 = hashlib.md5(extent.read()).hexdigest()
    assert guest_md5 == host_md5


def _check_vmdk_size(ssh, dev_path, size_bytes):
    """Verify the virtio-block device reports the flat extent's size in bytes."""
    _, stdout, stderr = ssh.run("blockdev --getsize64 {}".format(dev_path))
    assert stderr == "", stderr
    assert int(stdout.strip()) == size_bytes


def test_vmdk_readonly_read(uvm):
    """Boot with a read-only VMDK data disk and verify the end-to-end read path.

    The VMDK is mounted as a read-only virtio-block drive. The data read back
    from the guest must match the flat extent written on the host, and the
    device must report the expected size. A guest-side write must be rejected,
    guarding the read-only contract.
    """
    test_microvm = uvm
    test_microvm.spawn()
    test_microvm.basic_config()
    test_microvm.add_net_iface()

    vmdk = drive_tools.VmdkFile(
        os.path.join(test_microvm.fsfiles, "vmdk.vmdk"), size=16
    )
    # Both the descriptor and the flat extent must be reachable inside the
    # jail, otherwise the VMDK backend cannot open the extent.
    test_microvm.create_jailed_resource(vmdk.extent_path)
    test_microvm.add_drive("vmdk", vmdk.descriptor_path, is_read_only=True)

    test_microvm.start()

    _check_vmdk_data(test_microvm.ssh, "/dev/vdb", vmdk.extent_path)
    _check_vmdk_size(test_microvm.ssh, "/dev/vdb", vmdk.size * MB)

    # Writes to a read-only disk must fail from the guest. When the virtio-blk
    # device negotiates VIRTIO_BLK_F_RO, the Linux block layer rejects writes
    # before they ever reach Firecracker, surfacing as EPERM
    # ("Operation not permitted") rather than an I/O error from the device.
    _, _, stderr = test_microvm.ssh.run("dd if=/dev/zero of=/dev/vdb bs=512 count=1")
    assert "Operation not permitted" in stderr


def test_vmdk_requires_read_only(uvm):
    """A VMDK drive must be attached with ``is_read_only=true``."""
    test_microvm = uvm
    test_microvm.spawn()
    test_microvm.basic_config()

    vmdk = drive_tools.VmdkFile(
        os.path.join(test_microvm.fsfiles, "vmdk.vmdk"), size=16
    )
    jail_path = test_microvm.create_jailed_resource(vmdk.descriptor_path)
    with pytest.raises(RuntimeError, match="VMDK backend requires is_read_only=true."):
        test_microvm.api.drive.put(
            drive_id="vmdk",
            path_on_host=jail_path,
            is_read_only=False,
            is_root_device=False,
            io_engine="Sync",
        )
