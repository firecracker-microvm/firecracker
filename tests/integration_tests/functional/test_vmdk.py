# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for read-only VMDK disk image support."""

import hashlib
import os

import pytest

import host_tools.drive as drive_tools
from framework.utils import get_threads


@pytest.mark.parametrize(
    "pattern", [b"x", b"abcde", bytes(range(256))], ids=["single", "odd", "binary"]
)
def test_vmdk_pattern(tmp_path, pattern):
    """The extent is allocated and its pattern continues across write boundaries."""
    vmdk = drive_tools.VmdkFile(str(tmp_path / "pattern.vmdk"), pattern=pattern)
    size = vmdk.size * 1024 * 1024
    assert os.stat(vmdk.extent_path).st_size == size
    assert os.stat(vmdk.extent_path).st_blocks > 0
    with open(vmdk.extent_path, "rb") as extent:
        for offset in [0, 64 * 1024 - 13, size - 13]:
            extent.seek(offset)
            assert extent.read(13) == bytes(
                pattern[(offset + i) % len(pattern)] for i in range(13)
            )


def test_vmdk_pattern_required(tmp_path):
    """Missing and empty patterns are rejected."""
    path = str(tmp_path / "pattern.vmdk")
    with pytest.raises(TypeError, match="pattern"):
        drive_tools.VmdkFile(path)  # pylint: disable=missing-kwoa
    for pattern in [None, b""]:
        with pytest.raises(ValueError, match="pattern must not be empty"):
            drive_tools.VmdkFile(path, pattern=pattern)
    assert not list(tmp_path.iterdir())


def test_vmdk_readonly_read(uvm, num_queues):
    """Verify VMDK reads, capacity, and rejection of guest writes."""
    uvm.spawn()
    uvm.basic_config()
    uvm.add_net_iface()

    vmdk = drive_tools.VmdkFile(
        os.path.join(uvm.fsfiles, "vmdk.vmdk"),
        size=16,
        pattern=b"FIRECRACKER VMDK INTEGRATION TEST",
    )
    # add_drive only jails the descriptor, so jail the extent separately.
    uvm.create_jailed_resource(vmdk.extent_path)
    uvm.add_drive(
        "vmdk",
        vmdk.descriptor_path,
        is_read_only=True,
        image_format="Vmdk",
        num_queues=num_queues,
    )

    uvm.start()
    if num_queues is not None:
        assert "fc_q0_vmdk" in get_threads(uvm.firecracker_pid)

    _, stdout, stderr = uvm.ssh.run("md5sum /dev/vdb")
    assert stderr == "", stderr
    with open(vmdk.extent_path, "rb") as extent:
        assert stdout.split()[0] == hashlib.md5(extent.read()).hexdigest()

    _, stdout, stderr = uvm.ssh.run("blockdev --getsize64 /dev/vdb")
    assert stderr == "", stderr
    assert int(stdout.strip()) == vmdk.size * 1024 * 1024

    # Linux rejects guest writes with EPERM after negotiating VIRTIO_BLK_F_RO.
    _, _, stderr = uvm.ssh.run("dd if=/dev/zero of=/dev/vdb bs=512 count=1")
    assert "Operation not permitted" in stderr


def test_vmdk_diff_snapshot_restore(uvm, microvm_factory, num_queues):
    """VMDK reads and read errors survive dirty-tracked snapshot restoration."""
    uvm.spawn()
    uvm.basic_config(track_dirty_pages=True)
    uvm.add_net_iface()
    vmdk = drive_tools.VmdkFile(
        os.path.join(uvm.fsfiles, "vmdk.vmdk"),
        size=16,
        pattern=b"VMDK DIRTY TRACKING SNAPSHOT TEST",
    )
    uvm.create_jailed_resource(vmdk.extent_path)
    uvm.add_drive(
        "vmdk",
        vmdk.descriptor_path,
        is_read_only=True,
        image_format="Vmdk",
        num_queues=num_queues,
    )

    error_descriptor = os.path.join(uvm.fsfiles, "error.vmdk")
    with open(vmdk.descriptor_path, encoding="utf-8") as descriptor:
        content = descriptor.read()
    with open(error_descriptor, "w", encoding="utf-8") as descriptor:
        descriptor.write(
            content.replace("RW 32768", "RW 136", 1).replace(
                "# The Disk Data Base", "NOACCESS 8 ZERO\n\n# The Disk Data Base"
            )
        )
    uvm.add_drive(
        "error",
        error_descriptor,
        is_read_only=True,
        image_format="Vmdk",
        num_queues=num_queues,
    )
    uvm.start()
    base = uvm.snapshot_full(mem_path="base.mem", vmstate_path="base.vmstate")
    uvm.resume()

    uvm.ssh.check_output(
        "dd if=/dev/vdb of=/dev/shm/vmdk-data bs=4096 count=256 iflag=direct"
    )
    with open(vmdk.extent_path, "rb") as extent:
        expected = hashlib.md5(extent.read(1024 * 1024)).hexdigest()
    _, stdout, _ = uvm.ssh.check_output("md5sum /dev/shm/vmdk-data")
    assert stdout.split()[0] == expected

    rc, _, stderr = uvm.ssh.run(
        "dd if=/dev/vdc of=/dev/null bs=8192 skip=8 count=1 iflag=direct"
    )
    assert rc != 0
    assert "Input/output error" in stderr
    uvm.ssh.check_output("dd if=/dev/vdc of=/dev/null bs=4096 count=1 iflag=direct")

    diff = uvm.snapshot_diff(mem_path="diff.mem", vmstate_path="diff.vmstate")
    uvm.kill()
    snapshot = diff.rebase_snapshot(
        base, use_snapshot_editor=True, binary_dir=uvm.fc_binary_path.parent
    )
    restored = microvm_factory.build(pci=uvm.pci_enabled)
    restored.spawn()
    restored.create_jailed_resource(vmdk.extent_path)
    restored.restore_from_snapshot(snapshot, resume=True)
    if num_queues is not None:
        assert "fc_q0_vmdk" in get_threads(restored.firecracker_pid)
        assert "fc_q0_error" in get_threads(restored.firecracker_pid)

    _, stdout, _ = restored.ssh.check_output("md5sum /dev/shm/vmdk-data")
    assert stdout.split()[0] == expected
    _, stdout, _ = restored.ssh.check_output(
        "dd if=/dev/vdb of=/dev/shm/vmdk-data bs=4096 count=256 iflag=direct"
        " && md5sum /dev/shm/vmdk-data"
    )
    assert stdout.split()[0] == expected
    rc, _, stderr = restored.ssh.run(
        "dd if=/dev/vdc of=/dev/null bs=8192 skip=8 count=1 iflag=direct"
    )
    assert rc != 0
    assert "Input/output error" in stderr
    restored.ssh.check_output(
        "dd if=/dev/vdc of=/dev/null bs=4096 count=1 iflag=direct"
    )


def test_vmdk_patch(uvm, num_queues):
    """Replacing a VMDK works with inline and worker-thread I/O."""
    uvm.spawn()
    uvm.basic_config()
    uvm.add_net_iface()
    images = [
        drive_tools.VmdkFile(
            os.path.join(uvm.fsfiles, f"vmdk-{index}.vmdk"), pattern=pattern
        )
        for index, pattern in enumerate([b"original", b"replacement"])
    ]
    uvm.create_jailed_resource(images[0].extent_path)
    uvm.add_drive(
        "vmdk",
        images[0].descriptor_path,
        is_read_only=True,
        image_format="Vmdk",
        num_queues=num_queues,
    )
    uvm.start()
    if num_queues is not None:
        assert "fc_q0_vmdk" in get_threads(uvm.firecracker_pid)

    for index, image in enumerate(images):
        if index:
            uvm.create_jailed_resource(image.extent_path)
            uvm.api.drive.patch(
                drive_id="vmdk",
                path_on_host=uvm.create_jailed_resource(image.descriptor_path),
            )
        _, stdout, _ = uvm.ssh.check_output(
            "dd if=/dev/vdb of=/dev/shm/vmdk-data bs=4096 count=1 iflag=direct"
            " && md5sum /dev/shm/vmdk-data"
        )
        with open(image.extent_path, "rb") as extent:
            assert stdout.split()[0] == hashlib.md5(extent.read(4096)).hexdigest()


def test_vmdk_requires_read_only(uvm):
    """A VMDK drive must be attached with ``is_read_only=true``."""
    uvm.spawn()
    uvm.basic_config()

    vmdk = drive_tools.VmdkFile(
        os.path.join(uvm.fsfiles, "vmdk.vmdk"), size=16, pattern=b"VMDK"
    )
    jail_path = uvm.create_jailed_resource(vmdk.descriptor_path)
    with pytest.raises(RuntimeError, match="VMDK backend requires is_read_only=true."):
        uvm.api.drive.put(
            drive_id="vmdk",
            path_on_host=jail_path,
            is_read_only=False,
            is_root_device=False,
            io_engine="Sync",
            image_format="Vmdk",
        )
