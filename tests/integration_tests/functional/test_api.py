# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that ensure the correctness of the Firecracker API."""

# Disable pylint C0302: Too many lines in module
# pylint: disable=C0302
import os
import platform
import re
import resource
import time
from pathlib import Path

import packaging.version
import pytest

import host_tools.drive as drive_tools
import host_tools.network as net_tools
from framework import utils_cpuid
from framework.utils import get_firecracker_version_from_toml, is_io_uring_supported

MEM_LIMIT = 1000000000

NOT_SUPPORTED_BEFORE_START = (
    "The requested operation is not supported before starting the microVM."
)
NOT_SUPPORTED_AFTER_START = (
    "The requested operation is not supported after starting the microVM"
)


def test_api_happy_start(uvm_plain):
    """
    Test that a regular microvm API config and boot sequence works.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    # Set up the microVM with 2 vCPUs, 256 MiB of RAM and
    # a root file system with the rw permission.
    test_microvm.basic_config()

    test_microvm.start()


def test_drive_io_engine(uvm_plain):
    """
    Test io_engine configuration.

    Test that the io_engine can be configured via the API on kernels that
    support the given type and that FC returns an error otherwise.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    test_microvm.basic_config(add_root_device=False)
    test_microvm.add_net_iface()

    supports_io_uring = is_io_uring_supported()

    kwargs = {
        "drive_id": "rootfs",
        "path_on_host": test_microvm.create_jailed_resource(test_microvm.rootfs_file),
        "is_root_device": True,
        "is_read_only": True,
    }

    # Test the opposite of the default backend type.
    if supports_io_uring:
        test_microvm.api.drive.put(io_engine="Sync", **kwargs)

    if not supports_io_uring:
        with pytest.raises(RuntimeError):
            test_microvm.api.drive.put(io_engine="Async", **kwargs)
        # The Async engine is not supported for older kernels.
        test_microvm.check_log_message(
            "Received Error. Status code: 400 Bad Request. Message: Drive config error: "
            "Unable to create the virtio block device: Virtio backend error: "
            "Error coming from the IO engine: Unsupported engine type: Async"
        )

        # Now configure the default engine type and check that it works.
        test_microvm.api.drive.put(**kwargs)

    test_microvm.start()
    test_microvm.wait_for_up()

    assert test_microvm.api.vm_config.get().json()["drives"][0]["io_engine"] == "Sync"


def test_api_put_update_pre_boot(uvm_plain, io_engine):
    """
    Test that PUT updates are allowed before the microvm boots.

    Tests updates on drives, boot source and machine config.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    # Set up the microVM with 2 vCPUs, 256 MiB of RAM  and
    # a root file system with the rw permission.
    test_microvm.basic_config()

    fs1 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "scratch"))
    response = test_microvm.api.drive.put(
        drive_id="scratch",
        path_on_host=test_microvm.create_jailed_resource(fs1.path),
        is_root_device=False,
        is_read_only=False,
        io_engine=io_engine,
    )

    # Updates to `kernel_image_path` with an invalid path are not allowed.
    expected_msg = re.escape(
        "The kernel file cannot be opened: No such file or directory (os error 2)"
    )
    with pytest.raises(RuntimeError, match=expected_msg):
        test_microvm.api.boot.put(kernel_image_path="foo.bar")

    # Updates to `kernel_image_path` with a valid path are allowed.
    test_microvm.api.boot.put(
        kernel_image_path=test_microvm.get_jailed_resource(test_microvm.kernel_file)
    )

    # Updates to `path_on_host` with an invalid path are not allowed.
    with pytest.raises(RuntimeError, match="No such file or directory"):
        test_microvm.api.drive.put(
            drive_id="rootfs",
            path_on_host="foo.bar",
            is_read_only=True,
            is_root_device=True,
            io_engine=io_engine,
        )

    # Updates to `is_root_device` that result in two root block devices are not
    # allowed.
    with pytest.raises(RuntimeError, match="A root block device already exists"):
        test_microvm.api.drive.put(
            drive_id="scratch",
            path_on_host=test_microvm.get_jailed_resource(fs1.path),
            is_read_only=False,
            is_root_device=True,
            io_engine=io_engine,
        )

    # Valid updates to `path_on_host` and `is_read_only` are allowed.
    fs2 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "otherscratch"))
    test_microvm.api.drive.put(
        drive_id="scratch",
        path_on_host=test_microvm.create_jailed_resource(fs2.path),
        is_read_only=True,
        is_root_device=False,
        io_engine=io_engine,
    )

    # Valid updates to all fields in the machine configuration are allowed.
    # The machine configuration has a default value, so all PUTs are updates.
    microvm_config_json = {
        "vcpu_count": 4,
        "smt": platform.machine() == "x86_64",
        "mem_size_mib": 256,
        "track_dirty_pages": True,
    }
    if platform.machine() == "x86_64":
        microvm_config_json["cpu_template"] = "C3"

    test_microvm.api.machine_config.put(**microvm_config_json)
    response = test_microvm.api.machine_config.get()
    response_json = response.json()

    vcpu_count = microvm_config_json["vcpu_count"]
    assert response_json["vcpu_count"] == vcpu_count

    smt = microvm_config_json["smt"]
    assert response_json["smt"] == smt

    mem_size_mib = microvm_config_json["mem_size_mib"]
    assert response_json["mem_size_mib"] == mem_size_mib

    if platform.machine() == "x86_64":
        cpu_template = str(microvm_config_json["cpu_template"])
        assert response_json["cpu_template"] == cpu_template

    track_dirty_pages = microvm_config_json["track_dirty_pages"]
    assert response_json["track_dirty_pages"] == track_dirty_pages


def test_net_api_put_update_pre_boot(uvm_plain):
    """
    Test PUT updates on network configurations before the microvm boots.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    first_if_name = "first_tap"
    tap1 = net_tools.Tap(first_if_name, test_microvm.netns.id)
    test_microvm.api.network.put(
        iface_id="1", guest_mac="06:00:00:00:00:01", host_dev_name=tap1.name
    )

    # Adding new network interfaces is allowed.
    second_if_name = "second_tap"
    tap2 = net_tools.Tap(second_if_name, test_microvm.netns.id)
    test_microvm.api.network.put(
        iface_id="2", guest_mac="07:00:00:00:00:01", host_dev_name=tap2.name
    )

    # Updates to a network interface with an unavailable MAC are not allowed.
    guest_mac = "06:00:00:00:00:01"
    expected_msg = f"The MAC address is already in use: {guest_mac}"
    with pytest.raises(RuntimeError, match=expected_msg):
        test_microvm.api.network.put(
            iface_id="2", host_dev_name=second_if_name, guest_mac=guest_mac
        )

    # Updates to a network interface with an available MAC are allowed.
    test_microvm.api.network.put(
        iface_id="2", host_dev_name=second_if_name, guest_mac="08:00:00:00:00:01"
    )

    # Updates to a network interface with an unavailable name are not allowed.
    expected_msg = "Could not create the network device"
    with pytest.raises(RuntimeError, match=expected_msg):
        test_microvm.api.network.put(
            iface_id="1", host_dev_name=second_if_name, guest_mac="06:00:00:00:00:01"
        )

    # Updates to a network interface with an available name are allowed.
    iface_id = "1"
    tapname = test_microvm.id[:8] + "tap" + iface_id

    tap3 = net_tools.Tap(tapname, test_microvm.netns.id)
    test_microvm.api.network.put(
        iface_id=iface_id, host_dev_name=tap3.name, guest_mac="06:00:00:00:00:01"
    )


def test_api_mmds_config(uvm_plain):
    """
    Test /mmds/config PUT scenarios that unit tests can't cover.

    Tests updates on MMDS config before and after attaching a network device.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    # Set up the microVM with 2 vCPUs, 256 MiB of RAM  and
    # a root file system with the rw permission.
    test_microvm.basic_config()

    # Setting MMDS config with empty network interface IDs list is not allowed.
    err_msg = (
        "The list of network interface IDs that allow "
        "forwarding MMDS requests is empty."
    )
    with pytest.raises(RuntimeError):
        test_microvm.api.mmds_config.put(network_interfaces=[])

    # Setting MMDS config when no network device has been attached
    # is not allowed.
    err_msg = (
        "The list of network interface IDs provided contains "
        "at least one ID that does not correspond to any "
        "existing network interface."
    )
    with pytest.raises(RuntimeError, match=err_msg):
        test_microvm.api.mmds_config.put(network_interfaces=["foo"])

    # Attach network interface.
    tap = net_tools.Tap("tap1", test_microvm.netns.id)
    test_microvm.api.network.put(
        iface_id="1", guest_mac="06:00:00:00:00:01", host_dev_name=tap.name
    )

    # Setting MMDS config with an ID that does not correspond to an already
    # attached network device is not allowed.
    err_msg = (
        "The list of network interface IDs provided contains"
        " at least one ID that does not correspond to any "
        "existing network interface."
    )
    with pytest.raises(RuntimeError, match=err_msg):
        test_microvm.api.mmds_config.put(network_interfaces=["1", "foo"])

    # Updates to MMDS version with invalid value are not allowed.
    err_msg = (
        "An error occurred when deserializing the json body of a "
        "request: unknown variant `foo`, expected `V1` or `V2`"
    )
    with pytest.raises(RuntimeError, match=err_msg):
        test_microvm.api.mmds_config.put(version="foo", network_interfaces=["1"])

    # Valid MMDS config not specifying version or IPv4 address.
    test_microvm.api.mmds_config.put(network_interfaces=["1"])
    assert test_microvm.api.vm_config.get().json()["mmds-config"]["version"] == "V1"

    # Valid MMDS config not specifying version.
    mmds_config = {"ipv4_address": "169.254.169.250", "network_interfaces": ["1"]}
    test_microvm.api.mmds_config.put(**mmds_config)
    assert (
        test_microvm.api.vm_config.get().json()["mmds-config"]["ipv4_address"]
        == "169.254.169.250"
    )

    # Valid MMDS config.
    mmds_config = {
        "version": "V2",
        "ipv4_address": "169.254.169.250",
        "network_interfaces": ["1"],
    }
    test_microvm.api.mmds_config.put(**mmds_config)
    assert test_microvm.api.vm_config.get().json()["mmds-config"]["version"] == "V2"


# pylint: disable=too-many-statements
def test_api_machine_config(uvm_plain):
    """
    Test /machine_config PUT/PATCH scenarios that unit tests can't cover.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    # Test invalid vcpu count < 0.
    with pytest.raises(RuntimeError):
        test_microvm.api.machine_config.put(vcpu_count="-2")

    # Test invalid type for smt flag.
    with pytest.raises(RuntimeError):
        test_microvm.api.machine_config.put(smt="random_string")

    # Test invalid CPU template.
    with pytest.raises(RuntimeError):
        test_microvm.api.machine_config.put(cpu_template="random_string")

    test_microvm.api.machine_config.patch(track_dirty_pages=True)

    # Test missing vcpu_count.
    with pytest.raises(
        RuntimeError, match="missing field `vcpu_count` at line 1 column 21."
    ):
        test_microvm.api.machine_config.put(mem_size_mib=128)

    # Test missing mem_size_mib.
    with pytest.raises(
        RuntimeError, match="missing field `mem_size_mib` at line 1 column 17."
    ):
        test_microvm.api.machine_config.put(vcpu_count=2)

    # Test default smt value.
    test_microvm.api.machine_config.put(mem_size_mib=128, vcpu_count=1)

    response = test_microvm.api.machine_config.get()
    assert response.json()["smt"] is False

    # Test that smt=True errors on ARM.
    if platform.machine() == "x86_64":
        test_microvm.api.machine_config.patch(smt=True)
    elif platform.machine() == "aarch64":
        expected_msg = (
            "Enabling simultaneous multithreading is not supported on aarch64"
        )
        with pytest.raises(RuntimeError, match=expected_msg):
            test_microvm.api.machine_config.patch(smt=True)

    # Test invalid mem_size_mib < 0.
    with pytest.raises(RuntimeError):
        test_microvm.api.machine_config.put(mem_size_mib="-2")

    # Test invalid mem_size_mib > usize::MAX.
    bad_size = 1 << 64
    fail_msg = (
        "error occurred when deserializing the json body of a request: invalid type"
    )
    with pytest.raises(RuntimeError, match=fail_msg):
        test_microvm.api.machine_config.put(mem_size_mib=bad_size)

    # Reset the configuration of the microvm
    # This will explicitly set vcpu_num = 2, mem_size_mib = 256
    # track_dirty_pages = false. All other parameters are
    # unspecified so will revert to default values.
    test_microvm.basic_config()

    # Test mem_size_mib of valid type, but too large.
    firecracker_pid = test_microvm.firecracker_pid
    resource.prlimit(
        firecracker_pid, resource.RLIMIT_AS, (MEM_LIMIT, resource.RLIM_INFINITY)
    )

    bad_size = (1 << 64) - 1
    test_microvm.api.machine_config.patch(mem_size_mib=bad_size)

    fail_msg = re.escape(
        "Invalid Memory Configuration: Cannot create mmap region: Out of memory (os error 12)"
    )
    with pytest.raises(RuntimeError, match=fail_msg):
        test_microvm.start()

    # Test invalid mem_size_mib = 0.
    with pytest.raises(
        RuntimeError,
        match=re.escape(
            "The memory size (MiB) is either 0, or not a multiple of the configured page size."
        ),
    ):
        test_microvm.api.machine_config.patch(mem_size_mib=0)

    # Test valid mem_size_mib.
    test_microvm.api.machine_config.patch(mem_size_mib=256)

    # Set the cpu template
    if platform.machine() == "x86_64":
        test_microvm.api.machine_config.patch(cpu_template="C3")
    else:
        # We test with "None" because this is the only option supported on
        # all aarch64 instances. It still tests setting `cpu_template`,
        # even though the values we set is "None".
        test_microvm.api.machine_config.patch(cpu_template="None")

    if utils_cpuid.get_cpu_vendor() == utils_cpuid.CpuVendor.AMD:
        # We shouldn't be able to apply Intel templates on AMD hosts
        fail_msg = "CPU vendor mismatched between actual CPU and CPU template"
        with pytest.raises(RuntimeError, match=fail_msg):
            test_microvm.start()
    else:
        test_microvm.start()

    # Validate full vm configuration after patching machine config.
    json = test_microvm.api.vm_config.get().json()
    assert json["machine-config"]["vcpu_count"] == 2
    assert json["machine-config"]["mem_size_mib"] == 256
    assert json["machine-config"]["smt"] is False


def test_negative_machine_config_api(uvm_plain):
    """
    Test the deprecated `cpu_template` field in PUT and PATCH requests on
    `/machine-config` API is handled correctly.

    When using the `cpu_template` field (even if the value is "None"), the HTTP
    response header should have "Deprecation: true".
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    # Use `cpu_template` field in PUT /machine-config
    response = test_microvm.api.machine_config.put(
        vcpu_count=2,
        mem_size_mib=256,
        cpu_template="None",
    )
    assert response.headers["deprecation"]
    assert (
        "PUT /machine-config: cpu_template field is deprecated."
        in test_microvm.log_data
    )

    # Use `cpu_template` field in PATCH /machine-config
    response = test_microvm.api.machine_config.patch(cpu_template="None")
    assert (
        "PATCH /machine-config: cpu_template field is deprecated."
        in test_microvm.log_data
    )


def test_api_cpu_config(uvm_plain, custom_cpu_template):
    """
    Test /cpu-config PUT scenarios.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    with pytest.raises(RuntimeError):
        test_microvm.api.cpu_config.put(foo=False)

    test_microvm.api.cpu_config.put(**custom_cpu_template["template"])


def test_api_put_update_post_boot(uvm_plain, io_engine):
    """
    Test that PUT updates are rejected after the microvm boots.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    # Set up the microVM with 2 vCPUs, 256 MiB of RAM  and
    # a root file system with the rw permission.
    test_microvm.basic_config()

    iface_id = "1"
    tapname = test_microvm.id[:8] + "tap" + iface_id
    tap1 = net_tools.Tap(tapname, test_microvm.netns.id)

    test_microvm.api.network.put(
        iface_id=iface_id, host_dev_name=tap1.name, guest_mac="06:00:00:00:00:01"
    )

    test_microvm.start()

    # Valid updates to `kernel_image_path` are not allowed after boot.
    with pytest.raises(RuntimeError, match=NOT_SUPPORTED_AFTER_START):
        test_microvm.api.boot.put(
            kernel_image_path=test_microvm.get_jailed_resource(test_microvm.kernel_file)
        )

    # Valid updates to the machine configuration are not allowed after boot.
    with pytest.raises(RuntimeError, match=NOT_SUPPORTED_AFTER_START):
        test_microvm.api.machine_config.patch(vcpu_count=4)

    with pytest.raises(RuntimeError, match=NOT_SUPPORTED_AFTER_START):
        test_microvm.api.machine_config.put(vcpu_count=4, mem_size_mib=128)

    # Network interface update is not allowed after boot.
    with pytest.raises(RuntimeError, match=NOT_SUPPORTED_AFTER_START):
        test_microvm.api.network.put(
            iface_id="1", host_dev_name=tap1.name, guest_mac="06:00:00:00:00:02"
        )

    # Block device update is not allowed after boot.
    with pytest.raises(RuntimeError, match=NOT_SUPPORTED_AFTER_START):
        test_microvm.api.drive.put(
            drive_id="rootfs",
            path_on_host=test_microvm.jailer.jailed_path(test_microvm.rootfs_file),
            is_read_only=False,
            is_root_device=True,
            io_engine=io_engine,
        )

    # MMDS config is not allowed post-boot.
    mmds_config = {
        "version": "V2",
        "ipv4_address": "169.254.169.250",
        "network_interfaces": ["1"],
    }
    with pytest.raises(RuntimeError, match=NOT_SUPPORTED_AFTER_START):
        test_microvm.api.mmds_config.put(**mmds_config)


def test_rate_limiters_api_config(uvm_plain, io_engine):
    """
    Test the IO rate limiter API config.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    # Test the DRIVE rate limiting API.

    # Test drive with bw rate-limiting.
    fs1 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "bw"))
    test_microvm.api.drive.put(
        drive_id="bw",
        path_on_host=test_microvm.create_jailed_resource(fs1.path),
        is_read_only=False,
        is_root_device=False,
        rate_limiter={"bandwidth": {"size": 1000000, "refill_time": 100}},
        io_engine=io_engine,
    )

    # Test drive with ops rate-limiting.
    fs2 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "ops"))
    test_microvm.api.drive.put(
        drive_id="ops",
        path_on_host=test_microvm.create_jailed_resource(fs2.path),
        is_read_only=False,
        is_root_device=False,
        rate_limiter={"ops": {"size": 1, "refill_time": 100}},
        io_engine=io_engine,
    )

    # Test drive with bw and ops rate-limiting.
    fs3 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "bwops"))
    test_microvm.api.drive.put(
        drive_id="bwops",
        path_on_host=test_microvm.create_jailed_resource(fs3.path),
        is_read_only=False,
        is_root_device=False,
        rate_limiter={
            "bandwidth": {"size": 1000000, "refill_time": 100},
            "ops": {"size": 1, "refill_time": 100},
        },
        io_engine=io_engine,
    )

    # Test drive with 'empty' rate-limiting (same as not specifying the field)
    fs4 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "nada"))
    test_microvm.api.drive.put(
        drive_id="nada",
        path_on_host=test_microvm.create_jailed_resource(fs4.path),
        is_read_only=False,
        is_root_device=False,
        rate_limiter={},
        io_engine=io_engine,
    )

    # Test the NET rate limiting API.

    # Test network with tx bw rate-limiting.
    iface_id = "1"
    tapname = test_microvm.id[:8] + "tap" + iface_id
    tap1 = net_tools.Tap(tapname, test_microvm.netns.id)

    test_microvm.api.network.put(
        iface_id=iface_id,
        guest_mac="06:00:00:00:00:01",
        host_dev_name=tap1.name,
        tx_rate_limiter={"bandwidth": {"size": 1000000, "refill_time": 100}},
    )

    # Test network with rx bw rate-limiting.
    iface_id = "2"
    tapname = test_microvm.id[:8] + "tap" + iface_id
    tap2 = net_tools.Tap(tapname, test_microvm.netns.id)
    test_microvm.api.network.put(
        iface_id=iface_id,
        guest_mac="06:00:00:00:00:02",
        host_dev_name=tap2.name,
        rx_rate_limiter={"bandwidth": {"size": 1000000, "refill_time": 100}},
    )

    # Test network with tx and rx bw and ops rate-limiting.
    iface_id = "3"
    tapname = test_microvm.id[:8] + "tap" + iface_id
    tap3 = net_tools.Tap(tapname, test_microvm.netns.id)
    test_microvm.api.network.put(
        iface_id=iface_id,
        guest_mac="06:00:00:00:00:03",
        host_dev_name=tap3.name,
        rx_rate_limiter={
            "bandwidth": {"size": 1000000, "refill_time": 100},
            "ops": {"size": 1, "refill_time": 100},
        },
        tx_rate_limiter={
            "bandwidth": {"size": 1000000, "refill_time": 100},
            "ops": {"size": 1, "refill_time": 100},
        },
    )

    # Test entropy device bw and ops rate-limiting.
    test_microvm.api.entropy.put(
        rate_limiter={
            "bandwidth": {"size": 1000000, "refill_time": 100},
            "ops": {"size": 1, "refill_time": 100},
        },
    )


def test_api_patch_pre_boot(uvm_plain, io_engine):
    """
    Test that PATCH updates are not allowed before the microvm boots.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    # Sets up the microVM with 2 vCPUs, 256 MiB of RAM, 1 network interface
    # and a root file system with the rw permission.
    test_microvm.basic_config()

    fs1 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "scratch"))
    drive_id = "scratch"
    test_microvm.api.drive.put(
        drive_id=drive_id,
        path_on_host=test_microvm.create_jailed_resource(fs1.path),
        is_root_device=False,
        is_read_only=False,
        io_engine=io_engine,
    )

    iface_id = "1"
    tapname = test_microvm.id[:8] + "tap" + iface_id
    tap1 = net_tools.Tap(tapname, test_microvm.netns.id)
    test_microvm.api.network.put(
        iface_id=iface_id, host_dev_name=tap1.name, guest_mac="06:00:00:00:00:01"
    )

    # Partial updates to the boot source are not allowed.
    with pytest.raises(RuntimeError, match="Invalid request method"):
        test_microvm.api.boot.patch(kernel_image_path="otherfile")

    # Partial updates to the machine configuration are allowed before boot.
    test_microvm.api.machine_config.patch(vcpu_count=4)
    response_json = test_microvm.api.machine_config.get().json()
    assert response_json["vcpu_count"] == 4

    # Partial updates to the logger configuration are not allowed.
    with pytest.raises(RuntimeError, match="Invalid request method"):
        test_microvm.api.logger.patch(level="Error")

    # Patching drive before boot is not allowed.
    with pytest.raises(RuntimeError, match=NOT_SUPPORTED_BEFORE_START):
        test_microvm.api.drive.patch(drive_id=drive_id, path_on_host="foo.bar")

    # Patching net before boot is not allowed.
    with pytest.raises(RuntimeError, match=NOT_SUPPORTED_BEFORE_START):
        test_microvm.api.network.patch(iface_id=iface_id)


def test_negative_api_patch_post_boot(uvm_plain, io_engine):
    """
    Test PATCH updates that are not allowed after the microvm boots.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    # Sets up the microVM with 2 vCPUs, 256 MiB of RAM, 1 network iface and
    # a root file system with the rw permission.
    test_microvm.basic_config()

    fs1 = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "scratch"))
    test_microvm.api.drive.put(
        drive_id="scratch",
        path_on_host=test_microvm.create_jailed_resource(fs1.path),
        is_root_device=False,
        is_read_only=False,
        io_engine=io_engine,
    )

    iface_id = "1"
    tapname = test_microvm.id[:8] + "tap" + iface_id
    tap1 = net_tools.Tap(tapname, test_microvm.netns.id)
    test_microvm.api.network.put(
        iface_id=iface_id, host_dev_name=tap1.name, guest_mac="06:00:00:00:00:01"
    )

    test_microvm.start()

    # Partial updates to the boot source are not allowed.
    with pytest.raises(RuntimeError, match="Invalid request method"):
        test_microvm.api.boot.patch(kernel_image_path="otherfile")

    # Partial updates to the machine configuration are not allowed after boot.
    with pytest.raises(RuntimeError, match=NOT_SUPPORTED_AFTER_START):
        test_microvm.api.machine_config.patch(vcpu_count=4)

    # Partial updates to the logger configuration are not allowed.
    with pytest.raises(RuntimeError, match="Invalid request method"):
        test_microvm.api.logger.patch(level="Error")


def test_drive_patch(uvm_plain):
    """
    Extensively test drive PATCH scenarios before and after boot.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    # Sets up the microVM with 2 vCPUs, 256 MiB of RAM and
    # a root file system with the rw permission.
    test_microvm.basic_config(rootfs_io_engine="Sync")

    fs = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "scratch"))
    test_microvm.add_drive(
        drive_id="scratch",
        path_on_host=fs.path,
        is_root_device=False,
        is_read_only=False,
        io_engine="Async" if is_io_uring_supported() else "Sync",
    )

    fs_vub = drive_tools.FilesystemFile(
        os.path.join(test_microvm.fsfiles, "scratch_vub")
    )
    test_microvm.add_vhost_user_drive("scratch_vub", fs_vub.path)

    # Patching drive before boot is not allowed.
    with pytest.raises(RuntimeError, match=NOT_SUPPORTED_BEFORE_START):
        test_microvm.api.drive.patch(drive_id="scratch", path_on_host="foo.bar")

    test_microvm.start()

    _drive_patch(test_microvm)


@pytest.mark.skipif(
    platform.machine() != "x86_64", reason="not yet implemented on aarch64"
)
def test_send_ctrl_alt_del(uvm_plain):
    """
    Test shutting down the microVM gracefully on x86, by sending CTRL+ALT+DEL.
    """
    # This relies on the i8042 device and AT Keyboard support being present in
    # the guest kernel.
    test_microvm = uvm_plain
    test_microvm.spawn()

    test_microvm.basic_config()
    test_microvm.start()

    # Wait around for the guest to boot up and initialize the user space
    time.sleep(2)

    test_microvm.api.actions.put(action_type="SendCtrlAltDel")

    firecracker_pid = test_microvm.firecracker_pid

    # If everything goes as expected, the guest OS will issue a reboot,
    # causing Firecracker to exit.
    # waitpid should block until the Firecracker process has exited. If
    # it has already exited by the time we call waitpid, WNOHANG causes
    # waitpid to raise a ChildProcessError exception.
    try:
        os.waitpid(firecracker_pid, os.WNOHANG)
    except ChildProcessError:
        pass


def _drive_patch(test_microvm):
    """Exercise drive patch test scenarios."""
    # Patches without mandatory fields for virtio block are not allowed.
    expected_msg = "Unable to patch the block device: Device manager error: Running method expected different backend. Please verify the request arguments"
    with pytest.raises(RuntimeError, match=expected_msg):
        test_microvm.api.drive.patch(drive_id="scratch")

    # Patches with any fields for vhost-user block are not allowed.
    with pytest.raises(RuntimeError, match=expected_msg):
        test_microvm.api.drive.patch(
            drive_id="scratch_vub",
            path_on_host="some_path",
        )

    # Patches with any fields for vhost-user block are not allowed.
    with pytest.raises(RuntimeError, match=expected_msg):
        test_microvm.api.drive.patch(
            drive_id="scratch_vub",
            rate_limiter={
                "bandwidth": {"size": 1000000, "refill_time": 100},
                "ops": {"size": 1, "refill_time": 100},
            },
        )

    drive_path = "foo.bar"

    # Cannot patch drive permissions post boot.
    with pytest.raises(RuntimeError, match="unknown field `is_read_only`"):
        test_microvm.api.drive.patch(
            drive_id="scratch", path_on_host=drive_path, is_read_only=True
        )

    # Cannot patch io_engine post boot.
    with pytest.raises(RuntimeError, match="unknown field `io_engine`"):
        test_microvm.api.drive.patch(
            drive_id="scratch", path_on_host=drive_path, io_engine="Sync"
        )

    # Updates to `is_root_device` with a valid value are not allowed.
    with pytest.raises(RuntimeError, match="unknown field `is_root_device`"):
        test_microvm.api.drive.patch(
            drive_id="scratch", path_on_host=drive_path, is_root_device=False
        )

    # Updates to `path_on_host` with an invalid path are not allowed.
    expected_msg = f"Unable to patch the block device: Device manager error: Virtio backend error: Error manipulating the backing file: No such file or directory (os error 2) {drive_path} Please verify the request arguments"
    with pytest.raises(RuntimeError, match=re.escape(expected_msg)):
        test_microvm.api.drive.patch(drive_id="scratch", path_on_host=drive_path)

    fs = drive_tools.FilesystemFile(os.path.join(test_microvm.fsfiles, "scratch_new"))
    # Updates to `path_on_host` with a valid path are allowed.
    test_microvm.api.drive.patch(
        drive_id="scratch", path_on_host=test_microvm.create_jailed_resource(fs.path)
    )

    # Updates to valid `path_on_host` and `rate_limiter` are allowed.
    test_microvm.api.drive.patch(
        drive_id="scratch",
        path_on_host=test_microvm.create_jailed_resource(fs.path),
        rate_limiter={
            "bandwidth": {"size": 1000000, "refill_time": 100},
            "ops": {"size": 1, "refill_time": 100},
        },
    )

    # Updates to `rate_limiter` only are allowed.
    test_microvm.api.drive.patch(
        drive_id="scratch",
        rate_limiter={
            "bandwidth": {"size": 5000, "refill_time": 100},
            "ops": {"size": 500, "refill_time": 100},
        },
    )

    # Updates to `rate_limiter` and invalid path fail.
    with pytest.raises(RuntimeError, match="No such file or directory"):
        test_microvm.api.drive.patch(
            drive_id="scratch",
            path_on_host="foo.bar",
            rate_limiter={
                "bandwidth": {"size": 5000, "refill_time": 100},
                "ops": {"size": 500, "refill_time": 100},
            },
        )

    # Validate full vm configuration after patching drives.
    response = test_microvm.api.vm_config.get().json()
    assert response["drives"] == [
        {
            "drive_id": "rootfs",
            "partuuid": None,
            "is_root_device": True,
            "cache_type": "Unsafe",
            "is_read_only": True,
            "path_on_host": "/ubuntu-22.04.squashfs",
            "rate_limiter": None,
            "io_engine": "Sync",
            "socket": None,
        },
        {
            "drive_id": "scratch",
            "partuuid": None,
            "is_root_device": False,
            "cache_type": "Unsafe",
            "is_read_only": False,
            "path_on_host": "/scratch_new.ext4",
            "rate_limiter": {
                "bandwidth": {"size": 5000, "one_time_burst": None, "refill_time": 100},
                "ops": {"size": 500, "one_time_burst": None, "refill_time": 100},
            },
            "io_engine": "Async" if is_io_uring_supported() else "Sync",
            "socket": None,
        },
        {
            "drive_id": "scratch_vub",
            "partuuid": None,
            "is_root_device": False,
            "cache_type": "Unsafe",
            "is_read_only": None,
            "path_on_host": None,
            "rate_limiter": None,
            "io_engine": None,
            "socket": str(
                Path("/")
                / test_microvm.disks_vhost_user["scratch_vub"].socket_path.name
            ),
        },
    ]


def test_api_version(uvm_plain):
    """
    Test the permanent VM version endpoint.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()
    test_microvm.basic_config()

    # Getting the VM version should be available pre-boot.
    preboot_response = test_microvm.api.version.get()
    # Check that the response contains the version.
    assert "firecracker_version" in preboot_response.json()

    # Start the microvm.
    test_microvm.start()

    # Getting the VM version should be available post-boot.
    postboot_response = test_microvm.api.version.get()
    # Check that the response contains the version.
    assert "firecracker_version" in postboot_response.json()
    # Validate VM version post-boot is the same as pre-boot.
    assert preboot_response.json() == postboot_response.json()

    cargo_version = get_firecracker_version_from_toml()
    api_version = packaging.version.parse(
        preboot_response.json()["firecracker_version"]
    )

    # Cargo version should match FC API version
    assert cargo_version == api_version

    binary_version = packaging.version.parse(test_microvm.firecracker_version)
    assert api_version == binary_version


def test_api_vsock(uvm_nano):
    """
    Test vsock related API commands.
    """
    vm = uvm_nano
    # Create a vsock device.
    vm.api.vsock.put(guest_cid=15, uds_path="vsock.sock")

    # Updating an existing vsock is currently fine.
    vm.api.vsock.put(guest_cid=166, uds_path="vsock.sock")

    # Check PUT request. Although vsock_id is deprecated, it must still work.
    response = vm.api.vsock.put(vsock_id="vsock1", guest_cid=15, uds_path="vsock.sock")
    assert response.headers["deprecation"]

    # Updating an existing vsock is currently fine even with deprecated
    # `vsock_id`.
    response = vm.api.vsock.put(vsock_id="vsock1", guest_cid=166, uds_path="vsock.sock")
    assert response.headers["deprecation"]

    # No other vsock action is allowed after booting the VM.
    vm.start()

    # Updating an existing vsock should not be fine at this point.
    with pytest.raises(RuntimeError):
        vm.api.vsock.put(guest_cid=17, uds_path="vsock.sock")


def test_api_entropy(uvm_plain):
    """
    Test entropy related API commands.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()
    test_microvm.basic_config()

    # Create a new entropy device should be OK.
    test_microvm.api.entropy.put()

    # Overwriting an existing should be OK.
    test_microvm.api.entropy.put()

    # Start the microvm
    test_microvm.start()

    with pytest.raises(RuntimeError):
        test_microvm.api.entropy.put()


def test_api_balloon(uvm_nano):
    """
    Test balloon related API commands.
    """
    test_microvm = uvm_nano

    # Updating an inexistent balloon device should give an error.
    with pytest.raises(RuntimeError):
        test_microvm.api.balloon.patch(amount_mib=0)

    # Adding a memory balloon should be OK.
    test_microvm.api.balloon.put(amount_mib=1, deflate_on_oom=True)

    # As is overwriting one.
    test_microvm.api.balloon.put(
        amount_mib=0, deflate_on_oom=False, stats_polling_interval_s=5
    )

    # Getting the device configuration should be available pre-boot.
    response = test_microvm.api.balloon.get()
    assert response.json()["amount_mib"] == 0
    assert response.json()["deflate_on_oom"] is False
    assert response.json()["stats_polling_interval_s"] == 5

    # Updating an existing balloon device is forbidden before boot.
    with pytest.raises(RuntimeError):
        test_microvm.api.balloon.patch(amount_mib=2)

    # We can't have a balloon device with a target size greater than
    # the available amount of memory.
    with pytest.raises(RuntimeError):
        test_microvm.api.balloon.put(
            amount_mib=1024, deflate_on_oom=False, stats_polling_interval_s=5
        )

    # Start the microvm.
    test_microvm.start()

    # Give the balloon driver time to initialize.
    # 500 ms is the maximum acceptable boot time.
    time.sleep(0.5)

    # But updating should be OK.
    test_microvm.api.balloon.patch(amount_mib=4)

    # Check we can't request more than the total amount of VM memory.
    with pytest.raises(RuntimeError):
        test_microvm.api.balloon.patch(amount_mib=300)

    # Check we can't disable statistics as they were enabled at boot.
    # We can, however, change the interval to a non-zero value.
    test_microvm.api.balloon_stats.patch(stats_polling_interval_s=5)

    # Getting the device configuration should be available post-boot.
    response = test_microvm.api.balloon.get()
    assert response.json()["amount_mib"] == 4
    assert response.json()["deflate_on_oom"] is False
    assert response.json()["stats_polling_interval_s"] == 5

    # Check we can't overflow the `num_pages` field in the config space by
    # requesting too many MB. There are 256 4K pages in a MB. Here, we are
    # requesting u32::MAX / 128.
    with pytest.raises(RuntimeError):
        test_microvm.api.balloon.patch(amount_mib=33554432)


def test_get_full_config_after_restoring_snapshot(microvm_factory, uvm_nano):
    """
    Test the configuration of a microVM after restoring from a snapshot.
    """
    net_iface = uvm_nano.add_net_iface()
    cpu_vendor = utils_cpuid.get_cpu_vendor()

    setup_cfg = {}
    # Basic config also implies a root block device.
    setup_cfg["machine-config"] = {
        "vcpu_count": 2,
        "mem_size_mib": 256,
        "smt": True,
        "track_dirty_pages": False,
        "huge_pages": "None",
    }

    if cpu_vendor == utils_cpuid.CpuVendor.ARM:
        setup_cfg["machine-config"]["smt"] = False

    if cpu_vendor == utils_cpuid.CpuVendor.INTEL:
        setup_cfg["machine-config"]["cpu_template"] = "C3"

    uvm_nano.api.machine_config.patch(**setup_cfg["machine-config"])

    setup_cfg["cpu-config"] = None

    setup_cfg["drives"] = [
        {
            "drive_id": "rootfs",
            "partuuid": None,
            "is_root_device": True,
            "cache_type": "Unsafe",
            "is_read_only": True,
            "path_on_host": f"/{uvm_nano.rootfs_file.name}",
            "rate_limiter": None,
            "io_engine": "Sync",
            "socket": None,
        }
    ]

    # Add a memory balloon device.
    uvm_nano.api.balloon.put(amount_mib=1, deflate_on_oom=True)
    setup_cfg["balloon"] = {
        "amount_mib": 1,
        "deflate_on_oom": True,
        "stats_polling_interval_s": 0,
    }

    # Add a vsock device.
    uvm_nano.api.vsock.put(guest_cid=15, uds_path="vsock.sock")
    setup_cfg["vsock"] = {"guest_cid": 15, "uds_path": "vsock.sock"}

    setup_cfg["logger"] = None
    setup_cfg["metrics"] = None
    setup_cfg["mmds-config"] = {
        "version": "V1",
        "network_interfaces": [net_iface.dev_name],
    }

    uvm_nano.api.mmds_config.put(**setup_cfg["mmds-config"])

    # Start the microvm.
    uvm_nano.start()

    # Add a tx rate limiter to the net device.
    tx_rl = {
        "bandwidth": {"size": 1000000, "refill_time": 100, "one_time_burst": None},
        "ops": None,
    }

    response = uvm_nano.api.network.patch(
        iface_id=net_iface.dev_name, tx_rate_limiter=tx_rl
    )
    setup_cfg["network-interfaces"] = [
        {
            "guest_mac": net_tools.mac_from_ip(net_iface.guest_ip),
            "iface_id": net_iface.dev_name,
            "host_dev_name": net_iface.tap_name,
            "rx_rate_limiter": None,
            "tx_rate_limiter": tx_rl,
        }
    ]

    snapshot = uvm_nano.snapshot_full()
    uvm2 = microvm_factory.build()
    uvm2.spawn()
    uvm2.restore_from_snapshot(snapshot, resume=True)

    expected_cfg = setup_cfg.copy()

    # We expect boot-source to be set with the following values
    expected_cfg["boot-source"] = {
        "kernel_image_path": uvm_nano.get_jailed_resource(uvm_nano.kernel_file),
        "initrd_path": None,
        "boot_args": None,
    }

    # no ipv4 specified during PUT /mmds/config so we expect the default
    expected_cfg["mmds-config"] = {
        "version": "V1",
        "ipv4_address": "169.254.169.254",
        "network_interfaces": [net_iface.dev_name],
    }

    # We should expect a null entropy device
    expected_cfg["entropy"] = None

    # Validate full vm configuration post-restore.
    response = uvm2.api.vm_config.get().json()
    assert response != setup_cfg
    assert response == expected_cfg


def test_get_full_config(uvm_plain):
    """
    Test the reported configuration of a microVM configured with all resources.
    """
    test_microvm = uvm_plain

    expected_cfg = {}

    test_microvm.spawn()
    # Basic config also implies a root block device.
    test_microvm.basic_config(boot_args="", rootfs_io_engine="Sync")
    expected_cfg["machine-config"] = {
        "vcpu_count": 2,
        "mem_size_mib": 256,
        "smt": False,
        "track_dirty_pages": False,
        "huge_pages": "None",
    }
    expected_cfg["cpu-config"] = None
    expected_cfg["boot-source"] = {
        "boot_args": "",
        "kernel_image_path": f"/{test_microvm.kernel_file.name}",
        "initrd_path": None,
    }
    expected_cfg["drives"] = [
        {
            "drive_id": "rootfs",
            "partuuid": None,
            "is_root_device": True,
            "cache_type": "Unsafe",
            "is_read_only": True,
            "path_on_host": "/ubuntu-22.04.squashfs",
            "rate_limiter": None,
            "io_engine": "Sync",
            "socket": None,
        }
    ]

    # Add a memory balloon device.
    test_microvm.api.balloon.put(amount_mib=1, deflate_on_oom=True)
    expected_cfg["balloon"] = {
        "amount_mib": 1,
        "deflate_on_oom": True,
        "stats_polling_interval_s": 0,
    }

    # Add a vsock device.
    response = test_microvm.api.vsock.put(guest_cid=15, uds_path="vsock.sock")
    expected_cfg["vsock"] = {"guest_cid": 15, "uds_path": "vsock.sock"}

    # Add a net device.
    iface_id = "1"
    tapname = test_microvm.id[:8] + "tap" + iface_id
    tap1 = net_tools.Tap(tapname, test_microvm.netns.id)
    guest_mac = "06:00:00:00:00:01"
    tx_rl = {
        "bandwidth": {"size": 1000000, "refill_time": 100, "one_time_burst": None},
        "ops": None,
    }
    response = test_microvm.api.network.put(
        iface_id=iface_id,
        guest_mac=guest_mac,
        host_dev_name=tap1.name,
        tx_rate_limiter=tx_rl,
    )
    expected_cfg["network-interfaces"] = [
        {
            "iface_id": iface_id,
            "host_dev_name": tap1.name,
            "guest_mac": "06:00:00:00:00:01",
            "rx_rate_limiter": None,
            "tx_rate_limiter": tx_rl,
        }
    ]

    # Update MMDS config.
    mmds_config = {
        "version": "V2",
        "ipv4_address": "169.254.169.250",
        "network_interfaces": ["1"],
    }
    response = test_microvm.api.mmds_config.put(**mmds_config)

    expected_cfg["logger"] = None
    expected_cfg["metrics"] = None
    expected_cfg["mmds-config"] = {
        "version": "V2",
        "ipv4_address": "169.254.169.250",
        "network_interfaces": ["1"],
    }

    # We should expect a null entropy device
    expected_cfg["entropy"] = None

    # Getting full vm configuration should be available pre-boot.
    response = test_microvm.api.vm_config.get()
    assert response.json() == expected_cfg

    # Start the microvm.
    test_microvm.start()

    # Validate full vm configuration post-boot as well.
    response = test_microvm.api.vm_config.get()
    assert response.json() == expected_cfg


def test_map_private_seccomp_regression(uvm_plain):
    """
    Seccomp mmap MAP_PRIVATE regression test.

    When sending large buffer to an api endpoint there will be an attempt to
    call mmap with MAP_PRIVATE|MAP_ANONYMOUS. This would result in vmm being
    killed by the seccomp filter before this PR.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.extra_args.update(
        {"http-api-max-payload-size": str(1024 * 1024 * 2)}
    )
    test_microvm.spawn()
    test_microvm.time_api_request = False

    response = test_microvm.api.mmds.get()
    assert response.json() == {}

    data_store = {"latest": {"meta-data": {"ami-id": "b" * (1024 * 1024)}}}
    test_microvm.api.mmds.put(**data_store)


# pylint: disable=protected-access
def test_negative_snapshot_load_api(microvm_factory):
    """
    Test snapshot load API.
    """
    vm = microvm_factory.build()
    vm.spawn()

    # Specifying both `mem_backend` and 'mem_file_path` should fail.
    err_msg = (
        "too many fields: either `mem_backend` or "
        "`mem_file_path` exclusively is required."
    )
    with pytest.raises(RuntimeError, match=err_msg):
        vm.api.snapshot_load.put(
            snapshot_path="foo",
            mem_backend={"backend_type": "File", "backend_path": "bar"},
            mem_file_path="bar",
        )

    # API request with `mem_backend` but no `backend_type` should fail.
    with pytest.raises(RuntimeError, match="missing field `backend_type`"):
        vm.api.snapshot_load.put(
            snapshot_path="foo",
            mem_backend={"backend_path": "bar"},
        )

    # API request with `mem_backend` but no `backend_path` should fail.
    with pytest.raises(RuntimeError, match="missing field `backend_path`"):
        vm.api.snapshot_load.put(
            snapshot_path="foo",
            mem_backend={"backend_type": "File"},
        )

    # API request with invalid `backend_type` should fail.
    with pytest.raises(
        RuntimeError, match="unknown variant `foo`, expected `File` or `Uffd`"
    ):
        vm.api.snapshot_load.put(
            snapshot_path="foo",
            mem_backend={"backend_type": "foo", "backend_path": "bar"},
        )

    # API request without `snapshot_path` should fail.
    with pytest.raises(RuntimeError, match="missing field `snapshot_path`"):
        vm.api.snapshot_load.put(
            mem_backend={"backend_type": "File", "backend_path": "bar"},
        )

    # API request without `mem_backend` or `mem_file_path` should fail.
    err_msg = "missing field: either `mem_backend` or " "`mem_file_path` is required"
    with pytest.raises(RuntimeError, match=err_msg):
        vm.api.snapshot_load.put(snapshot_path="foo")

    # Deprecated API should return deprecation response header.
    with pytest.raises(RuntimeError) as exc_info:
        vm.api.snapshot_load.put(
            snapshot_path="foo",
            mem_file_path="bar",
        )

    assert exc_info.value.args[2].headers["deprecation"]

    # The snapshot/memory files above don't exist, but the request is otherwise syntactically valid.
    # In this case, Firecracker exits.
    vm.mark_killed()
