# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for verifying the virtio-mem is working correctly"""


def test_virtio_mem_detected(uvm_plain_6_1):
    """
    Check that the guest kernel has enabled PV steal time.
    """
    uvm = uvm_plain_6_1
    uvm.spawn()
    uvm.memory_monitor = None
    uvm.basic_config(
        boot_args="console=ttyS0 reboot=k panic=1 memhp_default_state=online_movable"
    )
    uvm.add_net_iface()
    uvm.api.memory_hotplug.put(total_size_mib=1024)
    uvm.start()

    _, stdout, _ = uvm.ssh.check_output("dmesg | grep 'virtio_mem'")
    for line in stdout.splitlines():
        _, key, value = line.strip().split(":")
        key = key.strip()
        value = int(value.strip(), base=0)
        match key:
            case "start address":
                assert value >= (512 << 30), "start address isn't in past MMIO64 region"
            case "region size":
                assert value == 1024 << 20, "region size doesn't match"
            case "device block size":
                assert value == 2 << 20, "block size doesn't match"
            case "plugged size":
                assert value == 0, "plugged size doesn't match"
            case "requested size":
                assert value == 0, "requested size doesn't match"
            case _:
                continue
