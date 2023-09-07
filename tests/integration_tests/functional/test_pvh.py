# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for PVH boot mode"""

# pylint:disable=redefined-outer-name


def test_linux_pvh_boot(uvm_pvh):
    """
    Tests booting a PVH-enabled linux kernel for supported guest kernel version 5.10 and newer (as non-XEN PVH
    support was added to linux in 5.0).

    Asserts that the 'Kernel loaded using PVH boot protocol' log message is present
    """
    uvm_pvh.spawn()
    uvm_pvh.basic_config()
    uvm_pvh.add_net_iface()
    uvm_pvh.start()

    uvm_pvh.ssh.run("true")

    uvm_pvh.check_log_message("Kernel loaded using PVH boot protocol")
