# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check that the kvm_ptp device works"""

import pytest


def test_kvm_ptp(uvm_plain_any):
    """Test kvm_ptp is usable"""

    vm = uvm_plain_any
    if vm.guest_kernel_version[:2] < (6, 1):
        pytest.skip("Only supported in kernel 6.1 and after")

    vm.spawn()
    vm.basic_config(vcpu_count=2, mem_size_mib=256)
    vm.add_net_iface()
    vm.start()

    ret, _, stderr = vm.ssh.run("[ -c /dev/ptp0 ]")
    assert ret == 0, stderr

    # phc_ctl[14515.127]: clock time is 1697545854.728335694 or Tue Oct 17 12:30:54 2023
    ret, _, stderr = vm.ssh.run("phc_ctl /dev/ptp0 -- get")
    assert ret == 0, stderr
