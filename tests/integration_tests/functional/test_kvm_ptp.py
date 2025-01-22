# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Check that the kvm_ptp device works"""

import pytest


def test_kvm_ptp(uvm_any_booted):
    """Test kvm_ptp is usable"""

    vm = uvm_any_booted
    if vm.guest_kernel_version[:2] < (6, 1):
        pytest.skip("Only supported in kernel 6.1 and after")

    _, dmesg, _ = vm.ssh.check_output("dmesg |grep -i ptp")
    assert "PTP clock support registered" in dmesg

    # wait up to 5s to see the PTP device
    vm.ssh.check_output("udevadm wait -t 5 /dev/ptp0")

    # phc_ctl[14515.127]: clock time is 1697545854.728335694 or Tue Oct 17 12:30:54 2023
    vm.ssh.check_output("phc_ctl /dev/ptp0 -- get")
