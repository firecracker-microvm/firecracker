# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CPU features for aarch64."""

import os

import pytest

from framework import utils
from framework.properties import global_props
from framework.utils_cpuid import CPU_FEATURES_CMD, CpuModel

pytestmark = pytest.mark.skipif(
    global_props.cpu_architecture != "aarch64", reason="Only run in aarch64"
)

G2_FEATS = set(
    (
        "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
        "asimdhp cpuid asimdrdm lrcpc dcpop asimddp ssbs"
    ).split()
)

G3_FEATS = G2_FEATS | set(
    "sha512 asimdfhm dit uscat ilrcpc flagm jscvt fcma sha3 sm3 sm4 rng dcpodp i8mm bf16 dgh".split()
)

G3_SVE_AND_PAC = set("paca pacg sve svebf16 svei8mm".split())


def test_guest_cpu_features(uvm_any):
    """Check the CPU features for a microvm with different CPU templates"""

    vm = uvm_any
    expected_cpu_features = set()
    match global_props.cpu_model, vm.cpu_template_name:
        case CpuModel.ARM_NEOVERSE_N1, "v1n1":
            expected_cpu_features = G2_FEATS
        case CpuModel.ARM_NEOVERSE_N1, None:
            expected_cpu_features = G2_FEATS

        # [cm]7g with guest kernel 5.10 and later
        case CpuModel.ARM_NEOVERSE_V1, "v1n1":
            expected_cpu_features = G2_FEATS
        case CpuModel.ARM_NEOVERSE_V1, "aarch64_with_sve_and_pac":
            expected_cpu_features = G3_FEATS | G3_SVE_AND_PAC
        case CpuModel.ARM_NEOVERSE_V1, None:
            expected_cpu_features = G3_FEATS

    guest_feats = set(vm.ssh.check_output(CPU_FEATURES_CMD).stdout.split())
    assert guest_feats == expected_cpu_features


def test_host_vs_guest_cpu_features(uvm_nano):
    """Check CPU features host vs guest"""

    vm = uvm_nano
    vm.add_net_iface()
    vm.start()
    host_feats = set(utils.check_output(CPU_FEATURES_CMD).stdout.split())
    guest_feats = set(vm.ssh.check_output(CPU_FEATURES_CMD).stdout.split())
    cpu_model = global_props.cpu_model
    match cpu_model:
        case CpuModel.ARM_NEOVERSE_N1:
            expected_guest_minus_host = set()
            expected_host_minus_guest = set()

            # Upstream kernel v6.11+ hides "ssbs" from "lscpu" on Neoverse-N1 and Neoverse-V1 since
            # they have an errata whereby an MSR to the SSBS special-purpose register does not
            # affect subsequent speculative instructions, permitting speculative store bypassing for
            # a window of time.
            # https://github.com/torvalds/linux/commit/adeec61a4723fd3e39da68db4cc4d924e6d7f641
            #
            # While Amazon Linux kernels (v5.10 and v6.1) backported the above commit, our test
            # ubuntu kernel (v6.8) and our guest kernels (v5.10 and v6.1) don't pick it.
            host_has_ssbs = global_props.host_os not in {
                "amzn2",
                "amzn2023",
            } and global_props.host_linux_version_tpl < (6, 11)
            guest_has_ssbs = vm.guest_kernel_version < (6, 11)

            if host_has_ssbs and not guest_has_ssbs:
                expected_host_minus_guest |= {"ssbs"}
            if not host_has_ssbs and guest_has_ssbs:
                expected_guest_minus_host |= {"ssbs"}

            assert host_feats - guest_feats == expected_host_minus_guest
            assert guest_feats - host_feats == expected_guest_minus_host
        case CpuModel.ARM_NEOVERSE_V1:
            expected_guest_minus_host = set()
            # KVM does not enable PAC or SVE features by default
            # and Firecracker does not enable them either.
            expected_host_minus_guest = {
                "paca",
                "pacg",
                "sve",
                "svebf16",
                "svei8mm",
            }

            # Upstream kernel v6.11+ hides "ssbs" from "lscpu" on Neoverse-N1 and Neoverse-V1 since
            # they have an errata whereby an MSR to the SSBS special-purpose register does not
            # affect subsequent speculative instructions, permitting speculative store bypassing for
            # a window of time.
            # https://github.com/torvalds/linux/commit/adeec61a4723fd3e39da68db4cc4d924e6d7f641
            #
            # While Amazon Linux kernels (v5.10 and v6.1) backported the above commit, our test
            # ubuntu kernel (v6.8) and our guest kernels (v5.10 and v6.1) don't pick it.
            host_has_ssbs = global_props.host_os not in {
                "amzn2",
                "amzn2023",
            } and global_props.host_linux_version_tpl < (6, 11)
            guest_has_ssbs = vm.guest_kernel_version < (6, 11)

            if host_has_ssbs and not guest_has_ssbs:
                expected_host_minus_guest |= {"ssbs"}
            if not host_has_ssbs and guest_has_ssbs:
                expected_guest_minus_host |= {"ssbs"}

            assert host_feats - guest_feats == expected_host_minus_guest
            assert guest_feats - host_feats == expected_guest_minus_host
        case _:
            if os.environ.get("BUILDKITE") is not None:
                assert (
                    False
                ), f"Cpu model {cpu_model} is not supported, please onboard it."
