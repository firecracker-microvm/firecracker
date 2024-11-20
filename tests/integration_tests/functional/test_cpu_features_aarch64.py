# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CPU features for aarch64."""

import os
import platform
import re

import pytest

import framework.utils_cpuid as cpuid_utils
from framework import utils
from framework.properties import global_props
from framework.utils_cpuid import CPU_FEATURES_CMD, CpuModel

PLATFORM = platform.machine()

DEFAULT_G2_FEATURES = set(
    (
        "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
        "asimdhp cpuid asimdrdm lrcpc dcpop asimddp ssbs"
    ).split(" ")
)

DEFAULT_G3_FEATURES_5_10 = DEFAULT_G2_FEATURES | set(
    "sha512 asimdfhm dit uscat ilrcpc flagm jscvt fcma sha3 sm3 sm4 rng dcpodp i8mm bf16 dgh".split(
        " "
    )
)

DEFAULT_G3_FEATURES_WITH_SVE_AND_PAC_5_10 = DEFAULT_G3_FEATURES_5_10 | set(
    "paca pacg sve svebf16 svei8mm".split(" ")
)

DEFAULT_G3_FEATURES_V1N1 = DEFAULT_G2_FEATURES


def _check_cpu_features_arm(test_microvm, guest_kv, template_name=None):
    expected_cpu_features = {"Flags": []}
    match cpuid_utils.get_cpu_model_name(), guest_kv, template_name:
        case CpuModel.ARM_NEOVERSE_N1, _, "v1n1":
            expected_cpu_features = DEFAULT_G2_FEATURES
        case CpuModel.ARM_NEOVERSE_N1, _, None:
            expected_cpu_features = DEFAULT_G2_FEATURES

        # [cm]7g with guest kernel 5.10 and later
        case CpuModel.ARM_NEOVERSE_V1, _, "v1n1":
            expected_cpu_features = DEFAULT_G3_FEATURES_V1N1
        case CpuModel.ARM_NEOVERSE_V1, _, "aarch64_with_sve_and_pac":
            expected_cpu_features = DEFAULT_G3_FEATURES_WITH_SVE_AND_PAC_5_10
        case CpuModel.ARM_NEOVERSE_V1, _, None:
            expected_cpu_features = DEFAULT_G3_FEATURES_5_10

    _, stdout, _ = test_microvm.ssh.check_output(CPU_FEATURES_CMD)
    flags = set(stdout.strip().split(" "))
    assert flags == expected_cpu_features


def get_cpu_template_dir(cpu_template):
    """
    Utility function to return a valid string which will be used as
    name of the directory where snapshot artifacts are stored during
    snapshot test and loaded from during restore test.

    """
    return cpu_template if cpu_template else "none"


@pytest.mark.skipif(
    PLATFORM != "aarch64",
    reason="This is aarch64 specific test.",
)
def test_host_vs_guest_cpu_features_aarch64(uvm_nano):
    """Check CPU features host vs guest"""

    vm = uvm_nano
    vm.add_net_iface()
    vm.start()
    host_feats = set(utils.check_output(CPU_FEATURES_CMD).stdout.strip().split(" "))
    guest_feats = set(vm.ssh.check_output(CPU_FEATURES_CMD).stdout.strip().split(" "))

    cpu_model = cpuid_utils.get_cpu_model_name()
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
                assert False, f"Cpu model {cpu_model} is not supported"


@pytest.mark.skipif(
    PLATFORM != "aarch64",
    reason="This is aarch64 specific test.",
)
def test_default_cpu_features(microvm_factory, guest_kernel, rootfs):
    """
    Check the CPU features for a microvm with the specified config.
    """

    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()
    vm.start()
    guest_kv = re.search(r"vmlinux-(\d+\.\d+)", guest_kernel.name).group(1)
    _check_cpu_features_arm(vm, guest_kv)


@pytest.mark.skipif(
    PLATFORM != "aarch64",
    reason="This is aarch64 specific test.",
)
def test_cpu_features_with_static_template(
    microvm_factory, guest_kernel, rootfs, cpu_template
):
    """
    Check the CPU features for a microvm with the specified config.
    """

    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn()
    vm.basic_config(cpu_template=cpu_template)
    vm.add_net_iface()
    vm.start()
    guest_kv = re.search(r"vmlinux-(\d+\.\d+)", guest_kernel.name).group(1)
    _check_cpu_features_arm(vm, guest_kv, "v1n1")

    # Check that cpu features are still correct
    # after snap/restore cycle.
    snapshot = vm.snapshot_full()
    restored_vm = microvm_factory.build()
    restored_vm.spawn()
    restored_vm.restore_from_snapshot(snapshot, resume=True)
    _check_cpu_features_arm(restored_vm, guest_kv, "v1n1")


@pytest.mark.skipif(
    PLATFORM != "aarch64",
    reason="This is aarch64 specific test.",
)
def test_cpu_features_with_custom_template(
    microvm_factory, guest_kernel, rootfs, custom_cpu_template
):
    """
    Check the CPU features for a microvm with the specified config.
    """

    vm = microvm_factory.build(guest_kernel, rootfs, monitor_memory=False)
    vm.spawn()
    vm.basic_config()
    vm.api.cpu_config.put(**custom_cpu_template["template"])
    vm.add_net_iface()
    vm.start()
    guest_kv = re.search(r"vmlinux-(\d+\.\d+)", guest_kernel.name).group(1)
    _check_cpu_features_arm(vm, guest_kv, custom_cpu_template["name"])

    # Check that cpu features are still correct
    # after snap/restore cycle.
    snapshot = vm.snapshot_full()
    restored_vm = microvm_factory.build()
    restored_vm.spawn()
    restored_vm.restore_from_snapshot(snapshot, resume=True)
    _check_cpu_features_arm(restored_vm, guest_kv, custom_cpu_template["name"])
