# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CPU features for aarch64."""

import platform
import re

import pytest

import framework.utils_cpuid as cpuid_utils
from framework.utils_cpuid import CpuModel

PLATFORM = platform.machine()

DEFAULT_G2_FEATURES = set(
    (
        "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
        "asimdhp cpuid asimdrdm lrcpc dcpop asimddp ssbs"
    ).split(" ")
)

DEFAULT_G3_FEATURES_4_14 = DEFAULT_G2_FEATURES | set(
    "sha512 asimdfhm dit uscat ilrcpc flagm jscvt fcma sha3 sm3 sm4 rng".split(" ")
)

DEFAULT_G3_FEATURES_5_10 = DEFAULT_G3_FEATURES_4_14 | set(
    "dcpodp i8mm bf16 dgh".split(" ")
)

DEFAULT_G3_FEATURES_WITH_SVE_AND_PAC_4_14 = DEFAULT_G3_FEATURES_4_14
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
        case CpuModel.ARM_NEOVERSE_V1, "4.14", "aarch64_with_sve_and_pac":
            expected_cpu_features = DEFAULT_G3_FEATURES_WITH_SVE_AND_PAC_4_14
        case CpuModel.ARM_NEOVERSE_V1, "4.14", None:
            expected_cpu_features = DEFAULT_G3_FEATURES_4_14

        # [cm]7g with guest kernel 5.10 and later
        case CpuModel.ARM_NEOVERSE_V1, _, "v1n1":
            expected_cpu_features = DEFAULT_G3_FEATURES_V1N1
        case CpuModel.ARM_NEOVERSE_V1, _, "aarch64_with_sve_and_pac":
            expected_cpu_features = DEFAULT_G3_FEATURES_WITH_SVE_AND_PAC_5_10
        case CpuModel.ARM_NEOVERSE_V1, _, None:
            expected_cpu_features = DEFAULT_G3_FEATURES_5_10

    _, stdout, _ = test_microvm.ssh.check_output(r"lscpu |grep -oP '^Flags:\s+\K.+'")
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
def test_default_cpu_features(microvm_factory, guest_kernel, rootfs_ubuntu_22):
    """
    Check the CPU features for a microvm with the specified config.
    """

    vm = microvm_factory.build(guest_kernel, rootfs_ubuntu_22, monitor_memory=False)
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
    microvm_factory, guest_kernel, rootfs_ubuntu_22, cpu_template
):
    """
    Check the CPU features for a microvm with the specified config.
    """

    vm = microvm_factory.build(guest_kernel, rootfs_ubuntu_22, monitor_memory=False)
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
    restored_vm.wait_for_up()
    _check_cpu_features_arm(restored_vm, guest_kv, "v1n1")


@pytest.mark.skipif(
    PLATFORM != "aarch64",
    reason="This is aarch64 specific test.",
)
def test_cpu_features_with_custom_template(
    microvm_factory, guest_kernel, rootfs_ubuntu_22, custom_cpu_template
):
    """
    Check the CPU features for a microvm with the specified config.
    """

    vm = microvm_factory.build(guest_kernel, rootfs_ubuntu_22, monitor_memory=False)
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
    restored_vm.wait_for_up()
    _check_cpu_features_arm(restored_vm, guest_kv, custom_cpu_template["name"])
