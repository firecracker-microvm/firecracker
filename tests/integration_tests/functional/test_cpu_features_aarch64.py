# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CPU features for aarch64."""

import platform
import re

import pytest

import framework.utils_cpuid as cpuid_utils
from framework.utils_cpu_templates import nonci_on_arm

PLATFORM = platform.machine()

DEFAULT_G2_FEATURES = (
    "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
    "asimdhp cpuid asimdrdm lrcpc dcpop asimddp ssbs"
)

DEFAULT_G2_FEATURES_NO_SSBS = (
    "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
    "asimdhp cpuid asimdrdm lrcpc dcpop asimddp"
)

DEFAULT_G3_FEATURES_4_14 = (
    "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
    "asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp "
    "sha512 asimdfhm dit uscat ilrcpc flagm ssbs"
)

DEFAULT_G3_FEATURES_5_10 = (
    "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
    "asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp "
    "sha512 asimdfhm dit uscat ilrcpc flagm ssbs dcpodp i8mm bf16 dgh rng"
)

DEFAULT_G3_FEATURES_NO_SSBS_4_14 = (
    "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
    "asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp "
    "sha512 asimdfhm dit uscat ilrcpc flagm dcpodp i8mm bf16 dgh rng"
)

DEFAULT_G3_FEATURES_WITH_SVE_AND_PAC_4_14 = (
    "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
    "asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp "
    "sha512 asimdfhm dit uscat ilrcpc flagm ssbs"
)

DEFAULT_G3_FEATURES_NO_SSBS_4_14 = (
    "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
    "asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp "
    "sha512 asimdfhm dit uscat ilrcpc flagm"
)

DEFAULT_G3_FEATURES_NO_SSBS_5_10 = (
    "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
    "asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp "
    "sha512 asimdfhm dit uscat ilrcpc flagm dcpodp i8mm bf16 dgh rng"
)

DEFAULT_G3_FEATURES_WITH_SVE_AND_PAC_5_10 = (
    "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
    "asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp "
    "sha512 sve asimdfhm dit uscat ilrcpc flagm ssbs paca pacg dcpodp svei8mm svebf16 i8mm bf16 dgh rng"
)

DEFAULT_G3_FEATURES_V1N1 = (
    "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
    "asimdhp cpuid asimdrdm lrcpc dcpop asimddp ssbs"
)


def _check_cpu_features_arm(test_microvm, guest_kv, template_name=None):
    expected_cpu_features = {"Flags": []}
    match (cpuid_utils.get_instance_type(), guest_kv, template_name):
        case ("m6g.metal", _, "aarch64_remove_ssbs"):
            expected_cpu_features["Flags"] = DEFAULT_G2_FEATURES_NO_SSBS
        case ("m6g.metal", _, "aarch64_v1n1"):
            expected_cpu_features["Flags"] = DEFAULT_G2_FEATURES
        case ("m6g.metal", _, None):
            expected_cpu_features["Flags"] = DEFAULT_G2_FEATURES
        case ("c7g.metal", "4.14", "aarch64_remove_ssbs"):
            expected_cpu_features["Flags"] = DEFAULT_G3_FEATURES_NO_SSBS_4_14
        case ("c7g.metal", "5.10", "aarch64_remove_ssbs"):
            expected_cpu_features["Flags"] = DEFAULT_G3_FEATURES_NO_SSBS_5_10
        case ("c7g.metal", "4.14", "aarch64_with_sve_and_pac"):
            expected_cpu_features["Flags"] = DEFAULT_G3_FEATURES_WITH_SVE_AND_PAC_4_14
        case ("c7g.metal", "5.10", "aarch64_with_sve_and_pac"):
            expected_cpu_features["Flags"] = DEFAULT_G3_FEATURES_WITH_SVE_AND_PAC_5_10
        case ("c7g.metal", _, "aarch64_v1n1"):
            expected_cpu_features["Flags"] = DEFAULT_G3_FEATURES_V1N1
        case ("c7g.metal", "4.14", None):
            expected_cpu_features["Flags"] = DEFAULT_G3_FEATURES_4_14
        case ("c7g.metal", "5.10", None):
            expected_cpu_features["Flags"] = DEFAULT_G3_FEATURES_5_10

    cpuid_utils.check_guest_cpuid_output(
        test_microvm, "lscpu", None, ":", expected_cpu_features
    )


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
@nonci_on_arm
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
    _check_cpu_features_arm(vm, guest_kv, "aarch64_v1n1")


@pytest.mark.skipif(
    PLATFORM != "aarch64",
    reason="This is aarch64 specific test.",
)
@nonci_on_arm
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
