# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CPU features for aarch64."""

# pylint: disable=too-many-lines

import platform

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

DEFAULT_G3_FEATURES = (
    "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
    "asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp "
    "sha512 asimdfhm dit uscat ilrcpc flagm ssbs"
)

DEFAULT_G3_FEATURES_NO_SSBS = (
    "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
    "asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp "
    "sha512 asimdfhm dit uscat ilrcpc flagm"
)

DEFAULT_G3_FEATURES_V1N1 = (
    "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp "
    "asimdhp cpuid asimdrdm lrcpc dcpop asimddp ssbs"
)


def _check_cpu_features_arm(test_microvm, template_name=None):
    expected_cpu_features = {"Flags": []}
    match cpuid_utils.get_instance_type():
        case "m6g.metal":
            match template_name:
                case "aarch64_remove_ssbs":
                    expected_cpu_features["Flags"] = DEFAULT_G2_FEATURES_NO_SSBS
                case "aarch64_v1n1":
                    expected_cpu_features["Flags"] = DEFAULT_G2_FEATURES
                case None:
                    expected_cpu_features["Flags"] = DEFAULT_G2_FEATURES
        case "c7g.metal":
            match template_name:
                case "aarch64_remove_ssbs":
                    expected_cpu_features["Flags"] = DEFAULT_G3_FEATURES_NO_SSBS
                case "aarch64_v1n1":
                    expected_cpu_features["Flags"] = DEFAULT_G3_FEATURES_V1N1
                case None:
                    expected_cpu_features["Flags"] = DEFAULT_G3_FEATURES

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
def test_default_cpu_features(test_microvm_with_api, network_config):
    """
    Check the CPU features for a microvm with the specified config.
    """
    vm = test_microvm_with_api
    vm.spawn()
    vm.basic_config()
    _tap, _, _ = vm.ssh_network_config(network_config, "1")
    vm.start()
    _check_cpu_features_arm(vm)


@pytest.mark.skipif(
    PLATFORM != "aarch64",
    reason="This is aarch64 specific test.",
)
@nonci_on_arm
def test_cpu_features_with_static_template(
    test_microvm_with_api, network_config, cpu_template
):
    """
    Check the CPU features for a microvm with the specified config.
    """
    vm = test_microvm_with_api
    vm.spawn()
    vm.basic_config(cpu_template=cpu_template)
    _tap, _, _ = vm.ssh_network_config(network_config, "1")
    vm.start()
    _check_cpu_features_arm(vm, "aarch64_v1n1")


@pytest.mark.skipif(
    PLATFORM != "aarch64",
    reason="This is aarch64 specific test.",
)
@nonci_on_arm
def test_cpu_features_with_custom_template(
    test_microvm_with_api, network_config, custom_cpu_template
):
    """
    Check the CPU features for a microvm with the specified config.
    """
    vm = test_microvm_with_api
    vm.spawn()
    vm.basic_config()
    vm.cpu_config(custom_cpu_template["template"])
    _tap, _, _ = vm.ssh_network_config(network_config, "1")
    vm.start()
    _check_cpu_features_arm(vm, custom_cpu_template["name"])
