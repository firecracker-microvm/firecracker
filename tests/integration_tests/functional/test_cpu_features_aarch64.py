# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CPU features for aarch64."""

import pytest

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

G4_FEATS = (G3_FEATS | set("bti flagm2 frint sb".split())) - set("sm3 sm4".split())

G4_SVE_AND_PAC = set(
    "paca pacg sve sve2 sveaes svebitperm svepmull svesha3 svebf16 svei8mm".split()
)


def test_guest_cpu_features(uvm_any):
    """Check the CPU features for a microvm with different CPU templates"""

    vm = uvm_any
    expected_cpu_features = set()
    match global_props.cpu_model, vm.cpu_template_name:
        case CpuModel.ARM_NEOVERSE_N1, "V1N1":
            expected_cpu_features = G2_FEATS
        case CpuModel.ARM_NEOVERSE_N1, "None":
            expected_cpu_features = G2_FEATS

        # [cm]7g with guest kernel 5.10 and later
        case CpuModel.ARM_NEOVERSE_V1, "V1N1":
            expected_cpu_features = G2_FEATS
        case CpuModel.ARM_NEOVERSE_V1, "AARCH64_WITH_SVE_AND_PAC":
            expected_cpu_features = G3_FEATS | G3_SVE_AND_PAC
        case CpuModel.ARM_NEOVERSE_V1, "None":
            expected_cpu_features = G3_FEATS
        case CpuModel.ARM_NEOVERSE_V2, "None":
            expected_cpu_features = G4_FEATS
        case CpuModel.ARM_NEOVERSE_V2, "AARCH64_WITH_SVE_AND_PAC":
            expected_cpu_features = G4_FEATS | G4_SVE_AND_PAC

    guest_feats = set(vm.ssh.check_output(CPU_FEATURES_CMD).stdout.split())
    assert guest_feats == expected_cpu_features
