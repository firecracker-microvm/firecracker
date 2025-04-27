# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-statements
# pylint: disable=too-many-branches

"""
Check CPU features in the host vs the guest.

This test can highlight differences between the host and what the guest sees.

No CPU templates as we are interested only on what is passed through to the guest by default.
For that, check test_feat_parity.py
"""

import os

from framework import utils
from framework.properties import global_props
from framework.utils_cpuid import CPU_FEATURES_CMD, CpuModel

CPU_MODEL = global_props.cpu_codename

INTEL_HOST_ONLY_FEATS = {
    "acpi",
    "aperfmperf",
    "arch_perfmon",
    "art",
    "bts",
    "cat_l3",
    "cdp_l3",
    "cqm",
    "cqm_llc",
    "cqm_mbm_local",
    "cqm_mbm_total",
    "cqm_occup_llc",
    "dca",
    "ds_cpl",
    "dtes64",
    "dtherm",
    "dts",
    "epb",
    "ept",
    "ept_ad",
    "est",
    "flexpriority",
    "flush_l1d",
    "hwp",
    "hwp_act_window",
    "hwp_epp",
    "hwp_pkg_req",
    "ida",
    "intel_ppin",
    "intel_pt",
    "mba",
    "monitor",
    "pbe",
    "pdcm",
    "pebs",
    "pln",
    "pts",
    "rdt_a",
    "sdbg",
    "smx",
    "tm",
    "tm2",
    "tpr_shadow",
    "vmx",
    "vnmi",
    "vpid",
    "xtpr",
}

INTEL_GUEST_ONLY_FEATS = {
    "hypervisor",
    "tsc_known_freq",
    "umip",
}

AMD_MILAN_HOST_ONLY_FEATS = {
    "amd_ppin",
    "aperfmperf",
    "bpext",
    "cat_l3",
    "cdp_l3",
    "cpb",
    "cqm",
    "cqm_llc",
    "cqm_mbm_local",
    "cqm_mbm_total",
    "cqm_occup_llc",
    "decodeassists",
    "extapic",
    "extd_apicid",
    "flushbyasid",
    "hw_pstate",
    "ibs",
    "irperf",
    "lbrv",
    "mba",
    "monitor",
    "mwaitx",
    "overflow_recov",
    "pausefilter",
    "perfctr_llc",
    "perfctr_nb",
    "pfthreshold",
    "rdpru",
    "rdt_a",
    "sev",
    "sev_es",
    "skinit",
    "smca",
    "sme",
    "succor",
    "svm_lock",
    "tce",
    "tsc_scale",
    "v_vmsave_vmload",
    "vgif",
    "vmcb_clean",
    "wdt",
}

AMD_GUEST_ONLY_FEATS = {
    "hypervisor",
    "tsc_adjust",
    "tsc_deadline_timer",
    "tsc_known_freq",
}

AMD_MILAN_HOST_ONLY_FEATS_6_1 = AMD_MILAN_HOST_ONLY_FEATS - {
    "lbrv",
    "pausefilter",
    "pfthreshold",
    "sme",
    "tsc_scale",
    "v_vmsave_vmload",
    "vgif",
    "vmcb_clean",
} | {"brs", "rapl", "v_spec_ctrl"}

AMD_GENOA_HOST_ONLY_FEATS = AMD_MILAN_HOST_ONLY_FEATS | {
    "avic",
    "flush_l1d",
    "ibrs_enhanced",
}

AMD_GENOA_HOST_ONLY_FEATS_6_1 = AMD_MILAN_HOST_ONLY_FEATS_6_1 - {"brs"} | {
    "avic",
    "amd_lbr_v2",
    "cppc",
    "flush_l1d",
    "ibrs_enhanced",
    "perfmon_v2",
    "x2avic",
}


def test_host_vs_guest_cpu_features(uvm_plain_any):
    """Check CPU features host vs guest"""

    vm = uvm_plain_any
    vm.spawn()
    vm.basic_config()
    vm.add_net_iface()
    vm.start()
    host_feats = set(utils.check_output(CPU_FEATURES_CMD).stdout.split())
    guest_feats = set(vm.ssh.check_output(CPU_FEATURES_CMD).stdout.split())

    match CPU_MODEL:
        case CpuModel.AMD_MILAN:
            if global_props.host_linux_version_tpl < (6, 1):
                assert host_feats - guest_feats == AMD_MILAN_HOST_ONLY_FEATS
            else:
                assert host_feats - guest_feats == AMD_MILAN_HOST_ONLY_FEATS_6_1

            assert guest_feats - host_feats == AMD_GUEST_ONLY_FEATS

        case CpuModel.AMD_GENOA:
            if global_props.host_linux_version_tpl < (6, 1):
                assert host_feats - guest_feats == AMD_GENOA_HOST_ONLY_FEATS
            else:
                assert host_feats - guest_feats == AMD_GENOA_HOST_ONLY_FEATS_6_1

            assert guest_feats - host_feats == AMD_GUEST_ONLY_FEATS

        case CpuModel.INTEL_SKYLAKE:
            assert host_feats - guest_feats == INTEL_HOST_ONLY_FEATS
            assert guest_feats - host_feats == INTEL_GUEST_ONLY_FEATS

        case CpuModel.INTEL_CASCADELAKE:
            expected_host_minus_guest = INTEL_HOST_ONLY_FEATS
            expected_guest_minus_host = INTEL_GUEST_ONLY_FEATS

            # Linux kernel v6.4+ passes through the CPUID bit for "flush_l1d" to guests.
            # https://github.com/torvalds/linux/commit/45cf86f26148e549c5ba4a8ab32a390e4bde216e
            #
            # Our test ubuntu host kernel is v6.8 and has the commit.
            if global_props.host_linux_version_tpl >= (6, 4):
                expected_host_minus_guest -= {"flush_l1d"}

            # Linux kernel v6.6+ drops the "invpcid_single" synthetic feature bit.
            # https://github.com/torvalds/linux/commit/54e3d9434ef61b97fd3263c141b928dc5635e50d
            #
            # Our test ubuntu host kernel is v6.8 and has the commit.
            host_has_invpcid_single = global_props.host_linux_version_tpl < (6, 6)
            guest_has_invpcid_single = vm.guest_kernel_version < (6, 6)
            if host_has_invpcid_single and not guest_has_invpcid_single:
                expected_host_minus_guest |= {"invpcid_single"}
            if not host_has_invpcid_single and guest_has_invpcid_single:
                expected_guest_minus_host |= {"invpcid_single"}

            assert host_feats - guest_feats == expected_host_minus_guest
            assert guest_feats - host_feats == expected_guest_minus_host

        case CpuModel.INTEL_ICELAKE:
            host_guest_diff_5_10 = INTEL_HOST_ONLY_FEATS - {"cdp_l3"} | {
                "pconfig",
                "tme",
                "split_lock_detect",
            }
            host_guest_diff_6_1 = host_guest_diff_5_10 - {
                "bts",
                "dtes64",
                "dts",
                "pebs",
            }

            if global_props.host_linux_version_tpl < (6, 1):
                assert host_feats - guest_feats == host_guest_diff_5_10
            else:
                assert host_feats - guest_feats == host_guest_diff_6_1
            assert guest_feats - host_feats == INTEL_GUEST_ONLY_FEATS - {"umip"}

        case CpuModel.INTEL_SAPPHIRE_RAPIDS:
            expected_host_minus_guest = INTEL_HOST_ONLY_FEATS.copy()
            expected_guest_minus_host = INTEL_GUEST_ONLY_FEATS.copy()

            host_version = global_props.host_linux_version_tpl
            guest_version = vm.guest_kernel_version

            # KVM does not support virtualization of the following hardware features yet for several
            # reasons (e.g. security, simply difficulty of implementation).
            expected_host_minus_guest |= {
                # Intel Total Memory Encryption (TME) is the capability to encrypt the entirety of
                # physical memory of a system. TME is enabled by system BIOS/hardware and applies to
                # the phyiscal memory as a whole.
                "tme",
                # PCONFIG instruction allows software to configure certain platform features. It
                # supports these features with multiple leaf functions, selecting a leaf function
                # using the value in EAX. As of this writing, the only defined PCONFIG leaf function
                # is for key programming for total memory encryption-multi-key (TME-MK).
                "pconfig",
                # Architectural Last Branch Record (Arch LBR) that is a feature that logs the most
                # recently executed branch instructions (e.g. source and destination addresses).
                # Traditional LBR implementations have existed in Intel CPUs for years and the MSR
                # interface varied by CPU model. Arch LBR is a standardized version. There is a
                # kernel patch created in 2022 but didn't get merged due to a mess.
                # https://lore.kernel.org/all/20221125040604.5051-1-weijiang.yang@intel.com/
                "arch_lbr",
                # ENQCMD/ENQCMDS are instructions that allow software to atomically write 64-byte
                # commands to enqueue registers, which are special device registers accessed using
                # memory-mapped I/O.
                "enqcmd",
                # Intel Resource Director Technology (RDT) feature set provides a set of allocation
                # (resource control) capabilities including Cache Allocation Technology (CAT) and
                # Code and Data Prioritization (CDP).
                # L3 variants are listed in INTEL_HOST_ONLY_FEATS.
                "cat_l2",
                "cdp_l2",
                # This is a synthesized bit for split lock detection that raise an Alignment Check
                # (#AC) exception if an operand of an atomic operation crosses two cache lines. It
                # is not enumerated on CPUID, instead detected by actually attempting to read from
                # MSR address 0x33 (MSR_MEMORY_CTRL in Intel SDM, MSR_TEST_CTRL in Linux kernel).
                "split_lock_detect",
                # Firecracker disables WAITPKG in CPUID normalization.
                # https://github.com/firecracker-microvm/firecracker/pull/5118
                "waitpkg",
            }

            # The following features are also not virtualized by KVM yet but are only supported on
            # newer kernel versions.
            if host_version >= (5, 18):
                expected_host_minus_guest |= {
                    # Hardware Feedback Interface (HFI) is a feature that gives OSes a performance
                    # and energy efficiency capability data for each CPU that can be used to
                    # influence task placement decisions.
                    # https://github.com/torvalds/linux/commit/7b8f40b3de75c971a4e5f9308b06deb59118dbac
                    "hfi",
                    # Indirect Brach Tracking (IBT) is a feature where the CPU ensures that indirect
                    # branch targets start with ENDBRANCH instruction (`endbr32` or `endbr64`),
                    # which executes as a no-op; if anything else is found, a control-protection
                    # (#CP) fault will be raised.
                    # https://github.com/torvalds/linux/commit/991625f3dd2cbc4b787deb0213e2bcf8fa264b21
                    "ibt",
                }

            # AVX512 FP16 is supported and passed through on v5.11+.
            # https://github.com/torvalds/linux/commit/e1b35da5e624f8b09d2e98845c2e4c84b179d9a4
            # https://github.com/torvalds/linux/commit/2224fc9efb2d6593fbfb57287e39ba4958b188ba
            if host_version >= (5, 11) and guest_version < (5, 11):
                expected_host_minus_guest |= {"avx512_fp16"}

            # AVX VNNI support is supported and passed through on v5.12+.
            # https://github.com/torvalds/linux/commit/b85a0425d8056f3bd8d0a94ecdddf2a39d32a801
            # https://github.com/torvalds/linux/commit/1085a6b585d7d1c441cd10fdb4c7a4d96a22eba7
            if host_version >= (5, 12) and guest_version < (5, 12):
                expected_host_minus_guest |= {"avx_vnni"}

            # Bus lock detection is supported on v5.12+ and passed through on v5.13+.
            # https://github.com/torvalds/linux/commit/f21d4d3b97a8603567e5d4250bd75e8ebbd520af
            # https://github.com/torvalds/linux/commit/76ea438b4afcd9ee8da3387e9af4625eaccff58f
            if host_version >= (5, 13) and guest_version < (5, 12):
                expected_host_minus_guest |= {"bus_lock_detect"}

            # Intel AMX is supported and passed through on v5.17+.
            # https://github.com/torvalds/linux/commit/690a757d610e50c2c3acd2e4bc3992cfc63feff2
            if host_version >= (5, 17) and guest_version < (5, 17):
                expected_host_minus_guest |= {"amx_bf16", "amx_int8", "amx_tile"}

            expected_guest_minus_host -= {
                # UMIP can be emulated by KVM on Intel processors, but is supported in hardware on
                # Intel Sapphire Rapids and passed through.
                "umip",
                # This is a synthesized bit and it is always set on guest thanks to kvm-clock. But
                # Intel Sapphire Rapids reports TSC frequency on CPUID leaf 0x15, so the bit is also
                # set on host.
                "tsc_known_freq",
            }

            assert host_feats - guest_feats == expected_host_minus_guest
            assert guest_feats - host_feats == expected_guest_minus_host

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

        case CpuModel.ARM_NEOVERSE_V1 | CpuModel.ARM_NEOVERSE_V2:
            expected_guest_minus_host = set()
            # KVM does not enable PAC or SVE features by default
            # and Firecracker does not enable them either.
            expected_host_minus_guest = {"paca", "pacg", "sve", "svebf16", "svei8mm"}

            if CPU_MODEL == CpuModel.ARM_NEOVERSE_V2:
                expected_host_minus_guest |= {
                    "svebitperm",
                    "svesha3",
                    "sveaes",
                    "sve2",
                    "svepmull",
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
            # only fail if running in CI
            if os.environ.get("BUILDKITE") is not None:
                assert (
                    guest_feats == host_feats
                ), f"Cpu model {CPU_MODEL} is not supported"
