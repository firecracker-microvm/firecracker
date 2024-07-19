# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that verify the cpu-template-helper's behavior."""

import json
import platform
from pathlib import Path

import pytest

from framework import utils
from framework.defs import SUPPORTED_HOST_KERNELS
from framework.properties import global_props
from framework.utils_cpuid import get_guest_cpuid
from host_tools import cargo_build

PLATFORM = platform.machine()
TEST_RESOURCES_DIR = Path("./data/cpu_template_helper")


class CpuTemplateHelper:
    """
    Class for CPU template helper tool.
    """

    # Class constants
    BINARY_NAME = "cpu-template-helper"

    def __init__(self):
        """Build CPU template helper tool binary"""
        self.binary = cargo_build.get_binary(self.BINARY_NAME)

    def template_dump(self, output_path):
        """Dump guest CPU config in the JSON custom CPU template format"""
        cmd = f"{self.binary} template dump --output {output_path}"
        utils.check_output(cmd)

    def template_strip(self, paths, suffix=""):
        """Strip entries shared between multiple CPU template files"""
        paths = " ".join([str(path) for path in paths])
        cmd = f"{self.binary} template strip --paths {paths} --suffix '{suffix}'"
        utils.check_output(cmd)

    def template_verify(self, template_path):
        """Verify the specified CPU template"""
        cmd = f"{self.binary} template verify --template {template_path}"
        utils.check_output(cmd)

    def fingerprint_dump(self, output_path):
        """Dump a fingerprint"""
        cmd = f"{self.binary} fingerprint dump --output {output_path}"
        utils.check_output(cmd)

    def fingerprint_compare(
        self,
        prev_path,
        curr_path,
        filters,
    ):
        """Compare two fingerprint files"""
        cmd = (
            f"{self.binary} fingerprint compare"
            f" --prev {prev_path} --curr {curr_path}"
        )
        if filters:
            cmd += f" --filters {' '.join(filters)}"
        utils.check_output(cmd)


@pytest.fixture(scope="session", name="cpu_template_helper")
def cpu_template_helper_fixture():
    """Fixture of CPU template helper tool"""
    return CpuTemplateHelper()


def build_cpu_config_dict(cpu_config_path):
    """Build a dictionary from JSON CPU config file."""
    cpu_config_dict = {
        "cpuid": {},
        "msrs": {},
    }

    cpu_config_json = json.loads(cpu_config_path.read_text(encoding="utf-8"))
    # CPUID
    for leaf_modifier in cpu_config_json["cpuid_modifiers"]:
        for register_modifier in leaf_modifier["modifiers"]:
            cpu_config_dict["cpuid"][
                (
                    int(leaf_modifier["leaf"], 16),
                    int(leaf_modifier["subleaf"], 16),
                    register_modifier["register"],
                )
            ] = int(register_modifier["bitmap"], 2)
    # MSR
    for msr_modifier in cpu_config_json["msr_modifiers"]:
        cpu_config_dict["msrs"][int(msr_modifier["addr"], 16)] = int(
            msr_modifier["bitmap"], 2
        )

    return cpu_config_dict


# List of CPUID leaves / subleaves that are not enumerated in
# KVM_GET_SUPPORTED_CPUID on Intel and AMD.
UNAVAILABLE_CPUID_ON_DUMP_LIST = [
    # KVM changed to not return the host's processor topology information on
    # CPUID.Bh in the following commit (backported into kernel 5.10 and 6.1,
    # but not into kernel 4.14 due to merge conflict), since it's confusing
    # and the userspace VMM has to populate it with meaningful values.
    # https://github.com/torvalds/linux/commit/45e966fcca03ecdcccac7cb236e16eea38cc18af
    # Since Firecracker only populates subleaves 0 and 1 (thread level and core
    # level) in the normalization process and the subleaf 2 is left empty or
    # not listed, the subleaf 2 should be skipped when the userspace cpuid
    # enumerates it.
    (0xB, 0x2),
    # On CPUID.12h, the subleaves 0 and 1 enumerate Intel SGX capability and
    # attributes respectively, and subleaves 2 or higher enumerate Intel SGX
    # EPC that is listed only when CPUID.07h:EBX[2] is 1, meaning that SGX is
    # supported. However, as seen in CPU config baseline files, CPUID.07h:EBX[2]
    # is 0 on all tested platforms. On the other hand, the userspace cpuid
    # command enumerates subleaves up to 2 regardless of CPUID.07h:EBX[2].
    # KVM_GET_SUPPORTED_CPUID returns 0 in CPUID.12h.0 and firecracker passes
    # it as it is, so here we ignore subleaves 1 and 2.
    (0x12, 0x1),
    (0x12, 0x2),
    # CPUID.18h enumerates deterministic address translation parameters and the
    # subleaf 0 reports the maximum supported subleaf in EAX, and all the tested
    # platforms reports 0 in EAX. However, the userspace cpuid command in ubuntu
    # 22 also lists the subleaf 1.
    (0x18, 0x1),
    # CPUID.1Bh enumerates PCONFIG information. The availability of PCONFIG is
    # enumerated in CPUID.7h.0:EDX[18]. While all the supported platforms don't
    # support it, the userspace cpuid command in ubuntu 22 reports not only
    # the subleaf 0 but also the subleaf 1.
    (0x1B, 0x1),
    # CPUID.20000000h is not documented in Intel SDM and AMD APM. KVM doesn't
    # report it, but the userspace cpuid command in ubuntu 22 does.
    (0x20000000, 0x0),
    # CPUID.40000100h is Xen-specific leaf.
    # https://xenbits.xen.org/docs/4.6-testing/hypercall/x86_64/include,public,arch-x86,cpuid.h.html
    (0x40000100, 0x0),
    # CPUID.8000001Bh or later are not supported on kernel 4.14 with an
    # exception CPUID.8000001Dh and CPUID.8000001Eh normalized by firecracker.
    # https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/x86/kvm/cpuid.c?h=v4.14.313#n637
    # On kernel 4.16 or later, these leaves are supported.
    # https://github.com/torvalds/linux/commit/8765d75329a386dd7742f94a1ea5fdcdea8d93d0
    (0x8000001B, 0x0),
    (0x8000001C, 0x0),
    (0x8000001F, 0x0),
    # CPUID.80860000h is a Transmeta-specific leaf.
    (0x80860000, 0x0),
    # CPUID.C0000000h is a Centaur-specific leaf.
    (0xC0000000, 0x0),
]


# Dictionary of CPUID bitmasks that should not be tested due to its mutability.
CPUID_EXCEPTION_LIST = {
    # CPUID.01h:ECX[OSXSAVE (bit 27)] is linked to CR4[OSXSAVE (bit 18)] that
    # can be updated by guest OS.
    # https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/x86/kvm/x86.c?h=v5.10.176#n9872
    (0x1, 0x0, "ecx"): 1 << 27,
    # CPUID.07h:ECX[OSPKE (bit 4)] is linked to CR4[PKE (bit 22)] that can be
    # updated by guest OS.
    # https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/x86/kvm/x86.c?h=v5.10.176#n9872
    (0x7, 0x0, "ecx"): 1 << 4,
    # CPUID.0Dh:EBX is variable depending on XCR0 that can be updated by guest
    # OS with XSETBV instruction.
    # https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/x86/kvm/x86.c?h=v5.10.176#n973
    (0xD, 0x0, "ebx"): 0xFFFF_FFFF,
    (0xD, 0x1, "ebx"): 0xFFFF_FFFF,
}


# List of MSR indices that should not be tested due to its mutability.
MSR_EXCEPTION_LIST = [
    # MSR_KVM_WALL_CLOCK and MSR_KVM_SYSTEM_TIME depend on the elapsed time.
    0x11,
    0x12,
    # MSR_IA32_FEAT_CTL and MSR_IA32_SPEC_CTRL are R/W MSRs that can be
    # modified by OS to control features.
    0x3A,
    0x48,
    # MSR_IA32_SMBASE is not accessible outside of System Management Mode.
    0x9E,
    # MSR_IA32_TSX_CTRL is R/W MSR to disable Intel TSX feature as a mitigation
    # against TAA vulnerability.
    0x122,
    # MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP and MSR_IA32_SYSENTER_EIP are
    # R/W MSRs that will be set up by OS to call fast system calls with
    # SYSENTER.
    0x174,
    0x175,
    0x176,
    # MSR_IA32_TSC_DEADLINE specifies the time at which a timer interrupt
    # should occur and depends on the elapsed time.
    0x6E0,
    # MSR_KVM_SYSTEM_TIME_NEW and MSR_KVM_WALL_CLOCK_NEW depend on the elapsed
    # time.
    0x4B564D00,
    0x4B564D01,
    # MSR_KVM_ASYNC_PF_EN is an asynchronous page fault (APF) control MSR and
    # is intialized in VM setup process.
    0x4B564D02,
    # MSR_KVM_STEAL_TIME indicates CPU steal time filled in by the hypervisor
    # periodically.
    0x4B564D03,
    # MSR_KVM_PV_EOI_EN is PV End Of Interrupt (EOI) MSR and is initialized in
    # VM setup process.
    0x4B564D04,
    # MSR_KVM_ASYNC_PF_INT is an interrupt vector for delivery of 'page ready'
    # APF events and is initialized just before MSR_KVM_ASYNC_PF_EN.
    0x4B564D06,
    # MSR_STAR, MSR_LSTAR, MSR_CSTAR and MSR_SYSCALL_MASK are R/W MSRs that
    # will be set up by OS to call fast system calls with SYSCALL.
    0xC0000081,
    0xC0000082,
    0xC0000083,
    0xC0000084,
    # MSR_AMD64_VIRT_SPEC_CTRL is R/W and can be modified by OS to control
    # security features for speculative attacks.
    0xC001011F,
]


def get_guest_msrs(microvm, msr_index_list):
    """
    Return the guest MSR in the form of a dictionary where the key is a MSR
    index and the value is the register value.
    """
    msrs_dict = {}

    for index in msr_index_list:
        if index in MSR_EXCEPTION_LIST:
            continue
        rdmsr_cmd = f"rdmsr -0 {index}"
        code, stdout, stderr = microvm.ssh.run(rdmsr_cmd)
        assert stderr == "", f"Failed to get MSR for {index=:#x}: {code=}"
        msrs_dict[index] = int(stdout, 16)

    return msrs_dict


@pytest.mark.skipif(
    PLATFORM != "x86_64",
    reason=(
        "`cpuid` and `rdmsr` commands are only available on x86_64. "
        "System registers are not accessible on aarch64."
    ),
)
def test_cpu_config_dump_vs_actual(
    microvm_factory,
    guest_kernel,
    rootfs,
    cpu_template_helper,
    tmp_path,
):
    """
    Verify that the dumped CPU config matches the actual CPU config inside
    guest.
    """
    # Dump CPU config with the helper tool.
    cpu_config_path = tmp_path / "cpu_config.json"
    cpu_template_helper.template_dump(cpu_config_path)
    dump_cpu_config = build_cpu_config_dict(cpu_config_path)

    # Retrieve actual CPU config from guest
    microvm = microvm_factory.build(guest_kernel, rootfs)
    microvm.spawn()
    microvm.basic_config(vcpu_count=1)
    microvm.add_net_iface()
    microvm.start()
    actual_cpu_config = {
        "cpuid": get_guest_cpuid(microvm),
        "msrs": get_guest_msrs(microvm, dump_cpu_config["msrs"].keys()),
    }

    # Compare CPUID between actual and dumped CPU config.
    # Verify all the actual CPUIDs are covered and match with the dumped one.
    keys_not_in_dump = {}
    for key, actual in actual_cpu_config["cpuid"].items():
        if (key[0], key[1]) in UNAVAILABLE_CPUID_ON_DUMP_LIST:
            continue
        if key not in dump_cpu_config["cpuid"]:
            keys_not_in_dump[key] = actual_cpu_config["cpuid"][key]
            continue
        dump = dump_cpu_config["cpuid"][key]

        if key in CPUID_EXCEPTION_LIST:
            actual &= ~CPUID_EXCEPTION_LIST[key]
            dump &= ~CPUID_EXCEPTION_LIST[key]
        assert actual == dump, (
            f"Mismatched CPUID for leaf={key[0]:#x} subleaf={key[1]:#x} reg={key[2]}:"
            f"{actual=:#034b} vs. {dump=:#034b}"
        )

    assert len(keys_not_in_dump) == 0

    # Verify all CPUID on the dumped CPU config are covered in actual one.
    for key, dump in dump_cpu_config["cpuid"].items():
        actual = actual_cpu_config["cpuid"].get(key)
        # `cpuid -r` command does not list up invalid leaves / subleaves
        # without specifying them.
        if actual is None:
            actual = get_guest_cpuid(microvm, key[0], key[1])[key]

        if key in CPUID_EXCEPTION_LIST:
            actual &= ~CPUID_EXCEPTION_LIST[key]
            dump &= ~CPUID_EXCEPTION_LIST[key]
        assert actual == dump, (
            f"Mismatched CPUID for leaf={key[0]:#x} subleaf={key[1]:#x} reg={key[2]}:"
            f"{actual=:#034b} vs. {dump=:#034b}"
        )

    # Compare MSR between actual and dumped CPU config.
    for key in dump_cpu_config["msrs"]:
        if key in MSR_EXCEPTION_LIST:
            continue
        actual = actual_cpu_config["msrs"][key]
        dump = dump_cpu_config["msrs"][key]
        assert (
            actual == dump
        ), f"Mismatched MSR for {key:#010x}: {actual=:#066b} vs. {dump=:#066b}"


@pytest.mark.no_block_pr
@pytest.mark.skipif(
    global_props.host_linux_version not in SUPPORTED_HOST_KERNELS,
    reason=f"Supported kernels are {SUPPORTED_HOST_KERNELS}",
)
def test_guest_cpu_config_change(results_dir, cpu_template_helper):
    """
    Verify that the guest CPU config has not changed since the baseline
    fingerprint was gathered.
    """
    fname = f"fingerprint_{global_props.cpu_codename}_{global_props.host_linux_version}host.json"

    # Dump a fingerprint with the generated VM config.
    fingerprint_path = results_dir / fname
    cpu_template_helper.fingerprint_dump(fingerprint_path)

    # Baseline fingerprint.
    baseline_path = TEST_RESOURCES_DIR / fname

    # Compare with baseline
    cpu_template_helper.fingerprint_compare(
        baseline_path,
        fingerprint_path,
        ["guest_cpu_config"],
    )


def test_json_static_templates(cpu_template_helper, tmp_path, custom_cpu_template):
    """
    Verify that JSON static CPU templates are applied as intended.
    """
    custom_cpu_template_path = tmp_path / "template.json"
    Path(custom_cpu_template_path).write_text(
        json.dumps(custom_cpu_template["template"]), encoding="utf-8"
    )

    # Verify the JSON static CPU template.
    cpu_template_helper.template_verify(custom_cpu_template_path)


def test_consecutive_fingerprint_consistency(cpu_template_helper, tmp_path):
    """
    Verify that two fingerprints obtained consecutively are consistent.
    """
    # Dump a fingerprint with the helper tool.
    fp1 = tmp_path / "fp1.json"
    cpu_template_helper.fingerprint_dump(fp1)
    fp2 = tmp_path / "fp2.json"
    cpu_template_helper.fingerprint_dump(fp2)

    # Compare them.
    cpu_template_helper.fingerprint_compare(fp1, fp2, None)
