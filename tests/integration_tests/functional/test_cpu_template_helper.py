# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that verify the cpu-template-helper's behavior."""

import json
import platform
from pathlib import Path

import pytest

from framework import defs, utils
from framework.defs import SUPPORTED_HOST_KERNELS
from framework.properties import global_props
from framework.utils_cpu_templates import nonci_on_arm
from framework.utils_cpuid import get_guest_cpuid
from host_tools import cargo_build

PLATFORM = platform.machine()
TEST_RESOURCES_DIR = Path(
    f"{defs.FC_WORKSPACE_DIR}/resources/tests/cpu_template_helper/"
)


class CpuTemplateHelper:
    """
    Class for CPU template helper tool.
    """

    # Class constants
    BINARY_NAME = "cpu-template-helper"
    BINARY_PATH = Path(
        f"{defs.FC_WORKSPACE_TARGET_DIR}/"
        f"{cargo_build.DEFAULT_BUILD_TARGET}/"
        f"release/{BINARY_NAME}"
    )

    def __init__(self):
        """Build CPU template helper tool binary"""
        if not self.BINARY_PATH.exists():
            utils.run_cmd(
                f"RUSTFLAGS='{cargo_build.get_rustflags()}' "
                f"cargo build -p {self.BINARY_NAME} --release "
                f"--target {cargo_build.DEFAULT_BUILD_TARGET}",
                cwd=defs.FC_WORKSPACE_DIR,
            )
            utils.run_cmd(
                f"strip --strip-debug {self.BINARY_PATH}",
                cwd=defs.FC_WORKSPACE_DIR,
            )

    def template_dump(self, vm_config_path, output_path):
        """Dump guest CPU config in the JSON custom CPU template format"""
        cmd = (
            f"{self.BINARY_PATH} template dump"
            f" --config {vm_config_path} --output {output_path}"
        )
        utils.run_cmd(cmd)

    def template_strip(self, paths, suffix=""):
        """Strip entries shared between multiple CPU template files"""
        paths = " ".join([str(path) for path in paths])
        cmd = f"{self.BINARY_PATH} template strip --paths {paths} --suffix '{suffix}'"
        utils.run_cmd(cmd)

    def template_verify(self, vm_config_path):
        """Verify the specified CPU template"""
        cmd = f"{self.BINARY_PATH} template verify --config {vm_config_path}"
        utils.run_cmd(cmd)

    def fingerprint_dump(self, vm_config_path, output_path):
        """Dump a fingerprint"""
        cmd = (
            f"{self.BINARY_PATH} fingerprint dump"
            f" --config {vm_config_path} --output {output_path}"
        )
        utils.run_cmd(cmd)

    def fingerprint_compare(
        self,
        prev_path,
        curr_path,
        filters,
    ):
        """Compare two fingerprint files"""
        cmd = (
            f"{self.BINARY_PATH} fingerprint compare"
            f" --prev {prev_path} --curr {curr_path}"
            f" --filters {' '.join(filters)}"
        )
        utils.run_cmd(cmd)


@pytest.fixture(scope="session", name="cpu_template_helper")
def cpu_template_helper_fixture():
    """Fixture of CPU template helper tool"""
    return CpuTemplateHelper()


def save_vm_config(microvm, tmp_path, custom_cpu_template=None):
    """
    Save VM config into JSON file.
    """
    config_json = microvm.full_cfg.get().json()
    config_json["boot-source"]["kernel_image_path"] = str(microvm.kernel_file)
    config_json["drives"][0]["path_on_host"] = str(microvm.rootfs_file)
    if custom_cpu_template is not None:
        custom_cpu_template_path = tmp_path / "template.json"
        Path(custom_cpu_template_path).write_text(
            json.dumps(custom_cpu_template), encoding="utf-8"
        )
        config_json["cpu-config"] = str(custom_cpu_template_path)

    vm_config_path = tmp_path / "vm_config.json"
    Path(vm_config_path).write_text(json.dumps(config_json), encoding="utf-8")
    return vm_config_path


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
        code, stdout, stderr = microvm.ssh.execute_command(rdmsr_cmd)
        assert stderr.read() == "", f"Failed to get MSR for {index=:#x}: {code=}"
        msrs_dict[index] = int(stdout.read(), 16)

    return msrs_dict


@pytest.mark.skipif(
    PLATFORM != "x86_64",
    reason=(
        "`cpuid` and `rdmsr` commands are only available on x86_64. "
        "System registers are not accessible on aarch64."
    ),
)
@nonci_on_arm
def test_cpu_config_dump_vs_actual(
    test_microvm_with_api_and_msrtools,
    cpu_template_helper,
    network_config,
    tmp_path,
):
    """
    Verify that the dumped CPU config matches the actual CPU config inside
    guest.
    """
    microvm = test_microvm_with_api_and_msrtools
    microvm.spawn()
    microvm.basic_config()
    microvm.ssh_network_config(network_config, "1")
    vm_config_path = save_vm_config(microvm, tmp_path)

    # Dump CPU config with the helper tool.
    cpu_config_path = tmp_path / "cpu_config.json"
    cpu_template_helper.template_dump(vm_config_path, cpu_config_path)
    dump_cpu_config = build_cpu_config_dict(cpu_config_path)

    # Retrieve actual CPU config from guest
    microvm.start()
    actual_cpu_config = {
        "cpuid": get_guest_cpuid(microvm),
        "msrs": get_guest_msrs(microvm, dump_cpu_config["msrs"].keys()),
    }

    # Compare CPUID between actual and dumped CPU config.
    # Verify all the actual CPUIDs are covered and match with the dumped one.
    for key, actual in actual_cpu_config["cpuid"].items():
        if (key[0], key[1]) in UNAVAILABLE_CPUID_ON_DUMP_LIST:
            continue
        dump = dump_cpu_config["cpuid"][key]

        if key in CPUID_EXCEPTION_LIST:
            actual &= ~CPUID_EXCEPTION_LIST[key]
            dump &= ~CPUID_EXCEPTION_LIST[key]
        assert actual == dump, (
            f"Mismatched CPUID for leaf={key[0]:#x} subleaf={key[1]:#x} reg={key[2]}:"
            f"{actual=:#034b} vs. {dump=:#034b}"
        )

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


def detect_fingerprint_change(microvm, tmp_path, cpu_template_helper, filters):
    """
    Compare fingerprint files with filters between one taken at the moment and
    a baseline file taken in a specific point in time.
    """
    # Generate VM config from test_microvm_with_api
    microvm.spawn()
    microvm.basic_config()
    vm_config_path = save_vm_config(microvm, tmp_path)

    # Dump a fingerprint with the generated VM config.
    fingerprint_path = tmp_path / "fingerprint.json"
    cpu_template_helper.fingerprint_dump(vm_config_path, fingerprint_path)

    # Baseline fingerprint.
    baseline_path = Path(
        f"{TEST_RESOURCES_DIR}/"
        f"fingerprint_{global_props.cpu_codename}_{global_props.host_linux_version}host.json"
    )
    # Use this code to generate baseline fingerprint.
    # cpu_template_helper.fingerprint_dump(vm_config_path, baseline_path)

    # Compare with baseline
    cpu_template_helper.fingerprint_compare(
        baseline_path,
        fingerprint_path,
        filters,
    )


@pytest.mark.skipif(
    utils.get_kernel_version(level=1) not in SUPPORTED_HOST_KERNELS,
    reason=f"Supported kernels are {SUPPORTED_HOST_KERNELS}",
)
def test_guest_cpu_config_change(test_microvm_with_api, tmp_path, cpu_template_helper):
    """
    Verify that the guest CPU config has not changed since the baseline
    fingerprint was gathered.
    """
    detect_fingerprint_change(
        test_microvm_with_api,
        tmp_path,
        cpu_template_helper,
        ["guest_cpu_config"],
    )


@pytest.mark.nonci
def test_host_fingerprint_change(test_microvm_with_api, tmp_path, cpu_template_helper):
    """
    Verify that the host fingerprint has not changed since the baseline
    fingerprint was gathered.
    """
    detect_fingerprint_change(
        test_microvm_with_api,
        tmp_path,
        cpu_template_helper,
        [
            "kernel_version",
            "microcode_version",
            "bios_version",
            "bios_revision",
        ],
    )


@nonci_on_arm
def test_json_static_templates(
    test_microvm_with_api, cpu_template_helper, tmp_path, custom_cpu_template
):
    """
    Verify that JSON static CPU templates are applied as intended.
    """
    # Generate VM config with JSON static CPU template
    microvm = test_microvm_with_api
    microvm.spawn()
    microvm.basic_config()
    vm_config_path = save_vm_config(microvm, tmp_path, custom_cpu_template["template"])

    # Verify the JSON static CPU template.
    cpu_template_helper.template_verify(vm_config_path)


def test_consecutive_cpu_config_consistency(
    test_microvm_with_api, cpu_template_helper, tmp_path
):
    """
    Verify that two dumped guest CPU configs obtained consecutively are
    consistent. The dumped guest CPU config should not change without
    any environmental changes (firecracker, kernel, microcode updates).
    """
    microvm = test_microvm_with_api
    microvm.spawn()
    microvm.basic_config()
    vm_config_path = save_vm_config(microvm, tmp_path)

    # Dump CPU config with the helper tool.
    cpu_config_1 = tmp_path / "cpu_config_1.json"
    cpu_template_helper.template_dump(vm_config_path, cpu_config_1)
    cpu_config_2 = tmp_path / "cpu_config_2.json"
    cpu_template_helper.template_dump(vm_config_path, cpu_config_2)

    # Strip common entries.
    cpu_template_helper.template_strip([cpu_config_1, cpu_config_2])

    # Check the stripped result is empty.
    if PLATFORM == "x86_64":
        empty_cpu_config = {
            "cpuid_modifiers": [],
            "msr_modifiers": [],
        }
    elif PLATFORM == "aarch64":
        empty_cpu_config = {"reg_modifiers": []}
    assert json.loads(cpu_config_1.read_text(encoding="utf-8")) == empty_cpu_config
    assert json.loads(cpu_config_2.read_text(encoding="utf-8")) == empty_cpu_config
