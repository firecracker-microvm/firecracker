# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Utilities for CPU template related functionality."""

import json
from pathlib import Path

import pytest

import framework.utils_cpuid as cpuid_utils

# All existing CPU templates available on Intel
INTEL_TEMPLATES = ["C3", "T2", "T2CL", "T2S"]
# All existing CPU templates available on AMD
AMD_TEMPLATES = ["T2A"]
# All existing CPU templates available on ARM
ARM_TEMPLATES = ["V1N1"]


def get_supported_cpu_templates():
    """
    Return the list of CPU templates supported by the platform.
    """
    match cpuid_utils.get_cpu_vendor():
        case cpuid_utils.CpuVendor.INTEL:
            # T2CL template is only supported on Cascade Lake and newer CPUs.
            skylake_model = "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"
            if cpuid_utils.get_cpu_model_name() == skylake_model:
                return sorted(set(INTEL_TEMPLATES) - set(["T2CL"]))
            return INTEL_TEMPLATES
        case cpuid_utils.CpuVendor.AMD:
            return AMD_TEMPLATES
        case cpuid_utils.CpuVendor.ARM:
            match cpuid_utils.get_instance_type():
                case "m6g.metal":
                    return []
                case "c7g.metal":
                    return ARM_TEMPLATES
    return []


SUPPORTED_CPU_TEMPLATES = get_supported_cpu_templates()

# Custom CPU templates for Aarch64 for testing
AARCH64_CUSTOM_CPU_TEMPLATES_G2 = ["aarch64_remove_ssbs", "aarch64_v1n1"]
AARCH64_CUSTOM_CPU_TEMPLATES_G3 = ["aarch64_remove_ssbs", "aarch64_v1n1"]


def get_supported_custom_cpu_templates():
    """
    Return the list of custom CPU templates supported by the platform.
    """

    def tmpl_name_to_json(name):
        template_path = Path(f"./data/static_cpu_templates/{name.lower()}.json")
        return {"name": name, "template": json.loads(template_path.read_text("utf-8"))}

    def name_list_to_tmpl_list(name_list):
        return [tmpl_name_to_json(name) for name in name_list]

    match cpuid_utils.get_cpu_vendor():
        case cpuid_utils.CpuVendor.INTEL:
            # T2CL template is only supported on Cascade Lake and newer CPUs.
            skylake_model = "Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz"
            if cpuid_utils.get_cpu_model_name() == skylake_model:
                return name_list_to_tmpl_list(set(INTEL_TEMPLATES) - set(["T2CL"]))
            return name_list_to_tmpl_list(INTEL_TEMPLATES)
        case cpuid_utils.CpuVendor.AMD:
            return name_list_to_tmpl_list(AMD_TEMPLATES)
        case cpuid_utils.CpuVendor.ARM:
            match cpuid_utils.get_instance_type():
                case "m6g.metal":
                    return name_list_to_tmpl_list(AARCH64_CUSTOM_CPU_TEMPLATES_G2)
                case "c7g.metal":
                    return name_list_to_tmpl_list(AARCH64_CUSTOM_CPU_TEMPLATES_G3)


SUPPORTED_CUSTOM_CPU_TEMPLATES = get_supported_custom_cpu_templates()


skip_on_arm = pytest.mark.skipif(
    cpuid_utils.get_cpu_vendor() == cpuid_utils.CpuVendor.ARM,
    reason="skip specific cpu template related tests on ARM platforms until kernel patches required for V1N1 come",
)
