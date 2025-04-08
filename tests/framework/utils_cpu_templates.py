# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Utilities for CPU template related functionality."""

# pylint:disable=too-many-return-statements

import json
from pathlib import Path

import pytest

from framework.properties import global_props
from framework.utils_cpuid import CpuModel, CpuVendor, get_cpu_vendor

# All existing CPU templates available on Intel
INTEL_TEMPLATES = ["C3", "T2", "T2CL", "T2S"]
# All existing CPU templates available on AMD
AMD_TEMPLATES = ["T2A"]
# All existing CPU templates available on ARM
ARM_TEMPLATES = ["V1N1"]


def get_supported_cpu_templates():
    """Return the list of static CPU templates supported by the platform."""
    host_linux = global_props.host_linux_version_tpl
    match get_cpu_vendor(), global_props.cpu_codename:
        case CpuVendor.INTEL, CpuModel.INTEL_SKYLAKE:
            return sorted(set(INTEL_TEMPLATES) - {"T2CL"})
        case CpuVendor.INTEL, CpuModel.INTEL_CASCADELAKE:
            return INTEL_TEMPLATES
        case CpuVendor.INTEL, CpuModel.INTEL_ICELAKE:
            return sorted(set(INTEL_TEMPLATES) - {"T2S"})
        case CpuVendor.AMD, CpuModel.AMD_MILAN:
            return AMD_TEMPLATES
        case CpuVendor.ARM, CpuModel.ARM_NEOVERSE_V1 if host_linux >= (6, 1):
            return ARM_TEMPLATES
        case _:
            return []


SUPPORTED_CPU_TEMPLATES = get_supported_cpu_templates()


def get_supported_custom_cpu_templates():
    """Return the list of custom CPU templates supported by the platform."""
    host_linux = global_props.host_linux_version_tpl
    match get_cpu_vendor(), global_props.cpu_codename:
        case CpuVendor.INTEL, CpuModel.INTEL_SKYLAKE:
            return set(INTEL_TEMPLATES) - {"T2CL"}
        case CpuVendor.INTEL, CpuModel.INTEL_CASCADELAKE:
            return INTEL_TEMPLATES
        case CpuVendor.INTEL, CpuModel.INTEL_ICELAKE:
            return set(INTEL_TEMPLATES) - {"T2S"}
        case CpuVendor.AMD, CpuModel.AMD_MILAN:
            return AMD_TEMPLATES
        case CpuVendor.ARM, CpuModel.ARM_NEOVERSE_N1 if host_linux >= (6, 1):
            return ["V1N1"]
        case CpuVendor.ARM, CpuModel.ARM_NEOVERSE_V1 if host_linux >= (6, 1):
            return ["V1N1", "AARCH64_WITH_SVE_AND_PAC"]
        case CpuVendor.ARM, CpuModel.ARM_NEOVERSE_V1:
            return ["AARCH64_WITH_SVE_AND_PAC"]
        case CpuVendor.ARM, CpuModel.ARM_NEOVERSE_V2:
            return ["AARCH64_WITH_SVE_AND_PAC"]
        case _:
            return []


def custom_cpu_templates_params():
    """Return Custom CPU templates as pytest parameters"""
    for name in sorted(get_supported_custom_cpu_templates()):
        tmpl = Path(f"./data/custom_cpu_templates/{name}.json")
        yield pytest.param(
            {"name": name, "template": json.loads(tmpl.read_text("utf-8"))},
            id="custom_" + name,
        )


def static_cpu_templates_params():
    """Return Static CPU templates as pytest parameters"""
    for name in sorted(get_supported_cpu_templates()):
        yield pytest.param(name, id="static_" + name)


def get_cpu_template_name(cpu_template, with_type=False):
    """Return the CPU template name."""
    if isinstance(cpu_template, str):
        return ("static_" if with_type else "") + cpu_template
    if isinstance(cpu_template, dict):
        return ("custom_" if with_type else "") + cpu_template["name"]
    return "None"
