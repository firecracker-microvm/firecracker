# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Utilities for CPU template related functionality."""

import framework.utils_cpuid as cpuid_utils

# All existing CPU templates available on Intel
INTEL_TEMPLATES = ["C3", "T2", "T2CL", "T2S"]
# All existing CPU templates available on AMD
AMD_TEMPLATES = ["T2A"]
# All existing CPU templates
ALL_TEMPLATES = INTEL_TEMPLATES + AMD_TEMPLATES


def get_supported_cpu_templates():
    """
    Return the list of CPU templates supported by the platform.
    """
    vendor = cpuid_utils.get_cpu_vendor()
    if vendor == cpuid_utils.CpuVendor.INTEL:
        return INTEL_TEMPLATES
    if vendor == cpuid_utils.CpuVendor.AMD:
        return AMD_TEMPLATES
    return []


SUPPORTED_CPU_TEMPLATES = get_supported_cpu_templates()
