// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Copied from main branch.
// https://github.com/firecracker-microvm/firecracker/tree/d79b7d456db28e8a34b174a48067da2376a63f14/src/vmm/src/cpuid/template

// Contains Intel specific templates.
pub mod intel;
// Contains AMD specific templates.
pub mod amd;

mod bit_helper;
mod cpu_leaf;
