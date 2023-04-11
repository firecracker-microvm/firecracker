// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(target_arch = "x86_64")]
pub mod cpuid;

/// Module for types used for custom CPU templates
pub mod templates;

/// Module containing type implementations needed for x86 CPU configuration
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

/// Module containing type implementations needed for aarch64 (ARM) CPU configuration
#[cfg(target_arch = "aarch64")]
pub mod aarch64;
