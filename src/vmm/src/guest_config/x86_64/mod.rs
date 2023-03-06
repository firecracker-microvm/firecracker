// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

/// CPU configuration for x86_64 CPUs
#[derive(Clone, Debug)]
pub struct X86_64CpuConfiguration {
    /// CPUID configuration
    // pub cpuid: Cpuid,
    /// Register values as a key pair for model specific registers
    /// Key: MSR address
    /// Value: MSR value
    pub msrs: HashMap<u32, u64>,
}
