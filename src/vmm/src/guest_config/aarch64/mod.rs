// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

/// CPU configuration for aarch64 CPUs
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct Aarch64CpuConfiguration {
    /// Register values as a key pair
    /// Key: Register pointer
    /// Value: Register value
    pub regs: HashMap<u64, u128>,
}
