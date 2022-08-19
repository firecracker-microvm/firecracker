// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Types used for configuring guest vCPUs
pub mod cpu_config;

/// Binding data and logic to map symbolic names
/// to CPU features.
pub mod cpu_symbolic_engine;

pub use cpuid::common;
