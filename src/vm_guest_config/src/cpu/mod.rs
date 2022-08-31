// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Types used for configuring guest vCPUs
pub mod cpu_config;

/// Binding data and logic to map symbolic names
/// to CPU features.
pub mod cpu_symbolic_engine;

/// Errors associated with processing configuration
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConfigurationErrorBase {
    /// General configuration error
    #[error("Error while configuring CPU - {0}")]
    CpuConfigurationError(CustomCpuConfigurationError),
}

/// Errors associated with processing CPU configuration
#[derive(Debug, Clone, thiserror::Error)]
pub enum CustomCpuConfigurationError {
    /// Error while configuring CPU features via CPUID
    #[error("Failed to configure CPU features via CPUID.")]
    CpuId,
    /// Error while configuration model-specific registers
    #[error("Error while configuring CPU features via model-specific registers.")]
    MSR,
}
