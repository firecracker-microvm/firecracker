// Copyright 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
mod machine_config;
mod rate_limiter;

pub use vm::machine_config::{CpuFeaturesTemplate, VmConfig, VmConfigError};
pub use vm::rate_limiter::{description_into_implementation, RateLimiterDescription};
