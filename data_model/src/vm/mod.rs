// Copyright 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.

mod devices;
mod machine_config;
mod rate_limiter;

pub use vm::devices::{BlockDeviceConfig, BlockDeviceConfigs, DriveError};
pub use vm::machine_config::{CpuFeaturesTemplate, MachineConfiguration};
pub use vm::rate_limiter::{description_into_implementation, RateLimiterDescription};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum DeviceState {
    Attached,
}

#[derive(Debug)]
pub enum PatchError {
    IdNotFound,
    InvalidFields(Vec<String>),
    InvalidPayload,
}

pub trait ValidatePatch {
    fn validate(&self) -> Result<(), PatchError>;
}
