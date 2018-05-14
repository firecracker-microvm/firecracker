pub mod boot_source;
mod logger;
pub mod machine_configuration;

pub use vm::boot_source::{BootSource, BootSourceError};
pub use vm::logger::{LoggerDescription, LoggerError, LoggerLevel, PutLoggerOutcome};
pub use vm::machine_configuration::CpuFeaturesTemplate;
pub use vm::machine_configuration::{MachineConfiguration, MachineConfigurationError,
                                    PutMachineConfigurationOutcome};
