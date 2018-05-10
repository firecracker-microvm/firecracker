pub mod boot_source;
pub mod machine_configuration;

pub use vm::boot_source::{BootSource, BootSourceError};
pub use vm::machine_configuration::CpuFeaturesTemplate;
pub use vm::machine_configuration::{MachineConfiguration, MachineConfigurationError,
                                    PutMachineConfigurationOutcome};
