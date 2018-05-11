mod drive;
mod net;
mod rate_limiter;

pub use device_config::drive::{DriveConfig, DriveError, DrivePermissions, PutDriveOutcome};
pub use device_config::rate_limiter::{description_into_implementation as rate_limiter_description_into_implementation,
                                      RateLimiterConfig};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum DeviceState {
    Attached,
}
