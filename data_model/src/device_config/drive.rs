use std::path::PathBuf;

use super::{DeviceState, RateLimiterConfig};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[allow(non_camel_case_types)]
pub enum DrivePermissions {
    ro,
    rw,
}

// This struct represents the strongly typed equivalent of the json body from drive
// related requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct DriveConfig {
    drive_id: String,
    path_on_host: PathBuf,
    state: DeviceState,
    is_root_device: bool,
    permissions: DrivePermissions,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_limiter: Option<RateLimiterConfig>,
}

impl DriveConfig {
    pub fn get_id(&self) -> &str {
        &self.drive_id
    }

    pub fn get_path_on_host(&self) -> &PathBuf {
        &self.path_on_host
    }

    pub fn get_rate_limiter(&self) -> Option<&RateLimiterConfig> {
        if let Some(ref rl) = self.rate_limiter {
            Some(&rl)
        } else {
            None
        }
    }
    pub fn is_read_only(&self) -> bool {
        self.permissions == DrivePermissions::ro
    }

    pub fn is_root_device(&self) -> bool {
        self.is_root_device == true
    }

    pub fn set_is_read_only(&mut self, is_read_only: bool) {
        if is_read_only == true {
            self.permissions = DrivePermissions::ro;
        } else {
            self.permissions = DrivePermissions::rw;
        }
    }

    pub fn set_is_root_device(&mut self, is_root_device: bool) {
        self.is_root_device = is_root_device;
    }

    pub fn set_path_on_host(&mut self, path_on_host: &PathBuf) {
        self.path_on_host = path_on_host.clone();
    }
}

#[derive(Debug)]
pub enum DriveError {
    RootBlockDeviceAlreadyAdded,
    InvalidBlockDevicePath,
    BlockDevicePathAlreadyExists,
    BlockDeviceUpdateFailed,
    BlockDeviceUpdateNotAllowed,
    NotImplemented,
}

pub enum PutDriveOutcome {
    Created,
    Updated,
    Error(DriveError),
}

#[cfg(test)]
mod tests {
    extern crate serde_json;

    use super::*;

    #[test]
    fn test_block_device_config() {
        let body = r#"{
            "drive_id": "1",
            "path_on_host": "test_block_device_config",
            "is_root_device": true,
            "permissions": "ro",
            "state": "Attached"
        }"#;

        let result: Result<DriveConfig, serde_json::Error> = serde_json::from_str(body);
        assert!(result.is_ok());
        let mut device1 = result.unwrap();

        assert_eq!(device1.is_read_only(), true);
        device1.set_is_read_only(false);
        assert_eq!(device1.is_read_only(), false);
        device1.set_is_read_only(true);
        assert_eq!(device1.is_read_only(), true);

        assert_eq!(device1.is_root_device(), true);
        device1.set_is_root_device(false);
        assert_eq!(device1.is_root_device(), false);

        assert_eq!(device1.get_id(), "1");

        assert_eq!(
            device1.get_path_on_host().to_str().unwrap(),
            "test_block_device_config"
        );
        device1.set_path_on_host(&PathBuf::from("test_block_device_config_update"));
        assert_eq!(
            device1.get_path_on_host().to_str().unwrap(),
            "test_block_device_config_update"
        );

        assert!(device1.get_rate_limiter().is_none());
    }

    #[test]
    fn test_drive_error() {
        assert_eq!(
            format!("{:?}", DriveError::RootBlockDeviceAlreadyAdded),
            "RootBlockDeviceAlreadyAdded"
        );
        assert_eq!(
            format!("{:?}", DriveError::InvalidBlockDevicePath),
            "InvalidBlockDevicePath"
        );
        assert_eq!(
            format!("{:?}", DriveError::BlockDevicePathAlreadyExists),
            "BlockDevicePathAlreadyExists"
        );
        assert_eq!(
            format!("{:?}", DriveError::BlockDeviceUpdateFailed),
            "BlockDeviceUpdateFailed"
        );
        assert_eq!(
            format!("{:?}", DriveError::BlockDeviceUpdateNotAllowed),
            "BlockDeviceUpdateNotAllowed"
        );
        assert_eq!(
            format!("{:?}", DriveError::NotImplemented),
            "NotImplemented"
        );
    }
}
