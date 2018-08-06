// Copyright 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.

use vm::{DeviceState, RateLimiterDescription};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[allow(non_camel_case_types)]
pub enum DrivePermissions {
    ro,
    rw,
}

// This struct represents the strongly typed equivalent of the json body from drive
// related requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DriveDescription {
    pub drive_id: String,
    pub path_on_host: String,
    pub state: DeviceState,
    pub is_root_device: bool,
    pub permissions: DrivePermissions,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partuuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter: Option<RateLimiterDescription>,
}

impl DriveDescription {
    pub fn is_read_only(&self) -> bool {
        self.permissions == DrivePermissions::ro
    }

    pub fn check_id(&self, id_from_path: &str) -> Result<(), String> {
        if id_from_path != self.drive_id.as_str() {
            Err(String::from(
                "The id from the path does not match the id from the body!",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum DriveError {
    RootBlockDeviceAlreadyAdded,
    InvalidBlockDeviceID,
    InvalidBlockDevicePath,
    BlockDevicePathAlreadyExists,
    BlockDeviceUpdateFailed,
    BlockDeviceUpdateNotAllowed,
    NotImplemented,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_read_only() {
        assert!(
            DriveDescription {
                drive_id: String::from("foo"),
                path_on_host: String::from("/foo/bar"),
                state: DeviceState::Attached,
                is_root_device: true,
                permissions: DrivePermissions::ro,
                partuuid: None,
                rate_limiter: None,
            }.is_read_only()
        );
    }

    #[test]
    fn test_check_id() {
        let desc = DriveDescription {
            drive_id: String::from("foo"),
            path_on_host: String::from("/foo/bar"),
            state: DeviceState::Attached,
            is_root_device: true,
            permissions: DrivePermissions::ro,
            partuuid: None,
            rate_limiter: None,
        };

        assert!(desc.check_id("foo").is_ok());
        assert!(desc.check_id("bar").is_err());
    }
}
