// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::sync::{Arc, Mutex};

pub use devices::virtio::balloon::device::BalloonStats;
use devices::virtio::balloon::Error as BalloonError;
pub use devices::virtio::BALLOON_DEV_ID;
use devices::virtio::{Balloon, BalloonConfig};

use serde::{Deserialize, Serialize};

type MutexBalloon = Arc<Mutex<Balloon>>;

/// Errors associated with the operations allowed on the balloon.
#[derive(Debug)]
pub enum BalloonConfigError {
    /// The user made a request on an inexistent balloon device.
    DeviceNotFound,
    /// Device not activated yet.
    DeviceNotActive,
    /// The user tried to enable/disable the statistics after boot.
    InvalidStatsUpdate,
    /// Amount of pages requested is too large.
    TooManyPagesRequested,
    /// The user polled the statistics of a balloon device that
    /// does not have the statistics enabled.
    StatsNotFound,
    /// Failed to create a balloon device.
    CreateFailure(devices::virtio::balloon::Error),
    /// Failed to update the configuration of the ballon device.
    UpdateFailure(std::io::Error),
}

impl fmt::Display for BalloonConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        use self::BalloonConfigError::*;
        match self {
            DeviceNotFound => write!(f, "No balloon device found."),
            DeviceNotActive => write!(f, "Device is inactive, check balloon driver is enabled."),
            InvalidStatsUpdate => write!(f, "Cannot enable/disable the statistics after boot."),
            TooManyPagesRequested => write!(f, "Amount of pages requested is too large."),
            StatsNotFound => write!(f, "Statistics for the balloon device are not enabled"),
            CreateFailure(e) => write!(f, "Error creating the balloon device: {:?}", e),
            UpdateFailure(e) => write!(
                f,
                "Error updating the balloon device configuration: {:?}",
                e
            ),
        }
    }
}

impl From<BalloonError> for BalloonConfigError {
    fn from(error: BalloonError) -> Self {
        match error {
            BalloonError::DeviceNotFound => Self::DeviceNotFound,
            BalloonError::DeviceNotActive => Self::DeviceNotActive,
            BalloonError::InterruptError(io_error) => Self::UpdateFailure(io_error),
            BalloonError::StatisticsStateChange => Self::InvalidStatsUpdate,
            BalloonError::StatisticsDisabled => Self::StatsNotFound,
            BalloonError::TooManyPagesRequested => Self::TooManyPagesRequested,
            e => Self::CreateFailure(e),
        }
    }
}

type Result<T> = std::result::Result<T, BalloonConfigError>;

/// This struct represents the strongly typed equivalent of the json body
/// from balloon related requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BalloonDeviceConfig {
    /// Target balloon size in MB.
    pub amount_mb: u32,
    /// Option to make the guest obtain permission from the host in
    /// order to deflate.
    pub must_tell_host: bool,
    /// Option to deflate the balloon in case the guest is out of memory.
    pub deflate_on_oom: bool,
    /// Interval in seconds between refreshing statistics.
    #[serde(default)]
    pub stats_polling_interval_s: u16,
}

impl From<BalloonConfig> for BalloonDeviceConfig {
    fn from(state: BalloonConfig) -> Self {
        BalloonDeviceConfig {
            amount_mb: state.amount_mb,
            deflate_on_oom: state.deflate_on_oom,
            must_tell_host: state.must_tell_host,
            stats_polling_interval_s: state.stats_polling_interval_s,
        }
    }
}

/// The data fed into a balloon update request. Currently, only the number
/// of pages and the stats polling interval can be updated.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BalloonUpdateConfig {
    /// Target balloon size in MB.
    pub amount_mb: u32,
}

/// The data fed into a balloon statistics interval update request.
/// Note that the state of the statistics cannot be changed from ON to OFF
/// or vice versa after boot, only the interval of polling can be changed
/// if the statistics were activated in the device configuration.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BalloonUpdateStatsConfig {
    /// Interval in seconds between refreshing statistics.
    pub stats_polling_interval_s: u16,
}

/// A builder for `Balloon` devices from 'BalloonDeviceConfig'.
#[derive(Default)]
pub struct BalloonBuilder {
    inner: Option<MutexBalloon>,
}

impl BalloonBuilder {
    /// Creates an empty Balloon Store.
    pub fn new() -> Self {
        Self { inner: None }
    }

    /// Inserts a Balloon device in the store.
    /// If an entry already exists, it will overwrite it.
    pub fn set(&mut self, cfg: BalloonDeviceConfig) -> Result<()> {
        self.inner = Some(Arc::new(Mutex::new(
            Balloon::new(
                cfg.amount_mb,
                cfg.must_tell_host,
                cfg.deflate_on_oom,
                cfg.stats_polling_interval_s,
                // `restored` flag is false because this code path
                // is never called by snapshot restore functionality.
                false,
            )
            .map_err(BalloonConfigError::CreateFailure)?,
        )));

        Ok(())
    }

    /// Provides a reference to the Balloon if present.
    pub fn get(&self) -> Option<&MutexBalloon> {
        self.inner.as_ref()
    }

    /// Returns the same structure that was used to configure the device.
    pub fn get_config(&self) -> Result<BalloonDeviceConfig> {
        self.get()
            .ok_or(BalloonConfigError::DeviceNotFound)
            .map(|balloon_mutex| balloon_mutex.lock().expect("Poisoned lock").config())
            .map(BalloonDeviceConfig::from)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn default_config() -> BalloonDeviceConfig {
        BalloonDeviceConfig {
            amount_mb: 0,
            must_tell_host: false,
            deflate_on_oom: false,
            stats_polling_interval_s: 0,
        }
    }

    #[test]
    fn test_balloon_create() {
        let default_balloon_config = default_config();
        let balloon_config = BalloonDeviceConfig {
            amount_mb: 0,
            must_tell_host: false,
            deflate_on_oom: false,
            stats_polling_interval_s: 0,
        };
        assert_eq!(default_balloon_config, balloon_config);
        let mut builder = BalloonBuilder::new();
        assert!(builder.get().is_none());

        builder.set(balloon_config).unwrap();
        assert_eq!(builder.get().unwrap().lock().unwrap().num_pages(), 0);
        assert_eq!(builder.get_config().unwrap(), default_balloon_config);

        let _update_config = BalloonUpdateConfig { amount_mb: 5 };
        let _stats_update_config = BalloonUpdateStatsConfig {
            stats_polling_interval_s: 5,
        };
    }

    #[test]
    fn test_from_balloon_state() {
        let expected_balloon_config = BalloonDeviceConfig {
            amount_mb: 5,
            deflate_on_oom: false,
            must_tell_host: true,
            stats_polling_interval_s: 3,
        };

        let actual_balloon_config = BalloonDeviceConfig::from(BalloonConfig {
            amount_mb: 5,
            deflate_on_oom: false,
            must_tell_host: true,
            stats_polling_interval_s: 3,
        });

        assert_eq!(expected_balloon_config, actual_balloon_config);
    }

    #[test]
    fn test_error_messages() {
        use super::BalloonConfigError::*;
        use std::io;
        let err = CreateFailure(devices::virtio::balloon::Error::EventFd(
            io::Error::from_raw_os_error(0),
        ));
        let _ = format!("{}{:?}", err, err);

        let err = UpdateFailure(io::Error::from_raw_os_error(0));
        let _ = format!("{}{:?}", err, err);

        let err = DeviceNotFound;
        let _ = format!("{}{:?}", err, err);

        let err = InvalidStatsUpdate;
        let _ = format!("{}{:?}", err, err);

        let err = TooManyPagesRequested;
        let _ = format!("{}{:?}", err, err);

        let err = StatsNotFound;
        let _ = format!("{}{:?}", err, err);
    }
}
