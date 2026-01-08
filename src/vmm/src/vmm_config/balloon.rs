// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

pub use crate::devices::virtio::balloon::BALLOON_DEV_ID;
pub use crate::devices::virtio::balloon::device::BalloonStats;
use crate::devices::virtio::balloon::{Balloon, BalloonConfig};

type MutexBalloon = Arc<Mutex<Balloon>>;

/// Errors associated with the operations allowed on the balloon.
#[derive(Debug, derive_more::From, thiserror::Error, displaydoc::Display)]
pub enum BalloonSpecError {
    /// No balloon device found.
    DeviceNotFound,
    /// Amount of pages requested is too large.
    TooManyPagesRequested,
    /// Error creating the balloon device: {0}
    CreateFailure(crate::devices::virtio::balloon::BalloonError),
}

/// This struct represents the strongly typed equivalent of the json body
/// from balloon related requests.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BalloonDeviceSpec {
    /// Target balloon size in MiB.
    pub amount_mib: u32,
    /// Option to deflate the balloon in case the guest is out of memory.
    pub deflate_on_oom: bool,
    /// Interval in seconds between refreshing statistics.
    #[serde(default)]
    pub stats_polling_interval_s: u16,
    /// Free page hinting enabled
    #[serde(default)]
    pub free_page_hinting: bool,
    /// Free page reporting enabled
    #[serde(default)]
    pub free_page_reporting: bool,
}

impl From<BalloonConfig> for BalloonDeviceSpec {
    fn from(state: BalloonConfig) -> Self {
        BalloonDeviceSpec {
            amount_mib: state.amount_mib,
            deflate_on_oom: state.deflate_on_oom,
            stats_polling_interval_s: state.stats_polling_interval_s,
            free_page_hinting: state.free_page_hinting,
            free_page_reporting: state.free_page_reporting,
        }
    }
}

/// The data fed into a balloon update request. Currently, only the number
/// of pages and the stats polling interval can be updated.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BalloonUpdateSpec {
    /// Target balloon size in MiB.
    pub amount_mib: u32,
}

/// The data fed into a balloon statistics interval update request.
/// Note that the state of the statistics cannot be changed from ON to OFF
/// or vice versa after boot, only the interval of polling can be changed
/// if the statistics were activated in the device configuration.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BalloonUpdateStatsSpec {
    /// Interval in seconds between refreshing statistics.
    pub stats_polling_interval_s: u16,
}

/// A builder for `Balloon` devices from 'BalloonDeviceSpec'.
#[cfg_attr(not(test), derive(Default))]
#[derive(Debug)]
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
    pub fn set(&mut self, spec: BalloonDeviceSpec) -> Result<(), BalloonSpecError> {
        self.inner = Some(Arc::new(Mutex::new(Balloon::new(
            spec.amount_mib,
            spec.deflate_on_oom,
            spec.stats_polling_interval_s,
            spec.free_page_hinting,
            spec.free_page_reporting,
        )?)));

        Ok(())
    }

    /// Inserts an existing balloon device.
    pub fn set_device(&mut self, balloon: MutexBalloon) {
        self.inner = Some(balloon);
    }

    /// Provides a reference to the Balloon if present.
    pub fn get(&self) -> Option<&MutexBalloon> {
        self.inner.as_ref()
    }

    /// Returns the same structure that was used to configure the device.
    pub fn get_config(&self) -> Result<BalloonDeviceSpec, BalloonSpecError> {
        self.get()
            .ok_or(BalloonSpecError::DeviceNotFound)
            .map(|balloon_mutex| balloon_mutex.lock().expect("Poisoned lock").config())
            .map(BalloonDeviceSpec::from)
    }
}

#[cfg(test)]
impl Default for BalloonBuilder {
    fn default() -> BalloonBuilder {
        let mut balloon = BalloonBuilder::new();
        balloon.set(BalloonDeviceSpec::default()).unwrap();
        balloon
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn default_config() -> BalloonDeviceSpec {
        BalloonDeviceSpec {
            amount_mib: 0,
            deflate_on_oom: false,
            stats_polling_interval_s: 0,
            free_page_hinting: false,
            free_page_reporting: false,
        }
    }

    #[test]
    fn test_balloon_create() {
        let default_balloon_spec = default_config();
        let balloon_spec = BalloonDeviceSpec {
            amount_mib: 0,
            deflate_on_oom: false,
            stats_polling_interval_s: 0,
            free_page_hinting: false,
            free_page_reporting: false,
        };
        assert_eq!(default_balloon_spec, balloon_spec);
        let mut builder = BalloonBuilder::new();
        assert!(builder.get().is_none());

        builder.set(balloon_spec).unwrap();
        assert_eq!(builder.get().unwrap().lock().unwrap().num_pages(), 0);
        assert_eq!(builder.get_config().unwrap(), default_balloon_spec);

        let _update_spec = BalloonUpdateSpec { amount_mib: 5 };
        let _stats_update_spec = BalloonUpdateStatsSpec {
            stats_polling_interval_s: 5,
        };
    }

    #[test]
    fn test_from_balloon_state() {
        let expected_balloon_spec = BalloonDeviceSpec {
            amount_mib: 5,
            deflate_on_oom: false,
            stats_polling_interval_s: 3,
            free_page_hinting: false,
            free_page_reporting: false,
        };

        let actual_balloon_spec = BalloonDeviceSpec::from(BalloonConfig {
            amount_mib: 5,
            deflate_on_oom: false,
            stats_polling_interval_s: 3,
            free_page_hinting: false,
            free_page_reporting: false,
        });

        assert_eq!(expected_balloon_spec, actual_balloon_spec);
    }

    #[test]
    fn test_set_device() {
        let mut builder = BalloonBuilder::new();
        let balloon = Balloon::new(0, true, 0, false, false).unwrap();
        builder.set_device(Arc::new(Mutex::new(balloon)));
        assert!(builder.inner.is_some());
    }
}
