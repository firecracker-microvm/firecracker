// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::RateLimiterConfig;
use crate::devices::virtio::rng::{Entropy, EntropyError};

/// This struct represents the strongly typed equivalent of the json body from entropy device
/// related requests.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntropyDeviceConfig {
    /// Configuration for RateLimiter of Entropy device
    pub rate_limiter: Option<RateLimiterConfig>,
}

impl From<&Entropy> for EntropyDeviceConfig {
    fn from(dev: &Entropy) -> Self {
        let rate_limiter: RateLimiterConfig = dev.rate_limiter().into();
        EntropyDeviceConfig {
            rate_limiter: rate_limiter.into_option(),
        }
    }
}

/// Errors that can occur while handling configuration for
/// an entropy device
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum EntropyDeviceError {
    /// Could not create Entropy device: {0}
    CreateDevice(#[from] EntropyError),
    /// Could not create RateLimiter from configuration: {0}
    CreateRateLimiter(#[from] std::io::Error),
}

/// A builder type used to construct an Entropy device
#[derive(Debug, Default)]
pub struct EntropyDeviceBuilder(Option<Arc<Mutex<Entropy>>>);

impl EntropyDeviceBuilder {
    /// Create a new instance for the builder
    pub fn new() -> Self {
        Self(None)
    }

    /// Build an entropy device and return a (counted) reference to it protected by a mutex
    pub fn build(
        &mut self,
        config: EntropyDeviceConfig,
    ) -> Result<Arc<Mutex<Entropy>>, EntropyDeviceError> {
        let rate_limiter = config
            .rate_limiter
            .map(RateLimiterConfig::try_into)
            .transpose()?;
        let dev = Arc::new(Mutex::new(Entropy::new(rate_limiter.unwrap_or_default())?));
        self.0 = Some(dev.clone());

        Ok(dev)
    }

    /// Insert a new entropy device from a configuration object
    pub fn insert(&mut self, config: EntropyDeviceConfig) -> Result<(), EntropyDeviceError> {
        let _ = self.build(config)?;
        Ok(())
    }

    /// Get a reference to the entropy device, if present
    pub fn get(&self) -> Option<&Arc<Mutex<Entropy>>> {
        self.0.as_ref()
    }

    /// Get the configuration of the entropy device (if any)
    pub fn config(&self) -> Option<EntropyDeviceConfig> {
        self.0
            .as_ref()
            .map(|dev| EntropyDeviceConfig::from(dev.lock().unwrap().deref()))
    }

    /// Set the entropy device from an already created object
    pub fn set_device(&mut self, device: Arc<Mutex<Entropy>>) {
        self.0 = Some(device);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limiter::RateLimiter;

    #[test]
    fn test_entropy_device_create() {
        let config = EntropyDeviceConfig::default();
        let mut builder = EntropyDeviceBuilder::new();
        assert!(builder.get().is_none());

        builder.insert(config.clone()).unwrap();
        assert!(builder.get().is_some());
        assert_eq!(builder.config().unwrap(), config);
    }

    #[test]
    fn test_set_device() {
        let mut builder = EntropyDeviceBuilder::new();
        let device = Entropy::new(RateLimiter::default()).unwrap();
        assert!(builder.0.is_none());
        builder.set_device(Arc::new(Mutex::new(device)));
        assert!(builder.0.is_some());
    }
}
