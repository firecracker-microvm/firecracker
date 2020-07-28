// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auxiliary module for configuring the metrics system.
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

use super::{open_file_nonblock, FcLineWriter};
use logger::METRICS;

use serde::{Deserialize, Serialize};

/// Strongly typed structure used to describe the metrics system.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MetricsConfig {
    /// Named pipe or file used as output for metrics.
    pub metrics_path: PathBuf,
}

/// Errors associated with actions on the `MetricsConfig`.
#[derive(Debug)]
pub enum MetricsConfigError {
    /// Cannot initialize the metrics system due to bad user input.
    InitializationFailure(String),
}

impl Display for MetricsConfigError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::MetricsConfigError::*;
        match *self {
            InitializationFailure(ref err_msg) => write!(f, "{}", err_msg.replace("\"", "")),
        }
    }
}

/// Configures the metrics as described in `metrics_cfg`.
pub fn init_metrics(metrics_cfg: MetricsConfig) -> std::result::Result<(), MetricsConfigError> {
    let writer = FcLineWriter::new(
        open_file_nonblock(&metrics_cfg.metrics_path)
            .map_err(|e| MetricsConfigError::InitializationFailure(e.to_string()))?,
    );
    METRICS
        .init(Box::new(writer))
        .map_err(|e| MetricsConfigError::InitializationFailure(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::tempfile::TempFile;

    #[test]
    fn test_init_metrics() {
        // Error case: initializing metrics with invalid pipe returns error.
        let desc = MetricsConfig {
            metrics_path: PathBuf::from("not_found_file_metrics"),
        };
        assert!(init_metrics(desc).is_err());

        // Initializing metrics with valid pipe is ok.
        let metrics_file = TempFile::new().unwrap();
        let desc = MetricsConfig {
            metrics_path: metrics_file.as_path().to_path_buf(),
        };

        assert!(init_metrics(desc.clone()).is_ok());
        assert!(init_metrics(desc).is_err());
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!(
                "{}",
                MetricsConfigError::InitializationFailure(String::from(
                    "Failed to initialize metrics"
                ))
            ),
            "Failed to initialize metrics"
        );
    }
}
