// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auxiliary module for configuring the metrics system.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::open_file_nonblock;
use crate::logger::{FcLineWriter, METRICS};

/// Strongly typed structure used to describe the metrics system.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Named pipe or file used as output for metrics.
    pub metrics_path: PathBuf,
}

/// Errors associated with actions on the `MetricsConfig`.
#[derive(Debug, thiserror::Error)]
pub enum MetricsConfigError {
    /// Cannot initialize the metrics system due to bad user input.
    #[error("{}", format!("{:?}", .0).replace('\"', ""))]
    InitializationFailure(String),
}

/// Configures the metrics as described in `metrics_cfg`.
pub fn init_metrics(metrics_cfg: MetricsConfig) -> Result<(), MetricsConfigError> {
    let writer = FcLineWriter::new(
        open_file_nonblock(&metrics_cfg.metrics_path)
            .map_err(|err| MetricsConfigError::InitializationFailure(err.to_string()))?,
    );
    METRICS
        .init(writer)
        .map_err(|err| MetricsConfigError::InitializationFailure(err.to_string()))
}

#[cfg(test)]
mod tests {
    use utils::tempfile::TempFile;

    use super::*;

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
}
