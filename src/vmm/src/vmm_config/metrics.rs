// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auxiliary module for configuring the metrics system.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::logger::{FcLineWriter, METRICS};
use crate::utils::open_file_nonblock;

/// Strongly typed structure used to describe the metrics system.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Named pipe or file used as output for metrics.
    pub metrics_path: PathBuf,
}

/// Errors associated with actions on the `MetricsConfig`.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MetricsConfigError {
    /// Cannot initialize the metrics system due to bad user input: {0}
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
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_init_metrics() {
        // Initializing metrics with valid pipe is ok.
        let metrics_file = TempFile::new().unwrap();
        let desc = MetricsConfig {
            metrics_path: metrics_file.as_path().to_path_buf(),
        };

        init_metrics(desc.clone()).unwrap();
        init_metrics(desc).unwrap_err();
    }
}
