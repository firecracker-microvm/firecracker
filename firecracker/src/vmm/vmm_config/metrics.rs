// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auxiliary module for configuring the metrics system.
use std::fmt::{Display, Formatter};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::{open_file_nonblock, FcLineWriter};
use crate::logger::METRICS;

/// Strongly typed structure used to describe the metrics system.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Named pipe or file used as output for metrics.
    pub metrics_path: PathBuf,
}

/// Errors associated with actions on the `MetricsConfig`.
#[derive(Debug, PartialEq, Eq)]
pub enum MetricsConfigError {
    /// Cannot initialize the metrics system due to bad user input.
    InitializationFailure(String),
}

impl Display for MetricsConfigError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::MetricsConfigError::*;
        match *self {
            InitializationFailure(ref err_msg) => write!(f, "{}", err_msg.replace('\"', "")),
        }
    }
}

/// Configures the metrics as described in `metrics_cfg`.
pub fn init_metrics(metrics_cfg: MetricsConfig) -> std::result::Result<(), MetricsConfigError> {
    let writer = FcLineWriter::new(
        open_file_nonblock(&metrics_cfg.metrics_path)
            .map_err(|err| MetricsConfigError::InitializationFailure(err.to_string()))?,
    );
    METRICS
        .init(Box::new(writer))
        .map_err(|err| MetricsConfigError::InitializationFailure(err.to_string()))
}

#[cfg(test)]
mod tests {
    use utils::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_init_metrics_invalid_pipe() {
        // Error case: initializing metrics with invalid pipe returns error.
        let desc = MetricsConfig {
            metrics_path: PathBuf::from("not_found_file_metrics"),
        };
        let init = init_metrics(desc);
        assert_eq!(
            init,
            Err(MetricsConfigError::InitializationFailure(String::from(
                "No such file or directory (os error 2)"
            )))
        );
    }

    #[test]
    fn test_init_metrics() {
        // Initializing metrics with valid pipe is ok.
        let metrics_file = TempFile::new().unwrap();
        let desc = MetricsConfig {
            metrics_path: metrics_file.as_path().to_path_buf(),
        };

        // At this point we do not know if the metrics have been initialized in
        // this process, but we need to guarantee it is for the following
        // assertion. So we make this function call and do not check it.
        init_metrics(desc.clone()).ok();
        let init = init_metrics(desc);
        assert_eq!(
            init,
            Err(MetricsConfigError::InitializationFailure(String::from(
                "Reinitialization of metrics not allowed."
            )))
        )
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
