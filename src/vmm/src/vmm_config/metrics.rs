// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auxiliary module for configuring the metrics system.
use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::logger::{FcLineWriter, METRICS};
use crate::utils::open_file_nonblock;

/// Strongly typed structure used to describe the metrics system.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Named pipe or file used as output for metrics.
    pub metrics_path: PathBuf,
    /// Whether to emit the microVM instance id as a top-level `id` field on every metrics line.
    #[serde(default)]
    pub emit_id: bool,
    /// Operator-defined key-value properties emitted on every metrics line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<BTreeMap<String, String>>,
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
        .map_err(|err| MetricsConfigError::InitializationFailure(err.to_string()))?;

    if metrics_cfg.emit_id {
        METRICS.id.enable();
    }

    if let Some(properties) = metrics_cfg.properties {
        METRICS
            .properties
            .set(properties)
            .map_err(|err| MetricsConfigError::InitializationFailure(err.to_string()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_init_metrics() {
        // Initializing metrics with a valid pipe is ok. Enable both optional
        // fields so their configuration paths are exercised.
        let metrics_file = TempFile::new().unwrap();
        let mut properties = BTreeMap::new();
        properties.insert("customer_id".to_string(), "1234".to_string());
        let desc = MetricsConfig {
            metrics_path: metrics_file.as_path().to_path_buf(),
            emit_id: true,
            properties: Some(properties),
        };

        init_metrics(desc.clone()).unwrap();
        // Metrics can only be initialized once.
        init_metrics(desc).unwrap_err();
    }

    #[test]
    fn test_emit_id_defaults_to_false() {
        let cfg: MetricsConfig = serde_json::from_str(r#"{"metrics_path": "metrics"}"#).unwrap();
        assert!(!cfg.emit_id);
        assert_eq!(cfg.properties, None);

        let cfg: MetricsConfig =
            serde_json::from_str(r#"{"metrics_path": "metrics", "emit_id": true}"#).unwrap();
        assert!(cfg.emit_id);
    }
}
