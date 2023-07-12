// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// use crate::request::{Body, Method, StatusCode};
use http::StatusCode;
use hyper::Method;
use logger::{IncMetric, METRICS};
use serde::de::Error as DeserializeError;
use vmm::vmm_config::snapshot::{
    CreateSnapshotParams, LoadSnapshotConfig, LoadSnapshotParams, MemBackendConfig, MemBackendType,
    Vm, VmState,
};

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};

/// Deprecation message for the `mem_file_path` field.
const LOAD_DEPRECATION_MESSAGE: &str = "PUT /snapshot/load: mem_file_path field is deprecated.";
/// None of the `mem_backend` or `mem_file_path` fields has been specified.
pub const MISSING_FIELD: &str =
    "missing field: either `mem_backend` or `mem_file_path` is required";
/// Both the `mem_backend` and `mem_file_path` fields have been specified.
/// Only specifying one of them is allowed.
pub const TOO_MANY_FIELDS: &str =
    "too many fields: either `mem_backend` or `mem_file_path` exclusively is required";

pub(crate) fn parse_put_snapshot(
    body: serde_json::Value,
    request_type_from_path: Option<&str>,
) -> Result<ParsedRequest, Error> {
    match request_type_from_path {
        Some(request_type) => match request_type {
            "create" => Ok(ParsedRequest::new_sync(VmmAction::CreateSnapshot(
                serde_json::from_value::<CreateSnapshotParams>(body)?,
            ))),
            "load" => {
                let snapshot_config = serde_json::from_value::<LoadSnapshotConfig>(body)?;

                match (&snapshot_config.mem_backend, &snapshot_config.mem_file_path) {
                    // Ensure `mem_file_path` and `mem_backend` fields are not present at the same
                    // time.
                    (Some(_), Some(_)) => {
                        return Err(Error::SerdeJson(serde_json::Error::custom(TOO_MANY_FIELDS)))
                    }
                    // Ensure that one of `mem_file_path` or `mem_backend` fields is always
                    // specified.
                    (None, None) => {
                        return Err(Error::SerdeJson(serde_json::Error::custom(MISSING_FIELD)))
                    }
                    _ => {}
                }

                // Check for the presence of deprecated `mem_file_path` field and create
                // deprecation message if found.
                let mut deprecation_message = None;
                if snapshot_config.mem_file_path.is_some() {
                    // `mem_file_path` field in request is deprecated.
                    METRICS.deprecated_api.deprecated_http_api_calls.inc();
                    deprecation_message = Some(LOAD_DEPRECATION_MESSAGE);
                }

                // If `mem_file_path` is specified instead of `mem_backend`, we construct the
                // `MemBackendConfig` object from the path specified, with `File` as backend type.
                let mem_backend = match snapshot_config.mem_backend {
                    Some(backend_cfg) => backend_cfg,
                    None => {
                        MemBackendConfig {
                            // This is safe to unwrap() because we ensure above that one of the two:
                            // either `mem_file_path` or `mem_backend` field is always specified.
                            backend_path: snapshot_config.mem_file_path.unwrap(),
                            backend_type: MemBackendType::File,
                        }
                    }
                };

                let snapshot_params = LoadSnapshotParams {
                    snapshot_path: snapshot_config.snapshot_path,
                    mem_backend,
                    enable_diff_snapshots: snapshot_config.enable_diff_snapshots,
                    resume_vm: snapshot_config.resume_vm,
                };

                // Construct the `ParsedRequest` object.
                let mut parsed_req =
                    ParsedRequest::new_sync(VmmAction::LoadSnapshot(snapshot_params));

                // If `mem_file_path` was present, set the deprecation message in `parsing_info`.
                if let Some(msg) = deprecation_message {
                    parsed_req.parsing_info().append_deprecation_message(msg);
                }

                Ok(parsed_req)
            }
            _ => Err(Error::InvalidPathMethod(
                format!("/snapshot/{}", request_type),
                Method::PUT,
            )),
        },
        None => Err(Error::Generic(
            StatusCode::BAD_REQUEST,
            "Missing snapshot operation type.".to_string(),
        )),
    }
}

pub(crate) fn parse_patch_vm_state(body: serde_json::Value) -> Result<ParsedRequest, Error> {
    let vm = serde_json::from_value::<Vm>(body)?;

    match vm.state {
        VmState::Paused => Ok(ParsedRequest::new_sync(VmmAction::Pause)),
        VmState::Resumed => Ok(ParsedRequest::new_sync(VmmAction::Resume)),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use vmm::vmm_config::snapshot::{MemBackendConfig, MemBackendType};

    use super::*;
    use crate::parsed_request::tests::vmm_action_from_request;
    #[test]
    fn test_parse_put_snapshot() {
        use std::path::PathBuf;

        use vmm::vmm_config::snapshot::SnapshotType;

        let body = json!({
          "snapshot_type": "Diff",
          "snapshot_path": "foo",
          "mem_file_path": "bar",
          "version": "0.23.0"
        });

        let mut expected_cfg = CreateSnapshotParams {
            snapshot_type: SnapshotType::Diff,
            snapshot_path: PathBuf::from("foo"),
            mem_file_path: PathBuf::from("bar"),
            version: Some(String::from("0.23.0")),
        };

        match vmm_action_from_request(parse_put_snapshot(body, Some("create")).unwrap()) {
            VmmAction::CreateSnapshot(cfg) => assert_eq!(cfg, expected_cfg),
            _ => panic!("Test failed."),
        }

        let body = json!({
          "snapshot_path": "foo",
          "mem_file_path": "bar"
        });

        expected_cfg = CreateSnapshotParams {
            snapshot_type: SnapshotType::Full,
            snapshot_path: PathBuf::from("foo"),
            mem_file_path: PathBuf::from("bar"),
            version: None,
        };

        match vmm_action_from_request(parse_put_snapshot(body, Some("create")).unwrap()) {
            VmmAction::CreateSnapshot(cfg) => assert_eq!(cfg, expected_cfg),
            _ => panic!("Test failed."),
        }

        let invalid_body = json!({
          "invalid_field": "foo",
          "mem_file_path": "bar"
        });

        assert!(parse_put_snapshot(invalid_body, Some("create")).is_err());

        let body = json!({
          "snapshot_path": "foo",
          "mem_backend": {
              "backend_path": "bar",
              "backend_type": "File"
          }
        });

        let mut expected_cfg = LoadSnapshotParams {
            snapshot_path: PathBuf::from("foo"),
            mem_backend: MemBackendConfig {
                backend_path: PathBuf::from("bar"),
                backend_type: MemBackendType::File,
            },
            enable_diff_snapshots: false,
            resume_vm: false,
        };

        let parsed_request = parse_put_snapshot(body, Some("load")).unwrap();

        match vmm_action_from_request(parsed_request) {
            VmmAction::LoadSnapshot(cfg) => assert_eq!(cfg, expected_cfg),
            _ => panic!("Test failed."),
        }

        let body = json!({
          "snapshot_path": "foo",
          "mem_backend": {
              "backend_path": "bar",
              "backend_type": "File"
          },
          "enable_diff_snapshots": true
        });

        expected_cfg = LoadSnapshotParams {
            snapshot_path: PathBuf::from("foo"),
            mem_backend: MemBackendConfig {
                backend_path: PathBuf::from("bar"),
                backend_type: MemBackendType::File,
            },
            enable_diff_snapshots: true,
            resume_vm: false,
        };

        let parsed_request = parse_put_snapshot(body, Some("load")).unwrap();
        match vmm_action_from_request(parsed_request) {
            VmmAction::LoadSnapshot(cfg) => assert_eq!(cfg, expected_cfg),
            _ => panic!("Test failed."),
        }

        let body = json!({
          "snapshot_path": "foo",
          "mem_backend": {
              "backend_path": "bar",
              "backend_type": "Uffd"
          },
          "resume_vm": true
        });

        expected_cfg = LoadSnapshotParams {
            snapshot_path: PathBuf::from("foo"),
            mem_backend: MemBackendConfig {
                backend_path: PathBuf::from("bar"),
                backend_type: MemBackendType::Uffd,
            },
            enable_diff_snapshots: false,
            resume_vm: true,
        };

        let parsed_request = parse_put_snapshot(body, Some("load")).unwrap();
        match vmm_action_from_request(parsed_request) {
            VmmAction::LoadSnapshot(cfg) => assert_eq!(cfg, expected_cfg),
            _ => panic!("Test failed."),
        }

        let body = json!({
          "snapshot_path": "foo",
          "mem_backend": {
              "backend_path": "bar"
          }
        });

        assert_eq!(
            parse_put_snapshot(body, Some("load"))
                .err()
                .unwrap()
                .to_string(),
            "An error occurred when deserializing the json body of a request: missing field \
             `backend_type` at line 5 column 17."
        );

        let body = json!({
          "snapshot_path": "foo",
          "mem_backend": {
              "backend_type": "File",
          }
        });

        assert_eq!(
            parse_put_snapshot(body, Some("load"))
                .err()
                .unwrap()
                .to_string(),
            "An error occurred when deserializing the json body of a request: trailing comma at \
             line 5 column 17."
        );

        let body = json!({
          "snapshot_path": "foo",
          "mem_file_path": "bar",
          "mem_backend": {
              "backend_path": "bar",
              "backend_type": "Uffd"
          }
        });

        assert_eq!(
            parse_put_snapshot(body, Some("load"))
                .err()
                .unwrap()
                .to_string(),
            Error::SerdeJson(serde_json::Error::custom(TOO_MANY_FIELDS.to_string())).to_string()
        );

        let body = json!({
          "snapshot_path": "foo"
        });

        assert_eq!(
            parse_put_snapshot(body, Some("load"))
                .err()
                .unwrap()
                .to_string(),
            Error::SerdeJson(serde_json::Error::custom(MISSING_FIELD.to_string())).to_string()
        );

        let body = json!({
          "mem_backend": {
              "backend_path": "bar",
              "backend_type": "Uffd"
          }
        });

        assert_eq!(
            parse_put_snapshot(body.clone(), Some("load"))
                .err()
                .unwrap()
                .to_string(),
            "An error occurred when deserializing the json body of a request: missing field \
             `snapshot_path` at line 6 column 15."
        );

        assert!(parse_put_snapshot(body.clone(), Some("invalid")).is_err());
        assert!(parse_put_snapshot(body, None).is_err());
    }

    #[test]
    fn test_parse_patch_vm_state() {
        let body = json!({
          "state": "Paused"
        });

        assert!(parse_patch_vm_state(body)
            .unwrap()
            .eq(&ParsedRequest::new_sync(VmmAction::Pause)));

        let body = json!({
          "state": "Resumed"
        });

        assert!(parse_patch_vm_state(body)
            .unwrap()
            .eq(&ParsedRequest::new_sync(VmmAction::Resume)));

        let invalid_body = json!({
          "invalid": "Paused"
        });

        assert!(parse_patch_vm_state(invalid_body).is_err());
    }
}
