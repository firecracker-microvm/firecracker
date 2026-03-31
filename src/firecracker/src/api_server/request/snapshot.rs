// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::de::Error as DeserializeError;
use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::snapshot::{
    CreateSnapshotParams, DriveOverride, DriveOverrideBacking, DriveOverrideConfig,
    LoadSnapshotConfig, LoadSnapshotParams, MemBackendConfig, MemBackendType, Vm, VmState,
};

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::super::request::{Body, Method, StatusCode};

/// Deprecation message for the `mem_file_path` field.
const LOAD_DEPRECATION_MESSAGE: &str =
    "PUT /snapshot/load: mem_file_path and enable_diff_snapshots fields are deprecated.";
/// None of the `mem_backend` or `mem_file_path` fields has been specified.
pub const MISSING_FIELD: &str =
    "missing field: either `mem_backend` or `mem_file_path` is required";
/// Both the `mem_backend` and `mem_file_path` fields have been specified.
/// Only specifying one of them is allowed.
pub const TOO_MANY_FIELDS: &str =
    "too many fields: either `mem_backend` or `mem_file_path` exclusively is required";
/// None of the `path_on_host` or `socket` fields has been specified for a drive override.
pub const DRIVE_OVERRIDE_MISSING_FIELD: &str =
    "missing field: either `path_on_host` or `socket` is required for each drive override";
/// Both the `path_on_host` and `socket` fields have been specified for a drive override.
/// Only specifying one of them is allowed.
pub const DRIVE_OVERRIDE_TOO_MANY_FIELDS: &str = "too many fields: either `path_on_host` or `socket` exclusively is required for each drive override";

pub(crate) fn parse_put_snapshot(
    body: &Body,
    request_type_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    match request_type_from_path {
        Some(request_type) => match request_type {
            "create" => parse_put_snapshot_create(body),
            "load" => parse_put_snapshot_load(body),
            _ => Err(RequestError::InvalidPathMethod(
                format!("/snapshot/{}", request_type),
                Method::Put,
            )),
        },
        None => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "Missing snapshot operation type.".to_string(),
        )),
    }
}

pub(crate) fn parse_patch_vm_state(body: &Body) -> Result<ParsedRequest, RequestError> {
    let vm = serde_json::from_slice::<Vm>(body.raw())?;

    match vm.state {
        VmState::Paused => Ok(ParsedRequest::new_sync(VmmAction::Pause)),
        VmState::Resumed => Ok(ParsedRequest::new_sync(VmmAction::Resume)),
    }
}

fn parse_put_snapshot_create(body: &Body) -> Result<ParsedRequest, RequestError> {
    let snapshot_config = serde_json::from_slice::<CreateSnapshotParams>(body.raw())?;
    Ok(ParsedRequest::new_sync(VmmAction::CreateSnapshot(
        snapshot_config,
    )))
}

/// Validate that a [`DriveOverrideConfig`] specifies exactly one of
/// `path_on_host` or `socket`, and convert it to the internal [`DriveOverride`].
fn convert_drive_override(cfg: DriveOverrideConfig) -> Result<DriveOverride, RequestError> {
    let backing = match (cfg.path_on_host, cfg.socket) {
        (Some(path), None) => DriveOverrideBacking::PathOnHost(path),
        (None, Some(socket)) => DriveOverrideBacking::Socket(socket),
        (Some(_), Some(_)) => {
            return Err(RequestError::SerdeJson(serde_json::Error::custom(
                DRIVE_OVERRIDE_TOO_MANY_FIELDS,
            )));
        }
        (None, None) => {
            return Err(RequestError::SerdeJson(serde_json::Error::custom(
                DRIVE_OVERRIDE_MISSING_FIELD,
            )));
        }
    };
    Ok(DriveOverride {
        drive_id: cfg.drive_id,
        backing,
    })
}

fn parse_put_snapshot_load(body: &Body) -> Result<ParsedRequest, RequestError> {
    let snapshot_config = serde_json::from_slice::<LoadSnapshotConfig>(body.raw())?;

    match (&snapshot_config.mem_backend, &snapshot_config.mem_file_path) {
        // Ensure `mem_file_path` and `mem_backend` fields are not present at the same time.
        (Some(_), Some(_)) => {
            return Err(RequestError::SerdeJson(serde_json::Error::custom(
                TOO_MANY_FIELDS,
            )));
        }
        // Ensure that one of `mem_file_path` or `mem_backend` fields is always specified.
        (None, None) => {
            return Err(RequestError::SerdeJson(serde_json::Error::custom(
                MISSING_FIELD,
            )));
        }
        _ => {}
    }

    // Check for the presence of deprecated `mem_file_path` field and create
    // deprecation message if found.
    let mut deprecation_message = None;
    #[allow(deprecated)]
    if snapshot_config.mem_file_path.is_some() || snapshot_config.enable_diff_snapshots {
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

    // Validate each drive override and convert to the internal representation.
    let drive_overrides = snapshot_config
        .drive_overrides
        .into_iter()
        .map(convert_drive_override)
        .collect::<Result<Vec<_>, _>>()?;

    let snapshot_params = LoadSnapshotParams {
        snapshot_path: snapshot_config.snapshot_path,
        mem_backend,
        #[allow(deprecated)]
        track_dirty_pages: snapshot_config.enable_diff_snapshots
            || snapshot_config.track_dirty_pages,
        resume_vm: snapshot_config.resume_vm,
        network_overrides: snapshot_config.network_overrides,
        vsock_override: snapshot_config.vsock_override,
        drive_overrides,
        clock_realtime: snapshot_config.clock_realtime,
    };

    // Construct the `ParsedRequest` object.
    let mut parsed_req = ParsedRequest::new_sync(VmmAction::LoadSnapshot(snapshot_params));

    // If `mem_file_path` was present, set the deprecation message in `parsing_info`.
    if let Some(msg) = deprecation_message {
        parsed_req.parsing_info().append_deprecation_message(msg);
    }

    Ok(parsed_req)
}

#[cfg(test)]
mod tests {
    use vmm::vmm_config::snapshot::{
        DriveOverride, DriveOverrideBacking, MemBackendConfig, MemBackendType, NetworkOverride,
    };

    use super::*;
    use crate::api_server::parsed_request::tests::{depr_action_from_req, vmm_action_from_request};

    #[test]
    fn test_parse_put_snapshot() {
        use std::path::PathBuf;

        use vmm::vmm_config::snapshot::SnapshotType;

        let body = r#"{
            "snapshot_type": "Diff",
            "snapshot_path": "foo",
            "mem_file_path": "bar"
        }"#;
        let expected_config = CreateSnapshotParams {
            snapshot_type: SnapshotType::Diff,
            snapshot_path: PathBuf::from("foo"),
            mem_file_path: PathBuf::from("bar"),
        };
        assert_eq!(
            vmm_action_from_request(parse_put_snapshot(&Body::new(body), Some("create")).unwrap()),
            VmmAction::CreateSnapshot(expected_config)
        );

        let body = r#"{
            "snapshot_path": "foo",
            "mem_file_path": "bar"
        }"#;
        let expected_config = CreateSnapshotParams {
            snapshot_type: SnapshotType::Full,
            snapshot_path: PathBuf::from("foo"),
            mem_file_path: PathBuf::from("bar"),
        };
        assert_eq!(
            vmm_action_from_request(parse_put_snapshot(&Body::new(body), Some("create")).unwrap()),
            VmmAction::CreateSnapshot(expected_config)
        );

        let invalid_body = r#"{
            "invalid_field": "foo",
            "mem_file_path": "bar"
        }"#;
        parse_put_snapshot(&Body::new(invalid_body), Some("create")).unwrap_err();

        let body = r#"{
            "snapshot_path": "foo",
            "mem_backend": {
                "backend_path": "bar",
                "backend_type": "File"
            }
        }"#;
        let expected_config = LoadSnapshotParams {
            snapshot_path: PathBuf::from("foo"),
            mem_backend: MemBackendConfig {
                backend_path: PathBuf::from("bar"),
                backend_type: MemBackendType::File,
            },
            track_dirty_pages: false,
            resume_vm: false,
            network_overrides: vec![],
            vsock_override: None,
            drive_overrides: vec![],
            clock_realtime: false,
        };
        let mut parsed_request = parse_put_snapshot(&Body::new(body), Some("load")).unwrap();
        assert!(
            parsed_request
                .parsing_info()
                .take_deprecation_message()
                .is_none()
        );
        assert_eq!(
            vmm_action_from_request(parsed_request),
            VmmAction::LoadSnapshot(expected_config)
        );

        let body = r#"{
            "snapshot_path": "foo",
            "mem_backend": {
                "backend_path": "bar",
                "backend_type": "File"
            },
            "track_dirty_pages": true
        }"#;
        let expected_config = LoadSnapshotParams {
            snapshot_path: PathBuf::from("foo"),
            mem_backend: MemBackendConfig {
                backend_path: PathBuf::from("bar"),
                backend_type: MemBackendType::File,
            },
            track_dirty_pages: true,
            resume_vm: false,
            network_overrides: vec![],
            vsock_override: None,
            drive_overrides: vec![],
            clock_realtime: false,
        };
        let mut parsed_request = parse_put_snapshot(&Body::new(body), Some("load")).unwrap();
        assert!(
            parsed_request
                .parsing_info()
                .take_deprecation_message()
                .is_none()
        );
        assert_eq!(
            vmm_action_from_request(parsed_request),
            VmmAction::LoadSnapshot(expected_config)
        );

        let body = r#"{
            "snapshot_path": "foo",
            "mem_backend": {
                "backend_path": "bar",
                "backend_type": "Uffd"
            },
            "resume_vm": true
        }"#;
        let expected_config = LoadSnapshotParams {
            snapshot_path: PathBuf::from("foo"),
            mem_backend: MemBackendConfig {
                backend_path: PathBuf::from("bar"),
                backend_type: MemBackendType::Uffd,
            },
            track_dirty_pages: false,
            resume_vm: true,
            network_overrides: vec![],
            vsock_override: None,
            drive_overrides: vec![],
            clock_realtime: false,
        };
        let mut parsed_request = parse_put_snapshot(&Body::new(body), Some("load")).unwrap();
        assert!(
            parsed_request
                .parsing_info()
                .take_deprecation_message()
                .is_none()
        );
        assert_eq!(
            vmm_action_from_request(parsed_request),
            VmmAction::LoadSnapshot(expected_config)
        );

        let body = r#"{
            "snapshot_path": "foo",
            "mem_backend": {
                "backend_path": "bar",
                "backend_type": "Uffd"
            },
            "resume_vm": true,
            "network_overrides": [
                {
                    "iface_id": "eth0",
                    "host_dev_name": "vmtap2"
                }
            ]
        }"#;
        let expected_config = LoadSnapshotParams {
            snapshot_path: PathBuf::from("foo"),
            mem_backend: MemBackendConfig {
                backend_path: PathBuf::from("bar"),
                backend_type: MemBackendType::Uffd,
            },
            track_dirty_pages: false,
            resume_vm: true,
            network_overrides: vec![NetworkOverride {
                iface_id: String::from("eth0"),
                host_dev_name: String::from("vmtap2"),
            }],
            vsock_override: None,
            drive_overrides: vec![],
            clock_realtime: false,
        };
        let mut parsed_request = parse_put_snapshot(&Body::new(body), Some("load")).unwrap();
        assert!(
            parsed_request
                .parsing_info()
                .take_deprecation_message()
                .is_none()
        );
        assert_eq!(
            vmm_action_from_request(parsed_request),
            VmmAction::LoadSnapshot(expected_config)
        );

        let body = r#"{
            "snapshot_path": "foo",
            "mem_backend": {
                "backend_path": "bar",
                "backend_type": "File"
            },
            "resume_vm": true,
            "drive_overrides": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": "/new/path/rootfs.ext4"
                }
            ]
        }"#;
        let expected_config = LoadSnapshotParams {
            snapshot_path: PathBuf::from("foo"),
            mem_backend: MemBackendConfig {
                backend_path: PathBuf::from("bar"),
                backend_type: MemBackendType::File,
            },
            track_dirty_pages: false,
            resume_vm: true,
            network_overrides: vec![],
            vsock_override: None,
            drive_overrides: vec![DriveOverride {
                drive_id: String::from("rootfs"),
                backing: DriveOverrideBacking::PathOnHost(String::from("/new/path/rootfs.ext4")),
            }],
            clock_realtime: false,
        };
        let mut parsed_request = parse_put_snapshot(&Body::new(body), Some("load")).unwrap();
        assert!(
            parsed_request
                .parsing_info()
                .take_deprecation_message()
                .is_none()
        );
        assert_eq!(
            vmm_action_from_request(parsed_request),
            VmmAction::LoadSnapshot(expected_config)
        );

        let body = r#"{
            "snapshot_path": "foo",
            "mem_file_path": "bar",
            "resume_vm": true
        }"#;
        let expected_config = LoadSnapshotParams {
            snapshot_path: PathBuf::from("foo"),
            mem_backend: MemBackendConfig {
                backend_path: PathBuf::from("bar"),
                backend_type: MemBackendType::File,
            },
            track_dirty_pages: false,
            resume_vm: true,
            network_overrides: vec![],
            vsock_override: None,
            drive_overrides: vec![],
            clock_realtime: false,
        };
        let parsed_request = parse_put_snapshot(&Body::new(body), Some("load")).unwrap();
        assert_eq!(
            depr_action_from_req(parsed_request, Some(LOAD_DEPRECATION_MESSAGE.to_string())),
            VmmAction::LoadSnapshot(expected_config)
        );

        let body = r#"{
            "snapshot_path": "foo",
            "mem_backend": {
                "backend_path": "bar"
            }
        }"#;
        assert_eq!(
            parse_put_snapshot(&Body::new(body), Some("load"))
                .err()
                .unwrap()
                .to_string(),
            "An error occurred when deserializing the json body of a request: missing field \
             `backend_type` at line 5 column 13."
        );

        let body = r#"{
            "snapshot_path": "foo",
            "mem_backend": {
                "backend_type": "File",
            }
        }"#;
        assert_eq!(
            parse_put_snapshot(&Body::new(body), Some("load"))
                .err()
                .unwrap()
                .to_string(),
            "An error occurred when deserializing the json body of a request: trailing comma at \
             line 5 column 13."
        );

        let body = r#"{
            "snapshot_path": "foo",
            "mem_file_path": "bar",
            "mem_backend": {
                "backend_path": "bar",
                "backend_type": "Uffd"
            }
        }"#;
        assert_eq!(
            parse_put_snapshot(&Body::new(body), Some("load"))
                .err()
                .unwrap()
                .to_string(),
            RequestError::SerdeJson(serde_json::Error::custom(TOO_MANY_FIELDS.to_string()))
                .to_string()
        );

        let body = r#"{
            "snapshot_path": "foo"
        }"#;
        assert_eq!(
            parse_put_snapshot(&Body::new(body), Some("load"))
                .err()
                .unwrap()
                .to_string(),
            RequestError::SerdeJson(serde_json::Error::custom(MISSING_FIELD.to_string()))
                .to_string()
        );

        let body = r#"{
            "mem_backend": {
                "backend_path": "bar",
                "backend_type": "Uffd"
            }
        }"#;
        assert_eq!(
            parse_put_snapshot(&Body::new(body), Some("load"))
                .err()
                .unwrap()
                .to_string(),
            "An error occurred when deserializing the json body of a request: missing field \
             `snapshot_path` at line 6 column 9."
        );
        parse_put_snapshot(&Body::new(body), Some("invalid")).unwrap_err();
        parse_put_snapshot(&Body::new(body), None).unwrap_err();

        // Drive override that supplies both `path_on_host` and `socket` must be rejected.
        let body = r#"{
            "snapshot_path": "foo",
            "mem_backend": {
                "backend_path": "bar",
                "backend_type": "File"
            },
            "drive_overrides": [
                {
                    "drive_id": "rootfs",
                    "path_on_host": "/p",
                    "socket": "/s"
                }
            ]
        }"#;
        assert_eq!(
            parse_put_snapshot(&Body::new(body), Some("load"))
                .err()
                .unwrap()
                .to_string(),
            RequestError::SerdeJson(serde_json::Error::custom(
                DRIVE_OVERRIDE_TOO_MANY_FIELDS.to_string()
            ))
            .to_string()
        );

        // Drive override that supplies neither field must be rejected.
        let body = r#"{
            "snapshot_path": "foo",
            "mem_backend": {
                "backend_path": "bar",
                "backend_type": "File"
            },
            "drive_overrides": [
                { "drive_id": "rootfs" }
            ]
        }"#;
        assert_eq!(
            parse_put_snapshot(&Body::new(body), Some("load"))
                .err()
                .unwrap()
                .to_string(),
            RequestError::SerdeJson(serde_json::Error::custom(
                DRIVE_OVERRIDE_MISSING_FIELD.to_string()
            ))
            .to_string()
        );
    }

    #[test]
    fn test_parse_patch_vm_state() {
        let body = r#"{
            "state": "Paused"
        }"#;
        assert!(
            parse_patch_vm_state(&Body::new(body))
                .unwrap()
                .eq(&ParsedRequest::new_sync(VmmAction::Pause))
        );

        let body = r#"{
            "state": "Resumed"
        }"#;
        assert!(
            parse_patch_vm_state(&Body::new(body))
                .unwrap()
                .eq(&ParsedRequest::new_sync(VmmAction::Resume))
        );

        let invalid_body = r#"{
            "invalid": "Paused"
        }"#;
        parse_patch_vm_state(&Body::new(invalid_body)).unwrap_err();
    }
}
