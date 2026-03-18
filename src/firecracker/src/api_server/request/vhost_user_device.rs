// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::vhost_user_device::VhostUserDeviceConfig;

use super::super::parsed_request::{ParsedRequest, RequestError, checked_id};
use super::{Body, StatusCode};

pub(crate) fn parse_put_vhost_user_device(
    body: &Body,
    id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.vhost_user_count.inc();
    let id = if let Some(id) = id_from_path {
        checked_id(id)?
    } else {
        METRICS.put_api_requests.vhost_user_fails.inc();
        return Err(RequestError::EmptyID);
    };

    let device_cfg =
        serde_json::from_slice::<VhostUserDeviceConfig>(body.raw()).inspect_err(|_| {
            METRICS.put_api_requests.vhost_user_fails.inc();
        })?;

    if id != device_cfg.id {
        METRICS.put_api_requests.vhost_user_fails.inc();
        Err(RequestError::Generic(
            StatusCode::BadRequest,
            "The id from the path does not match the id from the body!".to_string(),
        ))
    } else {
        Ok(ParsedRequest::new_sync(VmmAction::InsertVhostUserDevice(
            device_cfg,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_vhost_user_device_request() {
        parse_put_vhost_user_device(&Body::new("invalid_payload"), None).unwrap_err();
        parse_put_vhost_user_device(&Body::new("invalid_payload"), Some("id")).unwrap_err();

        let body = r#"{
            "id": "bar",
            "device_type": 26,
            "socket": "/tmp/test.sock",
            "num_queues": 2
        }"#;
        parse_put_vhost_user_device(&Body::new(body), Some("1")).unwrap_err();

        let body = r#"{
            "foo": "1"
        }"#;
        parse_put_vhost_user_device(&Body::new(body), Some("1")).unwrap_err();

        let body = r#"{
            "id": "fs0",
            "device_type": 26,
            "socket": "/tmp/virtiofsd.sock",
            "num_queues": 2
        }"#;
        let r = vmm_action_from_request(
            parse_put_vhost_user_device(&Body::new(body), Some("fs0")).unwrap(),
        );

        let expected_config = VhostUserDeviceConfig {
            id: "fs0".to_string(),
            device_type: 26,
            socket: "/tmp/virtiofsd.sock".to_string(),
            num_queues: 2,
            queue_size: None,
        };
        assert_eq!(r, VmmAction::InsertVhostUserDevice(expected_config));
    }
}
