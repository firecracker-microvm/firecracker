// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::pmem::PmemConfig;

use super::super::parsed_request::{ParsedRequest, RequestError, checked_id};
use super::{Body, StatusCode};

pub(crate) fn parse_put_pmem(
    body: &Body,
    id_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    METRICS.put_api_requests.pmem_count.inc();
    let id = if let Some(id) = id_from_path {
        checked_id(id)?
    } else {
        METRICS.put_api_requests.pmem_fails.inc();
        return Err(RequestError::EmptyID);
    };

    let device_cfg = serde_json::from_slice::<PmemConfig>(body.raw()).inspect_err(|_| {
        METRICS.put_api_requests.pmem_fails.inc();
    })?;

    if id != device_cfg.id {
        METRICS.put_api_requests.pmem_fails.inc();
        Err(RequestError::Generic(
            StatusCode::BadRequest,
            "The id from the path does not match the id from the body!".to_string(),
        ))
    } else {
        Ok(ParsedRequest::new_sync(VmmAction::InsertPmemDevice(
            device_cfg,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_pmem_request() {
        parse_put_pmem(&Body::new("invalid_payload"), None).unwrap_err();
        parse_put_pmem(&Body::new("invalid_payload"), Some("id")).unwrap_err();

        let body = r#"{
            "id": "bar",
        }"#;
        parse_put_pmem(&Body::new(body), Some("1")).unwrap_err();
        let body = r#"{
            "foo": "1",
        }"#;
        parse_put_pmem(&Body::new(body), Some("1")).unwrap_err();

        let body = r#"{
            "id": "1000",
            "path_on_host": "dummy",
            "root_device": true,
            "read_only": true
        }"#;
        let r = vmm_action_from_request(parse_put_pmem(&Body::new(body), Some("1000")).unwrap());

        let expected_config = PmemConfig {
            id: "1000".to_string(),
            path_on_host: "dummy".to_string(),
            root_device: true,
            read_only: true,
        };
        assert_eq!(r, VmmAction::InsertPmemDevice(expected_config));
    }
}
