// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use micro_http::StatusCode;
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::balloon::{
    BalloonDeviceConfig, BalloonUpdateConfig, BalloonUpdateStatsConfig,
};

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_get_balloon(
    path_second_token: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    match path_second_token {
        Some(stats_path) => match stats_path {
            "statistics" => Ok(ParsedRequest::new_sync(VmmAction::GetBalloonStats)),
            _ => Err(RequestError::Generic(
                StatusCode::BadRequest,
                format!("Unrecognized GET request path `{}`.", stats_path),
            )),
        },
        None => Ok(ParsedRequest::new_sync(VmmAction::GetBalloonConfig)),
    }
}

pub(crate) fn parse_put_balloon(body: &Body) -> Result<ParsedRequest, RequestError> {
    Ok(ParsedRequest::new_sync(VmmAction::SetBalloonDevice(
        serde_json::from_slice::<BalloonDeviceConfig>(body.raw())?,
    )))
}

pub(crate) fn parse_patch_balloon(
    body: &Body,
    path_second_token: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    match path_second_token {
        Some(config_path) => match config_path {
            "statistics" => Ok(ParsedRequest::new_sync(VmmAction::UpdateBalloonStatistics(
                serde_json::from_slice::<BalloonUpdateStatsConfig>(body.raw())?,
            ))),
            _ => Err(RequestError::Generic(
                StatusCode::BadRequest,
                format!("Unrecognized PATCH request path `{}`.", config_path),
            )),
        },
        None => Ok(ParsedRequest::new_sync(VmmAction::UpdateBalloon(
            serde_json::from_slice::<BalloonUpdateConfig>(body.raw())?,
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_get_balloon_request() {
        parse_get_balloon(None).unwrap();

        parse_get_balloon(Some("unrelated")).unwrap_err();

        parse_get_balloon(Some("statistics")).unwrap();
    }

    #[test]
    fn test_parse_patch_balloon_request() {
        parse_patch_balloon(&Body::new("invalid_payload"), None).unwrap_err();

        // PATCH with invalid fields.
        let body = r#"{
            "amount_mib": "bar",
            "foo": "bar"
        }"#;
        parse_patch_balloon(&Body::new(body), None).unwrap_err();

        // PATCH with invalid types on fields. Adding a polling interval as string instead of bool.
        let body = r#"{
            "amount_mib": 1000,
            "stats_polling_interval_s": "false"
        }"#;
        let res = parse_patch_balloon(&Body::new(body), None);
        res.unwrap_err();

        // PATCH with invalid types on fields. Adding a amount_mib as a negative number.
        let body = r#"{
            "amount_mib": -1000,
            "stats_polling_interval_s": true
        }"#;
        let res = parse_patch_balloon(&Body::new(body), None);
        res.unwrap_err();

        // PATCH on statistics with missing ppolling interval field.
        let body = r#"{
            "amount_mib": 100
        }"#;
        let res = parse_patch_balloon(&Body::new(body), Some("statistics"));
        res.unwrap_err();

        // PATCH with missing amount_mib field.
        let body = r#"{
            "stats_polling_interval_s": 0
        }"#;
        let res = parse_patch_balloon(&Body::new(body), None);
        res.unwrap_err();

        // PATCH that tries to update something else other than allowed fields.
        let body = r#"{
            "amount_mib": "dummy_id",
            "stats_polling_interval_s": "dummy_host"
        }"#;
        let res = parse_patch_balloon(&Body::new(body), None);
        res.unwrap_err();

        // PATCH with payload that is not a json.
        let body = r#"{
            "fields": "dummy_field"
        }"#;
        parse_patch_balloon(&Body::new(body), None).unwrap_err();

        // PATCH on unrecognized path.
        let body = r#"{
            "fields": "dummy_field"
        }"#;
        parse_patch_balloon(&Body::new(body), Some("config")).unwrap_err();

        let body = r#"{
            "amount_mib": 1
        }"#;
        let expected_config = BalloonUpdateConfig { amount_mib: 1 };
        assert_eq!(
            vmm_action_from_request(parse_patch_balloon(&Body::new(body), None).unwrap()),
            VmmAction::UpdateBalloon(expected_config)
        );

        let body = r#"{
            "stats_polling_interval_s": 1
        }"#;
        let expected_config = BalloonUpdateStatsConfig {
            stats_polling_interval_s: 1,
        };
        assert_eq!(
            vmm_action_from_request(
                parse_patch_balloon(&Body::new(body), Some("statistics")).unwrap()
            ),
            VmmAction::UpdateBalloonStatistics(expected_config)
        );
    }

    #[test]
    fn test_parse_put_balloon_request() {
        parse_put_balloon(&Body::new("invalid_payload")).unwrap_err();

        // PUT with invalid fields.
        let body = r#"{
            "amount_mib": "bar",
            "is_read_only": false
        }"#;
        parse_put_balloon(&Body::new(body)).unwrap_err();

        // PUT with valid input fields.
        let body = r#"{
            "amount_mib": 1000,
            "deflate_on_oom": true,
            "stats_polling_interval_s": 0
        }"#;
        parse_put_balloon(&Body::new(body)).unwrap();
    }
}
