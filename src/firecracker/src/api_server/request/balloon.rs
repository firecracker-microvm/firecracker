// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use micro_http::{Method, StatusCode};
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::balloon::{
    BalloonDeviceConfig, BalloonUpdateConfig, BalloonUpdateStatsConfig,
};

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;
use crate::api_server::parsed_request::method_to_error;

fn parse_get_hinting<'a, T>(mut path_tokens: T) -> Result<ParsedRequest, RequestError>
where
    T: Iterator<Item = &'a str>,
{
    match path_tokens.next() {
        Some("status") => Ok(ParsedRequest::new_sync(VmmAction::GetFreePageHintingStatus)),
        Some(stats_path) => Err(RequestError::Generic(
            StatusCode::BadRequest,
            format!("Unrecognized GET request path `/hinting/{stats_path}`."),
        )),
        None => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "Unrecognized GET request path `/hinting/`.".to_string(),
        )),
    }
}

pub(crate) fn parse_get_balloon<'a, T>(mut path_tokens: T) -> Result<ParsedRequest, RequestError>
where
    T: Iterator<Item = &'a str>,
{
    match path_tokens.next() {
        Some("statistics") => Ok(ParsedRequest::new_sync(VmmAction::GetBalloonStats)),
        Some("hinting") => parse_get_hinting(path_tokens),
        Some(stats_path) => Err(RequestError::Generic(
            StatusCode::BadRequest,
            format!("Unrecognized GET request path `{}`.", stats_path),
        )),
        None => Ok(ParsedRequest::new_sync(VmmAction::GetBalloonConfig)),
    }
}

pub(crate) fn parse_put_balloon(body: &Body) -> Result<ParsedRequest, RequestError> {
    Ok(ParsedRequest::new_sync(VmmAction::SetBalloonDevice(
        serde_json::from_slice::<BalloonDeviceConfig>(body.raw())?,
    )))
}

fn parse_patch_hinting<'a, T>(
    body: Option<&Body>,
    mut path_tokens: T,
) -> Result<ParsedRequest, RequestError>
where
    T: Iterator<Item = &'a str>,
{
    match path_tokens.next() {
        Some("start") => {
            let cmd = match body {
                None => Default::default(),
                Some(b) if b.is_empty() => Default::default(),
                Some(b) => serde_json::from_slice(b.raw())?,
            };

            Ok(ParsedRequest::new_sync(VmmAction::StartFreePageHinting(
                cmd,
            )))
        }
        Some("stop") => Ok(ParsedRequest::new_sync(VmmAction::StopFreePageHinting)),
        Some(stats_path) => Err(RequestError::Generic(
            StatusCode::BadRequest,
            format!("Unrecognized PATCH request path `/hinting/{stats_path}`."),
        )),
        None => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "Unrecognized PATCH request path `/hinting/`.".to_string(),
        )),
    }
}

pub(crate) fn parse_patch_balloon<'a, T>(
    body: Option<&Body>,
    mut path_tokens: T,
) -> Result<ParsedRequest, RequestError>
where
    T: Iterator<Item = &'a str>,
{
    match (path_tokens.next(), body) {
        (Some("statistics"), Some(body)) => {
            Ok(ParsedRequest::new_sync(VmmAction::UpdateBalloonStatistics(
                serde_json::from_slice::<BalloonUpdateStatsConfig>(body.raw())?,
            )))
        }
        (Some("hinting"), body) => parse_patch_hinting(body, path_tokens),
        (_, Some(body)) => Ok(ParsedRequest::new_sync(VmmAction::UpdateBalloon(
            serde_json::from_slice::<BalloonUpdateConfig>(body.raw())?,
        ))),
        (_, None) => method_to_error(Method::Patch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_get_balloon_request() {
        parse_get_balloon([].into_iter()).unwrap();

        parse_get_balloon(["unrelated"].into_iter()).unwrap_err();

        parse_get_balloon(["statistics"].into_iter()).unwrap();

        parse_get_balloon(["hinting", "status"].into_iter()).unwrap();
        parse_get_balloon(["hinting", "unrelated"].into_iter()).unwrap_err();
        parse_get_balloon(["hinting"].into_iter()).unwrap_err();
    }

    #[test]
    fn test_parse_patch_balloon_request() {
        parse_patch_balloon(Some(&Body::new("invalid_payload")), [].into_iter()).unwrap_err();

        // PATCH with invalid fields.
        let body = r#"{
            "amount_mib": "bar",
            "foo": "bar"
        }"#;
        parse_patch_balloon(Some(&Body::new(body)), [].into_iter()).unwrap_err();

        // PATCH with invalid types on fields. Adding a polling interval as string instead of bool.
        let body = r#"{
            "amount_mib": 1000,
            "stats_polling_interval_s": "false"
        }"#;
        let res = parse_patch_balloon(Some(&Body::new(body)), [].into_iter());
        res.unwrap_err();

        // PATCH with invalid types on fields. Adding a amount_mib as a negative number.
        let body = r#"{
            "amount_mib": -1000,
            "stats_polling_interval_s": true
        }"#;
        let res = parse_patch_balloon(Some(&Body::new(body)), [].into_iter());
        res.unwrap_err();

        // PATCH on statistics with missing ppolling interval field.
        let body = r#"{
            "amount_mib": 100
        }"#;
        let res = parse_patch_balloon(Some(&Body::new(body)), ["statistics"].into_iter());
        res.unwrap_err();

        // PATCH with missing amount_mib field.
        let body = r#"{
            "stats_polling_interval_s": 0
        }"#;
        let res = parse_patch_balloon(Some(&Body::new(body)), [].into_iter());
        res.unwrap_err();

        // PATCH that tries to update something else other than allowed fields.
        let body = r#"{
            "amount_mib": "dummy_id",
            "stats_polling_interval_s": "dummy_host"
        }"#;
        let res = parse_patch_balloon(Some(&Body::new(body)), [].into_iter());
        res.unwrap_err();

        // PATCH with payload that is not a json.
        let body = r#"{
            "fields": "dummy_field"
        }"#;
        parse_patch_balloon(Some(&Body::new(body)), [].into_iter()).unwrap_err();

        // PATCH on unrecognized path.
        let body = r#"{
            "fields": "dummy_field"
        }"#;
        parse_patch_balloon(Some(&Body::new(body)), ["config"].into_iter()).unwrap_err();

        let body = r#"{
            "amount_mib": 1
        }"#;
        let expected_config = BalloonUpdateConfig { amount_mib: 1 };
        assert_eq!(
            vmm_action_from_request(
                parse_patch_balloon(Some(&Body::new(body)), [].into_iter()).unwrap()
            ),
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
                parse_patch_balloon(Some(&Body::new(body)), ["statistics"].into_iter()).unwrap()
            ),
            VmmAction::UpdateBalloonStatistics(expected_config)
        );

        // PATCH start hinting run valid data
        let body = r#"{
            "acknowledge_on_stop": true
        }"#;
        parse_patch_balloon(Some(&Body::new(body)), ["hinting", "start"].into_iter()).unwrap();

        // PATCH start hinting run no body
        parse_patch_balloon(Some(&Body::new("")), ["hinting", "start"].into_iter()).unwrap();

        // PATCH start hinting run invalid data
        let body = r#"{
            "acknowledge_on_stop": "not valid"
        }"#;
        parse_patch_balloon(Some(&Body::new(body)), ["hinting", "start"].into_iter()).unwrap_err();

        // PATCH start hinting run no body
        parse_patch_balloon(Some(&Body::new(body)), ["hinting", "start"].into_iter()).unwrap_err();

        // PATCH stop hinting run
        parse_patch_balloon(Some(&Body::new("")), ["hinting", "stop"].into_iter()).unwrap();

        // PATCH stop hinting run
        parse_patch_balloon(None, ["hinting", "stop"].into_iter()).unwrap();

        // PATCH stop hinting invalid path
        parse_patch_balloon(Some(&Body::new("")), ["hinting"].into_iter()).unwrap_err();

        // PATCH stop hinting invalid path
        parse_patch_balloon(Some(&Body::new("")), ["hinting", "other path"].into_iter())
            .unwrap_err();

        // PATCH no body non hinting
        parse_patch_balloon(None, ["hinting"].into_iter()).unwrap_err();
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

        // PUT with valid input fields. Hinting reporting missing
        let body = r#"{
            "amount_mib": 1000,
            "deflate_on_oom": true,
            "stats_polling_interval_s": 0
        }"#;
        parse_put_balloon(&Body::new(body)).unwrap();

        // PUT with valid input hinting
        let body = r#"{
            "amount_mib": 1000,
            "deflate_on_oom": true,
            "stats_polling_interval_s": 0,
            "free_page_hinting": true
        }"#;
        parse_put_balloon(&Body::new(body)).unwrap();

        // PUT with valid reporting
        let body = r#"{
            "amount_mib": 1000,
            "deflate_on_oom": true,
            "stats_polling_interval_s": 0,
            "free_page_reporting": true
        }"#;
        parse_put_balloon(&Body::new(body)).unwrap();
    }
}
