// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};
use crate::request::Body;
use vmm::vmm_config::balloon::{BalloonDeviceConfig, BalloonUpdateConfig};

pub fn parse_get_balloon_stats() -> Result<ParsedRequest, Error> {
    Ok(ParsedRequest::new_sync(VmmAction::GetBalloonStats))
}

pub fn parse_put_balloon(body: &Body) -> Result<ParsedRequest, Error> {
    Ok(ParsedRequest::new_sync(VmmAction::SetBalloonDevice(
        serde_json::from_slice::<BalloonDeviceConfig>(body.raw()).map_err(Error::SerdeJson)?,
    )))
}

pub fn parse_patch_balloon(body: &Body) -> Result<ParsedRequest, Error> {
    Ok(ParsedRequest::new_sync(VmmAction::UpdateBalloon(
        serde_json::from_slice::<BalloonUpdateConfig>(body.raw()).map_err(Error::SerdeJson)?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_get_balloon_request() {
        assert!(parse_get_balloon_stats().is_ok());
    }

    #[test]
    fn test_parse_patch_balloon_request() {
        assert!(parse_patch_balloon(&Body::new("invalid_payload")).is_err());

        // PATCH with invalid fields.
        let body = r#"{
                "num_pages": "bar",
                "foo": "bar"
              }"#;
        assert!(parse_patch_balloon(&Body::new(body)).is_err());

        // PATCH with invalid types on fields. Adding a polling interval as string instead of bool.
        let body = r#"{
                "num_pages": 1000,
                "stats_polling_interval_s": "false"
              }"#;
        let res = parse_patch_balloon(&Body::new(body));
        assert!(res.is_err());

        // PATCH with invalid types on fields. Adding a num_pages as a negative number.
        let body = r#"{
                "num_pages": -1000,
                "stats_polling_interval_s": true
              }"#;
        let res = parse_patch_balloon(&Body::new(body));
        assert!(res.is_err());

        // PATCH with missing ppolling interval field.
        let body = r#"{
                "num_pages": 100
              }"#;
        let res = parse_patch_balloon(&Body::new(body));
        assert!(res.is_err());

        // PATCH with missing num_pages field.
        let body = r#"{
                "stats_polling_interval_s": 0
              }"#;
        let res = parse_patch_balloon(&Body::new(body));
        assert!(res.is_err());

        // PATCH that tries to update something else other than allowed fields.
        let body = r#"{
                "num_pages": "dummy_id",
                "stats_polling_interval_s": "dummy_host",
                "must_tell_host": false
              }"#;
        let res = parse_patch_balloon(&Body::new(body));
        assert!(res.is_err());

        // PATCH with payload that is not a json.
        let body = r#"{
                "fields": "dummy_field"
              }"#;
        assert!(parse_patch_balloon(&Body::new(body)).is_err());

        let body = r#"{
                "num_pages": 1,
                "stats_polling_interval_s": 1
              }"#;
        #[allow(clippy::match_wild_err_arm)]
        match vmm_action_from_request(parse_patch_balloon(&Body::new(body)).unwrap()) {
            VmmAction::UpdateBalloon(balloon_cfg) => {
                assert_eq!(balloon_cfg.num_pages, 1);
                assert_eq!(balloon_cfg.stats_polling_interval_s, 1);
            }
            _ => panic!("Test failed: Invalid parameters"),
        };
    }

    #[test]
    fn test_parse_put_balloon_request() {
        assert!(parse_put_balloon(&Body::new("invalid_payload")).is_err());

        // PUT with invalid fields.
        let body = r#"{
                "num_pages": "bar",
                "is_read_only": false
              }"#;
        assert!(parse_put_balloon(&Body::new(body)).is_err());

        // PUT with valid input fields.
        let body = r#"{
                "num_pages": 1000,
                "must_tell_host": true,
                "deflate_on_oom": true,
                "stats_polling_interval_s": 0
            }"#;
        assert!(parse_put_balloon(&Body::new(body)).is_ok());
    }
}
