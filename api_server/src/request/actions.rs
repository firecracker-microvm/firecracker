// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use super::super::VmmAction;
use logger::{Metric, METRICS};
use request::{Body, Error, ParsedRequest, StatusCode};

// The names of the members from this enum must precisely correspond (as a string) to the possible
// values of "action_type" from the json request body. This is useful to get a strongly typed
// struct from the Serde deserialization process.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
enum ActionType {
    BlockDeviceRescan,
    FlushMetrics,
    InstanceStart,
    SendCtrlAltDel,
}

// The model of the json body from a sync request. We use Serde to transform each associated
// json body into this.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBody {
    action_type: ActionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Value>,
}

fn validate_payload(action_body: &ActionBody) -> Result<(), Error> {
    match action_body.action_type {
        ActionType::BlockDeviceRescan => {
            match action_body.payload {
                Some(ref payload) => {
                    // Expecting to have drive_id as a String in the payload.
                    if !payload.is_string() {
                        return Err(Error::Generic(
                            StatusCode::BadRequest,
                            "Invalid payload type. Expected a string representing the drive_id"
                                .to_string(),
                        ));
                    }
                    Ok(())
                }
                None => Err(Error::Generic(
                    StatusCode::BadRequest,
                    "Payload is required for block device rescan.".to_string(),
                )),
            }
        }
        ActionType::FlushMetrics | ActionType::InstanceStart | ActionType::SendCtrlAltDel => {
            // Neither FlushMetrics nor InstanceStart should have a payload.
            if action_body.payload.is_some() {
                return Err(Error::Generic(
                    StatusCode::BadRequest,
                    format!("{:?} does not support a payload.", action_body.action_type),
                ));
            }
            Ok(())
        }
    }
}

pub fn parse_put_actions(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.actions_count.inc();
    let action_body = serde_json::from_slice::<ActionBody>(body.raw()).map_err(|e| {
        METRICS.put_api_requests.actions_fails.inc();
        Error::SerdeJson(e)
    })?;

    validate_payload(&action_body)?;
    match action_body.action_type {
        ActionType::BlockDeviceRescan => {
            // Safe to unwrap because we validated the payload in the validate_payload func.
            let block_device_id = action_body.payload.unwrap().as_str().unwrap().to_string();
            Ok(ParsedRequest::Sync(VmmAction::RescanBlockDevice(
                block_device_id,
            )))
        }
        ActionType::FlushMetrics => Ok(ParsedRequest::Sync(VmmAction::FlushMetrics)),
        ActionType::InstanceStart => Ok(ParsedRequest::Sync(VmmAction::StartMicroVm)),
        ActionType::SendCtrlAltDel => {
            // SendCtrlAltDel not supported on aarch64.
            #[cfg(target_arch = "aarch64")]
            return Err(Error::Generic(
                StatusCode::BadRequest,
                "SendCtrlAltDel does not supported on aarch64.".to_string(),
            ));

            #[cfg(target_arch = "x86_64")]
            Ok(ParsedRequest::Sync(VmmAction::SendCtrlAltDel))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_payload() {
        // Test InstanceStart.
        let action_body = ActionBody {
            action_type: ActionType::InstanceStart,
            payload: None,
        };
        assert!(validate_payload(&action_body).is_ok());
        // Error case: InstanceStart with payload.
        let action_body = ActionBody {
            action_type: ActionType::InstanceStart,
            payload: Some(Value::String("dummy-payload".to_string())),
        };
        assert!(validate_payload(&action_body).is_err());

        // Test BlockDeviceRescan
        let action_body = ActionBody {
            action_type: ActionType::BlockDeviceRescan,
            payload: Some(Value::String(String::from("dummy_id"))),
        };
        assert!(validate_payload(&action_body).is_ok());
        // Error case: no payload.
        let action_body = ActionBody {
            action_type: ActionType::BlockDeviceRescan,
            payload: None,
        };
        assert!(validate_payload(&action_body).is_err());
        // Error case: payload is not String.
        let action_body = ActionBody {
            action_type: ActionType::BlockDeviceRescan,
            payload: Some(Value::Bool(false)),
        };
        assert!(validate_payload(&action_body).is_err());

        // Test FlushMetrics.
        let action_body = ActionBody {
            action_type: ActionType::FlushMetrics,
            payload: None,
        };

        assert!(validate_payload(&action_body).is_ok());
        // Error case: FlushMetrics with payload.
        let action_body = ActionBody {
            action_type: ActionType::FlushMetrics,
            payload: Some(Value::String("metrics-payload".to_string())),
        };
        let res = validate_payload(&action_body);
        assert!(res.is_err());

        // Test SendCtrlAltDel.
        let action_body = ActionBody {
            action_type: ActionType::SendCtrlAltDel,
            payload: None,
        };
        assert!(validate_payload(&action_body).is_ok());
        // Error case: SendCtrlAltDel with payload.
        let action_body = ActionBody {
            action_type: ActionType::SendCtrlAltDel,
            payload: Some(Value::String("dummy-payload".to_string())),
        };
        assert!(validate_payload(&action_body).is_err());
    }

    #[test]
    fn test_into_parsed_request() {
        {
            assert!(parse_put_actions(&Body::new("invalid_body")).is_err());

            let json = r#"{
                "action_type": "BlockDeviceRescan",
                "payload": "dummy_id"
              }"#;
            let req = ParsedRequest::Sync(VmmAction::RescanBlockDevice("dummy_id".to_string()));
            let result = parse_put_actions(&Body::new(json));
            assert!(result.is_ok());
            assert!(result.unwrap().eq(&req));
        }

        {
            let json = r#"{
                "action_type": "InstanceStart"
            }"#;

            let req: ParsedRequest = ParsedRequest::Sync(VmmAction::StartMicroVm);
            let result = parse_put_actions(&Body::new(json));
            assert!(result.is_ok());
            assert!(result.unwrap().eq(&req));
        }

        #[cfg(target_arch = "x86_64")]
        {
            let json = r#"{
                "action_type": "SendCtrlAltDel"
            }"#;

            let req: ParsedRequest = ParsedRequest::Sync(VmmAction::SendCtrlAltDel);
            let result = parse_put_actions(&Body::new(json));
            assert!(result.is_ok());
            assert!(result.unwrap().eq(&req));
        }

        #[cfg(target_arch = "aarch64")]
        {
            let json = r#"{
                "action_type": "SendCtrlAltDel"
            }"#;

            let result = parse_put_actions(&Body::new(json));
            assert!(result.is_err());
        }

        {
            let json = r#"{
                "action_type": "FlushMetrics"
            }"#;

            let req: ParsedRequest = ParsedRequest::Sync(VmmAction::FlushMetrics);
            let result = parse_put_actions(&Body::new(json));
            assert!(result.is_ok());
            assert!(result.unwrap().eq(&req));

            let json = r#"{
                "action_type": "FlushMetrics",
                "payload": "metrics-payload"
            }"#;
            let result = parse_put_actions(&Body::new(json));
            assert!(result.is_err());
        }
    }
}
