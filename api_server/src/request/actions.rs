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
    fn test_() {
        let value = serde_json::from_slice::<ActionBody>(
            b"{ \"action_type\" : \"BlockDeviceRescan\", \"payload\" : \"5\" }",
        )
        .unwrap();
    }
}
