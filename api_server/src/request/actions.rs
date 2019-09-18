// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use request::ParsedRequest;
use vmm::VmmAction;

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

fn validate_payload(action_body: &ActionBody) -> Result<(), String> {
    match action_body.action_type {
        ActionType::BlockDeviceRescan => {
            match action_body.payload {
                Some(ref payload) => {
                    // Expecting to have drive_id as a String in the payload.
                    if !payload.is_string() {
                        return Err(
                            "Invalid payload type. Expected a string representing the drive_id"
                                .to_string(),
                        );
                    }
                    Ok(())
                }
                None => Err("Payload is required for block device rescan.".to_string()),
            }
        }
        ActionType::FlushMetrics | ActionType::InstanceStart | ActionType::SendCtrlAltDel => {
            // Neither FlushMetrics nor InstanceStart should have a payload.
            if action_body.payload.is_some() {
                return Err(format!(
                    "{:?} does not support a payload.",
                    action_body.action_type
                ));
            }
            Ok(())
        }
    }
}

impl ActionBody {
    pub fn into_parsed_request(self) -> Result<ParsedRequest, String> {
        validate_payload(&self)?;
        match self.action_type {
            ActionType::BlockDeviceRescan => {
                // Safe to unwrap because we validated the payload in the validate_payload func.
                let block_device_id = self.payload.unwrap().as_str().unwrap().to_string();
                Ok(ParsedRequest::Sync(VmmAction::RescanBlockDevice(
                    block_device_id,
                )))
            }
            ActionType::FlushMetrics => Ok(ParsedRequest::Sync(VmmAction::FlushMetrics)),
            ActionType::InstanceStart => Ok(ParsedRequest::Sync(VmmAction::StartMicroVm)),
            ActionType::SendCtrlAltDel => Ok(ParsedRequest::Sync(VmmAction::SendCtrlAltDel)),
        }
    }
}
