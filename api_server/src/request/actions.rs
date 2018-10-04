// Copyright 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.

use std::result;

use futures::sync::oneshot;
use hyper::Method;
use serde_json::Value;

use request::{IntoParsedRequest, ParsedRequest, SyncRequest};

// The names of the members from this enum must precisely correspond (as a string) to the possible
// values of "action_type" from the json request body. This is useful to get a strongly typed
// struct from the Serde deserialization process.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum ActionType {
    BlockDeviceRescan,
    InstanceStart,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum DeviceType {
    Drive,
}

// Represents the associated json block from the sync request body.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceDeviceDetachAction {
    pub device_type: DeviceType,
    pub device_resource_id: String,
    pub force: bool,
}

// The model of the json body from a sync request. We use Serde to transform each associated
// json body into this.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBody {
    pub action_type: ActionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_device_detach_action: Option<InstanceDeviceDetachAction>,
    pub payload: Option<Value>,
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
                None => return Err("Payload is required for block device rescan.".to_string()),
            }
        }
        ActionType::InstanceStart => {
            // InstanceStart does not have a payload
            if !action_body.payload.is_none() {
                return Err("InstanceStart does not support a payload.".to_string());
            }
            Ok(())
        }
    }
}

impl IntoParsedRequest for ActionBody {
    fn into_parsed_request(self, _: Method) -> result::Result<ParsedRequest, String> {
        validate_payload(&self)?;
        match self.action_type {
            ActionType::BlockDeviceRescan => {
                // Safe to unwrap because we validated the payload in the validate_payload func.
                let block_device_id = self.payload.unwrap().as_str().unwrap().to_string();
                let (sync_sender, sync_receiver) = oneshot::channel();
                Ok(ParsedRequest::Sync(
                    SyncRequest::RescanBlockDevice(block_device_id, sync_sender),
                    sync_receiver,
                ))
            }
            ActionType::InstanceStart => {
                let (sync_sender, sync_receiver) = oneshot::channel();
                Ok(ParsedRequest::Sync(
                    SyncRequest::StartInstance(sync_sender),
                    sync_receiver,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_validate_payload() {
        // Test InstanceStart.
        let action_body = ActionBody {
            action_type: ActionType::InstanceStart,
            instance_device_detach_action: None,
            payload: None,
        };
        assert!(validate_payload(&action_body).is_ok());
        // Error case: InstanceStart with payload.
        let action_body = ActionBody {
            action_type: ActionType::InstanceStart,
            instance_device_detach_action: None,
            payload: Some(Value::String("dummy-payload".to_string())),
        };
        assert!(validate_payload(&action_body).is_err());

        // Test BlockDeviceRescan
        let action_body = ActionBody {
            action_type: ActionType::BlockDeviceRescan,
            instance_device_detach_action: None,
            payload: Some(Value::String(String::from("dummy_id"))),
        };
        assert!(validate_payload(&action_body).is_ok());
        // Error case: no payload.
        let action_body = ActionBody {
            action_type: ActionType::BlockDeviceRescan,
            instance_device_detach_action: None,
            payload: None,
        };
        assert!(validate_payload(&action_body).is_err());
        // Error case: payload is not String.
        let action_body = ActionBody {
            action_type: ActionType::BlockDeviceRescan,
            instance_device_detach_action: None,
            payload: Some(Value::Bool(false)),
        };
        assert!(validate_payload(&action_body).is_err());
    }

    #[test]
    fn test_into_parsed_request() {
        {
            let json = r#"{
                "action_type": "BlockDeviceRescan",
                "payload": "dummy_id"
              }"#;
            let (sender, receiver) = oneshot::channel();
            let req = ParsedRequest::Sync(
                SyncRequest::RescanBlockDevice("dummy_id".to_string(), sender),
                receiver,
            );

            let result: Result<ActionBody, serde_json::Error> = serde_json::from_str(json);
            assert!(result.is_ok());
            assert!(
                result
                    .unwrap()
                    .into_parsed_request(Method::Put)
                    .unwrap()
                    .eq(&req)
            );
        }

        {
            let json = "{
                \"action_type\": \"InstanceStart\",
                \"instance_device_detach_action\": {\
                    \"device_type\": \"Drive\",
                    \"device_resource_id\": \"dummy\",
                    \"force\": true}
              }";
            let (sender, receiver) = oneshot::channel();
            let req: ParsedRequest =
                ParsedRequest::Sync(SyncRequest::StartInstance(sender), receiver);
            let result: Result<ActionBody, serde_json::Error> = serde_json::from_str(json);
            assert!(result.is_ok());
            assert!(
                result
                    .unwrap()
                    .into_parsed_request(Method::Put)
                    .unwrap()
                    .eq(&req)
            );
        }
    }
}
