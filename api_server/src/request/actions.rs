// Copyright 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.

use std::result;

use futures::sync::oneshot;
use hyper::Method;
use serde_json::Value;

use request::sync::{InstanceDeviceDetachAction, SyncRequest};
use request::{IntoParsedRequest, ParsedRequest};

// The names of the members from this enum must precisely correspond (as a string) to the possible
// values of "action_type" from the json request body. This is useful to get a strongly typed
// struct from the Serde deserialization process.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum ActionType {
    BlockDeviceRescan,
    InstanceStart,
}

// The model of the json body from an async request. We use Serde to transform each associated
// json body into this.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBody {
    pub action_type: ActionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_device_detach_action: Option<InstanceDeviceDetachAction>,
    pub payload: Option<Value>,
}

impl IntoParsedRequest for ActionBody {
    fn into_parsed_request(self, _: Method) -> result::Result<ParsedRequest, String> {
        match self.action_type {
            ActionType::BlockDeviceRescan => {
                let (sync_sender, sync_receiver) = oneshot::channel();
                Ok(ParsedRequest::Sync(
                    SyncRequest::RescanBlockDevice(self, sync_sender),
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
    fn test_into_parsed_request() {
        {
            let json = "{
                \"action_type\": \"BlockDeviceRescan\",
                \"payload\": \"foobar\"
              }";
            let (sender, receiver) = oneshot::channel();
            let body = ActionBody {
                action_type: ActionType::BlockDeviceRescan,
                instance_device_detach_action: None,
                payload: Some(Value::String(String::from("foobar"))),
            };
            let req = ParsedRequest::Sync(SyncRequest::RescanBlockDevice(body, sender), receiver);

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
                    \"force\": true},
                \"timestamp\": 1522850095
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
