// Copyright 2018 Amazon.com, Inc. or its affiliates.  All Rights Reserved.

use std::result;

use futures::sync::oneshot;
use hyper::Method;
use serde_json::Value;

use request::async::{AsyncRequest, InstanceDeviceDetachAction};
use request::{IntoParsedRequest, ParsedRequest};

// The names of the members from this enum must precisely correspond (as a string) to the possible
// values of "action_type" from the json request body. This is useful to get a strongly typed
// struct from the Serde deserialization process.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum ActionType {
    InstanceStart,
    InstanceHalt,
}

// The model of the json body from an async request. We use Serde to transform each associated
// json body into this.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBody {
    pub action_id: String,
    pub action_type: ActionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_device_detach_action: Option<InstanceDeviceDetachAction>,
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
}

impl IntoParsedRequest for ActionBody {
    fn into_parsed_request(self, _: Method) -> result::Result<ParsedRequest, String> {
        let id = self.action_id.clone();

        match self.action_type {
            ActionType::InstanceStart => {
                let (async_sender, async_receiver) = oneshot::channel();
                Ok(ParsedRequest::Async(
                    id,
                    AsyncRequest::StartInstance(async_sender),
                    async_receiver,
                ))
            }
            ActionType::InstanceHalt => {
                let (async_sender, async_receiver) = oneshot::channel();
                Ok(ParsedRequest::Async(
                    id,
                    AsyncRequest::StopInstance(async_sender),
                    async_receiver,
                ))
            }
        }
    }
}
