use std::result;

use futures::sync::oneshot;

use super::ParsedRequest;

// This defines the possible outcomes of an async request from the perspective of the VMM. Currently
// an async action can be successful (and have an associated timestamp of the completion time), or
// it can result in some error whose message is captured and sent to the API server.
#[derive(Debug)]
pub enum AsyncOutcome {
    Ok(u64),
    Error(String),
}

// The halves of a request/reponse channel associated with each async request.
pub type AsyncOutcomeSender = oneshot::Sender<AsyncOutcome>;
pub type AsyncOutcomeReceiver = oneshot::Receiver<AsyncOutcome>;

// This enum contains messages which convey to the VMM the type of async request. Each request must
// also be associated with an outcome sender, which is used by the VMM to transmit the result.
#[derive(Debug)]
pub enum AsyncRequest {
    StartInstance(AsyncOutcomeSender),
    StopInstance(AsyncOutcomeSender),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum DeviceType {
    Drive,
}

// Represents the associated json block from the async request body.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstanceDeviceDetachAction {
    device_type: DeviceType,
    device_resource_id: String,
    force: bool,
}

// The names of the members from this enum must precisely correspond (as a string) to the possible
// values of "action_type" from the json request body. This is useful to get a strongly typed
// struct from the Serde deserialization process.
#[derive(Debug, Deserialize, Serialize)]
pub enum AsyncActionType {
    InstanceStart,
    InstanceHalt,
}

// The model of the json body from an async request. We use Serde to transform each associated
// json body into this.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncRequestBody {
    action_id: String,
    action_type: AsyncActionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_device_detach_action: Option<InstanceDeviceDetachAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<u64>,
}

impl AsyncRequestBody {
    pub fn set_timestamp(&mut self, timestamp: u64) {
        self.timestamp = Some(timestamp);
    }

    // The same overall body structure is shared by all async action. This function extracts the
    // particular type of action from a body, while also handling validation.
    pub fn to_parsed_request(&self, _id_from_path: &str) -> result::Result<ParsedRequest, String> {
        // todo: how do we validate the input? (for example, what do we do when timestamp is
        // present in the request body?) do we check if the id_from_path is the same as the body id?
        let (sender, receiver) = oneshot::channel();
        let id = self.action_id.clone();

        match self.action_type {
            AsyncActionType::InstanceStart => Ok(ParsedRequest::Async(
                id,
                AsyncRequest::StartInstance(sender),
                receiver,
            )),
            AsyncActionType::InstanceHalt => Ok(ParsedRequest::Async(
                id,
                AsyncRequest::StopInstance(sender),
                receiver,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    impl PartialEq for AsyncRequest {
        fn eq(&self, other: &AsyncRequest) -> bool {
            match (self, other) {
                (&AsyncRequest::StartInstance(_), &AsyncRequest::StartInstance(_)) => true,
                (&AsyncRequest::StopInstance(_), &AsyncRequest::StopInstance(_)) => true,
                _ => false,
            }
        }
    }

    #[test]
    fn test_to_parsed_request() {
        let jsons = vec![
            "{
                \"action_id\": \"dummy\",
                \"action_type\": \"InstanceStart\",
                \"instance_device_detach_action\": {\
                    \"device_type\": \"Drive\",
                    \"device_resource_id\": \"dummy\",
                    \"force\": true},
                \"timestamp\": 1522850095
              }",
            "{
                \"action_id\": \"dummy\",
                \"action_type\": \"InstanceHalt\",
                \"instance_device_detach_action\": {\
                    \"device_type\": \"Drive\",
                    \"device_resource_id\": \"dummy\",
                    \"force\": true},
                \"timestamp\": 1522850095
              }",
            "{
                \"action_id\": \"not_dummy\",
                \"action_type\": \"InstanceStart\",
                \"instance_device_detach_action\": {\
                    \"device_type\": \"Drive\",
                    \"device_resource_id\": \"dummy\",
                    \"force\": true},
                \"timestamp\": 1522850095
              }",
            "{
                \"action_id\": \"dummy\",
                \"action_type\": \"IAmNotAnActionType\"\
              }",
        ];
        let (sender, receiver) = oneshot::channel();
        let req: ParsedRequest = ParsedRequest::Async(
            String::from("dummy"),
            AsyncRequest::StartInstance(sender),
            receiver,
        );

        let mut result: Result<AsyncRequestBody, serde_json::Error> =
            serde_json::from_str(jsons[0]);
        assert!(result.is_ok());
        assert!(result.unwrap().to_parsed_request("dummy").unwrap().eq(&req));

        for json in jsons[1..3].to_vec() {
            result = serde_json::from_str(json);
            assert!(result.is_ok());
            assert!(!result.unwrap().to_parsed_request("dummy").unwrap().eq(&req));
        }

        result = serde_json::from_str(jsons[3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_set_timestamp() {
        let j = b"{
                    \"action_id\": \"dummy\",
                    \"action_type\": \"InstanceStart\",
                    \"instance_device_detach_action\": {\
                        \"device_type\": \"Drive\",
                        \"device_resource_id\": \"dummy\",
                        \"force\": true},
                    \"timestamp\": 1522850095
                  }";
        let mut async_body: AsyncRequestBody = serde_json::from_slice(j).unwrap();
        async_body.set_timestamp(1522850096);

        assert_eq!(async_body.timestamp, Some(1522850096));
    }
}
