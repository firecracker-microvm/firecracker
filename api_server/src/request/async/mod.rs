use futures::sync::oneshot;

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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum DeviceType {
    Drive,
}

// Represents the associated json block from the async request body.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceDeviceDetachAction {
    pub device_type: DeviceType,
    pub device_resource_id: String,
    pub force: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use request::actions::ActionBody;
    use request::{IntoParsedRequest, ParsedRequest};

    use hyper::Method;
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
    fn test_into_parsed_request() {
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

        let mut result: Result<ActionBody, serde_json::Error> = serde_json::from_str(jsons[0]);
        println!("{:?}", result);
        assert!(result.is_ok());
        assert!(
            result
                .unwrap()
                .into_parsed_request(Method::Put)
                .unwrap()
                .eq(&req)
        );

        for json in jsons[1..3].to_vec() {
            result = serde_json::from_str(json);
            assert!(result.is_ok());
            assert!(!result
                .unwrap()
                .into_parsed_request(Method::Put)
                .unwrap()
                .eq(&req));
        }

        result = serde_json::from_str(jsons[3]);
        assert!(result.is_err());
    }
}
