// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use logger::{IncMetric, METRICS};
use serde::{Deserialize, Serialize};

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};

// The names of the members from this enum must precisely correspond (as a string) to the possible
// values of "action_type" from the json request body. This is useful to get a strongly typed
// struct from the Serde deserialization process.
#[derive(Debug, Deserialize, Serialize)]
enum ActionType {
    FlushMetrics,
    InstanceStart,
    SendCtrlAltDel,
}

// The model of the json body from a sync request. We use Serde to transform each associated
// json body into this.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActionBody {
    action_type: ActionType,
}

pub(crate) fn parse_put_actions(body: serde_json::Value) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.actions_count.inc();
    let action_body = serde_json::from_value::<ActionBody>(body).map_err(|err| {
        METRICS.put_api_requests.actions_fails.inc();
        err
    })?;

    match action_body.action_type {
        ActionType::FlushMetrics => Ok(ParsedRequest::new_sync(VmmAction::FlushMetrics)),
        ActionType::InstanceStart => Ok(ParsedRequest::new_sync(VmmAction::StartMicroVm)),
        ActionType::SendCtrlAltDel => {
            // SendCtrlAltDel not supported on aarch64.
            #[cfg(target_arch = "aarch64")]
            return Err(Error::Generic(
                hyper::StatusCode::BAD_REQUEST,
                "SendCtrlAltDel does not supported on aarch64.".to_string(),
            ));

            #[cfg(target_arch = "x86_64")]
            Ok(ParsedRequest::new_sync(VmmAction::SendCtrlAltDel))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_parse_put_actions_request() {
        {
            assert!(parse_put_actions(serde_json::Value::Null).is_err());

            let body = json!({
                "action_type": "InstanceStart"
            });

            let req: ParsedRequest = ParsedRequest::new_sync(VmmAction::StartMicroVm);
            let result = parse_put_actions(body);
            assert!(result.is_ok());
            assert!(result.unwrap().eq(&req));
        }

        #[cfg(target_arch = "x86_64")]
        {
            let body = json!({
                "action_type": "SendCtrlAltDel"
            });

            let req: ParsedRequest = ParsedRequest::new_sync(VmmAction::SendCtrlAltDel);
            let result = parse_put_actions(body);
            assert!(result.is_ok());
            assert!(result.unwrap().eq(&req));
        }

        #[cfg(target_arch = "aarch64")]
        {
            let body = json!({
                "action_type": "SendCtrlAltDel"
            });

            let result = parse_put_actions(body);
            assert!(result.is_err());
        }

        {
            let body = json!({
                "action_type": "FlushMetrics"
            });

            let req: ParsedRequest = ParsedRequest::new_sync(VmmAction::FlushMetrics);
            let result = parse_put_actions(body);
            assert!(result.is_ok());
            assert!(result.unwrap().eq(&req));
        }
    }
}
