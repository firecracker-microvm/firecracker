// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::pvpanic::PvPanicConfig;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_put_pvpanic(body: &Body) -> Result<ParsedRequest, RequestError> {
    let config = serde_json::from_slice::<PvPanicConfig>(body.raw())?;
    Ok(ParsedRequest::new_sync(VmmAction::SetPvPanicDevice(config)))
}

#[cfg(test)]
mod tests {
    use vmm::vmm_config::pvpanic::PvPanicAction;

    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_pvpanic_request() {
        // PUT with invalid payload.
        parse_put_pvpanic(&Body::new("invalid_payload")).unwrap_err();

        // PUT with valid fields.
        let body = r#"{
            "panic_action": "pause"
        }"#;
        assert_eq!(
            vmm_action_from_request(parse_put_pvpanic(&Body::new(body)).unwrap()),
            VmmAction::SetPvPanicDevice(PvPanicConfig {
                panic_action: PvPanicAction::Pause
            })
        );
    }
}
