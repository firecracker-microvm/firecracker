// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::entropy::EntropyDeviceConfig;

use crate::parsed_request::{Error, ParsedRequest};

pub(crate) fn parse_put_entropy(body: serde_json::Value) -> Result<ParsedRequest, Error> {
    let cfg = serde_json::from_value::<EntropyDeviceConfig>(body)?;
    Ok(ParsedRequest::new_sync(VmmAction::SetEntropyDevice(cfg)))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_parse_put_entropy_request() {
        assert!(parse_put_entropy(serde_json::Value::Null).is_err());

        // PUT with invalid fields.
        let body = json!({
            "some_id": 4
        });
        assert!(parse_put_entropy(body).is_err());

        // PUT with valid fields.
        let body = json!({});
        assert!(parse_put_entropy(body).is_ok());
    }
}
