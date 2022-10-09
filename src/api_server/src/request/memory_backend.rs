// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};
use crate::request::Body;
use logger::{IncMetric, METRICS};
use vmm::vmm_config::snapshot::MemBackendConfig;

pub(crate) fn parse_put_memory_backend(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.memory_backend_cfg_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::SetMemoryBackend(
        serde_json::from_slice::<MemBackendConfig>(body.raw()).map_err(|e| {
            METRICS.put_api_requests.memory_backend_cfg_fails.inc();
            Error::SerdeJson(e)
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use vmm::vmm_config::snapshot::MemBackendType;

    use super::*;

    #[test]
    fn test_parse_memory_backing_file() {
        assert!(parse_put_memory_backend(&Body::new("invalid_payload")).is_err());

        let body = r#"{
                "backend_type": "File",
                "backend_path": "./memory.snap"
              }"#;
        let same_body = MemBackendConfig {
            backend_type: MemBackendType::File,
            backend_path: PathBuf::from("./memory.snap"),
        };
        let result = parse_put_memory_backend(&Body::new(body));
        assert!(result.is_ok());
        let parsed_req = result.unwrap_or_else(|_e| panic!("Failed test."));

        assert!(parsed_req == ParsedRequest::new_sync(VmmAction::SetMemoryBackend(same_body)));
    }
}
