// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::VmmAction;
use crate::parsed_request::{Error, ParsedRequest};
use crate::request::Body;
use logger::{IncMetric, METRICS};
use vmm::vmm_config::memory_backing_file::MemoryBackingFileConfig;

pub(crate) fn parse_put_memory_backing_file(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.memory_backing_file_cfg_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::SetMemoryBackingFile(
        serde_json::from_slice::<MemoryBackingFileConfig>(body.raw()).map_err(|e| {
            METRICS.put_api_requests.memory_backing_file_cfg_fails.inc();
            Error::SerdeJson(e)
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_parse_memory_backing_file() {
        assert!(parse_put_memory_backing_file(&Body::new("invalid_payload")).is_err());

        let body = r#"{
                "path": "./memory.snap"
              }"#;
        let same_body = MemoryBackingFileConfig {
            path: PathBuf::from("./memory.snap"),
        };
        let result = parse_put_memory_backing_file(&Body::new(body));
        assert!(result.is_ok());
        let parsed_req = result.unwrap_or_else(|_e| panic!("Failed test."));

        assert!(parsed_req == ParsedRequest::new_sync(VmmAction::SetMemoryBackingFile(same_body)));
    }
}
