// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use logger::{Metric, METRICS};
use request::{Error, ParsedRequest};

pub fn parse_get_instance_info() -> Result<ParsedRequest, Error> {
    METRICS.get_api_requests.instance_info_count.inc();
    Ok(ParsedRequest::GetInstanceInfo)
}
