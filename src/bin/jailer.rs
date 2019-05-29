// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use chrono;


use fc_util;
use jailer;

fn main() {
    if let Err(error) = jailer::run(
        jailer::clap_app().get_matches(),
        (chrono::Utc::now().timestamp_nanos() / 1000) as u64,
        fc_util::now_cputime_us(),
    ) {
        panic!("Jailer error: {}", error);
    }
}
