// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate chrono;
extern crate clap;

extern crate fc_util;
extern crate jailer;

fn main() -> jailer::Result<()> {
    jailer::run(
        jailer::clap_app().get_matches(),
        (chrono::Utc::now().timestamp_nanos() / 1000) as u64,
        fc_util::now_cputime_us(),
    )
}
