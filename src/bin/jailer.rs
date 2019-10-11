// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
extern crate clap;

extern crate fc_util;
extern crate jailer;

fn main() {
    if let Err(error) = jailer::run(
        jailer::clap_app().get_matches(),
        fc_util::time::get_time(fc_util::time::ClockType::Monotonic) / 1000,
        fc_util::time::get_time(fc_util::time::ClockType::ProcessCpu) / 1000,
    ) {
        panic!("Jailer error: {}", error);
    }
}
