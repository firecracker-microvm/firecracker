// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
extern crate clap;

extern crate jailer;
extern crate utils;

fn main() {
    if let Err(error) = jailer::run(
        jailer::clap_app().get_matches(),
        utils::time::get_time(utils::time::ClockType::Monotonic) / 1000,
        utils::time::get_time(utils::time::ClockType::ProcessCpu) / 1000,
    ) {
        panic!("Jailer error: {}", error);
    }
}
