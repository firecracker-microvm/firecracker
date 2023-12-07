// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use log::*;

fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Trace)
        .init();
    info!("{}", one(2));
    info!("{}", one(3));
    info!("{}", one(4));
}
#[log_instrument::instrument]
fn one(x: u32) -> u32 {
    let cmp = x == 2;
    debug!("cmp: {cmp}");
    if cmp {
        return 4;
    }
    two(x + 3)
}
#[log_instrument::instrument]
fn two(x: u32) -> u32 {
    let res = x % 2;
    debug!("res: {res}");
    res
}
