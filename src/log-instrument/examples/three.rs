// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use log::*;

fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Trace)
        .init();
    info!("{:?}", one(&mut None));
    info!(
        "{:?}",
        one(&mut Some(vec![String::from("a"), String::from("b")]))
    );
}
#[log_instrument::instrument]
fn one(x: &mut Option<Vec<String>>) -> Option<&mut [String]> {
    match x {
        Some(y) => {
            debug!("{y:?}");
            Some(y)
        }
        _ => None,
    }
}
