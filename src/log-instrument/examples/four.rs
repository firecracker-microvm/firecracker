// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use log::*;

fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Trace)
        .init();
    let mut my_struct = MyStruct(None);
    info!("{:?}", my_struct.one());
    let mut my_struct = MyStruct(Some(vec![String::from("a"), String::from("b")]));
    info!("{:?}", my_struct.one());
}
struct MyStruct(Option<Vec<String>>);

impl MyStruct {
    #[log_instrument::instrument]
    fn one(&mut self) -> Option<&mut [String]> {
        match &mut self.0 {
            Some(y) => {
                debug!("{y:?}");
                Some(y)
            }
            _ => None,
        }
    }
}
