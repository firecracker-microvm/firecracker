// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::env::args;
use std::fs::File;

use vmm::seccomp::{apply_filter, deserialize_binary};

fn main() {
    let args: Vec<String> = args().collect();
    let bpf_path = &args[1];
    let filter_thread = &args[2];

    let filter_file = File::open(bpf_path).unwrap();
    let map = deserialize_binary(&filter_file).unwrap();
    apply_filter(map.get(filter_thread).unwrap()).unwrap();
    panic!("Expected panic.");
}
