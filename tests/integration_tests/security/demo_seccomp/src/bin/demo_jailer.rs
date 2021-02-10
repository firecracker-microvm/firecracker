// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::env::args;
use std::fs::File;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use seccomp::{deserialize_binary, SeccompFilter};

fn main() {
    let args: Vec<String> = args().collect();
    let exec_file = &args[1];
    let bpf_path = &args[2];

    let mut filter_file = File::open(bpf_path).unwrap();
    let mut map = deserialize_binary(&mut filter_file).unwrap();

    // Loads filters.
    SeccompFilter::apply(map.get("main").unwrap()).unwrap();

    Command::new(exec_file)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .exec();
}
