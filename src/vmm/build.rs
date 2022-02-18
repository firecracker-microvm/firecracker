// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryInto;
use std::env;
use std::fs::File;
use std::io::Write;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;

const BINARY_FILTER_FILE_NAME: &str = "advanced_filter.rs";

const JSON_DIR: &str = "../../resources/seccomp";

// This script is run on every modification in the target-specific JSON file in `resources/seccomp`.
// The generated binary code will get included in Firecracker's code, at compile-time.
fn main() {
    let target = env::var("TARGET").expect("Missing target.");
    let out_dir = env::var("OUT_DIR").expect("Missing build-level OUT_DIR.");

    // Path to the JSON seccomp policy.
    let mut json_path = PathBuf::from(JSON_DIR);
    json_path.push(format!("{}.json", target));

    // If the current target doesn't have a default filter, use a default, empty filter.
    // This is to make sure that Firecracker builds even with libc toolchains for which we don't provide
    // a default filter. For example, GNU libc.
    if !json_path.exists() {
        json_path.pop();
        json_path.push("unimplemented.json");

        println!(
            "cargo:warning=No default seccomp policy for target: {}. \
            Defaulting to `resources/seccomp/unimplemented.json`.",
            target
        );
    }

    // Retrigger the build script if the JSON file has changed.
    let json_path = json_path.to_str().expect("Invalid bytes");
    println!("cargo:rerun-if-changed={}", json_path);

    // Run seccompiler-bin, getting the default, advanced filter.
    let mut bpf_out_path = PathBuf::from(&out_dir);
    bpf_out_path.push(BINARY_FILTER_FILE_NAME);

    let input_file = File::open(&json_path).expect("Could not open JSON file");
    let input_reader = BufReader::new(input_file);
    let bpf_data = seccompiler::compile_from_json(
        input_reader,
        std::env::consts::ARCH.try_into().expect("Invalid arch"),
    )
    .expect("Could not write to file");

    let file = File::create(bpf_out_path.to_str().expect("Invalid bytes."))
        .expect("Could not create file");
    let mut writer = BufWriter::new(file);
    writer
        .write_all(
            r#"
                fn get_default_filters() -> Option<HashMap<String, Arc<BpfProgram>>> {
                    Some(
                        vec![
            "#
            .as_bytes(),
        )
        .expect("Could not write to file");

    for (name, bpf_program) in bpf_data {
        writer
            .write_all(
                format!(
                    r#"("{}".to_string(), Arc::new(vec!{:#?})),"#,
                    name, bpf_program
                )
                .as_bytes(),
            )
            .expect("Could not write to file");
    }

    writer
        .write_all("].into_iter().collect())}".as_bytes())
        .expect("Could not write to file");
}
