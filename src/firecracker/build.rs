// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

const ADVANCED_BINARY_FILTER_FILE_NAME: &str = "seccomp_filter.bpf";

const JSON_DIR: &str = "../../resources/seccomp";
const SECCOMPILER_SRC_DIR: &str = "../seccompiler/src";

// This script is run on every modification in the target-specific JSON file in `resources/seccomp`.
// It compiles the JSON seccomp policies into a serializable BPF format, using seccompiler-bin.
// The generated binary code will get included in Firecracker's code, at compile-time.
fn main() {
    // Target triple
    let target = std::env::var("TARGET").expect("Missing target.");
    let debug: bool = std::env::var("DEBUG")
        .expect("Missing debug.")
        .parse()
        .expect("Invalid env variable DEBUG");
    let out_dir = std::env::var("OUT_DIR").expect("Missing build-level OUT_DIR.");
    // Target arch (x86_64 / aarch64)
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("Missing target arch.");

    let seccomp_json_path = format!("{}/{}.json", JSON_DIR, target);
    // If the current target doesn't have a default filter, or if we're building a debug binary,
    // use a default, empty filter.
    // This is to make sure that Firecracker builds even with libc toolchains for which we don't
    // provide a default filter. For example, GNU libc.
    let seccomp_json_path = if debug {
        println!(
            "cargo:warning=Using empty default seccomp policy for debug builds: \
             `resources/seccomp/unimplemented.json`."
        );
        format!("{}/unimplemented.json", JSON_DIR)
    } else if !Path::new(&seccomp_json_path).exists() {
        println!(
            "cargo:warning=No default seccomp policy for target: {}. Defaulting to \
             `resources/seccomp/unimplemented.json`.",
            target
        );
        format!("{}/unimplemented.json", JSON_DIR)
    } else {
        seccomp_json_path
    };

    // Retrigger the build script if the JSON file has changed.
    // let json_path = json_path.to_str().expect("Invalid bytes");
    println!("cargo:rerun-if-changed={}", seccomp_json_path);
    // Also retrigger the build script on any seccompiler source code change.
    println!("cargo:rerun-if-changed={}", SECCOMPILER_SRC_DIR);

    let out_path = format!("{}/{}", out_dir, ADVANCED_BINARY_FILTER_FILE_NAME);
    seccompiler::compile_bpf(&seccomp_json_path, &target_arch, &out_path, false)
        .expect("Cannot compile seccomp filters");
}
