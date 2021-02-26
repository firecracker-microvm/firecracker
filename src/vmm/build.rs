// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const BINARY_FILTER_FILE_NAME: &str = "seccomp_filter.bpf";
const JSON_DIR: &str = "../../resources/seccomp";
const SECCOMPILER_BUILD_DIR: &str = "../../build/seccompiler";
const SECCOMPILER_SRC_DIR: &str = "../seccompiler/src";

// This script is run on every modification in the target-specific JSON file in `resources/seccomp`.
// It compiles the JSON seccomp policies into a serializable BPF format, using seccompiler.
// The generated binary code will get included in Firecracker's code, at compile-time.
fn main() {
    let target = env::var("TARGET").expect("Missing target.");
    let out_dir = env::var("OUT_DIR").expect("Missing build-level OUT_DIR.");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Missing target arch.");

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

    // Also retrigger the build script on any seccompiler source code change.
    register_seccompiler_src_watchlist(Path::new(SECCOMPILER_SRC_DIR));

    // Path of the generated binary file.
    let mut bpf_out_path = PathBuf::from(&out_dir);
    bpf_out_path.push(BINARY_FILTER_FILE_NAME);
    let bpf_out_path = bpf_out_path.to_str().expect("Invalid bytes.");

    // Command for running seccompiler
    let mut command = Command::new("cargo");
    command.args(&[
        "run",
        "-p",
        "seccompiler",
        "--verbose",
        "--target",
        &target,
        // We need to specify a separate build directory for seccompiler. Otherwise, cargo will
        // deadlock waiting to acquire a lock on the build folder that the parent cargo process is
        // holding.
        "--target-dir",
        SECCOMPILER_BUILD_DIR,
        "--",
        "--input-file",
        &json_path,
        "--target-arch",
        &target_arch,
        "--output-file",
        bpf_out_path,
    ]);

    match command.output() {
        Err(error) => panic!("\nSeccompiler error: {:?}\n", error),
        Ok(result) if !result.status.success() => {
            panic!(
                "\nSeccompiler returned non-zero exit code:\nstderr: {}\nstdout: {}\n",
                String::from_utf8(result.stderr).unwrap(),
                String::from_utf8(result.stdout).unwrap(),
            );
        }
        Ok(_) => {}
    }
}

// Recursively traverse the entire seccompiler source folder and trigger a re-run of this build
// script on any modification of these files.
fn register_seccompiler_src_watchlist(src_dir: &Path) {
    let contents = fs::read_dir(src_dir).expect("Unable to read folder contents.");
    for entry in contents {
        let path = entry.unwrap().path();
        let metadata = fs::metadata(&path).expect("Unable to read file/folder metadata.");

        if metadata.is_file() {
            // Watch all source files.
            println!(
                "cargo:rerun-if-changed={}",
                path.to_str().expect("Invalid unicode bytes.")
            );
        } else if metadata.is_dir() {
            // If is a folder, recurse.
            register_seccompiler_src_watchlist(&path);
        }
    }
}
