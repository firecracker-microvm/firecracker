// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;

use seccompiler::common::BpfProgram;
use seccompiler::compiler::{Compiler, JsonFile};

const ADVANCED_BINARY_FILTER_FILE_NAME: &str = "seccomp_filter.bpf";

const JSON_DIR: &str = "../../resources/seccomp";
const SECCOMPILER_SRC_DIR: &str = "../seccompiler/src";

// This script is run on every modification in the target-specific JSON file in `resources/seccomp`.
// It compiles the JSON seccomp policies into a serializable BPF format, using seccompiler-bin.
// The generated binary code will get included in Firecracker's code, at compile-time.
fn main() {
    let firecracker_version = env!("CARGO_PKG_VERSION").to_string();
    println!(
        "cargo:rustc-env=FIRECRACKER_VERSION={}",
        firecracker_version
    );

    // Target triple
    let target = std::env::var("TARGET").expect("Missing target.");
    let out_dir = std::env::var("OUT_DIR").expect("Missing build-level OUT_DIR.");
    // Target arch (x86_64 / aarch64)
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("Missing target arch.");

    let seccomp_json_path = format!("{}/{}.json", JSON_DIR, target);
    // If the current target doesn't have a default filter, use a default, empty filter.
    // This is to make sure that Firecracker builds even with libc toolchains for which we don't
    // provide a default filter. For example, GNU libc.
    let seccomp_json_path = if Path::new(&seccomp_json_path).exists() {
        seccomp_json_path
    } else {
        println!(
            "cargo:warning=No default seccomp policy for target: {}. Defaulting to \
             `resources/seccomp/unimplemented.json`.",
            target
        );
        format!("{}/unimplemented.json", JSON_DIR)
    };

    // Retrigger the build script if the JSON file has changed.
    // let json_path = json_path.to_str().expect("Invalid bytes");
    println!("cargo:rerun-if-changed={}", &seccomp_json_path);
    // Also retrigger the build script on any seccompiler source code change.
    register_seccompiler_src_watchlist(SECCOMPILER_SRC_DIR);

    let out_path = format!("{}/{}", out_dir, ADVANCED_BINARY_FILTER_FILE_NAME);

    // Run seccompiler-bin, getting the default, advanced filter.
    run_seccompiler_bin(&target_arch, &seccomp_json_path, &out_path);
}

// Run seccompiler with the given arguments.
fn run_seccompiler_bin(arch: &str, input_path: &str, out_path: &str) {
    let input = std::fs::read_to_string(input_path).expect("Correct input file");
    let filters: JsonFile = serde_json::from_str(&input).expect("Input read");

    let arch = arch.try_into().expect("Target");
    let compiler = Compiler::new(arch);

    // transform the IR into a Map of BPFPrograms
    let bpf_data: BTreeMap<String, BpfProgram> = compiler
        .compile_blob(filters.0, false)
        .expect("Successfull compilation");

    // serialize the BPF programs & output them to a file
    let output_file = File::create(out_path).expect("Create seccompiler output path");
    bincode::serialize_into(output_file, &bpf_data).expect("Seccompiler serialization");
}

// Recursively traverse the entire seccompiler source folder and trigger a re-run of this build
// script on any modification of these files.
fn register_seccompiler_src_watchlist<P: AsRef<Path>>(src_dir: P) {
    let contents = std::fs::read_dir(src_dir).expect("Unable to read folder contents.");
    for entry in contents {
        let path = entry.unwrap().path();
        let metadata = std::fs::metadata(&path).expect("Unable to read file/folder metadata.");

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
