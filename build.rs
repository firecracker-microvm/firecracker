// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

const ADVANCED_BINARY_FILTER_FILE_NAME: &str = "seccomp_filter.bpf";

const JSON_DIR: &str = "../../resources/seccomp";
const SECCOMPILER_BUILD_DIR: &str = "../../build/seccompiler";
const SECCOMPILER_SRC_DIR: &str = "../seccompiler/src";

// This script is run on every modification in the target-specific JSON file in `resources/seccomp`.
// It compiles the JSON seccomp policies into a serializable BPF format, using seccompiler-bin.
// The generated binary code will get included in Firecracker's code, at compile-time.
fn main() {
    // this build script is called on every `devtool build`,
    // embedding the FIRECRACKER_VERSION directly in the resulting binary
    let firecracker_version = env!("CARGO_PKG_VERSION").to_string();
    println!(
        "cargo:rustc-env=FIRECRACKER_VERSION={}",
        firecracker_version
    );

    // Only compile the seccomp filters for the firecracker binary - otherwise
    // we'll get stuck in an infinite loop as seccompiler-bin (which is invoked below)
    // also executes this build script to set the firecracker version env variable.
    if let Ok(package) = std::env::var("CARGO_MANIFEST_DIR") {
        if !package.ends_with("firecracker") {
            return;
        }
    }

    cpuid();

    let target = env::var("TARGET").expect("Missing target.");
    let out_dir = env::var("OUT_DIR").expect("Missing build-level OUT_DIR.");

    // Path to the JSON seccomp policy.
    let mut json_path = PathBuf::from(JSON_DIR);
    json_path.push(format!("{}.json", target));

    // If the current target doesn't have a default filter, use a default, empty filter.
    // This is to make sure that Firecracker builds even with libc toolchains for which we don't
    // provide a default filter. For example, GNU libc.
    if !json_path.exists() {
        json_path.pop();
        json_path.push("unimplemented.json");

        println!(
            "cargo:warning=No default seccomp policy for target: {}. Defaulting to \
             `resources/seccomp/unimplemented.json`.",
            target
        );
    }

    // Retrigger the build script if the JSON file has changed.
    let json_path = json_path.to_str().expect("Invalid bytes");
    println!("cargo:rerun-if-changed={}", json_path);

    // Also retrigger the build script on any seccompiler source code change.
    register_seccompiler_src_watchlist(Path::new(SECCOMPILER_SRC_DIR));

    // Run seccompiler-bin, getting the default, advanced filter.
    let mut bpf_out_path = PathBuf::from(&out_dir);
    bpf_out_path.push(ADVANCED_BINARY_FILTER_FILE_NAME);
    run_seccompiler_bin(json_path, bpf_out_path.to_str().expect("Invalid bytes."));
}

// Run seccompiler with the given arguments.
fn run_seccompiler_bin(json_path: &str, out_path: &str) {
    // We have a global `target` directive in our .cargo/config file specifying x86_64 architecture.
    // However, seccompiler-bin has to be compiled for the host architecture. Without this, cargo
    // would produce a x86_64 binary on aarch64 host, causing this compilation step to fail as such
    // a binary would not be executable.
    let host_arch = env::var("HOST").expect("Could not determine compilation host");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Missing target arch.");

    // Command for running seccompiler-bin
    let mut command = Command::new("cargo");
    command.args([
        "run",
        "-p",
        "seccompiler",
        "--verbose",
        "--target",
        &host_arch,
        // We need to specify a separate build directory for seccompiler-bin. Otherwise, cargo will
        // deadlock waiting to acquire a lock on the build folder that the parent cargo process is
        // holding.
        "--target-dir",
        SECCOMPILER_BUILD_DIR,
        "--",
        "--input-file",
        json_path,
        "--target-arch",
        &target_arch,
        "--output-file",
        out_path,
    ]);

    match command.output() {
        Err(error) => panic!("\nSeccompiler-bin error: {:?}\n", error),
        Ok(result) if !result.status.success() => {
            panic!(
                "\nSeccompiler-bin returned non-zero exit code:\nstderr: {}\nstdout: {}\n",
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

fn cpuid() {
    // Sets a `--cfg` flag for conditional compilation.
    //
    // TODO: Use `core::arch::x86_64::has_cpuid`
    // (https://github.com/firecracker-microvm/firecracker/issues/3271).
    #[cfg(any(
        all(target_arch = "x86", target_feature = "sse", not(target_env = "sgx")),
        all(target_arch = "x86_64", not(target_env = "sgx"))
    ))]
    println!("cargo:rustc-cfg=cpuid");
}
