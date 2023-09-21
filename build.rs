// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

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
}
