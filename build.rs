// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

// this build script is called on en every `devtool build`,
// embedding the FIRECRACKER_VERSION directly in the resulting binary
fn main() {
    let firecracker_version = Command::new("git")
        .args(&["describe", "--dirty"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                return Some(output.stdout);
            }
            None
        })
        .and_then(|version_bytes| String::from_utf8(version_bytes).ok())
        .map(|version_string| version_string.trim_start_matches('v').to_string())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    println!(
        "cargo:rustc-env=FIRECRACKER_VERSION={}",
        firecracker_version
    );
}
