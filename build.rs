// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// this build script is called on en every `devtool build`,
// embedding the FIRECRACKER_VERSION directly in the resulting binary
fn main() {
    let firecracker_version = env!("CARGO_PKG_VERSION").to_string();
    println!(
        "cargo:rustc-env=FIRECRACKER_VERSION={}",
        firecracker_version
    );
}
