// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    println!("cargo::rustc-link-search=/usr/local/lib");
    println!("cargo::rustc-link-lib=seccomp");
}
