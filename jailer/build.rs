// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    set_firecracker_version();
}
fn set_firecracker_version() {
    let res = std::process::Command::new("git")
        .args(["describe", "--dirty"])
        .output();
    let version = match res {
        Ok(ok) if ok.status.success() => {
            let s = String::from_utf8(ok.stdout).unwrap();
            s.trim_start_matches('v').to_string()
        }
        _ => env!("CARGO_PKG_VERSION").to_string(),
    };
    println!("cargo:rustc-env=FIRECRACKER_VERSION={version}");
}
