// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

/// Get the ld linker search paths
///
/// Cargo overwrites LD_LIBRARY_PATH with rust specific paths. But we need the default system
/// paths in order to find libfdt. So we query `ld` in order to get them.
fn get_ld_search_dirs() -> Vec<String> {
    // We need to extract from `ld --verbose` all the search paths.
    // For example `ld --verbose | grep SEARCH_DIR | tr -s ' ;' '\n'` returns the following:
    // ```
    // SEARCH_DIR("=/usr/local/lib/aarch64-linux-gnu")
    // SEARCH_DIR("=/lib/aarch64-linux-gnu")
    // SEARCH_DIR("=/usr/lib/aarch64-linux-gnu")
    // SEARCH_DIR("=/usr/local/lib")
    // SEARCH_DIR("=/lib")
    // SEARCH_DIR("=/usr/lib")
    // SEARCH_DIR("=/usr/aarch64-linux-gnu/lib")
    // ```
    let cmd = r#"
        ld --verbose | grep -oP '(?<=SEARCH_DIR\(\"=)[^"]+(?=\"\);)'
    "#;

    Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                return Some(output.stdout);
            }
            None
        })
        .and_then(|stdout_bytes| String::from_utf8(stdout_bytes).ok())
        .map_or(vec![], |stdout| {
            stdout.lines().map(|item| item.to_string()).collect()
        })
}

fn main() {
    for ld_search_dir in get_ld_search_dirs() {
        println!("cargo:rustc-link-search=native={}", ld_search_dir);
    }
}
