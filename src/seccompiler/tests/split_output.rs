// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]

use std::fs;
use std::process::Command;

use vmm_sys_util::tempdir::TempDir;

fn run(args: &[&str]) -> Result<Vec<u8>, String> {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.as_path().join("policy.json"),
        r#"{"main":{"default_action":"trap","filter_action":"allow","filter":[
            {"syscall":"write","feature":"net"},{"syscall":"read","feature":"block"}]}}"#,
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_seccompiler-bin"))
        .current_dir(dir.as_path())
        .args(["--input-file", "policy.json", "--target-arch", "x86_64"])
        .args(args)
        .output()
        .unwrap();
    let bpf = dir.as_path().join("main.bpf");
    if output.status.success() {
        Ok(fs::read(bpf).unwrap())
    } else {
        assert!(!bpf.exists());
        Err(String::from_utf8(output.stderr).unwrap())
    }
}

#[test]
fn split_output_selects_fragments() {
    let select = |list| run(&["--split-output", "--features", list]).unwrap();
    let all = run(&["--split-output"]).unwrap();
    let none = select("none");
    let block = select("block");
    assert_ne!(none, all);
    assert_ne!(block, none);
    assert_ne!(block, all);
    assert_eq!(select(" none "), none);
    assert_eq!(select(" all "), all);
    assert_eq!(select("pci, block "), block);
    assert_eq!(
        run(&["--split-output", "--features", "net", "--features", "block"]).unwrap(),
        all
    );
}

#[test]
fn reject_invalid_selections() {
    for list in ["nett", "net, all", "none, net", "", " ", "net,"] {
        assert!(
            run(&["--split-output", "--features", list])
                .unwrap_err()
                .contains("InvalidFeatureSelection"),
            "{list:?}"
        );
    }
    assert!(
        run(&["--split-output", "--features", "all", "--features", "net"])
            .unwrap_err()
            .contains("InvalidFeatureSelection")
    );
    assert!(
        run(&["--features", "net"])
            .unwrap_err()
            .contains("--split-output")
    );
}
