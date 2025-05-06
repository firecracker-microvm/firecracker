// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{OpenOptions, remove_file};
use std::io::{Read, Write};
use std::process::Command;

use uuid::Uuid;

const BINARY: &str = env!("CARGO_BIN_EXE_clippy-tracing");

fn setup(text: &str) -> String {
    let id = Uuid::new_v4();
    let path = format!("/tmp/{id}.rs");
    let mut file = OpenOptions::new()
        .create(true)
        .read(false)
        .write(true)
        .open(&path)
        .unwrap();
    file.write_all(text.as_bytes()).unwrap();
    path
}

fn check_file(text: &str, path: &str) {
    let mut file = OpenOptions::new()
        .create(false)
        .read(true)
        .write(false)
        .open(path)
        .unwrap();
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).unwrap();
    assert_eq!(text, buffer);
}

fn fix(given: &str, expected: &str, cfg_attr: Option<&'static str>) {
    let path = setup(given);

    let output = if let Some(cfg_attr) = cfg_attr {
        Command::new(BINARY)
            .args(["--action", "fix", "--path", &path, "--cfg-attr", cfg_attr])
            .output()
            .unwrap()
    } else {
        Command::new(BINARY)
            .args(["--action", "fix", "--path", &path])
            .output()
            .unwrap()
    };
    assert_eq!(std::str::from_utf8(&output.stdout).unwrap(), "");
    assert_eq!(std::str::from_utf8(&output.stderr).unwrap(), "");
    assert_eq!(output.status.code(), Some(0));
    check_file(expected, &path);
    remove_file(path).unwrap();
}

fn strip(given: &str, expected: &str) {
    let path = setup(given);
    let output = Command::new(BINARY)
        .args(["--action", "strip", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, []);
    assert_eq!(output.stderr, []);
    check_file(expected, &path);
    remove_file(path).unwrap();
}

#[test]
fn exec_error() {
    // Create file path for a file that doesn't exist.
    let id = Uuid::new_v4();
    let path = format!("/tmp/{id}.rs");

    let output = Command::new(BINARY)
        .args(["--action", "check", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, []);
    let expected_stderr = format!(
        "Error: Failed to read entry in file path: IO error for operation on {path}: No such file \
         or directory (os error 2)\n"
    );
    assert_eq!(output.stderr, expected_stderr.as_bytes());
}

#[test]
fn fix_one() {
    const GIVEN: &str = "fn main() { }\nfn add(lhs: i32, rhs: i32) {\n    lhs + rhs\n}";
    const EXPECTED: &str = "#[log_instrument::instrument]\nfn main() { \
                            }\n#[log_instrument::instrument]\nfn add(lhs: i32, rhs: i32) {\n    \
                            lhs + rhs\n}";
    fix(GIVEN, EXPECTED, None);
}

#[test]
fn fix_two() {
    const GIVEN: &str = "impl Unit {\n    fn one() {}\n}";
    const EXPECTED: &str = "impl Unit {\n    #[log_instrument::instrument]\n    fn one() {}\n}";
    fix(GIVEN, EXPECTED, None);
}

#[test]
fn fix_three() {
    const GIVEN: &str = "impl Unit {\n    fn one() {}\n}";
    const EXPECTED: &str = "impl Unit {\n    #[cfg_attr(feature = \"tracing\", \
                            log_instrument::instrument)]\n    fn one() {}\n}";
    fix(GIVEN, EXPECTED, Some("feature = \"tracing\""));
}

#[test]
fn check_one() {
    const GIVEN: &str = "fn main() { }";
    let path = setup(GIVEN);
    let output = Command::new(BINARY)
        .args(["--action", "check", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let expected_stdout = format!("Missing instrumentation at {path}:1:0.\n");
    assert_eq!(output.stdout, expected_stdout.as_bytes());
    assert_eq!(output.stderr, []);
    remove_file(path).unwrap();
}

#[test]
fn check_two() {
    const GIVEN: &str = "#[log_instrument::instrument]\nfn main() { }\n#[test]\nfn my_test() { }";
    let path: String = setup(GIVEN);
    let output = Command::new(BINARY)
        .args(["--action", "check", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, []);
    assert_eq!(output.stderr, []);
    remove_file(path).unwrap();
}

#[test]
fn check_three() {
    const GIVEN: &str = "impl Unit {\n    #[cfg_attr(feature = \"tracing\", \
                         tracing::instrument(level = \"trace\", skip()))]\n    fn one() {}\n}";
    let path = setup(GIVEN);
    let output = Command::new(BINARY)
        .args([
            "--action",
            "check",
            "--path",
            &path,
            "--cfg-attr",
            "feature = \"tracing\"",
        ])
        .output()
        .unwrap();
    assert_eq!(std::str::from_utf8(&output.stdout).unwrap(), "");
    assert_eq!(std::str::from_utf8(&output.stderr).unwrap(), "");
    assert_eq!(output.status.code(), Some(0));
    remove_file(path).unwrap();
}

#[test]
fn strip_one() {
    const GIVEN: &str = "#[log_instrument::instrument]\nfn main() { }";
    const EXPECTED: &str = "fn main() { }";
    strip(GIVEN, EXPECTED);
}

#[test]
fn strip_two() {
    const GIVEN: &str = "#[log_instrument::instrument]\nfn main() { }";
    const EXPECTED: &str = "fn main() { }";
    strip(GIVEN, EXPECTED);
}

#[test]
fn strip_three() {
    const EXPECTED: &str = "impl Unit {\n    fn one() {}\n}";
    const GIVEN: &str = "impl Unit {\n    #[log_instrument::instrument]\n    fn one() {}\n}";
    strip(GIVEN, EXPECTED);
}

#[test]
fn exclude() {
    const GIVEN: &str = "fn main() { }\nfn add(lhs: i32, rhs: i32) {\n    lhs + rhs\n}";
    const EXPECTED: &str = "#[log_instrument::instrument]\nfn main() { \
                            }\n#[log_instrument::instrument]\nfn add(lhs: i32, rhs: i32) {\n    \
                            lhs + rhs\n}";

    let dir_path = format!("/tmp/{}", Uuid::new_v4());
    std::fs::create_dir(&dir_path).unwrap();

    dbg!(&dir_path);

    let file_path_one = format!("{dir_path}/{}.rs", Uuid::new_v4());
    let file_path_two = format!("{dir_path}/{}.rs", Uuid::new_v4());

    dbg!(&file_path_one);
    dbg!(&file_path_two);

    let mut file_one = OpenOptions::new()
        .create(true)
        .read(false)
        .write(true)
        .open(&file_path_one)
        .unwrap();
    file_one.write_all(GIVEN.as_bytes()).unwrap();

    let mut file_two = OpenOptions::new()
        .create(true)
        .read(false)
        .write(true)
        .open(&file_path_two)
        .unwrap();
    file_two.write_all(GIVEN.as_bytes()).unwrap();

    let output = Command::new(BINARY)
        .args([
            "--action",
            "fix",
            "--path",
            &dir_path,
            "--exclude",
            &file_path_two,
        ])
        .output()
        .unwrap();

    assert_eq!(std::str::from_utf8(&output.stdout).unwrap(), "");
    assert_eq!(std::str::from_utf8(&output.stderr).unwrap(), "");
    assert_eq!(output.status.code(), Some(0));

    check_file(EXPECTED, &file_path_one);
    check_file(GIVEN, &file_path_two);

    remove_file(file_path_one).unwrap();
    remove_file(file_path_two).unwrap();
    std::fs::remove_dir(dir_path).unwrap();
}

#[test]
fn readme() {
    const GIVEN: &str = r#"fn main() {
    println!("Hello World!");
}
fn add(lhs: i32, rhs: i32) -> i32 {
    lhs + rhs
}
#[cfg(tests)]
mod tests {
    fn sub(lhs: i32, rhs: i32) -> i32 {
        lhs - rhs
    }
    #[test]
    fn test_one() {
        assert_eq!(add(1,1), sub(2, 1));
    }
}"#;
    let path: String = setup(GIVEN);

    // Check
    let output = Command::new(BINARY)
        .args(["--action", "check", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let missing = format!("Missing instrumentation at {path}:9:4.\n");
    assert_eq!(output.stdout, missing.as_bytes());
    assert_eq!(output.stderr, []);

    const EXPECTED: &str = r#"#[log_instrument::instrument]
fn main() {
    println!("Hello World!");
}
#[log_instrument::instrument]
fn add(lhs: i32, rhs: i32) -> i32 {
    lhs + rhs
}
#[cfg(tests)]
mod tests {
    #[log_instrument::instrument]
    fn sub(lhs: i32, rhs: i32) -> i32 {
        lhs - rhs
    }
    #[test]
    fn test_one() {
        assert_eq!(add(1,1), sub(2, 1));
    }
}"#;

    // Fix
    let output = Command::new(BINARY)
        .args(["--action", "fix", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, []);
    assert_eq!(output.stderr, []);
    check_file(EXPECTED, &path);

    // Check
    let output = Command::new(BINARY)
        .args(["--action", "check", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, []);
    assert_eq!(output.stderr, []);

    // Strip
    let output = Command::new(BINARY)
        .args(["--action", "strip", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, []);
    assert_eq!(output.stderr, []);
    check_file(GIVEN, &path);
}

#[test]
fn readme_empty_suffix() {
    const GIVEN: &str = r#"fn main() {
    println!("Hello World!");
}
fn add(lhs: i32, rhs: i32) -> i32 {
    lhs + rhs
}
#[cfg(tests)]
mod tests {
    fn sub(lhs: i32, rhs: i32) -> i32 {
        lhs - rhs
    }
    #[test]
    fn test_one() {
        assert_eq!(add(1,1), sub(2, 1));
    }
}"#;
    let path: String = setup(GIVEN);

    // Check
    let output = Command::new(BINARY)
        .args(["--action", "check", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let missing = format!("Missing instrumentation at {path}:9:4.\n");
    assert_eq!(output.stdout, missing.as_bytes());
    assert_eq!(output.stderr, []);

    const EXPECTED: &str = r#"#[instrument]
fn main() {
    println!("Hello World!");
}
#[instrument]
fn add(lhs: i32, rhs: i32) -> i32 {
    lhs + rhs
}
#[cfg(tests)]
mod tests {
    #[instrument]
    fn sub(lhs: i32, rhs: i32) -> i32 {
        lhs - rhs
    }
    #[test]
    fn test_one() {
        assert_eq!(add(1,1), sub(2, 1));
    }
}"#;

    // Fix
    let output = Command::new(BINARY)
        .args(["--action", "fix", "--suffix", "", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, []);
    assert_eq!(output.stderr, []);
    check_file(EXPECTED, &path);

    // Check
    let output = Command::new(BINARY)
        .args(["--action", "check", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, []);
    assert_eq!(output.stderr, []);

    // Strip
    let output = Command::new(BINARY)
        .args(["--action", "strip", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, []);
    assert_eq!(output.stderr, []);
    check_file(GIVEN, &path);
}

#[test]
fn readme_custom_suffix() {
    const GIVEN: &str = r#"fn main() {
    println!("Hello World!");
}
fn add(lhs: i32, rhs: i32) -> i32 {
    lhs + rhs
}
#[cfg(tests)]
mod tests {
    fn sub(lhs: i32, rhs: i32) -> i32 {
        lhs - rhs
    }
    #[test]
    fn test_one() {
        assert_eq!(add(1,1), sub(2, 1));
    }
}"#;
    let path: String = setup(GIVEN);

    // Check
    let output = Command::new(BINARY)
        .args(["--action", "check", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let missing = format!("Missing instrumentation at {path}:9:4.\n");
    assert_eq!(output.stdout, missing.as_bytes());
    assert_eq!(output.stderr, []);

    const EXPECTED: &str = r#"#[my::custom::suffix::instrument]
fn main() {
    println!("Hello World!");
}
#[my::custom::suffix::instrument]
fn add(lhs: i32, rhs: i32) -> i32 {
    lhs + rhs
}
#[cfg(tests)]
mod tests {
    #[my::custom::suffix::instrument]
    fn sub(lhs: i32, rhs: i32) -> i32 {
        lhs - rhs
    }
    #[test]
    fn test_one() {
        assert_eq!(add(1,1), sub(2, 1));
    }
}"#;

    // Fix
    let output = Command::new(BINARY)
        .args([
            "--action",
            "fix",
            "--suffix",
            "my::custom::suffix::",
            "--path",
            &path,
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, []);
    assert_eq!(output.stderr, []);
    check_file(EXPECTED, &path);

    // Check
    let output = Command::new(BINARY)
        .args(["--action", "check", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, []);
    assert_eq!(output.stderr, []);

    // Strip
    let output = Command::new(BINARY)
        .args(["--action", "strip", "--path", &path])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, []);
    assert_eq!(output.stderr, []);
    check_file(GIVEN, &path);
}
