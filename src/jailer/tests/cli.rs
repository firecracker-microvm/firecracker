// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use std::process::{Command, Output};

    fn jailer(args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_jailer"))
            .args(args)
            .output()
            .expect("failed to execute jailer")
    }

    #[test]
    fn test_version() {
        for args in [
            vec!["--version"],
            vec!["--version", "--verbose"],
            vec!["--verbose", "--version"],
        ] {
            let output = jailer(&args);
            assert!(output.status.success(), "{output:?}");
            assert!(output.stderr.is_empty());
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                format!("Jailer v{}\n\n", env!("CARGO_PKG_VERSION"))
            );
        }
    }

    #[test]
    fn test_features() {
        let features: Vec<_> = [
            ("log-instrument", cfg!(feature = "log-instrument")),
            ("tracing", cfg!(feature = "tracing")),
        ]
        .into_iter()
        .filter_map(|(feature, enabled)| enabled.then_some(feature))
        .collect();

        for args in [
            vec!["--features"],
            vec!["--features", "--version"],
            vec!["--version", "--features"],
        ] {
            let output = jailer(&args);
            assert!(output.status.success(), "{args:?}: {output:?}");
            assert!(output.stderr.is_empty());
            assert_eq!(
                String::from_utf8(output.stdout).unwrap(),
                format!("Enabled features: {features:?}\n\n")
            );
        }
    }

    #[test]
    fn test_features_after_separator() {
        let output = jailer(&["--version", "--", "--features"]);
        assert!(output.status.success(), "{output:?}");
        assert!(
            !String::from_utf8(output.stdout)
                .unwrap()
                .contains("features")
        );
    }

    #[test]
    fn test_verbose_is_not_an_option() {
        let output = jailer(&["--verbose"]);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("wasn't expected"), "{stderr}");
    }

    #[test]
    fn test_features_help() {
        for help in ["--help", "-h"] {
            let output = jailer(&["--features", help]);
            assert!(output.status.success(), "{output:?}");
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(stdout.contains("--features"), "{stdout}");
            assert!(!stdout.contains("--verbose"), "{stdout}");
            assert!(!stdout.contains("Enabled features:"), "{stdout}");
        }
    }
}
