// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(test)]
mod tests {
    use std::process::Command;

    fn version_output(args: &[&str]) -> String {
        let output = Command::new(env!("CARGO_BIN_EXE_firecracker"))
            .args(args)
            .output()
            .expect("Failed to run Firecracker");
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).expect("Invalid version output");
        // The existing exit log follows the blank line after the CLI output.
        let (version, _) = stdout.split_once("\n\n").expect("Missing version output");
        version.to_string()
    }

    #[test]
    fn test_version_without_features() {
        let suffix = if cfg!(feature = "fuzzing") {
            "+fuzzing"
        } else {
            ""
        };
        let expected = format!("Firecracker v{}{suffix}", env!("CARGO_PKG_VERSION"));
        assert_eq!(version_output(&["--version"]), expected);

        for level in [
            "off", "error", "warn", "warning", "info", "INFO", "invalid", "debug", "trace",
            "DEBUG", "TRACE",
        ] {
            assert_eq!(version_output(&["--version", "--level", level]), expected);
        }
    }

    #[test]
    fn test_features() {
        let features: Vec<_> = [
            ("fuzzing", cfg!(feature = "fuzzing")),
            ("gdb", cfg!(feature = "gdb")),
            ("log-instrument", cfg!(feature = "log-instrument")),
            ("tracing", cfg!(feature = "tracing")),
        ]
        .into_iter()
        .filter_map(|(feature, enabled)| enabled.then_some(feature))
        .collect();
        let expected = format!("Enabled features: {features:?}");

        for args in [
            vec!["--features"],
            vec!["--features", "--version"],
            vec!["--version", "--features"],
            vec!["--features", "--level", "debug"],
            vec!["--features", "--level", "trace"],
        ] {
            assert_eq!(version_output(&args), expected);
        }
    }

    #[test]
    fn test_features_after_separator() {
        assert_eq!(
            version_output(&["--version", "--", "--features"]),
            version_output(&["--version"])
        );
    }

    #[test]
    fn test_features_help() {
        for help in ["--help", "-h"] {
            let output = Command::new(env!("CARGO_BIN_EXE_firecracker"))
                .args(["--features", help])
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(stdout.contains("--features"), "{stdout}");
            assert!(!stdout.contains("Enabled features:"), "{stdout}");
        }
    }
}
