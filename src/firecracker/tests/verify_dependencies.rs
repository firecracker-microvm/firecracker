// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Debug;
use std::path::Path;

use cargo_toml::{Dependency, DependencyDetail, DepsSet, Manifest};
use regex::Regex;

#[test]
fn test_no_comparison_requirements() {
    // HashMap mapping crate -> [(violating dependency, specified version)]
    let mut violating_dependencies = HashMap::new();

    let src_firecracker_path = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let src_path = format!("{}/..", src_firecracker_path);

    for fc_crate in std::fs::read_dir(src_path).unwrap() {
        let fc_crate = fc_crate.unwrap();
        if fc_crate.metadata().unwrap().is_dir() {
            let violating_in_crate =
                violating_dependencies_of_cargo_toml(fc_crate.path().join("Cargo.toml"));

            if !violating_in_crate.is_empty() {
                violating_dependencies.insert(
                    fc_crate.file_name().into_string().unwrap(),
                    violating_in_crate,
                );
            }
        }
    }

    assert_eq!(
        violating_dependencies,
        HashMap::new(),
        "Dependencies should not be specified as comparison requirements. \
        They should use caret requirements. See: \
        https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html"
    );
}

/// Parses the specified Cargo.toml file and returns any dependencies specified using a comparison
/// requirements.
///
/// The return value maps the name of violating dependencies to the specified version
fn violating_dependencies_of_cargo_toml<T: AsRef<Path> + Debug>(
    path: T,
) -> HashMap<String, String> {
    let manifest = Manifest::from_path(path).unwrap();

    violating_dependencies_of_depsset(manifest.dependencies)
        .chain(violating_dependencies_of_depsset(manifest.dev_dependencies))
        .chain(violating_dependencies_of_depsset(
            manifest.build_dependencies,
        ))
        .collect()
}

/// Returns an iterator over all dependencies in the given DepsSet specified using comparison
/// requirements
///
/// The iterator produces tuples of the form (violating dependency, specified version)
#[allow(clippy::let_with_type_underscore)]
fn violating_dependencies_of_depsset(depsset: DepsSet) -> impl Iterator<Item = (String, String)> {
    depsset.into_iter().filter_map(|(name, dependency)| {
        match dependency {
            Dependency::Simple(version) // dependencies specified as `libc = "0.2.117"`
            | Dependency::Detailed(DependencyDetail {  // dependencies specified as `libc = {version = "0.2.117",...}
                version: Some(version),
                ..
            }) if !Regex::new(r"^=?\d*\.\d*\.\d*$").unwrap().is_match(&version) => Some((name, version)),
            _ => None, // dependencies specified without version, such as `libc = {path = "../libc"}
        }
    })
}
