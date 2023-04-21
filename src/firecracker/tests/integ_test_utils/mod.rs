// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::ErrorKind::NotFound;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use std::{env, io, thread};

use hyper::{Body, Client, Request, Response};
use hyperlocal::{UnixClientExt, Uri};

#[cfg(target_arch = "x86_64")]
const DEFAULT_BUILD_TARGET: &str = "x86_64-unknown-linux-musl";
#[cfg(target_arch = "aarch64")]
const DEFAULT_BUILD_TARGET: &str = "aarch64-unknown-linux-musl";

/// Launch the firecracker process with an API socket configured with a `tempfile` path.
///
/// # Returns
/// * Child Process
#[inline]
pub(crate) fn launch_firecracker_process(socket_path: &str) -> Child {
    // Build a path to the Firecracker binary
    let fc_bin_path = build_firecracker_path();
    println!("Using path for Firecracker binary [{}]", fc_bin_path);

    // Start Firecracker process
    let fc_process = Command::new(fc_bin_path)
        .arg("--api-sock")
        .arg(socket_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start Firecracker process");

    // Give the API server a moment to be ready before handing
    // testing continues.
    thread::sleep(Duration::from_millis(1500));

    fc_process
}

// Build path to the firecracker binary
//
// There are potentially three different execution contexts for tests.
// `cargo test` run from crate/module within the workspace
// `cargo test` run from Firecracker workspace
// Python tests framework - environment variable will have the value set in `FC_BIN_PATH`
fn build_firecracker_path() -> String {
    // First check to see if the environment variable
    // set by the Python tests is set.
    let fc_path_var = env::var("FC_BIN_PATH");
    if let Ok(fc_path) = fc_path_var {
        println!("Firecracker binary to be found at [{}]", fc_path);
        return PathBuf::from(fc_path.as_str())
            .to_str()
            .expect(
                format!(
                    "Expected path to existing Firecracker binary but was not found [{}]",
                    fc_path,
                )
                .as_str(),
            )
            .to_string();
    } else {
        println!(
            "Shell env variable FC_BIN_PATH not found. Firecracker binary to be built manually."
        );
    }

    // If the shell environment variable at 'FC_BIN_PATH' was not set,
    // assume that the test context is not via Python, but a cargo test run.
    let manifest_root_path = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("Failed to get root path for crate manifest"),
    );
    let manifest_root = manifest_root_path
        .to_str()
        .expect("Failed to get root path for crate manifest");

    // Get a build target to differentiate between CPU architectures,
    // but also build targets (musl/gnu)
    // Default will assume musl
    let built_target_arch_result = env::var("CARGO_CFG_TARGET_ARCH");
    let build_target = if let Ok(build_target_arch) = built_target_arch_result {
        build_target_arch
    } else {
        DEFAULT_BUILD_TARGET.to_string()
    };

    if let Ok(fc_path) = build_fc_path_string(manifest_root, &build_target) {
        fc_path
    } else {
        // The test's execution context differs depending on whether they are being
        // run from the workspace root, or from a crate/module.
        let workspace_root = manifest_root_path
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_str()
            .expect("Failed to get workspace root path");

        let fc_path_result = build_fc_path_string(workspace_root, &build_target);
        fc_path_result.expect(
            format!(
                "Unable to find Firecracker build targets in \n[{}] or \n[{}]",
                manifest_root, workspace_root
            )
            .as_str(),
        )
    }
}

fn build_fc_path_string(root_path: &str, build_target: &String) -> Result<String, std::io::Error> {
    let fc_path = format!(
        "{}/build/cargo_target/{}/debug/firecracker",
        root_path, build_target
    );
    if !Path::new(fc_path.as_str()).exists() {
        return Err(io::Error::new(
            NotFound,
            format!("Unable to find Firecracker file [{}]", fc_path),
        ));
    }
    Ok(fc_path)
}

pub(crate) fn cleanup(mut process: Child) {
    process.kill().expect("Failed to stop process");
}

pub(crate) async fn fc_put_api_request(
    api_socket_path: &str,
    payload: &str,
    endpoint: &str,
) -> hyper::Result<Response<Body>> {
    let uri = Uri::new(api_socket_path, format!("/{}", endpoint).as_str());
    let client = Client::unix();

    let req = Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();

    let timed_response = tokio::time::timeout(Duration::from_secs(3), client.request(req)).await;
    timed_response.expect("Timed out waiting for response from Firecracker API server.")
}
