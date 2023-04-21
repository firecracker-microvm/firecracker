// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::thread;
use std::time::Duration;

use hyper::StatusCode;
use tempfile::Builder;
use vmm::guest_config::templates::test_utils::{test_static_template, TEST_INVALID_TEMPLATE_JSON};

mod integ_test_utils;

const CPU_CONFIG_ENDPOINT: &str = "cpu-config";

#[tokio::test]
async fn test_cpu_config() {
    // Bootstrap Firecracker for testing against
    let dir = Builder::new()
        .prefix("fc_integ_tests")
        .tempdir()
        .expect("Failed to create a temporary directory");
    let temp_socket_pathbuffer = dir.path().join("firecracker_test.sock");
    let temp_socket_path = temp_socket_pathbuffer
        .to_str()
        .expect("Failed to create socket file path");
    let fc_process = integ_test_utils::launch_firecracker_process(temp_socket_path);
    // Give the API server a moment to be ready before handing
    // testing continues.
    thread::sleep(Duration::from_millis(500));

    // Test successful request - PUT /cpu-config
    {
        let response_result = integ_test_utils::fc_put_api_request(
            temp_socket_path,
            test_static_template().as_str(),
            CPU_CONFIG_ENDPOINT,
        )
        .await;
        let response = response_result.expect("Error retrieving response from HTTP future");
        assert_eq!(
            response.status(),
            StatusCode::NO_CONTENT,
            "Failed to set CPU configuration"
        );
    }

    // Test failed request - PUT /cpu-config
    {
        let response_result = integ_test_utils::fc_put_api_request(
            temp_socket_path,
            &TEST_INVALID_TEMPLATE_JSON,
            CPU_CONFIG_ENDPOINT,
        )
        .await;
        let response = response_result.expect("Error retrieving response from HTTP future");
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "CPU configuration set successfully when it should have failed."
        );
    }

    // Cleanup the Firecracker process
    integ_test_utils::cleanup(fc_process);
}
