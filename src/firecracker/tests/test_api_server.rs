// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

const BINARY: &str = env!("CARGO_BIN_EXE_firecracker");

#[test]
fn test_api_socket_in_use() {
    // Create a unix socket with a temporary file.
    let file = utils::tempfile::TempFile::new().unwrap();
    let socket = std::os::unix::net::UnixListener::bind(file.as_path());

    // Start firecracker process pointing to this file as the API socket.
    let socket_path = file.as_path().as_os_str().to_str().unwrap();
    let output = std::process::Command::new(BINARY)
        .args(["--api-sock", socket_path])
        .output()
        .unwrap();

    // Assert the firecracker process exited with expected results.
    assert_eq!(output.status.code().unwrap(), 1);
    assert_eq!(output.stdout, b"");

    // The specific message used can vary between "Address already in use" and "Address in use" so
    // we cannot match it exactly.
    let expected_stderr_option_1 = b"Error: RunWithApi(BindAndRun(ServerCreation(IOError(Os { code: 98, kind: AddrInUse, message: \"Address in use\" }))))\n";
    let expected_stderr_option_2 = b"Error: RunWithApi(BindAndRun(ServerCreation(IOError(Os { code: 98, kind: AddrInUse, message: \"Address already in use\" }))))\n";
    assert!(
        output.stderr == expected_stderr_option_1 || output.stderr == expected_stderr_option_2,
        "{:?} != {:?} || {:?}",
        std::str::from_utf8(&output.stderr),
        std::str::from_utf8(expected_stderr_option_1),
        std::str::from_utf8(expected_stderr_option_2)
    );

    // This will happen implicitly, but it helps to explicitly ensure and document the unix socket
    // is dropped after the firecracker process.
    drop(socket);
}
