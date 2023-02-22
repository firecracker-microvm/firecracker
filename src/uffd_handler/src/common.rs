// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::os::unix::net::UnixStream;

use utils::sock_ctrl_msg::ScmSocket;

/// Parse the unix stream received from the Firecracker process to obtain
/// the userfaultfd used to poll for events and the message containing memory mappings.
pub fn parse_unix_stream(stream: &UnixStream) -> (File, String) {
    let mut message_buf = vec![0u8; 1024];
    let (bytes_read, file) = stream
        .recv_with_fd(&mut message_buf[..])
        .expect("Cannot recv_with_fd");
    message_buf.resize(bytes_read, 0);

    let body = String::from_utf8(message_buf).unwrap();
    let file = file.expect("Uffd not passed through UDS!");

    (file, body)
}
