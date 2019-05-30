// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
fn main() {
    unsafe {
        // In this example, the malicious component is outputing to standard input.
        libc::syscall(libc::SYS_write, libc::STDIN_FILENO, "Hello, world!\n", 14);
    }
}
