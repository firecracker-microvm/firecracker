// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
fn main() {
    // SAFETY: This is just an example to demonstrate syscall filtering.
    // The syscall is safe because we're only writing a static string to a file descriptor.
    unsafe {
        // In this example, the malicious component is outputting to standard input.
        libc::syscall(libc::SYS_write, libc::STDIN_FILENO, "Hello, world!\n", 14);
    }
}
