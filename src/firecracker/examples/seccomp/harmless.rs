// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
fn main() {
    // SAFETY: This is just an example to demonstrate syscall filtering.
    // The syscall is safe because we're only writing a static string to a file descriptor.
    unsafe {
        // Harmless print to standard output.
        libc::syscall(libc::SYS_write, libc::STDOUT_FILENO, "Hello, world!\n", 14);
    }
}
