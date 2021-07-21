// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
fn main() {
    unsafe {
        // Simulate a Firecracker panic by aborting.
        // The Firecracker build is configured with panic = "abort".
        unsafe { libc::abort() };
    }
}