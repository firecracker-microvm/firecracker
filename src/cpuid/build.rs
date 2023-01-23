// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    // Sets a `--cfg` flag for conditional compilation.
    //
    // TODO: Use `core::arch::x86_64::has_cpuid`
    // (https://github.com/firecracker-microvm/firecracker/issues/3271).
    #[cfg(any(
        all(target_arch = "x86", target_feature = "sse", not(target_env = "sgx")),
        all(target_arch = "x86_64", not(target_env = "sgx"))
    ))]
    println!("cargo:rustc-cfg=cpuid");
}
