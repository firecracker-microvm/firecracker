// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    // Cargo provides original feature names, including optional dependencies.
    let features = std::env::var("CARGO_CFG_FEATURE").unwrap_or_default();
    let mut features: Vec<_> = features.split(',').filter(|s| !s.is_empty()).collect();
    features.sort_unstable();
    println!("cargo:rustc-env=JAILER_ENABLED_FEATURES={features:?}");
}
