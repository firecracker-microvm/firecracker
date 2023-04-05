// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Benchmarking cases:
//   * `CustomCpuTemplate` Deserialization

use std::path::Path;

use criterion::{criterion_group, criterion_main, Criterion};
use vmm::guest_config::templates::test_utils::TEST_TEMPLATE_JSON;
use vmm::guest_config::templates::CustomCpuTemplate;

#[inline]
pub fn bench_deserialize_cpu_template(cpu_template_str: &str) {
    serde_json::from_str::<CustomCpuTemplate>(cpu_template_str);
}

pub fn cpu_template_benchmark(c: &mut Criterion) {
    println!(
        "Template size (JSON string): [{}] bytes.",
        TEST_TEMPLATE_JSON.len()
    );

    c.bench_function("Deserialize custom CPU Template", |b| {
        b.iter(|| bench_deserialize_cpu_template(TEST_TEMPLATE_JSON))
    });
}

criterion_group! {
    name = cpu_template_benches;
    config = Criterion::default().sample_size(200).output_directory(Path::new("../../build/vmm_benchmark/cpu_templates"));
    targets = cpu_template_benchmark
}

criterion_main! {
    cpu_template_benches
}
