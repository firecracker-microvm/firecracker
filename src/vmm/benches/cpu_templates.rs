// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Benchmarking cases:
//   * `CustomCpuTemplate` JSON deserialization
//   * `CustomCpuTemplate` JSON serialization

use std::mem::size_of_val;

use criterion::{Criterion, criterion_group, criterion_main};
use vmm::cpu_config::templates::CustomCpuTemplate;
use vmm::cpu_config::templates::test_utils::{TEST_TEMPLATE_JSON, build_test_template};

#[inline]
pub fn bench_serialize_cpu_template(cpu_template: &CustomCpuTemplate) {
    let _ = serde_json::to_string(cpu_template);
}

#[inline]
pub fn bench_deserialize_cpu_template(cpu_template_str: &str) {
    let _ = serde_json::from_str::<CustomCpuTemplate>(cpu_template_str);
}

pub fn cpu_template_benchmark(c: &mut Criterion) {
    println!(
        "Deserialization test - Template size (JSON string): [{}] bytes.",
        TEST_TEMPLATE_JSON.len()
    );

    let test_cpu_template = build_test_template();
    println!(
        "Serialization test - Template size: [{}] bytes.",
        size_of_val(&test_cpu_template)
    );

    c.bench_function("deserialize_cpu_template", |b| {
        b.iter(|| bench_deserialize_cpu_template(TEST_TEMPLATE_JSON))
    });

    c.bench_function("serialize_cpu_template", |b| {
        b.iter(|| bench_serialize_cpu_template(&test_cpu_template))
    });
}

criterion_group! {
    name = cpu_template_benches;
    config = Criterion::default().sample_size(200).noise_threshold(0.05);
    targets = cpu_template_benchmark
}

criterion_main! {
    cpu_template_benches
}
