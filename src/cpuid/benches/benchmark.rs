use std::convert::{From, TryFrom};

use cpuid::{Cpuid, RawCpuid};
use criterion::{criterion_group, criterion_main, Criterion};

pub fn conversions(c: &mut Criterion) {
    let kvm = kvm_ioctls::Kvm::new().unwrap();
    let kvm_cpuid = kvm
        .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        .unwrap();
    let raw_cpuid = RawCpuid::from(kvm_cpuid.clone());
    let cpuid = Cpuid::try_from(raw_cpuid.clone()).unwrap();

    let json_cpuid = serde_json::to_vec(&cpuid).unwrap();
    let bincode_cpuid = bincode::serialize(&cpuid).unwrap();

    c.bench_function("kvm.clone()", |b| b.iter(|| kvm_cpuid.clone()));
    c.bench_function("raw.clone()", |b| b.iter(|| raw_cpuid.clone()));
    c.bench_function("cpuid.clone()", |b| b.iter(|| cpuid.clone()));

    c.bench_function("kvm->raw", |b| b.iter(|| RawCpuid::from(kvm_cpuid.clone())));
    c.bench_function("raw->kvm", |b| {
        b.iter(|| kvm_bindings::CpuId::from(raw_cpuid.clone()))
    });
    c.bench_function("raw->cpuid", |b| {
        b.iter(|| Cpuid::try_from(raw_cpuid.clone()))
    });
    c.bench_function("cpuid->raw", |b| b.iter(|| RawCpuid::from(cpuid.clone())));

    c.bench_function("cpuid->json", |b| {
        b.iter(|| serde_json::to_vec(&cpuid).unwrap())
    });

    // This fails in the benchmark, but not in the test
    // c.bench_function("json->cpuid", |b| {
    //     b.iter(|| serde_json::from_slice::<Cpuid>(&json_cpuid).unwrap())
    // });

    c.bench_function("cpuid->bincode", |b| {
        b.iter(|| bincode::serialize(&cpuid).unwrap())
    });
    c.bench_function("bincode->cpuid", |b| {
        b.iter(|| bincode::deserialize::<Cpuid>(&bincode_cpuid).unwrap())
    });
}

criterion_group!(benches, conversions);
criterion_main!(benches);
