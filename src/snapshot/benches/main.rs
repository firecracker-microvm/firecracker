// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
extern crate criterion;
extern crate snapshot;
extern crate versionize;
extern crate versionize_derive;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use snapshot::Snapshot;
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;

mod version_map;

#[derive(Clone, Debug, Default, Versionize)]
struct Test {
    dummy: Vec<Dummy>,
    field_x: u64,
    field0: u64,
    field1: u32,
    #[version(start = 2, default_fn = "field2_default")]
    field2: u64,
    #[version(
        start = 3,
        default_fn = "field3_default",
        ser_fn = "field3_serialize",
        de_fn = "field3_deserialize"
    )]
    field3: String,
    #[version(
        start = 4,
        default_fn = "field4_default",
        ser_fn = "field4_serialize",
        de_fn = "field4_deserialize"
    )]
    field4: Vec<u64>,
}

#[derive(Clone, Debug, Default, Versionize)]
struct Dummy {
    dummy: u64,
    string: String,
}

impl Test {
    fn field2_default(_: u16) -> u64 {
        20
    }
    fn field3_default(_: u16) -> String {
        "default".to_owned()
    }
    fn field4_default(_: u16) -> Vec<u64> {
        vec![1, 2, 3, 4]
    }

    fn field4_serialize(&mut self, target_version: u16) -> VersionizeResult<()> {
        // Fail if semantic serialization is called for the latest version.
        assert_ne!(target_version, Test::version());
        self.field0 = self.field4.iter().sum();

        if self.field0 == 6666 {
            return Err(VersionizeError::Semantic(
                "field4 element sum is 6666".to_owned(),
            ));
        }
        Ok(())
    }

    fn field4_deserialize(&mut self, source_version: u16) -> VersionizeResult<()> {
        // Fail if semantic deserialization is called for the latest version.
        assert_ne!(source_version, Test::version());
        self.field4 = vec![self.field0; 4];
        Ok(())
    }

    fn field3_serialize(&mut self, target_version: u16) -> VersionizeResult<()> {
        // Fail if semantic serialization is called for the previous versions only.
        assert!(target_version < 3);
        self.field_x += 1;
        Ok(())
    }

    fn field3_deserialize(&mut self, source_version: u16) -> VersionizeResult<()> {
        // Fail if semantic deserialization is called for the latest version.
        assert!(source_version < 3);
        self.field_x += 1;
        if self.field0 == 7777 {
            return Err(VersionizeError::Semantic("field0 is 7777".to_owned()));
        }
        Ok(())
    }
}

#[inline]
pub fn bench_restore_v1(mut snapshot_mem: &[u8], vm: VersionMap, crc: bool) {
    if crc {
        Snapshot::load_with_crc64::<&[u8], Test>(&mut snapshot_mem, vm).unwrap();
    } else {
        Snapshot::load::<&[u8], Test>(&mut snapshot_mem, vm).unwrap();
    }
}

#[inline]
pub fn bench_snapshot_v1<W: std::io::Write>(mut snapshot_mem: &mut W, vm: VersionMap, crc: bool) {
    let state = Test {
        dummy: vec![
            Dummy {
                dummy: 123,
                string: "xxx".to_owned()
            };
            100
        ],
        field0: 0,
        field1: 1,
        field2: 2,
        field3: "test".to_owned(),
        field4: vec![4; 1024 * 10],
        field_x: 0,
    };

    let mut snapshot = Snapshot::new(vm.clone(), 4);
    if crc {
        snapshot.save_with_crc64(&mut snapshot_mem, &state).unwrap();
    } else {
        snapshot.save(&mut snapshot_mem, &state).unwrap();
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut snapshot_mem = vec![0u8; 1024 * 1024 * 128];
    let mut vm = VersionMap::new();

    vm.new_version()
        .set_type_version(Test::type_id(), 2)
        .new_version()
        .set_type_version(Test::type_id(), 3)
        .new_version()
        .set_type_version(Test::type_id(), 4);

    let mut slice = &mut snapshot_mem.as_mut_slice();
    bench_snapshot_v1(&mut slice, vm.clone(), false);
    let mut snapshot_len = slice.as_ptr() as usize - snapshot_mem.as_slice().as_ptr() as usize;

    println!("Snapshot length: {} bytes", snapshot_len);

    c.bench_function("Serialize to v4", |b| {
        b.iter(|| {
            bench_snapshot_v1(
                black_box(&mut snapshot_mem.as_mut_slice()),
                black_box(vm.clone()),
                black_box(false),
            )
        })
    });
    c.bench_function("Deserialize to v4", |b| {
        b.iter(|| {
            bench_restore_v1(
                black_box(&mut snapshot_mem.as_slice()),
                black_box(vm.clone()),
                black_box(false),
            )
        })
    });

    let another_slice = &mut snapshot_mem.as_mut_slice();
    bench_snapshot_v1(another_slice, vm.clone(), true);
    snapshot_len = another_slice.as_ptr() as usize - snapshot_mem.as_slice().as_ptr() as usize;
    println!("Snapshot with crc64 length: {} bytes", snapshot_len);

    c.bench_function("Serialize with crc64 to v4", |b| {
        b.iter(|| {
            bench_snapshot_v1(
                black_box(&mut snapshot_mem.as_mut_slice()),
                black_box(vm.clone()),
                black_box(true),
            )
        })
    });
    c.bench_function("Deserialize with crc64 from v4", |b| {
        b.iter(|| {
            bench_restore_v1(
                black_box(&mut snapshot_mem.as_slice()),
                black_box(vm.clone()),
                black_box(true),
            )
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(200);
    targets = criterion_benchmark
}

criterion_main! {
    benches,
    version_map::benches,
}
