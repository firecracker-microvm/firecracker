extern crate criterion;
extern crate snapshot;
extern crate snapshot_derive;

use criterion::{criterion_group, criterion_main, Criterion};
use snapshot::{Snapshot, Result, Error};
use snapshot::version_map::VersionMap;
use snapshot::Versionize;
use snapshot_derive::Versionize;


#[derive(Versionize, Clone, Default, Debug)]
struct Test {
    dummy: Vec<Dummy>,
    field_x: u64,
    field0: u64,
    field1: u32,
    #[snapshot(start_version = 2, default_fn = "field2_default")]
    field2: u64,
    #[snapshot(
        start_version = 3,
        default_fn = "field3_default",
        semantic_ser_fn = "field3_serialize",
        semantic_de_fn = "field3_deserialize"
    )]
    field3: String,
    #[snapshot(
        start_version = 4,
        default_fn = "field4_default",
        semantic_ser_fn = "field4_serialize",
        semantic_de_fn = "field4_deserialize"
    )]
    field4: Vec<u64>,
}

#[derive(Versionize, Clone, Default, Debug)]
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

    fn field4_serialize(&mut self, target_version: u16) -> Result<()> {
        // Fail if semantic serialization is called for the latest version.
        assert_ne!(target_version, Test::version());
        self.field0 = self.field4.iter().sum();

        if self.field0 == 6666 {
            return Err(Error::Semantic("field4 element sum is 6666".to_owned()));
        }
        Ok(())
    }

    fn field4_deserialize(&mut self, source_version: u16) -> Result<()> {
        // Fail if semantic deserialization is called for the latest version.
        assert_ne!(source_version, Test::version());
        self.field4 = vec![self.field0; 4];
        Ok(())
    }

    fn field3_serialize(&mut self, target_version: u16) -> Result<()> {
        // Fail if semantic serialization is called for the previous versions only.
        assert!(target_version < 3);
        self.field_x += 1;
        Ok(())
    }

    fn field3_deserialize(&mut self, source_version: u16) -> Result<()> {
        // Fail if semantic deserialization is called for the latest version.
        assert!(source_version < 3);
        self.field_x += 1;
        if self.field0 == 7777 {
            return Err(Error::Semantic("field0 is 7777".to_owned()));
        }
        Ok(())
    }
}

#[inline]
pub fn bench_restore_v1(mut snapshot_mem: &[u8], vm: VersionMap) {
    let mut loaded_snapshot = Snapshot::load(&mut snapshot_mem, vm).unwrap();

    if let Some(mut state) = loaded_snapshot
        .read_section::<Test>("test")
        .unwrap()
    {
        state.field2 += 1;
    }
}

#[inline]
pub fn bench_snapshot_v1(mut snapshot_mem: &mut [u8], vm: VersionMap) -> usize{
    let state = Test {
        dummy: vec![Dummy{ dummy: 123, string: "xxx".to_owned()}; 100],
        field0: 0,
        field1: 1,
        field2: 2,
        field3: "test".to_owned(),
        field4: vec![4; 1024*10],
        field_x: 0,
    };
    
    // Serialize as v4.
    let mut snapshot = Snapshot::new(vm.clone(), 4);
    let size = snapshot.write_section("test", &state).unwrap();
    snapshot.save(&mut snapshot_mem).unwrap();
    size
}

#[inline]
pub fn bench_restore_crc_v1(mut snapshot_mem: &[u8], vm: VersionMap) {
    let mut loaded_snapshot = Snapshot::load_with_crc64(&mut snapshot_mem, vm).unwrap();

    if let Some(mut state) = loaded_snapshot
        .read_section::<Test>("test")
        .unwrap()
    {
        state.field2 += 1;
    }
}

#[inline]
pub fn bench_snapshot_crc_v1(mut snapshot_mem: &mut [u8], vm: VersionMap) -> usize{
    let state = Test {
        dummy: vec![Dummy{ dummy: 123, string: "xxx".to_owned()}; 100],
        field0: 0,
        field1: 1,
        field2: 2,
        field3: "test".to_owned(),
        field4: vec![4; 1024*10],
        field_x: 0,
    };
    
    // Serialize as v4.
    let mut snapshot = Snapshot::new(vm.clone(), 4);
    let size = snapshot.write_section("test", &state).unwrap();
    snapshot.save_with_crc64(&mut snapshot_mem).unwrap();
    size
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut snapshot_mem = vec![0u8; 1024*1024*128];
    let mut vm = VersionMap::new();

    vm.new_version()
        .set_type_version(Test::name(), 2)
        .new_version()
        .set_type_version(Test::name(), 3)
        .new_version()
        .set_type_version(Test::name(), 4);
    
    let mut snapshot_len = bench_snapshot_v1(&mut snapshot_mem.as_mut_slice(), vm.clone());
    println!("Snapshot len {}", snapshot_len);
    
    c.bench_function("Serialize to v4", |b| b.iter(|| bench_snapshot_v1(&mut snapshot_mem.as_mut_slice(), vm.clone())));
    c.bench_function("Deserialize to v4", |b| b.iter(|| bench_restore_v1(&mut snapshot_mem.as_slice(), vm.clone())));
    
    snapshot_len = bench_snapshot_crc_v1(&mut snapshot_mem.as_mut_slice(), vm.clone());
    println!("Snapshot with crc64 len {}", snapshot_len);

    c.bench_function("Serialize with crc64 to v4", |b| b.iter(|| bench_snapshot_crc_v1(&mut snapshot_mem.as_mut_slice(), vm.clone())));
    c.bench_function("Deserialize with crc64 from v4", |b| b.iter(|| bench_restore_crc_v1(&mut snapshot_mem.as_slice(), vm.clone())));

}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = criterion_benchmark
}

criterion_main!(benches);
