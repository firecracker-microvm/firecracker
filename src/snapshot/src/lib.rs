// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate bincode;
extern crate crc64;
extern crate serde;
extern crate serde_derive;
extern crate snapshot_derive;
extern crate vmm_sys_util;

pub mod crc;
pub mod primitives;
pub mod version_map;

use crc::{CRC64Reader, CRC64Writer};
use serde_derive::{Deserialize, Serialize};
use snapshot_derive::Versionize;
use std::collections::hash_map::HashMap;
use std::fmt;
use std::io::{Read, Write};
use version_map::VersionMap;

// 256k max section size.
const SNAPSHOT_MAX_SECTION_SIZE: usize = 0x40000;
const SNAPSHOT_FORMAT_VERSION: u16 = 1;
const BASE_MAGIC_ID_MASK: u64 = !0xFFFFu64;

#[cfg(target_arch = "x86_64")]
const BASE_MAGIC_ID: u64 = 0x0710_1984_8664_0000u64;

#[cfg(target_arch = "aarch64")]
const BASE_MAGIC_ID: u64 = 0x0710_1984_AAAA_0000u64;

// Returns format version if arch id is valid.
// Returns none otherwise.
fn validate_magic_id(magic_id: u64) -> Option<u16> {
    let magic_arch = magic_id & BASE_MAGIC_ID_MASK;
    if magic_arch == BASE_MAGIC_ID {
        return Some((magic_id & !BASE_MAGIC_ID_MASK) as u16);
    }
    None
}

fn build_magic_id(format_version: u16) -> u64 {
    BASE_MAGIC_ID | format_version as u64
}

/// Firecracker snapshot format.
///  
///  |----------------------------|
///  |         SnapshotHdr        |
///  |----------------------------|
///  |         Section  #1        |
///  |----------------------------|
///  |         Section  #2        |
///  |----------------------------|
///  |         Section  #3        |
///  |----------------------------|
///             ..........

#[derive(Default, Debug, Versionize)]
struct SnapshotHdr {
    /// Snapshot data version (firecracker version).
    data_version: u16,
    /// Number of sections
    section_count: u16,
}

#[derive(Debug)]
pub struct Snapshot {
    hdr: SnapshotHdr,
    format_version: u16,
    version_map: VersionMap,
    sections: HashMap<String, Section>,
    // Required for serialization.
    target_version: u16,
}

#[derive(Default, Debug, Versionize)]
pub struct Section {
    name: String,
    data: Vec<u8>,
}

#[derive(PartialEq)]
pub enum Error {
    Io(i32),
    Serialize(String),
    Deserialize(String),
    Semantic(String),
    Crc64,
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::Serialize(ref err) => write!(f, "Serialization error: {}", err),
            Error::Deserialize(ref err) => write!(f, "Deserialization error: {}", err),
            Error::Semantic(ref err) => write!(f, "Semantic error: {}", err),
            Error::Crc64 => write!(f, "Crc64 check failed"),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::Serialize(ref err) => write!(f, "Serialization error: {}", err),
            Error::Deserialize(ref err) => write!(f, "Deserialization error: {}", err),
            Error::Semantic(ref err) => write!(f, "Semantic error: {}", err),
            Error::Crc64 => write!(f, "Crc64 check failed"),
        }
    }
}

/// Trait that provides an implementation to deconstruct/restore structs
/// into typed fields backed by the Snapshot storage.
/// This trait is automatically implemented on user specified structs
/// or otherwise manually implemented.
pub trait Versionize {
    fn serialize<W: Write>(
        &self,
        writer: &mut W,
        version_map: &VersionMap,
        target_app_version: u16,
    ) -> Result<()>;

    fn deserialize<R: Read>(
        reader: &mut R,
        version_map: &VersionMap,
        src_app_version: u16,
    ) -> Result<Self>
    where
        Self: Sized;

    fn name() -> String;
    // Returns latest struct version.
    fn version() -> u16;
}

impl Snapshot {
    // Creates a new instance which can only be used to save a new snapshot.
    pub fn new(version_map: VersionMap, target_version: u16) -> Snapshot {
        Snapshot {
            version_map,
            hdr: SnapshotHdr::default(),
            format_version: SNAPSHOT_FORMAT_VERSION,
            sections: HashMap::new(),
            target_version,
        }
    }

    // Loads an existing snapshot.
    pub fn load<T>(mut reader: &mut T, version_map: VersionMap) -> Result<Snapshot>
    where
        T: Read,
    {
        let format_version_map = Self::format_version_map();
        let magic_id = <u64 as Versionize>::deserialize(
            &mut reader,
            &format_version_map,
            0, /* unused */
        )?;
        let format_version = validate_magic_id(magic_id).unwrap();
        let hdr: SnapshotHdr =
            SnapshotHdr::deserialize(&mut reader, &format_version_map, format_version)?;
        let mut sections = HashMap::new();

        for _ in 0..hdr.section_count {
            let section = Section::deserialize(&mut reader, &format_version_map, format_version)?;
            sections.insert(section.name.clone(), section);
        }

        Ok(Snapshot {
            version_map,
            hdr,
            format_version,
            sections,
            // Not used when loading a snapshot.
            target_version: 0,
        })
    }

    // Loads an existing snapshot and validates CRC 64.
    pub fn load_with_crc64<T>(reader: &mut T, version_map: VersionMap) -> Result<Snapshot>
    where
        T: Read,
    {
        let mut crc_reader = CRC64Reader::new(reader);

        // Read entire buffer in memory.
        let snapshot = Snapshot::load(&mut crc_reader, version_map.clone())?;
        let computed_checksum = crc_reader.checksum();
        let stored_checksum: u64 =
            Versionize::deserialize(&mut crc_reader, &snapshot.version_map, 0)?;

        if computed_checksum != stored_checksum {
            println!(
                "Computed = {}, stored = {}",
                computed_checksum, stored_checksum
            );
            return Err(Error::Crc64);
        }

        Ok(snapshot)
    }

    pub fn save_with_crc64<T>(&mut self, writer: &mut T) -> Result<()>
    where
        T: std::io::Write,
    {
        let mut crc_writer = CRC64Writer::new(writer);
        self.save(&mut crc_writer)?;

        let checksum = crc_writer.checksum();
        checksum.serialize(&mut crc_writer, &Self::format_version_map(), 0)?;
        Ok(())
    }

    // Save a snapshot.
    pub fn save<T>(&mut self, mut writer: &mut T) -> Result<()>
    where
        T: std::io::Write,
    {
        self.hdr = SnapshotHdr {
            data_version: self.target_version,
            section_count: self.sections.len() as u16,
        };

        let format_version_map = Self::format_version_map();
        let magic_id = build_magic_id(format_version_map.get_latest_version());

        // Serialize magic id using the format version map.
        magic_id.serialize(&mut writer, &format_version_map, 0 /* unused */)?;
        // Serialize header using the format version map.
        self.hdr.serialize(
            &mut writer,
            &format_version_map,
            format_version_map.get_latest_version(),
        )?;

        // Serialize all the sections.
        for (_, section) in &self.sections {
            // The sections are already serialized.
            section.serialize(
                &mut writer,
                &format_version_map,
                format_version_map.get_latest_version(),
            )?;
        }
        writer
            .flush()
            .map_err(|ref err| Error::Io(err.raw_os_error().unwrap_or(0)))?;

        Ok(())
    }

    // Reads a section (deserialize/translate) from a snapshot.
    pub fn read_section<T>(&mut self, name: &str) -> Result<Option<T>>
    where
        T: Versionize,
    {
        if self.sections.contains_key(name) {
            let section = &mut self.sections.get_mut(name).unwrap();
            return Ok(Some(T::deserialize(
                &mut section.data.as_mut_slice().as_ref(),
                &self.version_map,
                self.hdr.data_version,
            )?));
        }
        Ok(None)
    }

    // Write a section (serialize/translate) to a snapshot.
    pub fn write_section<T>(&mut self, name: &str, object: &T) -> Result<usize>
    where
        T: Versionize,
    {
        let mut new_section = Section {
            name: name.to_owned(),
            data: vec![0; SNAPSHOT_MAX_SECTION_SIZE],
        };

        let slice = &mut new_section.data.as_mut_slice();
        object.serialize(slice, &self.version_map, self.target_version)?;
        // Resize vec to serialized section len.
        let serialized_len =
            slice.as_ptr() as usize - new_section.data.as_slice().as_ptr() as usize;
        new_section.data.truncate(serialized_len);
        self.sections.insert(name.to_owned(), new_section);
        Ok(serialized_len)
    }

    // Returns the current snapshot format version.
    // Not to be confused with data version which refers to the aplication
    // defined structures.
    // This version map allows us to change the underlying storage format -
    // for example the way we encode vectors or moving to something else than bincode.
    fn format_version_map() -> VersionMap {
        // Firecracker snapshot format version 1.
        VersionMap::new()
    }
}

mod tests {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    use super::*;
    pub type __s8 = ::std::os::raw::c_schar;
    pub type __u8 = ::std::os::raw::c_uchar;
    pub type __s16 = ::std::os::raw::c_short;
    pub type __u16 = ::std::os::raw::c_ushort;
    pub type __s32 = ::std::os::raw::c_int;
    pub type __u32 = ::std::os::raw::c_uint;
    pub type __s64 = ::std::os::raw::c_longlong;
    pub type __u64 = ::std::os::raw::c_ulonglong;

    #[repr(u32)]
    #[derive(Debug, Versionize, Serialize, Deserialize, PartialEq, Clone)]
    pub enum TestState {
        One = 1,
        #[snapshot(start_version = 2, default_fn = "test_state_default_one")]
        Two = 2,
        #[snapshot(start_version = 3, default_fn = "test_state_default_two")]
        Three = 3,
    }

    impl Default for TestState {
        fn default() -> Self {
            Self::One
        }
    }

    impl TestState {
        fn test_state_default_one(&self, target_version: u16) -> TestState {
            println!("test_state_default_one target version {}", target_version);

            match target_version {
                2 => TestState::Two,
                _ => TestState::Two,
            }
        }
        fn test_state_default_two(&self, target_version: u16) -> TestState {
            println!("test_state_default_two target version {}", target_version);
            match target_version {
                3 => TestState::Three,
                2 => TestState::Two,
                _ => TestState::One,
            }
        }
    }

    #[derive(Versionize, Clone, Default, Debug)]
    pub struct Test1 {
        field_x: u64,
        field0: u64,
        field1: u32,
    }

    #[derive(Versionize, Clone, Default, Debug)]
    pub struct Test {
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

    #[test]
    fn test_struct_semantic_fn() {
        let mut vm = VersionMap::new();
        vm.new_version()
            .set_type_version(Test::name(), 2)
            .new_version()
            .set_type_version(Test::name(), 3)
            .new_version()
            .set_type_version(Test::name(), 4);
        let state = Test {
            field0: 0,
            field1: 1,
            field2: 2,
            field3: "test".to_owned(),
            field4: vec![4, 3, 2, 1],
            field_x: 0,
        };

        let mut snapshot_mem = vec![0u8; 1024];

        // Serialize as v1.
        let mut snapshot = Snapshot::new(vm.clone(), 1);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        let mut restored_state: Test = snapshot.read_section::<Test>("test").unwrap().unwrap();

        // The semantic serializer fn for field4 will set field0 to field4.iter().sum() == 10.
        assert_eq!(restored_state.field0, state.field4.iter().sum::<u64>());
        assert_eq!(restored_state.field4, vec![restored_state.field0; 4]);
        assert_eq!(restored_state.field_x, 2);

        // Serialize as v3.
        let mut snapshot = Snapshot::new(vm.clone(), 3);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        restored_state = snapshot.read_section::<Test>("test").unwrap().unwrap();

        // The semantic fn for field4 will set field0 to field4.iter().sum() == 10.
        assert_eq!(restored_state.field0, state.field4.iter().sum::<u64>());
        // The semantic deserializer fn will create 4 element vec with all values == field0
        assert_eq!(restored_state.field4, vec![restored_state.field0; 4]);

        // Serialize as v4.
        let mut snapshot = Snapshot::new(vm.clone(), 4);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        restored_state = snapshot.read_section::<Test>("test").unwrap().unwrap();

        // The semantic fn must not be called.
        assert_eq!(restored_state.field0, 0);
        assert_eq!(restored_state.field4, vec![4, 3, 2, 1]);
    }

    #[test]
    fn test_semantic_serialize_error() {
        let mut vm = VersionMap::new();
        vm.new_version()
            .set_type_version(Test::name(), 2)
            .new_version()
            .set_type_version(Test::name(), 3)
            .new_version()
            .set_type_version(Test::name(), 4);

        let state = Test {
            field0: 0,
            field1: 1,
            field2: 2,
            field3: "test".to_owned(),
            field4: vec![6000, 600, 60, 6],
            field_x: 0,
        };

        let mut snapshot = Snapshot::new(vm.clone(), 4);
        // The section will succesfully be serialized.
        assert!(snapshot.write_section("test", &state).is_ok());

        snapshot = Snapshot::new(vm.clone(), 1);
        // The section will fail due to a custom semantic error.
        assert_eq!(
            snapshot.write_section("test", &state),
            Err(Error::Semantic("field4 element sum is 6666".to_owned()))
        );
    }

    #[test]
    fn test_semantic_deserialize_error() {
        let mut vm = VersionMap::new();
        vm.new_version()
            .set_type_version(Test::name(), 2)
            .new_version()
            .set_type_version(Test::name(), 3)
            .new_version()
            .set_type_version(Test::name(), 4);

        let state = Test {
            field0: 6666,
            field1: 1,
            field2: 2,
            field3: "fail".to_owned(),
            field4: vec![7000, 700, 70, 7],
            field_x: 0,
        };

        let mut snapshot_mem = vec![0u8; 1024];

        let mut snapshot = Snapshot::new(vm.clone(), 2);
        // The section will succesfully be serialized.
        assert!(snapshot.write_section("test", &state).is_ok());
        assert_eq!(snapshot.save(&mut snapshot_mem.as_mut_slice()), Ok(()));

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        // The section load will fail due to a custom semantic error.
        let section_read_error = snapshot.read_section::<Test>("test").unwrap_err();
        assert_eq!(
            section_read_error,
            Error::Semantic("field0 is 7777".to_owned())
        );
    }

    #[test]
    fn test_serialize_error() {
        let vm = VersionMap::new();
        let state_1 = Test1 {
            field_x: 0,
            field0: 0,
            field1: 1,
        };

        let mut snapshot_mem = vec![0u8; 1];

        // Serialize as v1.
        let mut snapshot = Snapshot::new(vm.clone(), 1);
        // The section will succesfully be serialized.
        assert!(snapshot.write_section("test", &state_1).is_ok());
        assert_eq!(
            snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap_err(),
            Error::Serialize("io error: failed to write whole buffer".to_owned())
        );
    }

    #[test]
    fn test_crc_ok() {
        let vm = VersionMap::new();
        let state_1 = Test1 {
            field_x: 0,
            field0: 0,
            field1: 1,
        };

        let mut snapshot_mem = vec![0u8; 1024];

        // Serialize as v1.
        let mut snapshot = Snapshot::new(vm.clone(), 1);
        // The section will succesfully be serialized.
        snapshot.write_section("test", &state_1).unwrap();
        snapshot
            .save_with_crc64(&mut snapshot_mem.as_mut_slice())
            .unwrap();
        Snapshot::load_with_crc64(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
    }

    #[test]
    fn test_corrupted_snapshot() {
        let vm = VersionMap::new();
        let state_1 = Test1 {
            field_x: 0,
            field0: 0,
            field1: 1,
        };

        let mut snapshot_mem = vec![0u8; 1024];

        // Serialize as v1.
        let mut snapshot = Snapshot::new(vm.clone(), 1);
        // The section will succesfully be serialized.
        snapshot.write_section("test", &state_1).unwrap();
        snapshot
            .save_with_crc64(&mut snapshot_mem.as_mut_slice())
            .unwrap();
        snapshot_mem[20] = 123;
        assert_eq!(
            Snapshot::load_with_crc64(&mut snapshot_mem.as_slice(), vm.clone()).unwrap_err(),
            Error::Crc64
        );
    }

    #[test]
    fn test_deserialize_error() {
        let mut vm = VersionMap::new();
        vm.new_version()
            .set_type_version(Test::name(), 2)
            .new_version()
            .set_type_version(Test::name(), 3)
            .new_version()
            .set_type_version(Test::name(), 4);
        let state = Test {
            field0: 0,
            field1: 1,
            field2: 2,
            field3: "test".to_owned(),
            field4: vec![4, 3, 2, 1],
            field_x: 0,
        };

        let mut snapshot_mem = vec![0u8; 1024];

        let mut snapshot = Snapshot::new(vm.clone(), 4);
        // The section will succesfully be serialized.
        assert!(snapshot.write_section("test", &state).is_ok());
        assert_eq!(snapshot.save(&mut snapshot_mem.as_mut_slice()), Ok(()));

        snapshot_mem.truncate(10);
        let snapshot_load_error =
            Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap_err();
        assert_eq!(
            snapshot_load_error,
            Error::Deserialize("io error: failed to fill whole buffer".to_owned())
        );
    }

    #[test]
    fn test_struct_default_fn() {
        let mut vm = VersionMap::new();
        vm.new_version()
            .set_type_version(Test::name(), 2)
            .new_version()
            .set_type_version(Test::name(), 3)
            .new_version()
            .set_type_version(Test::name(), 4);
        let state = Test {
            field0: 0,
            field1: 1,
            field2: 2,
            field3: "test".to_owned(),
            field4: vec![4, 3, 2, 1],
            field_x: 0,
        };

        let state_1 = Test1 {
            field_x: 0,
            field0: 0,
            field1: 1,
        };

        let mut snapshot_mem = vec![0u8; 1024];

        // Serialize as v1.
        let mut snapshot = Snapshot::new(vm.clone(), 1);
        snapshot.write_section("test", &state_1).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        let restored_state: Test = snapshot.read_section::<Test>("test").unwrap().unwrap();
        assert_eq!(restored_state.field1, state_1.field1);
        assert_eq!(restored_state.field2, 20);
        assert_eq!(restored_state.field3, "default");

        // Serialize as v2.
        let mut snapshot = Snapshot::new(vm.clone(), 2);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        let restored_state: Test = snapshot.read_section::<Test>("test").unwrap().unwrap();
        assert_eq!(restored_state.field1, state.field1);
        assert_eq!(restored_state.field2, 2);
        assert_eq!(restored_state.field3, "default");

        // Serialize as v3.
        let mut snapshot = Snapshot::new(vm.clone(), 3);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        let restored_state: Test = snapshot.read_section::<Test>("test").unwrap().unwrap();
        assert_eq!(restored_state.field1, state.field1);
        assert_eq!(restored_state.field2, 2);
        assert_eq!(restored_state.field3, "test");

        // Serialize as v4.
        let mut snapshot = Snapshot::new(vm.clone(), 4);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        let restored_state: Test = snapshot.read_section::<Test>("test").unwrap().unwrap();
        assert_eq!(restored_state.field1, state.field1);
        assert_eq!(restored_state.field2, 2);
        assert_eq!(restored_state.field3, "test");
    }

    #[test]
    fn test_union_version() {
        #[repr(C)]
        #[derive(Versionize, Copy, Clone)]
        union kvm_irq_level__bindgen_ty_1 {
            pub irq: __u32,
            pub status: __s32,

            #[snapshot(start_version = 1, end_version = 1)]
            _bindgen_union_align: u32,

            #[snapshot(start_version = 2)]
            pub extended_status: __s64,

            #[snapshot(start_version = 2)]
            _bindgen_union_align_2: [u64; 4usize],
        }

        impl Default for kvm_irq_level__bindgen_ty_1 {
            fn default() -> Self {
                unsafe { ::std::mem::zeroed() }
            }
        }

        let mut state = kvm_irq_level__bindgen_ty_1::default();
        state.extended_status = 0x1234_5678_8765_4321;

        let vm = VersionMap::new();
        let mut snapshot_mem = vec![0u8; 1024 * 2];
        // Serialize as v1.
        let mut snapshot = Snapshot::new(vm.clone(), 1);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        let restored_state = snapshot
            .read_section::<kvm_irq_level__bindgen_ty_1>("test")
            .unwrap()
            .unwrap();
        unsafe {
            assert_eq!(restored_state.irq, 0x8765_4321);
        }
    }
    #[test]
    fn test_kvm_bindings_struct() {
        #[repr(C)]
        #[derive(Versionize, Debug, Default, Copy, Clone, PartialEq)]
        pub struct kvm_pit_config {
            pub flags: __u32,
            pub pad: [__u32; 15usize],
        }

        let state = kvm_pit_config {
            flags: 123456,
            pad: [0; 15usize],
        };

        let vm = VersionMap::new();
        let mut snapshot_mem = vec![0u8; 1024 * 2];
        // Serialize as v1.
        let mut snapshot = Snapshot::new(vm.clone(), 1);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        let restored_state = snapshot
            .read_section::<kvm_pit_config>("test")
            .unwrap()
            .unwrap();
        println!("State: {:?}", restored_state);
        // Check if we serialized x correctly, that is if semantic_x() was called.
        assert_eq!(restored_state, state);
    }

    #[test]
    fn test_basic_add_remove_field() {
        #[derive(Versionize, Debug, PartialEq, Clone)]
        pub struct A {
            #[snapshot(start_version = 1, end_version = 2)]
            x: u32,
            y: String,
            #[snapshot(start_version = 2, default_fn = "default_A_z")]
            z: String,
            #[snapshot(start_version = 3, semantic_ser_fn = "semantic_x")]
            q: u64,
        }

        #[derive(Versionize, Debug, PartialEq, Clone)]
        pub struct B {
            a: A,
            b: u64,
        }

        impl A {
            fn default_A_z(_source_version: u16) -> String {
                "whatever".to_owned()
            }

            fn semantic_x(&mut self, _target_version: u16) -> Result<()> {
                self.x = self.q as u32;
                Ok(())
            }
        }

        let mut vm = VersionMap::new();
        vm.new_version()
            .set_type_version(A::name(), 2)
            .new_version()
            .set_type_version(A::name(), 3);

        // The blobs have been serialized from this state:
        // let state = B {
        //     a: A {
        //         x: 0,
        //         y: "test".to_owned(),
        //         z: "basic".to_owned(),
        //         q: 1234,
        //     },
        //     b: 20,
        // };
        let mut snapshot_blob = std::fs::File::open("blobs/basic_add_remove_field_v1.bin").unwrap();

        let mut snapshot = Snapshot::load(&mut snapshot_blob, vm.clone()).unwrap();
        let mut restored_state = snapshot.read_section::<B>("test").unwrap().unwrap();
        println!("State: {:?}", restored_state);
        // Check if we serialized x correctly, that is if semantic_x() was called.
        assert_eq!(restored_state.a.x, 1234);
        assert_eq!(restored_state.a.z, stringify!(whatever));

        snapshot_blob = std::fs::File::open("blobs/basic_add_remove_field_v2.bin").unwrap();
        snapshot = Snapshot::load(&mut snapshot_blob, vm.clone()).unwrap();
        restored_state = snapshot.read_section::<B>("test").unwrap().unwrap();
        println!("State: {:?}", restored_state);
        // Check if x was not serialized, it should be 0.
        assert_eq!(restored_state.a.x, 0);
        // z field was added in version to, make sure it contains the original value
        assert_eq!(restored_state.a.z, stringify!(basic));
       
        snapshot_blob = std::fs::File::open("blobs/basic_add_remove_field_v3.bin").unwrap();
        snapshot = Snapshot::load(&mut snapshot_blob, vm.clone()).unwrap();
        restored_state = snapshot.read_section::<B>("test").unwrap().unwrap();
        println!("State: {:?}", restored_state);
        // Check if x was not serialized, it should be 0.
        assert_eq!(restored_state.a.x, 0);
        // z field was added in version to, make sure it contains the original value
        assert_eq!(restored_state.a.z, stringify!(basic));
        assert_eq!(restored_state.a.q, 1234);
    }
}
