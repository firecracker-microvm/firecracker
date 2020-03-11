// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]

//! Provides version tolerant serialization and deserialization facilities and
//! implements a persistent storage format for Firecracker state snapshots.
//!
//! The `Snapshot` API manages serialization and deserialization of collections of objects
//! that implement the `Versionize` trait. Each object is stored in a separate section
//! that can be save/loaded independently:
//!
//!  |----------------------------|
//!  |       64 bit magic_id      |
//!  |----------------------------|
//!  |         SnapshotHdr        |
//!  |----------------------------|
//!  |         Section  #1        |
//!  |----------------------------|
//!  |         Section  #2        |
//!  |----------------------------|
//!  |         Section  #3        |
//!  |----------------------------|
//!  |          ..........        |
//!  |----------------------------|
//!  |        optional CRC64      |
//!  |----------------------------|
//!
//! Each structure, union or enum is versioned separately and only need to increment their version
//! if a field is added or removed. For each state snapshot we define 2 versions:
//!  - **the format version** which refers to the SnapshotHdr, Section headers, CRC, or the
//! representation of primitives types (currentl we use serde bincode as a backend). The current
//! implementation does not have any logic dependent on it.
//!  - **the data version** which refers to the state stored in all of the snapshot sections.
//!

extern crate bincode;
extern crate serde;
extern crate serde_derive;
extern crate versionize;
extern crate versionize_derive;

use std::collections::hash_map::HashMap;
use std::io::Read;
use versionize::crc::{CRC64Reader, CRC64Writer};
use versionize::{Error, Result, VersionMap, Versionize};
use versionize_derive::Versionize;

// 256k max section size.
const SNAPSHOT_MAX_SECTION_SIZE: usize = 0x40000;
const SNAPSHOT_FORMAT_VERSION: u16 = 1;
const BASE_MAGIC_ID_MASK: u64 = !0xFFFFu64;

#[cfg(target_arch = "x86_64")]
const BASE_MAGIC_ID: u64 = 0x0710_1984_8664_0000u64;

#[cfg(target_arch = "aarch64")]
const BASE_MAGIC_ID: u64 = 0x0710_1984_AAAA_0000u64;

#[derive(Default, Debug, Versionize)]
struct SnapshotHdr {
    /// Snapshot data version (firecracker version).
    data_version: u16,
    /// Number of sections
    section_count: u16,
}

/// The `Snapshot` API manages serialization and deserialization of collections of objects
/// that implement the `Versionize` trait.
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
struct Section {
    name: String,
    data: Vec<u8>,
}

// Parse a magic_id and return the format version.
fn get_format_version(magic_id: u64) -> Result<u16> {
    let magic_arch = magic_id & BASE_MAGIC_ID_MASK;
    if magic_arch == BASE_MAGIC_ID {
        return Ok((magic_id & !BASE_MAGIC_ID_MASK) as u16);
    }
    Err(Error::InvalidMagic(magic_id))
}

fn build_magic_id(format_version: u16) -> u64 {
    BASE_MAGIC_ID | format_version as u64
}

impl Snapshot {
    /// Creates a new instance which can only be used to save a new snapshot.
    pub fn new(version_map: VersionMap, target_version: u16) -> Snapshot {
        Snapshot {
            version_map,
            hdr: SnapshotHdr::default(),
            format_version: SNAPSHOT_FORMAT_VERSION,
            sections: HashMap::new(),
            target_version,
        }
    }

    /// Attempts to load an existing snapshot.
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
        let format_version = get_format_version(magic_id).unwrap();
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

    /// Attempts to load an existing snapshot and validate CRC.
    pub fn load_with_crc64<T>(reader: &mut T, version_map: VersionMap) -> Result<Snapshot>
    where
        T: Read,
    {
        let mut crc_reader = CRC64Reader::new(reader);
        let format_vm = Self::format_version_map();

        // Read entire buffer in memory.
        let snapshot = Snapshot::load(&mut crc_reader, version_map)?;
        // Since the reader updates the checksum as bytes ar being read from it, the order of these 2 statements is
        // important, we first get the checksum computed on the read bytes then read the stored checksum.
        let computed_checksum = crc_reader.checksum();
        let stored_checksum: u64 = Versionize::deserialize(&mut crc_reader, &format_vm, 0)?;

        if computed_checksum != stored_checksum {
            return Err(Error::Crc64(computed_checksum));
        }

        Ok(snapshot)
    }

    /// Saves a snapshot and include a CRC64 checksum.
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

    /// Save a snapshot.
    pub fn save<T>(&mut self, mut writer: &mut T) -> Result<()>
    where
        T: std::io::Write,
    {
        self.hdr = SnapshotHdr {
            data_version: self.target_version,
            section_count: self.sections.len() as u16,
        };

        let format_version_map = Self::format_version_map();
        let magic_id = build_magic_id(format_version_map.latest_version());

        // Serialize magic id using the format version map.
        magic_id.serialize(&mut writer, &format_version_map, 0 /* unused */)?;
        // Serialize header using the format version map.
        self.hdr.serialize(
            &mut writer,
            &format_version_map,
            format_version_map.latest_version(),
        )?;

        // Serialize all the sections.
        for section in self.sections.values() {
            // The sections are already serialized.
            section.serialize(
                &mut writer,
                &format_version_map,
                format_version_map.latest_version(),
            )?;
        }
        writer
            .flush()
            .map_err(|ref err| Error::Io(err.raw_os_error().unwrap_or(0)))?;

        Ok(())
    }

    /// Attempts to find and reads a section (deserialize/translate) from a snapshot.
    pub fn read_section<T>(&mut self, name: &str) -> Result<T>
    where
        T: Versionize,
    {
        if let Some(section) = self.sections.get_mut(name) {
            Ok(T::deserialize(
                &mut section.data.as_mut_slice().as_ref(),
                &self.version_map,
                self.hdr.data_version,
            )?)
        } else {
            Err(Error::SectionNotFound)
        }
    }

    /// Write a section (serialize/translate) to a snapshot.
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

#[cfg(test)]
mod tests {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    use super::*;

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
            .set_type_version(Test::type_id(), 2)
            .new_version()
            .set_type_version(Test::type_id(), 3)
            .new_version()
            .set_type_version(Test::type_id(), 4);
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
        let mut restored_state: Test = snapshot.read_section::<Test>("test").unwrap();

        // The semantic serializer fn for field4 will set field0 to field4.iter().sum() == 10.
        assert_eq!(restored_state.field0, state.field4.iter().sum::<u64>());
        assert_eq!(restored_state.field4, vec![restored_state.field0; 4]);
        assert_eq!(restored_state.field_x, 2);

        // Serialize as v3.
        let mut snapshot = Snapshot::new(vm.clone(), 3);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        restored_state = snapshot.read_section::<Test>("test").unwrap();

        // The semantic fn for field4 will set field0 to field4.iter().sum() == 10.
        assert_eq!(restored_state.field0, state.field4.iter().sum::<u64>());
        // The semantic deserializer fn will create 4 element vec with all values == field0
        assert_eq!(restored_state.field4, vec![restored_state.field0; 4]);

        // Serialize as v4.
        let mut snapshot = Snapshot::new(vm.clone(), 4);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        restored_state = snapshot.read_section::<Test>("test").unwrap();

        // The semantic fn must not be called.
        assert_eq!(restored_state.field0, 0);
        assert_eq!(restored_state.field4, vec![4, 3, 2, 1]);
    }

    #[test]
    fn test_semantic_serialize_error() {
        let mut vm = VersionMap::new();
        vm.new_version()
            .set_type_version(Test::type_id(), 2)
            .new_version()
            .set_type_version(Test::type_id(), 3)
            .new_version()
            .set_type_version(Test::type_id(), 4);

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
            .set_type_version(Test::type_id(), 2)
            .new_version()
            .set_type_version(Test::type_id(), 3)
            .new_version()
            .set_type_version(Test::type_id(), 4);

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
            Error::Serialize(
                "Io(Custom { kind: WriteZero, error: \"failed to write whole buffer\" })"
                    .to_owned()
            )
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

        #[cfg(target_arch = "aarch64")]
        let expected_err = Error::Crc64(0x4050_C04F_509F_77E9);
        #[cfg(target_arch = "x86_64")]
        let expected_err = Error::Crc64(0x0A81_2693_BB8F_B0F1);

        assert_eq!(
            Snapshot::load_with_crc64(&mut snapshot_mem.as_slice(), vm.clone()).unwrap_err(),
            expected_err
        );
    }

    #[test]
    fn test_deserialize_error() {
        let mut vm = VersionMap::new();
        vm.new_version()
            .set_type_version(Test::type_id(), 2)
            .new_version()
            .set_type_version(Test::type_id(), 3)
            .new_version()
            .set_type_version(Test::type_id(), 4);
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
            Error::Deserialize(
                "Io(Custom { kind: UnexpectedEof, error: \"failed to fill whole buffer\" })"
                    .to_owned()
            )
        );
    }

    #[test]
    fn test_struct_default_fn() {
        let mut vm = VersionMap::new();
        vm.new_version()
            .set_type_version(Test::type_id(), 2)
            .new_version()
            .set_type_version(Test::type_id(), 3)
            .new_version()
            .set_type_version(Test::type_id(), 4);
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
        let restored_state: Test = snapshot.read_section::<Test>("test").unwrap();
        assert_eq!(restored_state.field1, state_1.field1);
        assert_eq!(restored_state.field2, 20);
        assert_eq!(restored_state.field3, "default");

        // Serialize as v2.
        let mut snapshot = Snapshot::new(vm.clone(), 2);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        let restored_state: Test = snapshot.read_section::<Test>("test").unwrap();
        assert_eq!(restored_state.field1, state.field1);
        assert_eq!(restored_state.field2, 2);
        assert_eq!(restored_state.field3, "default");

        // Serialize as v3.
        let mut snapshot = Snapshot::new(vm.clone(), 3);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        let restored_state: Test = snapshot.read_section::<Test>("test").unwrap();
        assert_eq!(restored_state.field1, state.field1);
        assert_eq!(restored_state.field2, 2);
        assert_eq!(restored_state.field3, "test");

        // Serialize as v4.
        let mut snapshot = Snapshot::new(vm.clone(), 4);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        let restored_state: Test = snapshot.read_section::<Test>("test").unwrap();
        assert_eq!(restored_state.field1, state.field1);
        assert_eq!(restored_state.field2, 2);
        assert_eq!(restored_state.field3, "test");
    }

    #[test]
    fn test_union_version() {
        #[repr(C)]
        #[derive(Versionize, Copy, Clone)]
        union kvm_irq_level__bindgen_ty_1 {
            pub irq: ::std::os::raw::c_uint,
            pub status: ::std::os::raw::c_int,

            #[version(start = 1, end = 1)]
            _bindgen_union_align: u32,

            #[version(start = 2)]
            pub extended_status: ::std::os::raw::c_longlong,

            #[version(start = 2)]
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
            pub flags: ::std::os::raw::c_uint,
            pub pad: [::std::os::raw::c_uint; 15usize],
        }

        let state = kvm_pit_config {
            flags: 123_456,
            pad: [0; 15usize],
        };

        let vm = VersionMap::new();
        let mut snapshot_mem = vec![0u8; 1024 * 2];
        // Serialize as v1.
        let mut snapshot = Snapshot::new(vm.clone(), 1);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        let restored_state = snapshot.read_section::<kvm_pit_config>("test").unwrap();
        println!("State: {:?}", restored_state);
        // Check if we serialized x correctly, that is if semantic_x() was called.
        assert_eq!(restored_state, state);
    }

    #[test]
    fn test_basic_add_remove_field() {
        #[rustfmt::skip]
        let basic_add_remove_field_v1: &[u8] = &[
            0x01, 0x00, 
            #[cfg(target_arch = "aarch64")]
            0xAA, 
            #[cfg(target_arch = "aarch64")]
            0xAA,
            #[cfg(target_arch = "x86_64")]
            0x64, 
            #[cfg(target_arch = "x86_64")]
            0x86, 
            0x84, 0x19, 0x10, 0x07, 0x01, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xD2, 0x04, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74,
            0x65, 0x73, 0x74, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        #[rustfmt::skip]
        let basic_add_remove_field_v2: &[u8] = &[
            0x01, 0x00,
            #[cfg(target_arch = "aarch64")]
            0xAA, 
            #[cfg(target_arch = "aarch64")]
            0xAA,
            #[cfg(target_arch = "x86_64")]
            0x64,
            #[cfg(target_arch = "x86_64")]
            0x86, 
            0x84, 0x19, 0x10, 0x07, 0x02, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x05,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x61, 0x73, 0x69, 0x63, 0x14, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        #[rustfmt::skip]
        let basic_add_remove_field_v3: &[u8] = &[
            0x01, 0x00, 
            #[cfg(target_arch = "aarch64")]
            0xAA, 
            #[cfg(target_arch = "aarch64")]
            0xAA,
            #[cfg(target_arch = "x86_64")]
            0x64, 
            #[cfg(target_arch = "x86_64")]
            0x86, 
            0x84, 0x19, 0x10, 0x07, 0x03, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x05,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x61, 0x73, 0x69, 0x63, 0xD2, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        #[derive(Versionize, Debug, PartialEq, Clone)]
        pub struct A {
            #[version(start = 1, end = 2)]
            x: u32,
            y: String,
            #[version(start = 2, default_fn = "default_A_z")]
            z: String,
            #[version(start = 3, ser_fn = "semantic_x")]
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
            .set_type_version(A::type_id(), 2)
            .new_version()
            .set_type_version(A::type_id(), 3);

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

        let mut snapshot_blob = basic_add_remove_field_v1;

        let mut snapshot = Snapshot::load(&mut snapshot_blob, vm.clone()).unwrap();
        let mut restored_state = snapshot.read_section::<B>("test").unwrap();
        println!("State: {:?}", restored_state);
        // Check if we serialized x correctly, that is if semantic_x() was called.
        assert_eq!(restored_state.a.x, 1234);
        assert_eq!(restored_state.a.z, stringify!(whatever));

        snapshot_blob = basic_add_remove_field_v2;
        snapshot = Snapshot::load(&mut snapshot_blob, vm.clone()).unwrap();
        restored_state = snapshot.read_section::<B>("test").unwrap();
        println!("State: {:?}", restored_state);
        // Check if x was not serialized, it should be 0.
        assert_eq!(restored_state.a.x, 0);
        // z field was added in version to, make sure it contains the original value
        assert_eq!(restored_state.a.z, stringify!(basic));

        snapshot_blob = basic_add_remove_field_v3;
        snapshot = Snapshot::load(&mut snapshot_blob, vm.clone()).unwrap();
        restored_state = snapshot.read_section::<B>("test").unwrap();
        println!("State: {:?}", restored_state);
        // Check if x was not serialized, it should be 0.
        assert_eq!(restored_state.a.x, 0);
        // z field was added in version to, make sure it contains the original value
        assert_eq!(restored_state.a.z, stringify!(basic));
        assert_eq!(restored_state.a.q, 1234);
    }
}
