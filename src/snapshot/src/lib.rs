// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]

//! Provides version tolerant serialization and deserialization facilities and
//! implements a persistent storage format for Firecracker state snapshots.
//!
//! The `Snapshot` API manages serialization and deserialization of collections of objects
//! that implement the `Versionize` trait. Each object is stored in a separate section
//! that can be saved/loaded independently:
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
//! Each structure, union or enum is versioned separately and only needs to increment their version
//! if a field is added or removed. For each state snapshot we define 2 versions:
//!  - **the format version** which refers to the SnapshotHdr, Section headers, CRC, or the
//! representation of primitives types (currently we use serde bincode as a backend). The current
//! implementation does not have any logic dependent on it.
//!  - **the data version** which refers to the state stored in all of the snapshot sections.
//!

extern crate bincode;
extern crate serde;
extern crate serde_derive;
extern crate versionize;
extern crate versionize_derive;

mod persist;
pub use persist::Persist;

use std::collections::hash_map::HashMap;
use std::io::Read;
use versionize::crc::{CRC64Reader, CRC64Writer};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

// 128k max section size.
const SNAPSHOT_MAX_SECTION_SIZE: usize = 0x20000;
const SNAPSHOT_FORMAT_VERSION: u16 = 1;
const BASE_MAGIC_ID_MASK: u64 = !0xFFFFu64;

#[cfg(target_arch = "x86_64")]
const BASE_MAGIC_ID: u64 = 0x0710_1984_8664_0000u64;

#[cfg(target_arch = "aarch64")]
const BASE_MAGIC_ID: u64 = 0x0710_1984_AAAA_0000u64;

/// Error definitions for the Snapshot API.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// An IO error occurred.
    Io(i32),
    /// A versioned serialization/deserialization error occured.
    Versionize(versionize::VersionizeError),
    /// CRC64 validation failed.
    Crc64(u64),
    /// Magic value does not match arch.
    InvalidMagic(u64),
    /// Section does not exist.
    SectionNotFound,
}

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
fn get_format_version(magic_id: u64) -> Result<u16, Error> {
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
    pub fn load<T>(mut reader: &mut T, version_map: VersionMap) -> Result<Snapshot, Error>
    where
        T: Read,
    {
        let format_version_map = Self::format_version_map();
        let magic_id =
            <u64 as Versionize>::deserialize(&mut reader, &format_version_map, 0 /* unused */)
                .map_err(Error::Versionize)?;

        let format_version = get_format_version(magic_id)?;
        let hdr: SnapshotHdr =
            SnapshotHdr::deserialize(&mut reader, &format_version_map, format_version)
                .map_err(Error::Versionize)?;
        let mut sections = HashMap::new();

        for _ in 0..hdr.section_count {
            let section = Section::deserialize(&mut reader, &format_version_map, format_version)
                .map_err(Error::Versionize)?;
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
    pub fn load_with_crc64<T>(reader: &mut T, version_map: VersionMap) -> Result<Snapshot, Error>
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
        let stored_checksum: u64 =
            Versionize::deserialize(&mut crc_reader, &format_vm, 0).map_err(Error::Versionize)?;

        if computed_checksum != stored_checksum {
            return Err(Error::Crc64(computed_checksum));
        }

        Ok(snapshot)
    }

    /// Saves a snapshot and include a CRC64 checksum.
    pub fn save_with_crc64<T>(&mut self, writer: &mut T) -> Result<(), Error>
    where
        T: std::io::Write,
    {
        let mut crc_writer = CRC64Writer::new(writer);
        self.save(&mut crc_writer)?;

        let checksum = crc_writer.checksum();
        checksum
            .serialize(&mut crc_writer, &Self::format_version_map(), 0)
            .map_err(Error::Versionize)?;
        Ok(())
    }

    /// Save a snapshot.
    pub fn save<T>(&mut self, mut writer: &mut T) -> Result<(), Error>
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
        magic_id
            .serialize(&mut writer, &format_version_map, 0 /* unused */)
            .map_err(Error::Versionize)?;
        // Serialize header using the format version map.
        self.hdr
            .serialize(
                &mut writer,
                &format_version_map,
                format_version_map.latest_version(),
            )
            .map_err(Error::Versionize)?;

        // Serialize all the sections.
        for section in self.sections.values() {
            // The sections are already serialized.
            section
                .serialize(
                    &mut writer,
                    &format_version_map,
                    format_version_map.latest_version(),
                )
                .map_err(Error::Versionize)?;
        }

        writer
            .flush()
            .map_err(|ref err| Error::Io(err.raw_os_error().unwrap_or(0)))?;

        Ok(())
    }

    /// Attempts to find and reads a section (deserialize/translate) from a snapshot.
    pub fn read_section<T>(&mut self, name: &str) -> Result<T, Error>
    where
        T: Versionize,
    {
        if let Some(section) = self.sections.get_mut(name) {
            Ok(T::deserialize(
                &mut section.data.as_mut_slice().as_ref(),
                &self.version_map,
                self.hdr.data_version,
            )
            .map_err(Error::Versionize)?)
        } else {
            Err(Error::SectionNotFound)
        }
    }

    /// Write a section (serialize/translate) to a snapshot.
    pub fn write_section<T>(&mut self, name: &str, object: &T) -> Result<usize, Error>
    where
        T: Versionize,
    {
        let mut new_section = Section {
            name: name.to_owned(),
            data: vec![0; SNAPSHOT_MAX_SECTION_SIZE],
        };

        let slice = &mut new_section.data.as_mut_slice();
        object
            .serialize(slice, &self.version_map, self.target_version)
            .map_err(Error::Versionize)?;
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
    use super::*;

    #[derive(Clone, Debug, Versionize)]
    pub struct Test1 {
        field_x: u64,
        field0: u64,
        field1: u32,
    }

    #[derive(Clone, Debug, Versionize)]
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
        fn field4_serialize(&mut self, target_version: u16) -> VersionizeResult<()> {
            // Fail if semantic serialization is called for the latest version.
            assert_ne!(target_version, Test::version());
            self.field0 = self.field4.iter().sum();

            if self.field0 == 6666 {
                return Err(versionize::VersionizeError::Semantic(
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
                return Err(versionize::VersionizeError::Semantic(
                    "field0 is 7777".to_owned(),
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn test_get_format_version() {
        // Check if `get_format_version()` returns indeed the format
        // version (the least significant 2 bytes) if the id is valid
        // (the other bytes == BASE_MAGIC_ID).
        #[cfg(target_arch = "x86_64")]
        let good_magic_id = 0x0710_1984_8664_0001u64;
        #[cfg(target_arch = "aarch64")]
        let good_magic_id = 0x0710_1984_AAAA_0001u64;

        assert_eq!(get_format_version(good_magic_id).unwrap(), 1u16);

        // Flip a bit to invalidate the arch id.
        let invalid_magic_id = good_magic_id | (1u64 << 63);
        assert_eq!(
            get_format_version(invalid_magic_id).unwrap_err(),
            Error::InvalidMagic(invalid_magic_id)
        );
    }

    #[test]
    fn test_section_ops() {
        let vm = VersionMap::new();
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

        let mut sections = &mut snapshot.sections;
        assert_eq!(sections.len(), 1);

        let section = sections.get_mut("test").unwrap();
        assert_eq!(section.name, "test");
        // Data should contain field_x (8 bytes), field0 (8 bytes) and field1 (4 bytes) in this order.
        // field_x == 1 because of the semantic serializer fn for field3, the semantic serializer fn
        // for field4 will set field0 to field4.iter().sum() = 10 and field1 == 1 (the original value).
        assert_eq!(
            section.data,
            [1, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]
        );

        let state_1 = Test1 {
            field_x: 0,
            field0: 0,
            field1: 1,
        };

        snapshot.write_section("test1", &state_1).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();
        sections = &mut snapshot.sections;
        assert_eq!(sections.len(), 2);

        // Trying to read a section with an invalid name should fail.
        assert_eq!(
            snapshot.read_section::<Test>("test2").unwrap_err(),
            Error::SectionNotFound
        );

        // Validate that the 2 inserted objects can be deserialized.
        assert!(snapshot.read_section::<Test>("test").is_ok());
        assert!(snapshot.read_section::<Test1>("test1").is_ok());
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
        // The semantic deserializer for field4 will change field's value to vec![field0; 4].
        assert_eq!(restored_state.field4, vec![restored_state.field0; 4]);
        // The semantic serializer and deserializer for field3 will both increment field_x value.
        assert_eq!(restored_state.field_x, 2);
        // field1 should have the original value.
        assert_eq!(restored_state.field1, 1);
        // field2 should have the default value as this field was added at version 2.
        assert_eq!(restored_state.field2, 20);

        // Serialize as v3.
        let mut snapshot = Snapshot::new(vm.clone(), 3);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        restored_state = snapshot.read_section::<Test>("test").unwrap();

        // We expect only the semantic serializer and deserializer for field4 to be called at version 3.
        // The semantic serializer will set field0 to field4.iter().sum() == 10.
        assert_eq!(restored_state.field0, state.field4.iter().sum::<u64>());
        // The semantic deserializer will create a 4 elements vec with all values == field0.
        assert_eq!(restored_state.field4, vec![restored_state.field0; 4]);
        // The semantic fn for field3 must not be called at version 3.
        assert_eq!(restored_state.field_x, 0);

        // Serialize as v4.
        snapshot = Snapshot::new(vm.clone(), 4);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        restored_state = snapshot.read_section::<Test>("test").unwrap();

        // The 4 semantic fns must not be called at version 4.
        assert_eq!(restored_state.field0, 0);
        assert_eq!(restored_state.field4, vec![4, 3, 2, 1]);

        // Test error propagation from `versionize` crate.
        // Load operation should fail if we don't use the whole `snapshot_mem` resulted from
        // serialization.
        snapshot_mem.truncate(10);
        let snapshot_load_error =
            Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap_err();
        assert_eq!(
            snapshot_load_error,
            Error::Versionize(versionize::VersionizeError::Deserialize(
                "Io(Custom { kind: UnexpectedEof, error: \"failed to fill whole buffer\" })"
                    .to_owned()
            ))
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
        let mut restored_state: Test = snapshot.read_section::<Test>("test").unwrap();
        assert_eq!(restored_state.field1, state_1.field1);
        assert_eq!(restored_state.field2, 20);
        assert_eq!(restored_state.field3, "default");

        // Serialize as v2.
        snapshot = Snapshot::new(vm.clone(), 2);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        restored_state = snapshot.read_section::<Test>("test").unwrap();
        assert_eq!(restored_state.field1, state.field1);
        assert_eq!(restored_state.field2, 2);
        assert_eq!(restored_state.field3, "default");

        // Serialize as v3.
        snapshot = Snapshot::new(vm.clone(), 3);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        restored_state = snapshot.read_section::<Test>("test").unwrap();
        assert_eq!(restored_state.field1, state.field1);
        assert_eq!(restored_state.field2, 2);
        assert_eq!(restored_state.field3, "test");

        // Serialize as v4.
        snapshot = Snapshot::new(vm.clone(), 4);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        restored_state = snapshot.read_section::<Test>("test").unwrap();
        assert_eq!(restored_state.field1, state.field1);
        assert_eq!(restored_state.field2, 2);
        assert_eq!(restored_state.field3, "test");
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
        // The section will successfully be serialized.
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
        // The section will successfully be serialized.
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

    #[allow(non_upper_case_globals)]
    #[allow(non_camel_case_types)]
    #[allow(non_snake_case)]
    #[test]
    fn test_kvm_bindings_struct() {
        #[repr(C)]
        #[derive(Debug, PartialEq, Versionize)]
        pub struct kvm_pit_config {
            pub flags: ::std::os::raw::c_uint,
            pub pad: [::std::os::raw::c_uint; 15usize],
        }

        let state = kvm_pit_config {
            flags: 123_456,
            pad: [0; 15usize],
        };

        let vm = VersionMap::new();
        let mut snapshot_mem = vec![0u8; 1024];
        // Serialize as v1.
        let mut snapshot = Snapshot::new(vm.clone(), 1);
        snapshot.write_section("test", &state).unwrap();
        snapshot.save(&mut snapshot_mem.as_mut_slice()).unwrap();

        snapshot = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        let restored_state = snapshot.read_section::<kvm_pit_config>("test").unwrap();
        assert_eq!(restored_state, state);
    }
}
