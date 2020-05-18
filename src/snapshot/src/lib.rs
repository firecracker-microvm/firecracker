// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![deny(missing_docs)]

//! Provides version tolerant serialization and deserialization facilities and
//! implements a persistent storage format for Firecracker state snapshots.
//!
//! The `Snapshot` API manages serialization and deserialization of collections of objects
//! that implement the `Versionize` trait.
//!
//!  |----------------------------|
//!  |       64 bit magic_id      |
//!  |----------------------------|
//!  |         SnapshotHdr        |
//!  |----------------------------|
//!  |          State             |
//!  |----------------------------|
//!  |        optional CRC64      |
//!  |----------------------------|
//!
//! Each structure, union or enum is versioned separately and only needs to increment their version
//! if a field is added or removed. For each state snapshot we define 2 versions:
//!  - **the format version** which refers to the SnapshotHdr, CRC, or the
//! representation of primitives types (currently we use serde bincode as a backend). The current
//! implementation does not have any logic dependent on it.
//!  - **the data version** which refers to the state.
//!
extern crate bincode;
extern crate serde;
extern crate serde_derive;
extern crate versionize;
extern crate versionize_derive;

mod persist;
pub use persist::Persist;

use std::io::{Read, Write};
use versionize::crc::{CRC64Reader, CRC64Writer};
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

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
}

#[derive(Default, Debug, Versionize)]
struct SnapshotHdr {
    /// Snapshot data version (firecracker version).
    data_version: u16,
}

/// The `Snapshot` API manages serialization and deserialization of collections of objects
/// that implement the `Versionize` trait.
#[derive(Debug)]
pub struct Snapshot {
    hdr: SnapshotHdr,
    format_version: u16,
    version_map: VersionMap,
    // Required for serialization.
    target_version: u16,
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
            target_version,
        }
    }

    /// Attempts to load an existing snapshot.
    pub fn load<T, O>(mut reader: &mut T, version_map: VersionMap) -> Result<O, Error>
    where
        T: Read,
        O: Versionize,
    {
        let format_version_map = Self::format_version_map();
        let magic_id =
            <u64 as Versionize>::deserialize(&mut reader, &format_version_map, 0 /* unused */)
                .map_err(Error::Versionize)?;

        let format_version = get_format_version(magic_id)?;
        let hdr: SnapshotHdr =
            SnapshotHdr::deserialize(&mut reader, &format_version_map, format_version)
                .map_err(Error::Versionize)?;

        Ok(O::deserialize(&mut reader, &version_map, hdr.data_version)
            .map_err(Error::Versionize)?)
    }

    /// Attempts to load an existing snapshot and validate CRC.
    pub fn load_with_crc64<T, O>(reader: &mut T, version_map: VersionMap) -> Result<O, Error>
    where
        T: Read,
        O: Versionize,
    {
        let mut crc_reader = CRC64Reader::new(reader);
        let format_vm = Self::format_version_map();
        let object: O = Snapshot::load(&mut crc_reader, version_map)?;

        // Since the reader updates the checksum as bytes ar being read from it, the order of these 2 statements is
        // important, we first get the checksum computed on the read bytes then read the stored checksum.
        let computed_checksum = crc_reader.checksum();
        let stored_checksum: u64 =
            Versionize::deserialize(&mut crc_reader, &format_vm, 0).map_err(Error::Versionize)?;

        if computed_checksum != stored_checksum {
            return Err(Error::Crc64(computed_checksum));
        }

        Ok(object)
    }

    /// Saves a snapshot and include a CRC64 checksum.
    pub fn save_with_crc64<T, O>(&mut self, writer: &mut T, object: &O) -> Result<(), Error>
    where
        T: Write,
        O: Versionize,
    {
        let mut crc_writer = CRC64Writer::new(writer);
        self.save(&mut crc_writer, object)?;

        let checksum = crc_writer.checksum();
        checksum
            .serialize(&mut crc_writer, &Self::format_version_map(), 0)
            .map_err(Error::Versionize)?;
        Ok(())
    }

    /// Save a snapshot.
    pub fn save<T, O>(&mut self, mut writer: &mut T, object: &O) -> Result<(), Error>
    where
        T: Write,
        O: Versionize,
    {
        self.hdr = SnapshotHdr {
            data_version: self.target_version,
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

        // Serialize the object using the state version map.
        object
            .serialize(&mut writer, &self.version_map, self.target_version)
            .map_err(Error::Versionize)?;
        writer
            .flush()
            .map_err(|ref err| Error::Io(err.raw_os_error().unwrap_or(0)))
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
        snapshot
            .save(&mut snapshot_mem.as_mut_slice(), &state)
            .unwrap();

        let mut restored_state: Test =
            Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();

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
        snapshot
            .save(&mut snapshot_mem.as_mut_slice(), &state)
            .unwrap();

        restored_state = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();

        // We expect only the semantic serializer and deserializer for field4 to be called at version 3.
        // The semantic serializer will set field0 to field4.iter().sum() == 10.
        assert_eq!(restored_state.field0, state.field4.iter().sum::<u64>());
        // The semantic deserializer will create a 4 elements vec with all values == field0.
        assert_eq!(restored_state.field4, vec![restored_state.field0; 4]);
        // The semantic fn for field3 must not be called at version 3.
        assert_eq!(restored_state.field_x, 0);

        // Serialize as v4.
        snapshot = Snapshot::new(vm.clone(), 4);
        snapshot
            .save(&mut snapshot_mem.as_mut_slice(), &state)
            .unwrap();

        restored_state = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();

        // The 4 semantic fns must not be called at version 4.
        assert_eq!(restored_state.field0, 0);
        assert_eq!(restored_state.field4, vec![4, 3, 2, 1]);

        // Test error propagation from `versionize` crate.
        // Load operation should fail if we don't use the whole `snapshot_mem` resulted from
        // serialization.
        snapshot_mem.truncate(10);
        let restored_state_result: Result<Test, Error> =
            Snapshot::load(&mut snapshot_mem.as_slice(), vm);

        assert_eq!(
            restored_state_result.unwrap_err(),
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
        snapshot
            .save(&mut snapshot_mem.as_mut_slice(), &state_1)
            .unwrap();

        let mut restored_state: Test =
            Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        assert_eq!(restored_state.field1, state_1.field1);
        assert_eq!(restored_state.field2, 20);
        assert_eq!(restored_state.field3, "default");

        // Serialize as v2.
        snapshot = Snapshot::new(vm.clone(), 2);
        snapshot
            .save(&mut snapshot_mem.as_mut_slice(), &state)
            .unwrap();

        restored_state = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        assert_eq!(restored_state.field1, state.field1);
        assert_eq!(restored_state.field2, 2);
        assert_eq!(restored_state.field3, "default");

        // Serialize as v3.
        snapshot = Snapshot::new(vm.clone(), 3);
        snapshot
            .save(&mut snapshot_mem.as_mut_slice(), &state)
            .unwrap();

        restored_state = Snapshot::load(&mut snapshot_mem.as_slice(), vm.clone()).unwrap();
        assert_eq!(restored_state.field1, state.field1);
        assert_eq!(restored_state.field2, 2);
        assert_eq!(restored_state.field3, "test");

        // Serialize as v4.
        snapshot = Snapshot::new(vm.clone(), 4);
        snapshot
            .save(&mut snapshot_mem.as_mut_slice(), &state)
            .unwrap();

        restored_state = Snapshot::load(&mut snapshot_mem.as_slice(), vm).unwrap();
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
        snapshot
            .save_with_crc64(&mut snapshot_mem.as_mut_slice(), &state_1)
            .unwrap();

        let _: Test1 = Snapshot::load_with_crc64(&mut snapshot_mem.as_slice(), vm).unwrap();
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
        snapshot
            .save_with_crc64(&mut snapshot_mem.as_mut_slice(), &state_1)
            .unwrap();
        snapshot_mem[20] = 123;

        #[cfg(target_arch = "aarch64")]
        let expected_err = Error::Crc64(0x1960_4E6A_A13F_6615);
        #[cfg(target_arch = "x86_64")]
        let expected_err = Error::Crc64(0x103F_8F52_8F51_20B1);

        let load_result: Result<Test1, Error> =
            Snapshot::load_with_crc64(&mut snapshot_mem.as_slice(), vm);
        assert_eq!(load_result.unwrap_err(), expected_err);
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
        snapshot
            .save(&mut snapshot_mem.as_mut_slice(), &state)
            .unwrap();

        let restored_state: kvm_pit_config =
            Snapshot::load(&mut snapshot_mem.as_slice(), vm).unwrap();
        assert_eq!(restored_state, state);
    }
}
