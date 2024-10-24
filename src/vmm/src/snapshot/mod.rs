// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides serialization and deserialization facilities and implements a persistent storage
//! format for Firecracker state snapshots.
//!
//! The `Snapshot` API manages serialization and deserialization of collections of objects
//! that implement the `serde` `Serialize`, `Deserialize` trait. Currently, we use
//! [`bincode`](https://docs.rs/bincode/latest/bincode/) for performing the serialization.
//!
//! The snapshot format uses the following layout:
//!
//!  |-----------------------------|
//!  |       64 bit magic_id       |
//!  |-----------------------------|
//!  |       version string        |
//!  |-----------------------------|
//!  |            State            |
//!  |-----------------------------|
//!  |        optional CRC64       |
//!  |-----------------------------|
//!
//!
//! The snapshot format uses a version value in the form of `MAJOR.MINOR.PATCH`. The version is
//! provided by the library clients (it is not tied to this crate).
pub mod crc;
mod persist;
use std::fmt::Debug;
use std::io::{Read, Write};

use bincode::Options;
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::snapshot::crc::{CRC64Reader, CRC64Writer};
pub use crate::snapshot::persist::Persist;

#[cfg(target_arch = "x86_64")]
const SNAPSHOT_MAGIC_ID: u64 = 0x0710_1984_8664_0000u64;

/// Constant bounding how much memory bincode may allocate during vmstate file deserialization
const VM_STATE_DESERIALIZE_LIMIT: u64 = 10_485_760; // 10MiB

#[cfg(target_arch = "aarch64")]
const SNAPSHOT_MAGIC_ID: u64 = 0x0710_1984_AAAA_0000u64;

/// Error definitions for the Snapshot API.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq)]
pub enum SnapshotError {
    /// CRC64 validation failed: {0}
    Crc64(u64),
    /// Invalid data version: {0}
    InvalidFormatVersion(Version),
    /// Magic value does not match arch: {0}
    InvalidMagic(u64),
    /// Snapshot file is smaller than CRC length.
    InvalidSnapshotSize,
    /// An IO error occurred: {0}
    Io(i32),
    /// An error occured with serialization/deserialization: {0}
    Serde(String),
}

/// Firecracker snapshot header
#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotHdr {
    /// magic value
    magic: u64,
    /// Snapshot data version
    version: Version,
}

impl SnapshotHdr {
    pub fn new(version: Version) -> Self {
        Self {
            magic: SNAPSHOT_MAGIC_ID,
            version,
        }
    }

    pub fn load<R: Read>(reader: &mut R) -> Result<Self, SnapshotError> {
        let hdr: SnapshotHdr = deserialize(reader)?;

        Ok(hdr)
    }

    pub fn store<W: Write>(&self, writer: &mut W) -> Result<(), SnapshotError> {
        match serialize(writer, self) {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot<Data> {
    // The snapshot version we can handle
    header: SnapshotHdr,
    pub data: Data,
}

impl<Data: DeserializeOwned> Snapshot<Data> {
    pub fn load_unchecked<R: Read>(reader: &mut R) -> Result<Self, SnapshotError>
    where
        Data: DeserializeOwned + Debug,
    {
        let hdr: SnapshotHdr = deserialize(reader)?;
        if hdr.magic != SNAPSHOT_MAGIC_ID {
            return Err(SnapshotError::InvalidMagic(hdr.magic));
        }

        let data: Data = deserialize(reader)?;
        Ok(Self { header: hdr, data })
    }

    pub fn load<R: Read>(reader: &mut R, snapshot_len: usize) -> Result<Self, SnapshotError>
    where
        Data: DeserializeOwned + Debug,
    {
        let mut crc_reader = CRC64Reader::new(reader);

        // Fail-fast if the snapshot length is too small
        let raw_snapshot_len = snapshot_len
            .checked_sub(std::mem::size_of::<u64>())
            .ok_or(SnapshotError::InvalidSnapshotSize)?;

        // Read everything apart from the CRC.
        let mut snapshot = vec![0u8; raw_snapshot_len];
        crc_reader
            .read_exact(&mut snapshot)
            .map_err(|ref err| SnapshotError::Io(err.raw_os_error().unwrap_or(libc::EINVAL)))?;

        // Since the reader updates the checksum as bytes ar being read from it, the order of these
        // 2 statements is important, we first get the checksum computed on the read bytes
        // then read the stored checksum.
        let computed_checksum = crc_reader.checksum();
        let stored_checksum: u64 = deserialize(&mut crc_reader)?;
        if computed_checksum != stored_checksum {
            return Err(SnapshotError::Crc64(computed_checksum));
        }

        let mut snapshot_slice: &[u8] = snapshot.as_mut_slice();
        Snapshot::load_unchecked::<_>(&mut snapshot_slice)
    }
}

impl<Data: Serialize + Debug> Snapshot<Data> {
    pub fn save<W: Write>(&self, mut writer: &mut W) -> Result<usize, SnapshotError> {
        // Write magic value and snapshot version
        serialize(&mut writer, &SnapshotHdr::new(self.header.version.clone()))?;
        // Write data
        serialize(&mut writer, &self.data)
    }

    pub fn save_with_crc<W: Write>(&self, writer: &mut W) -> Result<usize, SnapshotError> {
        let mut crc_writer = CRC64Writer::new(writer);
        self.save(&mut crc_writer)?;

        // Now write CRC value
        let checksum = crc_writer.checksum();
        serialize(&mut crc_writer, &checksum)
    }
}

impl<Data> Snapshot<Data> {
    pub fn new(header: SnapshotHdr, data: Data) -> Self {
        Snapshot { header, data }
    }

    pub fn version(&self) -> Version {
        self.header.version.clone()
    }
}

/// Helper function to deserialize an object from a reader
fn deserialize<T, O>(reader: &mut T) -> Result<O, SnapshotError>
where
    T: Read,
    O: DeserializeOwned + Debug,
{
    // flags below are those used by default by bincode::deserialize_from, plus `with_limit`.
    bincode::DefaultOptions::new()
        .with_limit(VM_STATE_DESERIALIZE_LIMIT)
        .with_fixint_encoding()
        .allow_trailing_bytes() // need this because we deserialize header and snapshot from the same file, so after
        // reading the header, there will be trailing bytes.
        .deserialize_from(reader)
        .map_err(|err| SnapshotError::Serde(err.to_string()))
}

/// Helper function to serialize an object to a writer
fn serialize<T, O>(writer: &mut T, data: &O) -> Result<usize, SnapshotError>
where
    T: Write,
    O: Serialize + Debug,
{
    let mut buffer = Vec::new();
    bincode::serialize_into(&mut buffer, data)
        .map_err(|err| SnapshotError::Serde(err.to_string()))?;

    writer
        .write_all(&buffer)
        .map_err(|err| SnapshotError::Serde(err.to_string()))?;

    Ok(buffer.len())
    // bincode::serialize_into(writer, data).map_err(|err| SnapshotError::Serde(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_from_file() {
        // Enough memory for the header, 1 byte and the CRC
        let mut snapshot_data = vec![0u8; 100];

        let snapshot = SnapshotHdr::new(Version::new(1, 0, 42));
        snapshot.store(&mut snapshot_data).unwrap();

        assert_eq!(
            SnapshotHdr::load(&mut snapshot_data.as_slice())
                .unwrap()
                .version,
            Version::new(1, 0, 42)
        );
    }

    // #[test]
    // fn test_bad_snapshot_size() {
    //     let snapshot_data = vec![0u8; 1];

    //     let snapshot = SnapshotHdr::new(Version::new(1, 6, 1));
    //     assert!(matches!(
    //         snapshot.load_with_version_check::<_, u8>(
    //             &mut snapshot_data.as_slice(),
    //             snapshot_data.len()
    //         ),
    //         Err(SnapshotError::InvalidSnapshotSize)
    //     ));
    // }

    // #[test]
    // fn test_bad_reader() {
    //     #[derive(Debug)]
    //     struct BadReader;

    //     impl Read for BadReader {
    //         fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
    //             Err(std::io::ErrorKind::InvalidInput.into())
    //         }
    //     }

    //     let mut reader = BadReader {};

    //     let snapshot = Snapshot::new(Version::new(42, 27, 18));
    //     assert!(matches!(
    //         snapshot.load_with_version_check::<_, u8>(&mut reader, 1024),
    //         Err(SnapshotError::Io(_))
    //     ));
    // }

    // #[test]
    // fn test_bad_magic() {
    //     let mut data = vec![0u8; 100];

    //     let snapshot = Snapshot::new(Version::new(24, 16, 1));
    //     snapshot.save(&mut data.as_mut_slice(), &42u8).unwrap();

    //     // Writing dummy values in the first bytes of the snapshot data (we are on little-endian
    //     // machines) should trigger an `Error::InvalidMagic` error.
    //     data[0] = 0x01;
    //     data[1] = 0x02;
    //     data[2] = 0x03;
    //     data[3] = 0x04;
    //     data[4] = 0x42;
    //     data[5] = 0x43;
    //     data[6] = 0x44;
    //     data[7] = 0x45;
    //     assert!(matches!(
    //         Snapshot::unchecked_load::<_, u8>(&mut data.as_slice()),
    //         Err(SnapshotError::InvalidMagic(0x4544_4342_0403_0201u64))
    //     ));
    // }

    // #[test]
    // fn test_bad_crc() {
    //     let mut data = vec![0u8; 100];

    //     let snapshot = Snapshot::new(Version::new(12, 1, 3));
    //     snapshot.save(&mut data.as_mut_slice(), &42u8).unwrap();

    //     // Tamper the bytes written, without touching the previously CRC.
    //     snapshot
    //         .save_without_crc(&mut data.as_mut_slice(), &43u8)
    //         .unwrap();

    //     assert!(matches!(
    //         snapshot.load_with_version_check::<_, u8>(&mut data.as_slice(), data.len()),
    //         Err(SnapshotError::Crc64(_))
    //     ));
    // }

    // #[test]
    // fn test_bad_version() {
    //     let mut data = vec![0u8; 100];

    //     // We write a snapshot with version "v1.3.12"
    //     let snapshot = Snapshot::new(Version::new(1, 3, 12));
    //     snapshot.save(&mut data.as_mut_slice(), &42u8).unwrap();

    //     // Different major versions should not work
    //     let snapshot = Snapshot::new(Version::new(2, 3, 12));
    //     assert!(matches!(
    //         snapshot.load_with_version_check::<_, u8>(&mut data.as_slice(), data.len()),
    //         Err(SnapshotError::InvalidFormatVersion(Version {
    //             major: 1,
    //             minor: 3,
    //             patch: 12,
    //             ..
    //         }))
    //     ));
    //     let snapshot = Snapshot::new(Version::new(0, 3, 12));
    //     assert!(matches!(
    //         snapshot.load_with_version_check::<_, u8>(&mut data.as_slice(), data.len()),
    //         Err(SnapshotError::InvalidFormatVersion(Version {
    //             major: 1,
    //             minor: 3,
    //             patch: 12,
    //             ..
    //         }))
    //     ));

    //     // We can't support minor versions bigger than ours
    //     let snapshot = Snapshot::new(Version::new(1, 2, 12));
    //     assert!(matches!(
    //         snapshot.load_with_version_check::<_, u8>(&mut data.as_slice(), data.len()),
    //         Err(SnapshotError::InvalidFormatVersion(Version {
    //             major: 1,
    //             minor: 3,
    //             patch: 12,
    //             ..
    //         }))
    //     ));

    //     // But we can support minor versions smaller or equeal to ours. We also support
    //     // all patch versions within our supported major.minor version.
    //     let snapshot = Snapshot::new(Version::new(1, 4, 12));
    //     snapshot
    //         .load_with_version_check::<_, u8>(&mut data.as_slice(), data.len())
    //         .unwrap();
    //     let snapshot = Snapshot::new(Version::new(1, 3, 0));
    //     snapshot
    //         .load_with_version_check::<_, u8>(&mut data.as_slice(), data.len())
    //         .unwrap();
    //     let snapshot = Snapshot::new(Version::new(1, 3, 12));
    //     snapshot
    //         .load_with_version_check::<_, u8>(&mut data.as_slice(), data.len())
    //         .unwrap();
    //     let snapshot = Snapshot::new(Version::new(1, 3, 1024));
    //     snapshot
    //         .load_with_version_check::<_, u8>(&mut data.as_slice(), data.len())
    //         .unwrap();
    // }
}
