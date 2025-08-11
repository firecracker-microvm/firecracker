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

use bincode::config;
use bincode::config::{Configuration, Fixint, Limit, LittleEndian};
use bincode::error::{DecodeError, EncodeError};
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::persist::SNAPSHOT_VERSION;
use crate::snapshot::crc::{CRC64Reader, CRC64Writer};
pub use crate::snapshot::persist::Persist;
use crate::utils::mib_to_bytes;

#[cfg(target_arch = "x86_64")]
const SNAPSHOT_MAGIC_ID: u64 = 0x0710_1984_8664_0000u64;

/// Constant bounding how much memory bincode may allocate during vmstate file deserialization
const DESERIALIZATION_BYTES_LIMIT: usize = mib_to_bytes(10);

const BINCODE_CONFIG: Configuration<LittleEndian, Fixint, Limit<DESERIALIZATION_BYTES_LIMIT>> =
    config::standard()
        .with_fixed_int_encoding()
        .with_limit::<DESERIALIZATION_BYTES_LIMIT>()
        .with_little_endian();

#[cfg(target_arch = "aarch64")]
const SNAPSHOT_MAGIC_ID: u64 = 0x0710_1984_AAAA_0000u64;

/// Error definitions for the Snapshot API.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SnapshotError {
    /// CRC64 validation failed: {0}
    Crc64(u64),
    /// Invalid data version: {0}
    InvalidFormatVersion(Version),
    /// Magic value does not match arch: {0}
    InvalidMagic(u64),
    /// An error occured during bincode encoding: {0}
    Encode(#[from] EncodeError),
    /// An error occured during bincode decoding: {0}
    Decode(#[from] DecodeError),
}

fn serialize<S: Serialize, W: Write>(data: &S, write: &mut W) -> Result<(), SnapshotError> {
    bincode::serde::encode_into_std_write(data, write, BINCODE_CONFIG)
        .map_err(SnapshotError::Encode)
        .map(|_| ())
}

/// Firecracker snapshot header
#[derive(Debug, Serialize, Deserialize)]
struct SnapshotHdr {
    /// magic value
    magic: u64,
    /// Snapshot data version
    version: Version,
}

impl SnapshotHdr {
    fn load<R: Read>(reader: &mut R) -> Result<Self, SnapshotError> {
        let hdr: SnapshotHdr = bincode::serde::decode_from_std_read(reader, BINCODE_CONFIG)?;

        if hdr.magic != SNAPSHOT_MAGIC_ID {
            return Err(SnapshotError::InvalidMagic(hdr.magic));
        }

        if hdr.version.major != SNAPSHOT_VERSION.major || hdr.version.minor > SNAPSHOT_VERSION.minor
        {
            return Err(SnapshotError::InvalidFormatVersion(hdr.version));
        }

        Ok(hdr)
    }
}

/// Assumes the raw bytes stream read from the given [`Read`] instance is a snapshot file,
/// and returns the version of it.
pub fn get_format_version<R: Read>(reader: &mut R) -> Result<Version, SnapshotError> {
    let hdr: SnapshotHdr = bincode::serde::decode_from_std_read(reader, BINCODE_CONFIG)?;
    Ok(hdr.version)
}

/// Firecracker snapshot type
///
/// A type used to store and load Firecracker snapshots of a particular version
#[derive(Debug, Serialize)]
pub struct Snapshot<Data> {
    header: SnapshotHdr,
    /// The data stored int his [`Snapshot`]
    pub data: Data,
}

impl<Data> Snapshot<Data> {
    /// Constructs a new snapshot with the given `data`.
    pub fn new(data: Data) -> Self {
        Self {
            header: SnapshotHdr {
                magic: SNAPSHOT_MAGIC_ID,
                version: SNAPSHOT_VERSION.clone(),
            },
            data,
        }
    }

    /// Gets the version of this snapshot
    pub fn version(&self) -> &Version {
        &self.header.version
    }
}

impl<Data: DeserializeOwned> Snapshot<Data> {
    fn load_without_crc_check<R: Read>(reader: &mut R) -> Result<Self, SnapshotError> {
        let header = SnapshotHdr::load(reader)?;
        let data = bincode::serde::decode_from_std_read(reader, BINCODE_CONFIG)?;
        Ok(Self { header, data })
    }

    /// Loads a snapshot from the given [`Read`] instance, performing all validations
    /// (CRC, snapshot magic value, snapshot version).
    pub fn load<R: Read>(reader: &mut R) -> Result<Self, SnapshotError> {
        let mut crc_reader = CRC64Reader::new(reader);
        let snapshot = Self::load_without_crc_check(&mut crc_reader)?;
        let computed_checksum = crc_reader.checksum();
        let stored_checksum: u64 =
            bincode::serde::decode_from_std_read(&mut crc_reader.reader, BINCODE_CONFIG)?;
        if computed_checksum != stored_checksum {
            return Err(SnapshotError::Crc64(computed_checksum));
        }
        Ok(snapshot)
    }
}

impl<Data: Serialize> Snapshot<Data> {
    /// Saves `self` to the given [`Write`] instance, computing the CRC of the written data,
    /// and then writing the CRC into the `Write` instance, too.
    pub fn save<W: Write>(&self, writer: &mut W) -> Result<(), SnapshotError> {
        let mut crc_writer = CRC64Writer::new(writer);
        serialize(self, &mut crc_writer)?;
        serialize(&crc_writer.checksum(), crc_writer.writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_from_file() {
        let snapshot = Snapshot::new(42);

        // Enough memory for the header, 1 byte and the CRC
        let mut snapshot_data = vec![0u8; 100];

        snapshot.save(&mut snapshot_data.as_mut_slice()).unwrap();

        assert_eq!(
            get_format_version(&mut snapshot_data.as_slice()).unwrap(),
            SNAPSHOT_VERSION
        );
    }

    #[test]
    fn test_bad_reader() {
        #[derive(Debug)]
        struct BadReader;

        impl Read for BadReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::InvalidInput.into())
            }
        }

        let mut reader = BadReader {};

        assert!(
            matches!(Snapshot::<()>::load(&mut reader), Err(SnapshotError::Decode(DecodeError::Io {inner, ..})) if inner.kind() == std::io::ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn test_bad_magic() {
        let mut data = vec![0u8; 100];

        let snapshot = Snapshot::new(());
        snapshot.save(&mut data.as_mut_slice()).unwrap();

        // Writing dummy values in the first bytes of the snapshot data (we are on little-endian
        // machines) should trigger an `Error::InvalidMagic` error.
        data[0] = 0x01;
        data[1] = 0x02;
        data[2] = 0x03;
        data[3] = 0x04;
        data[4] = 0x42;
        data[5] = 0x43;
        data[6] = 0x44;
        data[7] = 0x45;
        assert!(matches!(
            SnapshotHdr::load(&mut data.as_slice()),
            Err(SnapshotError::InvalidMagic(0x4544_4342_0403_0201u64))
        ));
    }

    #[test]
    fn test_bad_crc() {
        let mut data = vec![0u8; 100];

        let snapshot = Snapshot::new(());
        // Write the snapshot without CRC, so that when loading with CRC check, we'll read
        // zeros for the CRC and fail.
        serialize(&snapshot, &mut data.as_mut_slice()).unwrap();

        assert!(matches!(
            Snapshot::<()>::load(&mut data.as_slice()),
            Err(SnapshotError::Crc64(_))
        ));
    }

    #[test]
    fn test_bad_version() {
        let mut data = vec![0u8; 100];

        // Different major version: shouldn't work
        let mut snapshot = Snapshot::new(());
        snapshot.header.version.major = SNAPSHOT_VERSION.major + 1;
        snapshot.save(&mut data.as_mut_slice()).unwrap();

        assert!(matches!(
            Snapshot::<()>::load(&mut data.as_slice()),
            Err(SnapshotError::InvalidFormatVersion(v)) if v.major == SNAPSHOT_VERSION.major + 1
        ));

        //  minor > SNAPSHOT_VERSION.minor: shouldn't work
        let mut snapshot = Snapshot::new(());
        snapshot.header.version.minor = SNAPSHOT_VERSION.minor + 1;
        snapshot.save(&mut data.as_mut_slice()).unwrap();
        assert!(matches!(
            Snapshot::<()>::load(&mut data.as_slice()),
            Err(SnapshotError::InvalidFormatVersion(v)) if v.minor == SNAPSHOT_VERSION.minor + 1
        ));

        // But we can support minor versions smaller or equal to ours. We also support
        // all patch versions within our supported major.minor version.
        let snapshot = Snapshot::new(());
        snapshot.save(&mut data.as_mut_slice()).unwrap();
        Snapshot::<()>::load(&mut data.as_slice()).unwrap();

        if SNAPSHOT_VERSION.minor != 0 {
            let mut snapshot = Snapshot::new(());
            snapshot.header.version.minor = SNAPSHOT_VERSION.minor - 1;
            snapshot.save(&mut data.as_mut_slice()).unwrap();
            Snapshot::<()>::load(&mut data.as_slice()).unwrap();
        }

        let mut snapshot = Snapshot::new(());
        snapshot.header.version.patch = 0;
        snapshot.save(&mut data.as_mut_slice()).unwrap();
        Snapshot::<()>::load(&mut data.as_slice()).unwrap();

        let mut snapshot = Snapshot::new(());
        snapshot.header.version.patch = SNAPSHOT_VERSION.patch + 1;
        snapshot.save(&mut data.as_mut_slice()).unwrap();
        Snapshot::<()>::load(&mut data.as_slice()).unwrap();

        let mut snapshot = Snapshot::new(());
        snapshot.header.version.patch = 1024;
        snapshot.save(&mut data.as_mut_slice()).unwrap();
        Snapshot::<()>::load(&mut data.as_slice()).unwrap();
    }
}
