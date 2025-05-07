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
struct SnapshotHdr {
    /// Magic value
    magic: u64,
    /// Snapshot data version
    version: Version,
}

impl SnapshotHdr {
    /// Create a new header for writing snapshots
    fn new(version: Version) -> Self {
        Self {
            magic: SNAPSHOT_MAGIC_ID,
            version,
        }
    }

    /// Load and deserialize just the header (magic + version)
    fn load<R: Read>(reader: &mut R) -> Result<Self, SnapshotError> {
        let hdr: SnapshotHdr = deserialize(reader)?;
        if hdr.magic != SNAPSHOT_MAGIC_ID {
            Err(SnapshotError::InvalidMagic(hdr.magic))
        } else {
            Ok(hdr)
        }
    }

    /// Serialize and write just the header
    fn store<W: Write>(&self, writer: &mut W) -> Result<(), SnapshotError> {
        serialize(writer, self)?;
        Ok(())
    }
}

/// Helper function to serialize an object to a writer
pub fn serialize<T, O>(writer: &mut T, data: &O) -> Result<(), SnapshotError>
where
    T: Write,
    O: Serialize + Debug,
{
    bincode::serde::encode_into_std_write(data, writer, BINCODE_CONFIG)
        .map_err(|err| SnapshotError::Serde(err.to_string()))?;

    Ok(())
}

// Implementations for deserializing snapshots
// Publicly exposed functions:
// - load_unchecked()
//- load()
impl<Data: DeserializeOwned + Debug> Snapshot<Data> {
    /// Load without CRC or version‐check, but verify magic via `SnapshotHdr::load`.
    pub fn load_unchecked<R: Read + Debug>(reader: &mut R) -> Result<Self, SnapshotError> {
        // this calls `deserialize` + checks magic internally
        let hdr: SnapshotHdr = SnapshotHdr::load(reader)?;
        let data: Data = deserialize(reader)?;
        Ok(Self { header: hdr, data })
    }

    /// Load with CRC64 validation
    pub fn load<R: Read + Debug>(reader: &mut R) -> Result<Self, SnapshotError> {
        // 1) Wrap in CRC reader
        let mut crc_reader = CRC64Reader::new(reader);

        // 2) Parse header + payload & magic‐check
        let snapshot = Snapshot::load_unchecked(&mut crc_reader)?;

        // 3) Grab the computed CRC over everything read so far
        let computed = crc_reader.checksum();

        // 4) Deserialize the trailing u64 and compare
        let stored: u64 = deserialize(&mut crc_reader)?;
        if stored != computed {
            return Err(SnapshotError::Crc64(computed));
        }

        Ok(snapshot)
    }

    /// Load with CRC64 validation, and check that snapshot against the specified version
    pub fn load_with_verison_check<R: Read + Debug>(
        reader: &mut R,
        version: &Version,
    ) -> Result<Self, SnapshotError> {
        Self = load(reader)?;
        if Self.version.major != version.major || Self.version.minor > version.minor {
            Err(SnapshotError::InvalidFormatVersion(Self.version))
        } else {
            Ok(data)
        }
    }
}

// Implementations for serializing snapshots
// Publicly-exposed *methods*:
// - save(self,...)
// - save_with_crc(self,...)
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

// General methods for snapshots (related to serialization, see above, since an
// instance is needed to serialize)
impl<Data> Snapshot<Data> {
    /// Construct from a pre‐built header + payload
    pub fn new(version: Version, data: Data) -> Self {
        header = SnapshotHdr::new(version);
        Snapshot { header, data }
    }

    pub fn version(&self) -> Version {
        self.header.version.clone()
    }
}

/// Deserialize any `O: DeserializeOwned + Debug` via bincode + our config,
fn deserialize<T, O>(reader: &mut T) -> Result<O, SnapshotError>
where
    T: Read,
    O: DeserializeOwned + Debug,
{
    bincode::serde::decode_from_std_read(reader, BINCODE_CONFIG).map_err(|err| match err {
        // The reader hit an actual IO error.
        DecodeError::Io { inner, .. } => SnapshotError::Io(inner.raw_os_error().unwrap_or(EIO)),

        // Not enough bytes in the input for what we expected.
        DecodeError::UnexpectedEnd { .. } | DecodeError::LimitExceeded => {
            SnapshotError::InvalidSnapshotSize
        }

        // Anything else is a ser/de format issue.
        other => SnapshotError::Serde(other.to_string()),
    })
}

/// Serialize any `O: Serialize + Debug` into a Vec, write it, and return the byte‐count,
fn serialize<T, O>(writer: &mut T, data: &O) -> Result<usize, SnapshotError>
where
    T: Write,
    O: Serialize + Debug,
{
    // 1) Encode into an in-memory buffer
    let mut buf = Vec::new();
    bincode::serde::encode_into_std_write(data, &mut buf, BINCODE_CONFIG).map_err(
        |err| match err {
            // Ran out of room while encoding
            EncodeError::UnexpectedEnd => SnapshotError::Io(libc::EIO),

            // Underlying IO failure during encode (index tells how many bytes got written)
            EncodeError::Io { inner, .. } => {
                SnapshotError::Io(inner.raw_os_error().unwrap_or(libc::EIO))
            }

            // Any other encode error we surface as Serde
            other => SnapshotError::Serde(other.to_string()),
        },
    )?;

    // 2) Flush that buffer to the target writer
    writer
        .write_all(&buf)
        .map_err(|io_err| SnapshotError::Io(io_err.raw_os_error().unwrap_or(libc::EIO)))?;

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

    #[test]
    fn test_bad_snapshot_size() {
        let snapshot_data = vec![0u8; 1];

        let snapshot = SnapshotHdr::new(Version::new(1, 6, 1));
        assert!(matches!(
            Snapshot::load::<_, u8>(&mut snapshot_data.as_slice(),),
            Err(SnapshotError::InvalidSnapshotSize)
        ));
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

        assert!(matches!(
            Snapshot::load::<_, u8>(&mut reader),
            Err(SnapshotError::Io(_))
        ));
    }

    #[test]
    fn test_bad_magic() {
        let mut data = vec![0u8; 100];

        let snapshot = Snapshot::new(Version::new(24, 16, 1), &42u8);
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
            Snapshot::unchecked_load::<_, u8>(&mut data.as_slice()),
            Err(SnapshotError::InvalidMagic(0x4544_4342_0403_0201u64))
        ));
    }

    #[test]
    fn test_bad_crc() {
        let mut data = vec![0u8; 100];

        let snapshot = Snapshot::new(Version::new(12, 1, 3), &42u8);
        snapshot.save(&mut data.as_mut_slice()).unwrap();

        // Tamper the bytes written, without touching the previously CRC.
        let snapshot2 = Snapshot::new(Version::new(12, 1, 3), &43u8);
        snapshot2
            .save_without_crc(&mut data.as_mut_slice())
            .unwrap();

        assert!(matches!(
            Snapshot::load::<_, u8>(&mut data.as_slice()),
            Err(SnapshotError::Crc64(_))
        ));
    }

    #[test]
    fn test_bad_version() {
        let mut data = vec![0u8; 100];

        // We write a snapshot with version "v1.3.12"
        let snapshot = Snapshot::new(Version::new(1, 3, 12));
        snapshot.save(&mut data.as_mut_slice(), &42u8).unwrap();

        // Different major versions should not work
        assert!(matches!(
            Snapshot::load_with_version_check::<_, u8>(
                &mut data.as_slice(),
                Version::new(2, 3, 12)
            ),
            Err(SnapshotError::InvalidFormatVersion(Version {
                major: 1,
                minor: 3,
                patch: 12,
                ..
            }))
        ));
        assert!(matches!(
            snapshot.load_with_version_check::<_, u8>(&mut data.as_slice(), Version::new(0, 3, 12)),
            Err(SnapshotError::InvalidFormatVersion(Version {
                major: 1,
                minor: 3,
                patch: 12,
                ..
            }))
        ));

        // We can't support minor versions bigger than ours
        assert!(matches!(
            snapshot.load_with_version_check::<_, u8>(&mut data.as_slice(), Version::new(1, 2, 12)),
            Err(SnapshotError::InvalidFormatVersion(Version {
                major: 1,
                minor: 3,
                patch: 12,
                ..
            }))
        ));

        // But we can support minor versions smaller or equeal to ours. We also support
        // all patch versions within our supported major.minor version.
        snapshot
            .load_with_version_check::<_, u8>(&mut data.as_slice(), Version::new(1, 4, 12))
            .unwrap();
        snapshot
            .load_with_version_check::<_, u8>(&mut data.as_slice(), Version::new(1, 3, 0))
            .unwrap();
        snapshot
            .load_with_version_check::<_, u8>(&mut data.as_slice(), Version::new(1, 3, 12))
            .unwrap();
        snapshot
            .load_with_version_check::<_, u8>(&mut data.as_slice(), Version::new(1, 3, 1024))
            .unwrap();
    }
}
