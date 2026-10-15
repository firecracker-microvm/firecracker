// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The layout of a compiled filter file: [`FORMAT_MAGIC`], [`FORMAT_VERSION`] as a little endian
//! `u32`, and the bitcode serialized [`BpfMap`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// BPF code of one feature-tagged rule, as stored in a compiled filter file.
///
/// The code is position independent and falls through when its rule does not match, so
/// fragments can be concatenated in any order after the base program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfFragment {
    /// The names of the features the rule is needed for, see
    /// [`SeccompFeature::name`](crate::SeccompFeature::name); any one of them being in use is
    /// sufficient.
    pub features: Vec<String>,
    /// The BPF instructions of the fragment.
    pub code: Vec<u64>,
}

/// The compiled filter of one thread category, as stored in a compiled filter file.
///
/// `base` is the libseccomp program of the untagged rules. When the filter has tagged rules, the
/// base does not return the default action but falls through to the code appended after it, and
/// ends with a prologue re-checking the architecture; the enabled `fragments` follow and the
/// `epilogue` returns the default action. Without tagged rules the base is the whole program and
/// the other two parts are empty. [`SeccompFilter`](crate::SeccompFilter) is the checked form
/// Firecracker composes the installed program from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfFilter {
    /// The program of the untagged rules.
    pub base: Vec<u64>,
    /// One fragment per tagged rule.
    pub fragments: Vec<BpfFragment>,
    /// The return of the default action, when there are fragments.
    pub epilogue: Vec<u64>,
}

/// The compiled filters of all thread categories, keyed by thread name.
pub type BpfMap = BTreeMap<String, BpfFilter>;

/// First bytes of a compiled filter file.
pub const FORMAT_MAGIC: [u8; 4] = *b"FCBF";

/// Version of the compiled filter file format, bumped whenever the layout of [`BpfFilter`] or
/// its serialization changes.
pub const FORMAT_VERSION: u32 = 1;

/// Length of the magic and version header.
const HEADER_LEN: usize = FORMAT_MAGIC.len() + std::mem::size_of::<u32>();

/// The largest compiled filter file, header included, that is written or read.
///
/// It guards against memory allocation DoS when decoding a filter file that is too large. The
/// limit can be safely determined since the maximum length of a BPF program is 4096 instructions
/// and Firecracker has a finite number of threads.
pub const MAX_ENCODED_SIZE: usize = 100_000;

/// Errors encoding or decoding a compiled filter file.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum FormatError {
    /// Compiled filter of {0} bytes exceeds the limit of {1} bytes
    SizeLimitExceeded(usize, usize),
    /// Not a compiled seccomp filter; filters must be compiled with this version's seccompiler-bin
    UnknownFormat,
    /// Unsupported compiled filter format version {0}; recompile the filter with this version's seccompiler-bin
    UnsupportedVersion(u32),
    /// Bitcode (de)serialization failed: {0}
    Bitcode(#[from] bitcode::Error),
}

/// Serialize `map` into the content of a compiled filter file.
pub fn encode(map: &BpfMap) -> Result<Vec<u8>, FormatError> {
    let mut bytes = Vec::from(FORMAT_MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&bitcode::serialize(map)?);
    if bytes.len() > MAX_ENCODED_SIZE {
        return Err(FormatError::SizeLimitExceeded(
            bytes.len(),
            MAX_ENCODED_SIZE,
        ));
    }
    Ok(bytes)
}

/// Deserialize the content of a compiled filter file.
///
/// The parts of the filters are not checked; converting them into a
/// [`SeccompFilter`](crate::SeccompFilter) does that.
pub fn decode(bytes: &[u8]) -> Result<BpfMap, FormatError> {
    if bytes.len() > MAX_ENCODED_SIZE {
        return Err(FormatError::SizeLimitExceeded(
            bytes.len(),
            MAX_ENCODED_SIZE,
        ));
    }
    let Some((header, encoded)) = bytes.split_at_checked(HEADER_LEN) else {
        return Err(FormatError::UnknownFormat);
    };
    let (magic, version) = header.split_at(FORMAT_MAGIC.len());
    if magic != FORMAT_MAGIC {
        return Err(FormatError::UnknownFormat);
    }
    let version = u32::from_le_bytes(version.try_into().expect("the header length was checked"));
    if version != FORMAT_VERSION {
        return Err(FormatError::UnsupportedVersion(version));
    }
    Ok(bitcode::deserialize(encoded)?)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn sample() -> BpfMap {
        BpfMap::from([
            (
                "vcpu".to_string(),
                BpfFilter {
                    base: vec![0; 2],
                    fragments: vec![BpfFragment {
                        features: vec!["net".to_string(), "hotplug".to_string()],
                        code: vec![1; 3],
                    }],
                    epilogue: vec![2],
                },
            ),
            (
                "api".to_string(),
                BpfFilter {
                    base: vec![3],
                    ..Default::default()
                },
            ),
            ("vmm".to_string(), BpfFilter::default()),
        ])
    }

    #[test]
    fn test_roundtrip() {
        let bytes = encode(&sample()).unwrap();
        assert_eq!(&bytes[..4], b"FCBF");
        assert_eq!(&bytes[4..8], &1u32.to_le_bytes());
        assert_eq!(decode(&bytes).unwrap(), sample());
    }

    #[test]
    fn test_decode_errors() {
        // Not a compiled filter at all, or one written without the header by an older
        // seccompiler.
        for data in [
            &b"adassafvc"[..],
            &b"FCB"[..],
            &bitcode::serialize(&HashMap::<String, Vec<u64>>::new()).unwrap(),
        ] {
            assert!(matches!(
                decode(data).unwrap_err(),
                FormatError::UnknownFormat
            ));
        }

        // A format version this crate does not read.
        let mut bytes = encode(&BpfMap::new()).unwrap();
        bytes[4..8].copy_from_slice(&(FORMAT_VERSION + 1).to_le_bytes());
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            FormatError::UnsupportedVersion(version) if version == FORMAT_VERSION + 1
        ));

        // Garbage after a valid header.
        let mut bytes = encode(&BpfMap::new()).unwrap();
        bytes.extend_from_slice(b"adassafvc");
        assert!(matches!(
            decode(&bytes).unwrap_err(),
            FormatError::Bitcode(_)
        ));

        // Too large to be a compiled filter.
        let large_data = vec![0u8; MAX_ENCODED_SIZE + 1];
        assert!(matches!(
            decode(&large_data).unwrap_err(),
            FormatError::SizeLimitExceeded(len, MAX_ENCODED_SIZE) if len == MAX_ENCODED_SIZE + 1
        ));
    }

    #[test]
    fn test_encode_size_limit() {
        let map = BpfMap::from([(
            "vmm".to_string(),
            BpfFilter {
                base: (0..u64::try_from(MAX_ENCODED_SIZE).unwrap()).collect(),
                ..Default::default()
            },
        )]);
        assert!(matches!(
            encode(&map).unwrap_err(),
            FormatError::SizeLimitExceeded(_, MAX_ENCODED_SIZE)
        ));
    }
}
