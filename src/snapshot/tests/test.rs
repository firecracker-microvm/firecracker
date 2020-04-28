// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate snapshot;
extern crate versionize;
extern crate versionize_derive;

use snapshot::Snapshot;
use versionize::{VersionMap, Versionize, VersionizeError, VersionizeResult};
use versionize_derive::Versionize;

#[derive(Debug, PartialEq, Versionize)]
pub enum TestState {
    Zero,
    One(u32),
    #[version(start = 2, default_fn = "default_state_two")]
    Two(u64),
}

impl TestState {
    fn default_state_two(&self, target_version: u16) -> VersionizeResult<TestState> {
        match target_version {
            1 => Ok(TestState::One(2)),
            i => Err(VersionizeError::Serialize(format!(
                "Unknown target version: {}",
                i
            ))),
        }
    }
}

#[derive(Debug, PartialEq, Versionize)]
pub struct A {
    a: u32,
    #[version(start = 1, end = 2)]
    b: Option<TestState>,
    #[version(start = 2, default_fn = "default_c")]
    c: String,
}

impl A {
    fn default_c(_source_version: u16) -> String {
        "some_string".to_owned()
    }
}

#[test]
fn test_hardcoded_snapshot_deserialization() {
    // We are testing representation compatibility between versions, at the `snapshot` crate
    // level, by checking that only the version number and the newly added/removed fields changes
    // between versions are reflected in the hardcoded snapshot.

    #[rustfmt::skip]
    let v1_hardcoded_snapshot: &[u8] = &[
        // This blob is consisted of the following: magic_id (8 bytes),
        0x01, 0x00,
        #[cfg(target_arch = "aarch64")]
        0xAA,
        #[cfg(target_arch = "aarch64")]
        0xAA,
        #[cfg(target_arch = "x86_64")]
        0x64,
        #[cfg(target_arch = "x86_64")]
        0x86,
        0x84, 0x19, 0x10, 0x07,
        // target version (2 bytes), sections count (2 bytes) +
        0x01, 0x00, 0x02, 0x00,
        // first section: slice len of name section (8 bytes) + name ("enum" -> 4 bytes) +
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x6E, 0x75, 0x6D,
        // section len (only 4 bytes since the first enum variant doesn't have fields) +
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // number of enum variant (4 bytes) +
        0x00, 0x00, 0x00, 0x00,
        // second section: slice len of name section (8 bytes) + name ("struct" -> 6 bytes) +
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74,
        // section len (13 bytes) +
        0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // `a` field +
        0x10, 0x00, 0x00, 0x00,
        // `b` field: Option variant type (1 byte) + inner enum variant type (4 bytes)
        // + inner enum value (4 bytes).
        0x01, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    let v2_hardcoded_snapshot: &[u8] = &[
        0x01,
        0x00,
        #[cfg(target_arch = "aarch64")]
        0xAA,
        #[cfg(target_arch = "aarch64")]
        0xAA,
        #[cfg(target_arch = "x86_64")]
        0x64,
        #[cfg(target_arch = "x86_64")]
        0x86, 0x84, 0x19, 0x10, 0x07,
        // Version 2 + 2 sections +
        0x02, 0x00, 0x02, 0x00,
        // first section: slice len of name section (8 bytes) + name ("enum" -> 4 bytes) +
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65, 0x6E, 0x75, 0x6D,
        // section len (8 bytes this time since the second enum variant has also a 4 bytes field) +
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // number of enum variant (4 bytes) + value of that variant (4 bytes) +
        0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
        // second section: slice len of name section (8 bytes) + name ("struct" -> 6 bytes) +
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74,
        // section len (18 bytes)
        0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // `a` field +
        0x10, 0x00, 0x00, 0x00,
        // `c` field: String len (8 bytes) + actual String; the Option field is not available at v2.
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x61, 0x6E, 0x64, 0x6F, 0x6D,
    ];

    let mut vm = VersionMap::new();
    vm.new_version()
        .set_type_version(A::type_id(), 2)
        .set_type_version(TestState::type_id(), 2);

    let mut snapshot_blob = v1_hardcoded_snapshot;

    let mut snapshot = Snapshot::load(&mut snapshot_blob, vm.clone()).unwrap();
    let mut restored_struct = snapshot.read_section::<A>("struct").unwrap();
    let mut restored_enum = snapshot.read_section::<TestState>("enum").unwrap();

    let mut expected_struct = A {
        a: 16u32,
        b: Some(TestState::One(2)),
        c: "some_string".to_owned(),
    };
    let mut expected_enum = TestState::Zero;

    assert_eq!(restored_struct, expected_struct);
    assert_eq!(restored_enum, expected_enum);

    snapshot_blob = v2_hardcoded_snapshot;

    snapshot = Snapshot::load(&mut snapshot_blob, vm.clone()).unwrap();
    restored_struct = snapshot.read_section::<A>("struct").unwrap();
    restored_enum = snapshot.read_section::<TestState>("enum").unwrap();

    expected_struct = A {
        a: 16u32,
        b: None,
        c: "random".to_owned(),
    };
    expected_enum = TestState::One(16);

    assert_eq!(restored_struct, expected_struct);
    assert_eq!(restored_enum, expected_enum);
}
