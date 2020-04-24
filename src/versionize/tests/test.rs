// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate versionize;
extern crate versionize_derive;
extern crate vmm_sys_util;

use std::fmt::{Debug, Formatter, Result};
use std::num::Wrapping;

use vmm_sys_util::fam::{FamStruct, FamStructWrapper};
use vmm_sys_util::generate_fam_struct_impl;

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

#[test]
fn test_hardcoded_struct_deserialization() {
    // We are testing representation compatibility between versions, at the `versionize`
    // crate level, by checking that only the newly added/removed fields changes between
    // versions are reflected in the hardcoded snapshot.

    #[rustfmt::skip]
    let v1_hardcoded_snapshot: &[u8] = &[
        // usize field (8 bytes), u16 field (2 bytes) +
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
        // u64 (8 bytes), i8 (1 byte), i32 (4 bytes) +
        0xCD, 0xAB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x20, 0x00, 0x00, 0x00,
        // f32 (4 bytes), f64 (8 bytes), char (1 bytes) +
        0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x50, 0x40, 0x61,
        // String len (8 bytes) +
        0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // actual String (11 bytes in our case) +
        0x73, 0x6F, 0x6D, 0x65, 0x5F, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67,
        // enum variant number (4 bytes) + value of that variant (in this case it is
        // of u32 type -> 4 bytes) +
        0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        // Option variant (1 byte) + value of variant (u8 -> 1 byte) +
        0x01, 0x81,
        // Box: String len (8 bytes) + actual String (17 bytes in this case).
        0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x6F, 0x6D, 0x65, 0x5F,
        0x6F, 0x74, 0x68, 0x65, 0x72, 0x5F, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67,
    ];

    // At version 2 isize (8 bytes), i64 (8 bytes) and bool (1 byte) fields will be also
    // present. At v2 there is also a new variant available for enum, so we can store that in
    // memory and it occupies 4 more bytes than the one stored at v1.
    #[rustfmt::skip]
    let v2_hardcoded_snapshot: &[u8] = &[
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // New isize field.
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00,
        0xCD, 0xAB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x20, 0x00, 0x00, 0x00,
        // New i64 field.
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x50, 0x40, 0x61,
        // New bool field.
        0x01,
        0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x73, 0x6F, 0x6D, 0x65, 0x5F, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67,
        // New available enum variant.
        0x02, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x81,
        0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x6F, 0x6D, 0x65, 0x5F,
        0x6F, 0x74, 0x68, 0x65, 0x72, 0x5F, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67,
    ];

    // At version 3, u64 and i64 disappear (16 bytes) and Vec (8 + 4 = 12 bytes) and Wrapping
    // (4 bytes) fields are available.
    #[rustfmt::skip]
    let v3_hardcoded_snapshot: &[u8] = &[
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00,
        0xFF, 0x20, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x50, 0x40, 0x61,
        0x01,
        0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x73, 0x6F, 0x6D, 0x65, 0x5F, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67,
        0x02, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x81,
        // Vec len (8 bytes) + actual Vec (4 bytes).
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x61, 0x61, 0x61,
        0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x6F, 0x6D, 0x65, 0x5F,
        0x6F, 0x74, 0x68, 0x65, 0x72, 0x5F, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67,
        // Wrapping over an u32 (4 bytes).
        0xFF, 0x00, 0x00, 0x00,
    ];

    // At version 4, isize and Vec disappear (20 bytes): 0x6F - 0x14 = 0x5B.
    #[rustfmt::skip]
    let v4_hardcoded_snapshot: &[u8] = &[
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00,
        0xFF, 0x20, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x50, 0x40, 0x61,
        0x01,
        0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x73, 0x6F, 0x6D, 0x65, 0x5F, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67,
        0x02, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x81,
        0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x6F, 0x6D, 0x65, 0x5F,
        0x6F, 0x74, 0x68, 0x65, 0x72, 0x5F, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67,
        0xFF, 0x00, 0x00, 0x00,
    ];

    #[derive(Debug, PartialEq, Versionize)]
    pub struct TestStruct {
        usize_1: usize,
        #[version(start = 2, end = 4, default_fn = "default_isize")]
        isize_1: isize,
        u16_1: u16,
        #[version(end = 3, default_fn = "default_u64")]
        u64_1: u64,
        i8_1: i8,
        #[version(start = 2, end = 2)]
        i16_1: i16,
        i32_1: i32,
        #[version(start = 2, end = 3, default_fn = "default_i64")]
        i64_1: i64,
        f32_1: f32,
        f64_1: f64,
        char_1: char,
        #[version(start = 2, default_fn = "default_bool")]
        bool_1: bool,
        string_1: String,
        enum_1: TestState,
        option_1: Option<u8>,
        #[version(start = 3, end = 4, default_fn = "default_vec")]
        vec_1: Vec<char>,
        box_1: Box<String>,
        #[version(start = 3)]
        wrapping_1: Wrapping<u32>,
    }

    impl TestStruct {
        fn default_isize(_source_version: u16) -> isize {
            12isize
        }

        fn default_u64(_source_version: u16) -> u64 {
            0x0Du64
        }

        fn default_i64(_source_version: u16) -> i64 {
            0x0Ei64
        }

        fn default_bool(_source_version: u16) -> bool {
            false
        }

        fn default_vec(_source_version: u16) -> Vec<char> {
            vec!['v'; 8]
        }
    }

    let mut vm = VersionMap::new();
    vm.new_version()
        .set_type_version(TestStruct::type_id(), 2)
        .set_type_version(TestState::type_id(), 2)
        .new_version()
        .set_type_version(TestStruct::type_id(), 3)
        .new_version()
        .set_type_version(TestStruct::type_id(), 4);

    let mut snapshot_blob = v1_hardcoded_snapshot;

    let mut restored_state =
        <TestStruct as Versionize>::deserialize(&mut snapshot_blob, &vm, 1).unwrap();

    // We expect isize, i16, i64, bool, Vec and Wrapping fields to have the default values at v1.
    let mut expected_state = TestStruct {
        usize_1: 1,
        isize_1: 12,
        u16_1: 4,
        u64_1: 0xABCDu64,
        i8_1: -1,
        i16_1: 0,
        i32_1: 32,
        i64_1: 0x0Ei64,
        f32_1: 0.5,
        f64_1: 64.5,
        char_1: 'a',
        bool_1: false,
        string_1: "some_string".to_owned(),
        enum_1: TestState::One(2),
        option_1: Some(129),
        vec_1: vec!['v'; 8],
        box_1: Box::new("some_other_string".to_owned()),
        wrapping_1: Wrapping(0u32),
    };
    assert_eq!(restored_state, expected_state);

    snapshot_blob = v2_hardcoded_snapshot;

    restored_state = <TestStruct as Versionize>::deserialize(&mut snapshot_blob, &vm, 2).unwrap();

    // We expect only i16, Vec and Wrapping fields to have the default values at v2.
    expected_state = TestStruct {
        usize_1: 1,
        isize_1: 2,
        u16_1: 4,
        u64_1: 0xABCDu64,
        i8_1: -1,
        i16_1: 0,
        i32_1: 32,
        i64_1: 0xFFFFi64,
        f32_1: 0.5,
        f64_1: 64.5,
        char_1: 'a',
        bool_1: true,
        string_1: "some_string".to_owned(),
        enum_1: TestState::Two(14),
        option_1: Some(129),
        vec_1: vec!['v'; 8],
        box_1: Box::new("some_other_string".to_owned()),
        wrapping_1: Wrapping(0u32),
    };
    assert_eq!(restored_state, expected_state);

    snapshot_blob = v3_hardcoded_snapshot;

    restored_state = <TestStruct as Versionize>::deserialize(&mut snapshot_blob, &vm, 3).unwrap();

    // We expect u64, i16 and i64 fields to have the default values at v3.
    expected_state = TestStruct {
        usize_1: 1,
        isize_1: 2,
        u16_1: 4,
        u64_1: 0x0Du64,
        i8_1: -1,
        i16_1: 0,
        i32_1: 32,
        i64_1: 0x0Ei64,
        f32_1: 0.5,
        f64_1: 64.5,
        char_1: 'a',
        bool_1: true,
        string_1: "some_string".to_owned(),
        enum_1: TestState::Two(14),
        option_1: Some(129),
        vec_1: vec!['a'; 4],
        box_1: Box::new("some_other_string".to_owned()),
        wrapping_1: Wrapping(255u32),
    };
    assert_eq!(restored_state, expected_state);

    snapshot_blob = v4_hardcoded_snapshot;

    restored_state = <TestStruct as Versionize>::deserialize(&mut snapshot_blob, &vm, 4).unwrap();

    // We expect isize, u64, i16, i64 and Vec fields to have the default values at v4.
    expected_state = TestStruct {
        usize_1: 1,
        isize_1: 12,
        u16_1: 4,
        u64_1: 0x0Du64,
        i8_1: -1,
        i16_1: 0,
        i32_1: 32,
        i64_1: 0x0Ei64,
        f32_1: 0.5,
        f64_1: 64.5,
        char_1: 'a',
        bool_1: true,
        string_1: "some_string".to_owned(),
        enum_1: TestState::Two(14),
        option_1: Some(129),
        vec_1: vec!['v'; 8],
        box_1: Box::new("some_other_string".to_owned()),
        wrapping_1: Wrapping(255u32),
    };
    assert_eq!(restored_state, expected_state);
}

#[derive(Versionize)]
union TestUnion {
    a: i16,
    b: i32,
    #[version(start = 2, end = 3)]
    c: [u32; 4usize],
    #[version(start = 3)]
    d: u64,
}

impl Default for TestUnion {
    fn default() -> Self {
        TestUnion { b: 64i32 }
    }
}

impl Debug for TestUnion {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        unsafe {
            write!(
                f,
                "{{ a: {}, b: {}, c: {:?}, d: {} }}",
                self.a, self.b, self.c, self.d
            )
        }
    }
}

#[test]
fn test_hardcoded_union_deserialization() {
    // We are testing separately representation compatibility between versions for unions as it
    // is pretty awkward to implement PartialEq for unions.

    // The union instance size at a certain version will be equal with the max size of the available
    // fields at that version.
    #[rustfmt::skip]
    let v1_hardcoded_snapshot: &[u8] = &[
        // union value (4 bytes).
        0x01, 0x02, 0x03, 0x04,
    ];

    #[rustfmt::skip]
    let v2_hardcoded_snapshot: &[u8] = &[
        // 4 elements Vec of u32.
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
    ];

    #[rustfmt::skip]
    let v3_hardcoded_snapshot: &[u8] = &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];

    #[rustfmt::skip]
    let short_v3_hardcoded_snapshot: &[u8] = &[
        0x01, 0x02, 0x03, 0x04,
    ];

    #[rustfmt::skip]
    let long_v3_hardcoded_snapshot: &[u8] = &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00,
    ];

    let mut vm = VersionMap::new();
    vm.new_version()
        .set_type_version(TestUnion::type_id(), 2)
        .new_version()
        .set_type_version(TestUnion::type_id(), 3);

    let mut snapshot_blob = v1_hardcoded_snapshot;

    let mut restored_state =
        <TestUnion as Versionize>::deserialize(&mut snapshot_blob, &vm, 1).unwrap();
    unsafe {
        assert_eq!(restored_state.a, 0x0201i16);
        assert_eq!(restored_state.b, 0x0403_0201i32);
        assert_eq!(restored_state.c[0], 0x0403_0201u32);
        assert_eq!(restored_state.d as u32, 0x0403_0201u32);
    }

    snapshot_blob = v2_hardcoded_snapshot;

    restored_state = <TestUnion as Versionize>::deserialize(&mut snapshot_blob, &vm, 2).unwrap();
    unsafe {
        assert_eq!(restored_state.a, 0x0201i16);
        assert_eq!(restored_state.b, 0x0403_0201i32);
        assert_eq!(
            restored_state.c,
            [
                0x0403_0201u32,
                0x0807_0605u32,
                0x0C0B_0A09u32,
                0x000F_0E0Du32
            ]
        );
        assert_eq!(restored_state.d, 0x0807_0605_0403_0201u64);
    }

    snapshot_blob = v3_hardcoded_snapshot;

    restored_state = <TestUnion as Versionize>::deserialize(&mut snapshot_blob, &vm, 3).unwrap();
    unsafe {
        assert_eq!(restored_state.a, 0x0201i16);
        assert_eq!(restored_state.b, 0x0403_0201i32);
        assert_eq!(restored_state.c[0], 0x0403_0201u32);
        assert_eq!(restored_state.c[1], 0x0807_0605u32);
        assert_eq!(restored_state.d, 0x0807_0605_0403_0201u64);
    }

    // Let's try to deserialize a snapshot that is shorter than the expected one for version 3.
    snapshot_blob = short_v3_hardcoded_snapshot;

    // Reading a `TestUnion` value fails if we don't provide the expected number of bytes in the
    // snapshot.
    assert_eq!(
        <TestUnion as Versionize>::deserialize(&mut snapshot_blob, &vm, 3).unwrap_err(),
        VersionizeError::Deserialize(
            "Io(Custom { kind: UnexpectedEof, error: \"failed to fill whole buffer\" })".to_owned()
        )
    );

    // Now we will deserialize a longer snapshot than the expected one at version 3.
    snapshot_blob = long_v3_hardcoded_snapshot;

    // Reading a `TestUnion` value won't fail, but only the number of expected bytes for version 3
    // (8 bytes) will be stored in the union variable.
    restored_state = <TestUnion as Versionize>::deserialize(&mut snapshot_blob, &vm, 3).unwrap();
    unsafe {
        assert_eq!(restored_state.a, 0x0201i16);
        assert_eq!(restored_state.b, 0x0403_0201i32);
        assert_eq!(restored_state.c[0], 0x0403_0201u32);
        assert_eq!(restored_state.c[1], 0x0807_0605u32);
        assert_ne!(
            restored_state.c,
            [
                0x0403_0201u32,
                0x0807_0605u32,
                0x0C0B_0A09u32,
                0x000F_0E0Du32
            ]
        );
        assert_eq!(restored_state.d, 0x0807_0605_0403_0201u64);
    }
}

#[test]
fn test_hardcoded_enum_deserialization() {
    // We are testing separately also hardcoded snapshot deserialization for enums
    // as these have a different behavior in terms of serialization/deserialization.
    #[rustfmt::skip]
    let v1_hardcoded_snapshot: &[u8] = &[
        // Variant number (4 bytes), the first variant lacks a value.
        0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    let v2_hardcoded_snapshot: &[u8] = &[
        0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    let unexpected_v1_hardcoded_snapshot: &[u8] = &[
        // Second variant (4 bytes) + value of that variant (8 bytes).
        0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    let invalid_v1_hardcoded_snapshot: &[u8] = &[
        // Invalid enum variant number.
        0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let mut vm = VersionMap::new();
    vm.new_version().set_type_version(TestState::type_id(), 2);

    let mut snapshot_blob = v1_hardcoded_snapshot;

    let mut restored_state =
        <TestState as Versionize>::deserialize(&mut snapshot_blob, &vm, 1).unwrap();
    assert_eq!(restored_state, TestState::Zero);

    snapshot_blob = v2_hardcoded_snapshot;

    restored_state = <TestState as Versionize>::deserialize(&mut snapshot_blob, &vm, 2).unwrap();
    assert_eq!(restored_state, TestState::Zero);

    snapshot_blob = unexpected_v1_hardcoded_snapshot;

    // Versioned deserialization is not implemented for enums, so even though we do not have
    // `Two` state available at version 2, restoring the data won't fail :(.
    // TODO: This must be fixed.
    restored_state = <TestState as Versionize>::deserialize(&mut snapshot_blob, &vm, 1).unwrap();
    assert_eq!(restored_state, TestState::Two(5));

    // This snapshot contains a non-existent enum variant.
    snapshot_blob = invalid_v1_hardcoded_snapshot;

    assert_eq!(
        <TestState as Versionize>::deserialize(&mut snapshot_blob, &vm, 1).unwrap_err(),
        VersionizeError::Deserialize("Unknown variant_index 3".to_owned())
    );
}

#[derive(Debug, PartialEq, Versionize)]
pub struct A {
    a: u32,
    #[version(start = 1, end = 2)]
    b: Option<TestState>,
    #[version(start = 2, default_fn = "default_c")]
    c: String,
}

#[derive(Debug, PartialEq, Versionize)]
pub struct X {
    x: bool,
    a_1: A,
    #[version(end = 3, default_fn = "default_y")]
    y: Box<usize>,
    #[version(start = 3, default_fn = "default_z")]
    z: Vec<u8>,
}

impl A {
    fn default_c(_source_version: u16) -> String {
        "some_string".to_owned()
    }
}

impl X {
    fn default_y(_source_version: u16) -> Box<usize> {
        Box::from(4 as usize)
    }

    fn default_z(_source_version: u16) -> Vec<u8> {
        vec![16, 4]
    }
}

#[test]
fn test_nested_structs_deserialization() {
    #[rustfmt::skip]
    let v1_hardcoded_snapshot: &[u8] = &[
        // Bool field (1 byte) from X, `a` field from A (4 bytes) +
        0x00, 0x10, 0x00, 0x00, 0x00,
        // `b` field from A: Option type (1 byte), inner enum variant number (4 bytes) +
        // + value of that variant (4 bytes) +
        0x01, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
        // `y` field from A (8 bytes).
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    let v2_hardcoded_snapshot: &[u8] = &[
        // Bool field (1 byte) from X, `a` field from A (4 bytes) +
        0x00, 0x10, 0x00, 0x00, 0x00,
        // `c` field from X: String len (8 bytes) + actual String;
        // the Option field is not available at v2.
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x72, 0x61, 0x6E, 0x64, 0x6F, 0x6D,
        // `y` field from A (8 bytes).
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[rustfmt::skip]
    let v3_hardcoded_snapshot: &[u8] = &[
        0x00, 0x10, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x72, 0x61, 0x6E, 0x64, 0x6F, 0x6D,
        // `z` field from A (8 bytes).
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x18, 0x18, 0x18,
    ];

    let mut vm = VersionMap::new();
    vm.new_version()
        .set_type_version(A::type_id(), 2)
        .set_type_version(X::type_id(), 2)
        .set_type_version(TestState::type_id(), 2)
        .new_version()
        .set_type_version(X::type_id(), 3);

    let mut snapshot_blob = v1_hardcoded_snapshot;

    let mut restored_state = <X as Versionize>::deserialize(&mut snapshot_blob, &vm, 1).unwrap();
    // We expect `z` and `c` fields to have the default values.
    let mut expected_state = X {
        x: false,
        a_1: A {
            a: 16u32,
            b: Some(TestState::One(4)),
            c: "some_string".to_owned(),
        },
        y: Box::from(2 as usize),
        z: vec![16, 4],
    };
    assert_eq!(restored_state, expected_state);

    snapshot_blob = v2_hardcoded_snapshot;

    restored_state = <X as Versionize>::deserialize(&mut snapshot_blob, &vm, 2).unwrap();

    // We expect `b` and `z` fields to have the default values.
    expected_state = X {
        x: false,
        a_1: A {
            a: 16u32,
            b: None,
            c: "random".to_owned(),
        },
        y: Box::from(2 as usize),
        z: vec![16, 4],
    };
    assert_eq!(restored_state, expected_state);

    snapshot_blob = v3_hardcoded_snapshot;

    restored_state = <X as Versionize>::deserialize(&mut snapshot_blob, &vm, 3).unwrap();

    // We expect `b` and `y` fields to have the default values.
    expected_state = X {
        x: false,
        a_1: A {
            a: 16u32,
            b: None,
            c: "random".to_owned(),
        },
        y: Box::from(4 as usize),
        z: vec![24; 4],
    };
    assert_eq!(restored_state, expected_state);
}

pub const SIZE: usize = 10;

pub mod dummy_mod {
    pub const SIZE: usize = 20;
}

#[test]
fn test_versionize_struct_with_array() {
    #[derive(Debug, PartialEq, Versionize)]
    struct TestStruct {
        a: [u32; SIZE],
        b: [u8; dummy_mod::SIZE],
    }

    let test_struct = TestStruct {
        a: [1; SIZE],
        b: [2; dummy_mod::SIZE],
    };

    let mut mem = vec![0; 4096];
    let version_map = VersionMap::new();

    test_struct
        .serialize(&mut mem.as_mut_slice(), &version_map, 1)
        .unwrap();
    let restored_test_struct =
        TestStruct::deserialize(&mut mem.as_slice(), &version_map, 1).unwrap();

    assert_eq!(restored_test_struct, test_struct);
}

#[test]
fn test_versionize_union_with_array() {
    #[derive(Versionize)]
    union TestUnion {
        a: [u32; SIZE],
        b: [u8; dummy_mod::SIZE],
    }

    impl Default for TestUnion {
        fn default() -> Self {
            TestUnion { a: [3; SIZE] }
        }
    }

    impl Debug for TestUnion {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            unsafe { write!(f, "{{ a: {:?}, b: {:?} }}", self.a, self.b) }
        }
    }

    let test_union = TestUnion { a: [1; SIZE] };

    let mut mem = vec![0; 4096];
    let version_map = VersionMap::new();

    test_union
        .serialize(&mut mem.as_mut_slice(), &version_map, 1)
        .unwrap();
    let restored_test_union = TestUnion::deserialize(&mut mem.as_slice(), &version_map, 1).unwrap();

    unsafe {
        assert_eq!(restored_test_union.a, test_union.a);
        assert_eq!(restored_test_union.b, test_union.b);
    }
}

#[derive(Clone, Debug, PartialEq, Versionize)]
pub enum DeviceStatus {
    Inactive,
    Active,
    #[version(start = 2, default_fn = "default_is_activating")]
    IsActivating(u32),
}

impl Default for DeviceStatus {
    fn default() -> Self {
        Self::Inactive
    }
}

#[derive(Clone, Debug, PartialEq, Versionize)]
pub enum OperationSupported {
    Add,
    Remove,
    RemoveAndAdd(bool),
    #[version(start = 2, default_fn = "default_update")]
    Update(String),
}

impl Default for OperationSupported {
    fn default() -> Self {
        Self::Add
    }
}

impl DeviceStatus {
    fn default_is_activating(&self, target_version: u16) -> VersionizeResult<DeviceStatus> {
        match target_version {
            1 => Ok(DeviceStatus::Inactive),
            i => Err(VersionizeError::Serialize(format!(
                "Unknown target version: {}",
                i
            ))),
        }
    }
}

impl OperationSupported {
    fn default_update(&self, target_version: u16) -> VersionizeResult<OperationSupported> {
        match target_version {
            1 => Ok(OperationSupported::RemoveAndAdd(true)),
            i => Err(VersionizeError::Serialize(format!(
                "Unknown target version: {}",
                i
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Versionize)]
pub struct Device {
    name: String,
    id: Wrapping<u32>,
    #[version(start = 2, ser_fn = "ser_is_activated")]
    is_activated: bool,
    some_params: Vec<String>,
    #[version(
        start = 2,
        default_fn = "default_ops",
        ser_fn = "ser_ops",
        de_fn = "de_ops"
    )]
    operations: Vec<OperationSupported>,
    status: DeviceStatus,
    #[version(
        start = 2,
        default_fn = "default_queues_limit",
        ser_fn = "ser_queues_limit"
    )]
    no_queues_limit: usize,
    queues: Vec<u8>,
    features: u32,
    #[version(start = 3, ser_fn = "ser_extra", de_fn = "de_extra")]
    extra_features: u64,
}

impl Device {
    fn default_ops(_target_version: u16) -> Vec<OperationSupported> {
        vec![OperationSupported::Add, OperationSupported::Remove]
    }

    fn default_queues_limit(_target_version: u16) -> usize {
        2
    }

    fn ser_ops(&mut self, target_version: u16) -> VersionizeResult<()> {
        // Fail if semantic serialization is called for a version >= 2.
        assert!(target_version < 2);
        self.features |= 1;
        Ok(())
    }

    fn de_ops(&mut self, target_version: u16) -> VersionizeResult<()> {
        // Fail if semantic deserialization is called for a version >= 2.
        assert!(target_version < 2);
        if self.some_params.contains(&"active".to_owned()) {
            self.status = DeviceStatus::Active;
        }
        Ok(())
    }

    fn ser_queues_limit(&mut self, target_version: u16) -> VersionizeResult<()> {
        // Fail if semantic serialization is called for a version >= 2.
        assert!(target_version < 2);
        if self.queues.len() > 2 {
            return Err(VersionizeError::Semantic("Too many queues.".to_owned()));
        }
        Ok(())
    }

    fn ser_is_activated(&mut self, target_version: u16) -> VersionizeResult<()> {
        // Fail if semantic serialization is called for a version >= 2.
        assert!(target_version < 2);
        self.some_params.push("active".to_owned());
        self.some_params
            .retain(|x| x.clone() != "inactive".to_owned());
        Ok(())
    }

    fn ser_extra(&mut self, target_version: u16) -> VersionizeResult<()> {
        // Fail if semantic serialization is called for the latest version.
        assert!(target_version < 3);
        self.some_params.push("extra_features".to_owned());
        Ok(())
    }

    fn de_extra(&mut self, target_version: u16) -> VersionizeResult<()> {
        // Fail if semantic deserialization is called for the latest version.
        assert!(target_version < 3);
        if self.queues.len() > self.no_queues_limit {
            return Err(VersionizeError::Semantic("Too many queues.".to_owned()));
        }
        self.features |= 1u32 << 31;
        Ok(())
    }
}

#[test]
fn test_versionize_struct_with_enums() {
    let mut vm = VersionMap::new();
    vm.new_version()
        .set_type_version(Device::type_id(), 2)
        .set_type_version(DeviceStatus::type_id(), 2)
        .new_version()
        .set_type_version(Device::type_id(), 3)
        .set_type_version(OperationSupported::type_id(), 2);

    let mut state = Device {
        name: "block".to_owned(),
        id: Wrapping(1u32),
        is_activated: true,
        some_params: vec!["inactive".to_owned()],
        operations: vec![
            OperationSupported::Add,
            OperationSupported::Update("random".to_owned()),
        ],
        status: DeviceStatus::Inactive,
        no_queues_limit: 3,
        queues: vec![1u8, 2u8],
        features: 6u32,
        extra_features: 0u64,
    };

    let mut snapshot_mem = vec![0u8; 1024];

    // Serialize as v1.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
        .unwrap();
    let mut restored_state =
        <Device as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();

    // At v1, all of the semantic functions should be called.
    // `operations` and `no_queues_limit` will take the default values (set by `default_fn`s),
    // `features` will be modified by `ser_ops` and `de_extra`, `status` will be changed to
    // `Active` by `de_ops`, `is_activated` will take the default bool value, `some_params`
    // will be also modified and the other fields will take the original values.
    let mut expected_state = Device {
        name: "block".to_owned(),
        id: Wrapping(1u32),
        is_activated: false,
        some_params: vec!["active".to_owned(), "extra_features".to_owned()],
        operations: vec![OperationSupported::Add, OperationSupported::Remove],
        status: DeviceStatus::Active,
        no_queues_limit: 2,
        queues: vec![1u8, 2u8],
        features: 0x8000_0007u32,
        extra_features: 0u64,
    };
    assert_eq!(expected_state, restored_state);

    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 2)
        .unwrap();
    restored_state =
        <Device as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 2).unwrap();

    // At v2, we expect that only the semantic functions from `extra_features` to be called,
    // this means that `features` and `some_params` will take different values than the ones
    // at v1. `status` won't be modified anymore, `is_activated` and `no_queues_limit` will
    // take this time the original values. `operations` field will contain only the first
    // original element, the second one will be modified by `default_update` because at v2,
    // `Update` is not available.
    expected_state = Device {
        name: "block".to_owned(),
        id: Wrapping(1u32),
        is_activated: true,
        some_params: vec!["inactive".to_owned(), "extra_features".to_owned()],
        operations: vec![
            OperationSupported::Add,
            OperationSupported::RemoveAndAdd(true),
        ],
        status: DeviceStatus::Inactive,
        no_queues_limit: 3,
        queues: vec![1u8, 2u8],
        features: 0x8000_0006u32,
        extra_features: 0u64,
    };
    assert_eq!(expected_state, restored_state);

    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 3)
        .unwrap();
    restored_state =
        <Device as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 3).unwrap();

    // At v3, `Update` variant is available, so it will be deserialized to its original value.
    // We expect no semantic function to be called, so `features` and `some_params` will also
    // take the original values.
    expected_state = Device {
        name: "block".to_owned(),
        id: Wrapping(1u32),
        is_activated: true,
        some_params: vec!["inactive".to_owned()],
        operations: vec![
            OperationSupported::Add,
            OperationSupported::Update("random".to_owned()),
        ],
        status: DeviceStatus::Inactive,
        no_queues_limit: 3,
        queues: vec![1u8, 2u8],
        features: 6u32,
        extra_features: 0u64,
    };
    assert_eq!(expected_state, restored_state);

    // Test semantic errors.
    state.queues = vec![1u8, 2u8, 3u8, 4u8];
    assert_eq!(
        state
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap_err(),
        VersionizeError::Semantic("Too many queues.".to_owned())
    );

    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 2)
        .unwrap();
    assert_eq!(
        <Device as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 2).unwrap_err(),
        VersionizeError::Semantic("Too many queues.".to_owned())
    );
}

#[test]
fn test_versionize_union() {
    let mut vm = VersionMap::new();
    vm.new_version()
        .set_type_version(TestUnion::type_id(), 2)
        .new_version()
        .set_type_version(TestUnion::type_id(), 3);

    let state = TestUnion {
        c: [
            0x0403_0201u32,
            0x0807_0605u32,
            0x0000_0000u32,
            0x2222_1111u32,
        ],
    };

    let mut snapshot_mem = vec![0u8; 1024];

    // Serialize as v1.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
        .unwrap();
    let mut restored_state =
        <TestUnion as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();

    // At v1, `c` field is unavailable, so when we serialize the union, the memory occupied
    // by it will be = the max size of the fields that exist at v1 (`b` -> 4 bytes). So, when
    // we deserialize this union, `c` field will no longer be equal with its original value
    // (only the least significant 4 bytes will be preserved).
    unsafe {
        assert_eq!(restored_state.a, 0x0201i16);
        assert_eq!(restored_state.b, 0x0403_0201i32);
        assert_eq!(restored_state.c[0], 0x0403_0201u32);
        assert_ne!(
            restored_state.c,
            [
                0x0403_0201u32,
                0x0807_0605u32,
                0x0000_0000u32,
                0x2222_1111u32
            ]
        );
        assert_eq!(restored_state.d as u32, 0x0403_0201u32);
    }

    // Serialize as v2.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 2)
        .unwrap();
    restored_state =
        <TestUnion as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 2).unwrap();

    // At v2, `c` field is available. So, when we deserialize the union, we expect that `c` field
    // will be equal with its original value.
    unsafe {
        assert_eq!(restored_state.a, 0x0201i16);
        assert_eq!(restored_state.b, 0x0403_0201i32);
        assert_eq!(
            restored_state.c,
            [
                0x0403_0201u32,
                0x0807_0605u32,
                0x0000_0000u32,
                0x2222_1111u32
            ]
        );
        assert_eq!(restored_state.d, 0x0807_0605_0403_0201u64);
    }

    // Serialize as v3.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 3)
        .unwrap();
    restored_state =
        <TestUnion as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 3).unwrap();

    // At v3, `d` field is available and `c` field not, so the memory occupied by the union, when
    // serializing it, will be = `d` field size (8 bytes).
    unsafe {
        assert_eq!(restored_state.a, 0x0201i16);
        assert_eq!(restored_state.b, 0x0403_0201i32);
        assert_eq!(restored_state.c[0], 0x0403_0201u32);
        assert_eq!(restored_state.c[1], 0x0807_0605u32);
        assert_eq!(restored_state.d, 0x0807_0605_0403_0201u64);
    }
}

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[test]
fn test_versionize_union_with_struct() {
    #[derive(Clone, Copy, Versionize)]
    struct kvm_run__bindgen_ty_1 {
        pub code_1: u64,
        pub code_2: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Versionize)]
    union kvm_irq_level__bindgen_ty_1 {
        irq: ::std::os::raw::c_uint,
        status: ::std::os::raw::c_int,
        other_status: ::std::os::raw::c_longlong,

        #[version(start = 1, end = 1)]
        bindgen_union_align: [u64; 2usize],

        #[version(start = 2)]
        extended_status: ::std::os::raw::c_longlong,

        #[version(start = 2)]
        kvm_run_field: kvm_run__bindgen_ty_1,

        #[version(start = 3)]
        bindgen_union_align_2: [u64; 2usize],
    }

    impl Default for kvm_irq_level__bindgen_ty_1 {
        fn default() -> Self {
            unsafe { ::std::mem::zeroed() }
        }
    }

    let mut vm = VersionMap::new();
    vm.new_version()
        .set_type_version(kvm_irq_level__bindgen_ty_1::type_id(), 2)
        .new_version()
        .set_type_version(kvm_irq_level__bindgen_ty_1::type_id(), 3);

    let state = kvm_irq_level__bindgen_ty_1 {
        bindgen_union_align_2: [0x1234_5678_8765_4321u64, 0x1122_3344_5555_6666u64],
    };

    let mut snapshot_mem = vec![0u8; 256];

    // Serialize as v1.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
        .unwrap();
    let mut restored_state = <kvm_irq_level__bindgen_ty_1 as Versionize>::deserialize(
        &mut snapshot_mem.as_slice(),
        &vm,
        1,
    )
    .unwrap();
    unsafe {
        assert_eq!(restored_state.irq, 0x8765_4321);
        assert_eq!(restored_state.other_status, 0x1234_5678_8765_4321);
        assert_eq!(restored_state.kvm_run_field.code_1, 0x1234_5678_8765_4321);
        assert_ne!(restored_state.kvm_run_field.code_2, 0x5555_6666u32);
    }

    // Serialize as v2.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 2)
        .unwrap();
    restored_state = <kvm_irq_level__bindgen_ty_1 as Versionize>::deserialize(
        &mut snapshot_mem.as_slice(),
        &vm,
        2,
    )
    .unwrap();
    unsafe {
        assert_eq!(restored_state.irq, 0x8765_4321);
        assert_eq!(restored_state.other_status, 0x1234_5678_8765_4321);
        assert_eq!(restored_state.kvm_run_field.code_1, 0x1234_5678_8765_4321);
        assert_eq!(restored_state.kvm_run_field.code_2, 0x5555_6666u32);
        assert_ne!(
            restored_state.bindgen_union_align_2,
            [0x1234_5678_8765_4321u64, 0x1122_3344_5555_6666u64]
        );
    }

    // Serialize as v3.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 3)
        .unwrap();
    restored_state = <kvm_irq_level__bindgen_ty_1 as Versionize>::deserialize(
        &mut snapshot_mem.as_slice(),
        &vm,
        3,
    )
    .unwrap();
    unsafe {
        assert_eq!(restored_state.irq, 0x8765_4321);
        assert_eq!(restored_state.other_status, 0x1234_5678_8765_4321);
        assert_eq!(restored_state.kvm_run_field.code_1, 0x1234_5678_8765_4321);
        assert_eq!(restored_state.kvm_run_field.code_2, 0x5555_6666u32);
        assert_eq!(
            restored_state.bindgen_union_align_2,
            [0x1234_5678_8765_4321u64, 0x1122_3344_5555_6666u64]
        );
    }
}

#[derive(Clone, Debug, PartialEq, Versionize)]
pub enum State {
    Zero,
    One(bool),
    #[version(start = 2, default_fn = "default_state_two")]
    Two(Vec<u8>),
    #[version(start = 2, default_fn = "default_state_three")]
    Three(String),
    #[version(start = 3, default_fn = "default_state_four")]
    Four(Option<u64>),
}

impl Default for State {
    fn default() -> Self {
        Self::One(false)
    }
}

impl State {
    fn default_state_two(&self, target_version: u16) -> VersionizeResult<State> {
        match target_version {
            1 => Ok(State::One(true)),
            i => Err(VersionizeError::Serialize(format!(
                "Unknown target version: {}",
                i
            ))),
        }
    }

    fn default_state_three(&self, target_version: u16) -> VersionizeResult<State> {
        match target_version {
            1 => Ok(State::One(false)),
            i => Err(VersionizeError::Serialize(format!(
                "Unknown target version: {}",
                i
            ))),
        }
    }

    fn default_state_four(&self, target_version: u16) -> VersionizeResult<State> {
        match target_version {
            2 => Ok(State::Three("abc".to_owned())),
            1 => Ok(State::Zero),
            i => Err(VersionizeError::Serialize(format!(
                "Unknown target version: {}",
                i
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Versionize)]
pub struct S {
    a: f64,
    b: i64,
}

#[derive(Clone, Debug, PartialEq, Versionize)]
pub struct Test {
    usize_1: usize,
    #[version(start = 2, end = 3, ser_fn = "ser_isize", de_fn = "de_isize")]
    isize_1: isize,
    #[version(start = 2)]
    u8_1: u8,
    #[version(end = 4, default_fn = "default_vec")]
    vec_1: Vec<u16>,
    #[version(start = 3)]
    wrapping_1: Wrapping<u32>,
    #[version(
        end = 3,
        default_fn = "default_u64",
        ser_fn = "ser_u64",
        de_fn = "de_u64"
    )]
    u64_1: u64,
    #[version(start = 2, ser_fn = "ser_bool")]
    bool_1: bool,
    enum_1: State,
    i8_1: i8,
    i16_1: i16,
    #[version(start = 3, end = 4)]
    i32_1: i32,
    #[version(start = 2, default_fn = "default_box", de_fn = "de_box")]
    box_1: Box<S>,
    #[version(start = 2, end = 3, default_fn = "default_f32")]
    f32_1: f32,
    char_1: char,
    #[version(
        end = 3,
        default_fn = "default_option",
        ser_fn = "ser_option",
        de_fn = "de_option"
    )]
    option_1: Option<String>,
}

impl Test {
    fn default_vec(_target_version: u16) -> Vec<u16> {
        vec![0x0102u16; 4]
    }

    fn default_u64(_target_version: u16) -> u64 {
        0x0102_0102_0102_0102u64
    }

    fn default_f32(_target_version: u16) -> f32 {
        0.5
    }

    fn default_box(_target_version: u16) -> Box<S> {
        Box::new(S { a: 1.5, b: 2 })
    }

    fn default_option(_target_version: u16) -> Option<String> {
        Some("something".to_owned())
    }

    fn ser_isize(&mut self, target_version: u16) -> VersionizeResult<()> {
        assert_ne!(target_version, 2);
        self.vec_1.push(0x0304u16);
        if self.i8_1 == -1 {
            return Err(VersionizeError::Semantic(
                "Unexpected value for `i8` field.".to_owned(),
            ));
        }
        Ok(())
    }
    fn ser_u64(&mut self, target_version: u16) -> VersionizeResult<()> {
        assert!(target_version >= 3);
        self.vec_1.pop();
        if self.u8_1 == 4 {
            self.bool_1 = false;
        }
        Ok(())
    }

    fn ser_bool(&mut self, target_version: u16) -> VersionizeResult<()> {
        assert!(target_version < 2);
        self.vec_1.push(0x0506u16);
        self.vec_1.push(0x0708u16);
        Ok(())
    }

    fn ser_option(&mut self, target_version: u16) -> VersionizeResult<()> {
        assert!(target_version >= 3);
        self.u8_1 += 2;
        if self.vec_1.len() == 10 {
            return Err(VersionizeError::Semantic("Vec is full.".to_owned()));
        }
        Ok(())
    }

    fn de_isize(&mut self, target_version: u16) -> VersionizeResult<()> {
        assert_ne!(target_version, 2);
        self.u8_1 += 3;
        Ok(())
    }

    fn de_u64(&mut self, target_version: u16) -> VersionizeResult<()> {
        assert!(target_version >= 3);
        self.vec_1.push(0x0101u16);
        Ok(())
    }

    fn de_box(&mut self, target_version: u16) -> VersionizeResult<()> {
        assert!(target_version < 2);
        self.option_1 = Some("box_change".to_owned());
        if self.vec_1.len() == 3 {
            return Err(VersionizeError::Semantic(
                "Vec len is too small.".to_owned(),
            ));
        }
        Ok(())
    }

    fn de_option(&mut self, target_version: u16) -> VersionizeResult<()> {
        assert!(target_version >= 3);
        self.enum_1 = State::Two(vec![1; 4]);
        Ok(())
    }
}

#[test]
fn test_versionize_struct() {
    let mut vm = VersionMap::new();
    vm.new_version()
        .set_type_version(Test::type_id(), 2)
        .set_type_version(State::type_id(), 2)
        .new_version()
        .set_type_version(Test::type_id(), 3)
        .set_type_version(State::type_id(), 3);

    let mut state = Test {
        usize_1: 0x0102_0304_0506_0708usize,
        isize_1: -0x1122_3344_5566_7788isize,
        u8_1: 4,
        vec_1: vec![0x1122u16; 5],
        wrapping_1: Wrapping(4u32),
        u64_1: 0x0102_0304_0506_0708u64,
        bool_1: false,
        enum_1: State::Four(Some(0x0102_0304_0506_0708u64)),
        i8_1: 8,
        i16_1: -12,
        i32_1: -0x1234_5678,
        box_1: Box::new(S { a: 4.5, b: 4 }),
        f32_1: 1.25,
        char_1: 'c',
        option_1: None,
    };

    let mut snapshot_mem = vec![0u8; 1024];

    // Serialize as v1.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
        .unwrap();
    let mut restored_state =
        <Test as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();

    let mut expected_state = Test {
        // usize field exists at all versions, will take the original value.
        usize_1: 0x0102_0304_0506_0708usize,
        // isize field will take the default value as it is not available at v1.
        isize_1: 0isize,
        // u8 field doesn't exist at v1, it wll take the default value and then it will be
        // modified by `de_isize`: 0 + 3 = 3.
        u8_1: 3,
        // Vec field will be modified by the semantic fns of the fields that don't exist
        // at v1: `isize_1`, `bool_1`; there will be 3 new elements added in it.
        vec_1: vec![
            0x1122u16, 0x1122u16, 0x1122u16, 0x1122u16, 0x1122u16, 0x0304u16, 0x0506u16, 0x0708u16,
        ],
        // We expect here to have the default value.
        wrapping_1: Wrapping(0u32),
        // We expect here to have the original value.
        u64_1: 0x0102_0304_0506_0708u64,
        // We expect here to have the default value.
        bool_1: false,
        // This will take the default value for state `Four` and v1.
        enum_1: State::Zero,
        // i8, i16 fields take the original values.
        i8_1: 8,
        i16_1: -12,
        // i32 field takes the default value.
        i32_1: 0,
        // Box and f32 fields will take the default values set by `default_fn`s.
        box_1: Box::new(S { a: 1.5, b: 2 }),
        f32_1: 0.5,
        // We expect this field to take the original value.
        char_1: 'c',
        // This field will be modified by `de_box`.
        option_1: Some("box_change".to_owned()),
    };
    assert_eq!(expected_state, restored_state);

    // Serialize as v2.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 2)
        .unwrap();
    restored_state =
        <Test as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 2).unwrap();

    // At v2 isize, u8, bool, box and f32 fields will be available, their semantic fns won't
    // be called.
    expected_state = Test {
        usize_1: 0x0102_0304_0506_0708usize,
        isize_1: -0x1122_3344_5566_7788isize,
        u8_1: 4,
        // This should take the original value this time.
        vec_1: vec![0x1122u16, 0x1122u16, 0x1122u16, 0x1122u16, 0x1122u16],
        wrapping_1: Wrapping(0u32),
        u64_1: 0x0102_0304_0506_0708u64,
        bool_1: false,
        // This will take the default value for state `Four` and v2.
        enum_1: State::Three("abc".to_owned()),
        i8_1: 8,
        i16_1: -12,
        i32_1: 0,
        box_1: Box::new(S { a: 4.5, b: 4 }),
        f32_1: 1.25,
        char_1: 'c',
        option_1: None,
    };
    assert_eq!(expected_state, restored_state);

    // Serialize as v3.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 3)
        .unwrap();
    restored_state =
        <Test as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 3).unwrap();

    expected_state = Test {
        usize_1: 0x0102_0304_0506_0708usize,
        isize_1: 0isize,
        // This field will be modified by `de_isize` and `ser_option`: 4 + 2 + 3 = 9.
        u8_1: 9,
        // Vec field will be modified by `ser_isize` (add one elem), `ser_u64` (remove one elem)
        // and `de_64` (add one elem).
        vec_1: vec![
            0x1122u16, 0x1122u16, 0x1122u16, 0x1122u16, 0x1122u16, 0x0101u16,
        ],
        wrapping_1: Wrapping(4u32),
        u64_1: 0x0102_0102_0102_0102u64,
        bool_1: false,
        enum_1: State::Two(vec![1; 4]),
        i8_1: 8,
        i16_1: -12,
        i32_1: -0x1234_5678,
        box_1: Box::new(S { a: 4.5, b: 4 }),
        f32_1: 0.5,
        char_1: 'c',
        // We expect this field to take the default value set by its `default_fn`.
        option_1: Some("something".to_owned()),
    };
    assert_eq!(expected_state, restored_state);

    // Test semantic errors.
    state.vec_1 = Vec::new();
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
        .unwrap();
    assert_eq!(
        <Test as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap_err(),
        VersionizeError::Semantic("Vec len is too small.".to_owned())
    );

    state.vec_1 = vec![0x1122u16; 10];
    assert_eq!(
        state
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 3)
            .unwrap_err(),
        VersionizeError::Semantic("Vec is full.".to_owned())
    );

    state.i8_1 = -1;
    assert_eq!(
        state
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap_err(),
        VersionizeError::Semantic("Unexpected value for `i8` field.".to_owned())
    );
    state.i8_1 = 0;

    // Test serialize and deserialize errors.
    snapshot_mem = vec![0u8; 8];
    // Serializing `state` will fail due to the small size of `snapshot_mem`.
    assert_eq!(
        state
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap_err(),
        VersionizeError::Serialize(
            "Io(Custom { kind: WriteZero, error: \"failed to write whole buffer\" })".to_owned()
        )
    );
    snapshot_mem = vec![0u8; 256];

    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
        .unwrap();
    snapshot_mem.truncate(10);
    // Deserialization will fail if we don't use the whole `snapshot_mem` resulted from
    // serialization.
    assert_eq!(
        <Test as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap_err(),
        VersionizeError::Deserialize(
            "Io(Custom { kind: UnexpectedEof, error: \"failed to fill whole buffer\" })".to_owned()
        )
    );
}

#[repr(C)]
#[derive(Debug, Default, Versionize)]
struct Message {
    pub len: u32,
    #[version(end = 4)]
    pub padding: u32,
    pub value: u32,
    #[version(start = 2, default_fn = "default_extra_value")]
    pub extra_value: u16,
    #[version(start = 3, end = 4, default_fn = "default_status")]
    pub status: Wrapping<bool>,
    pub entries: __IncompleteArrayField<u32>,
}

impl Message {
    fn default_extra_value(_source_version: u16) -> u16 {
        4
    }

    fn default_status(_source_version: u16) -> Wrapping<bool> {
        Wrapping(false)
    }
}

generate_fam_struct_impl!(Message, u32, entries, u32, len, 100);

#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(::std::marker::PhantomData<T>, [T; 0]);

impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub fn new() -> Self {
        __IncompleteArrayField(::std::marker::PhantomData, [])
    }
    #[inline]
    pub unsafe fn as_ptr(&self) -> *const T {
        self as *const __IncompleteArrayField<T> as *const T
    }
    #[inline]
    pub unsafe fn as_mut_ptr(&mut self) -> *mut T {
        self as *mut __IncompleteArrayField<T> as *mut T
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::std::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}

impl<T> Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result {
        fmt.write_str("__IncompleteArrayField")
    }
}

impl<T> ::std::clone::Clone for __IncompleteArrayField<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<T> Versionize for __IncompleteArrayField<T> {
    #[inline]
    fn serialize<W: std::io::Write>(
        &self,
        _writer: &mut W,
        _version_map: &VersionMap,
        _app_version: u16,
    ) -> VersionizeResult<()> {
        Ok(())
    }

    #[inline]
    fn deserialize<R: std::io::Read>(
        _reader: &mut R,
        _version_map: &VersionMap,
        _app_version: u16,
    ) -> VersionizeResult<Self> {
        Ok(Self::new())
    }

    // Not used.
    fn version() -> u16 {
        1
    }
}

type MessageFamStructWrapper = FamStructWrapper<Message>;

#[test]
fn test_versionize_famstructwrapper() {
    let mut vm = VersionMap::new();
    vm.new_version()
        .set_type_version(Message::type_id(), 2)
        .new_version()
        .set_type_version(Message::type_id(), 3)
        .new_version()
        .set_type_version(Message::type_id(), 4);

    let mut state = MessageFamStructWrapper::new(0);
    state.as_mut_fam_struct().padding = 8;
    state.as_mut_fam_struct().extra_value = 16;
    state.as_mut_fam_struct().status = Wrapping(true);

    state.push(1).unwrap();
    state.push(2).unwrap();

    let mut snapshot_mem = vec![0u8; 256];

    // Serialize as v1.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
        .unwrap();
    let mut restored_state =
        <MessageFamStructWrapper as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1)
            .unwrap();

    let mut original_values = state.as_slice();
    let mut restored_values = restored_state.as_slice();
    assert_eq!(original_values, restored_values);
    assert_eq!(
        restored_values.len(),
        state.as_fam_struct_ref().len as usize
    );

    assert_eq!(
        state.as_fam_struct_ref().padding,
        restored_state.as_fam_struct_ref().padding
    );
    // `extra_value` and `status` should take the default values set by their corresponding `default_fn`s.
    assert_eq!(4, restored_state.as_fam_struct_ref().extra_value);
    assert_eq!(Wrapping(false), restored_state.as_fam_struct_ref().status);

    // Serialize as v2.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 2)
        .unwrap();
    restored_state =
        <MessageFamStructWrapper as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 2)
            .unwrap();

    original_values = state.as_slice();
    restored_values = restored_state.as_slice();
    assert_eq!(original_values, restored_values);

    assert_eq!(
        state.as_fam_struct_ref().padding,
        restored_state.as_fam_struct_ref().padding
    );
    // `extra_value` is available at v2, so it will take its original value.
    assert_eq!(
        state.as_fam_struct_ref().extra_value,
        restored_state.as_fam_struct_ref().extra_value
    );
    assert_eq!(Wrapping(false), restored_state.as_fam_struct_ref().status);

    // Serialize as v3.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 3)
        .unwrap();
    restored_state =
        <MessageFamStructWrapper as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 3)
            .unwrap();

    assert_eq!(
        state.as_fam_struct_ref().padding,
        restored_state.as_fam_struct_ref().padding
    );
    assert_eq!(
        state.as_fam_struct_ref().extra_value,
        restored_state.as_fam_struct_ref().extra_value
    );
    // At v3, `status` field exists, so it will take its original value.
    assert_eq!(Wrapping(true), restored_state.as_fam_struct_ref().status);

    // Serialize as v4.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 4)
        .unwrap();
    restored_state =
        <MessageFamStructWrapper as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 4)
            .unwrap();

    // At v4, `padding` field will take the default u32 value.
    assert_eq!(0, restored_state.as_fam_struct_ref().padding);
    assert_eq!(
        state.as_fam_struct_ref().extra_value,
        restored_state.as_fam_struct_ref().extra_value
    );
    // `status` is not available anymore, so it will take the default value.
    assert_eq!(Wrapping(false), restored_state.as_fam_struct_ref().status);

    snapshot_mem = vec![0u8; 16];

    assert_eq!(
        state
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap_err(),
        VersionizeError::Serialize(
            "Io(Custom { kind: WriteZero, error: \"failed to write whole buffer\" })".to_owned()
        )
    );
}

#[derive(Versionize)]
pub struct FamStructTest {
    some_u8: u8,
    message_box: Box<MessageFamStructWrapper>,
    #[version(start = 2, default_fn = "default_option", de_fn = "de_option")]
    some_option: Option<S>,
    #[version(start = 3)]
    some_string: String,
    #[version(end = 3, default_fn = "default_message", de_fn = "de_message")]
    messages: Vec<MessageFamStructWrapper>,
}

impl FamStructTest {
    fn default_message(_target_version: u16) -> Vec<MessageFamStructWrapper> {
        let mut f = MessageFamStructWrapper::new(0);
        f.as_mut_fam_struct().padding = 1;
        f.as_mut_fam_struct().extra_value = 2;

        f.push(10).unwrap();
        f.push(20).unwrap();

        vec![f]
    }

    fn default_option(_target_version: u16) -> Option<S> {
        Some(S { a: 0.5, b: 0 })
    }

    fn de_message(&mut self, target_version: u16) -> VersionizeResult<()> {
        // Fail if semantic deserialization is called for v2.
        assert_ne!(target_version, 2);
        self.some_option = None;
        self.some_string = "some_new_string".to_owned();
        Ok(())
    }

    fn de_option(&mut self, target_version: u16) -> VersionizeResult<()> {
        // Fail if semantic deserialization is called for a version >= 2.
        assert!(target_version < 2);

        let mut f = MessageFamStructWrapper::new(0);
        f.as_mut_fam_struct().padding = 3;
        f.as_mut_fam_struct().extra_value = 4;

        f.push(10).unwrap();
        f.push(20).unwrap();

        self.messages.push(f);
        Ok(())
    }
}

#[test]
fn test_versionize_struct_with_famstructs() {
    let mut vm = VersionMap::new();
    vm.new_version()
        .set_type_version(FamStructTest::type_id(), 2)
        .set_type_version(Message::type_id(), 2)
        .new_version()
        .set_type_version(FamStructTest::type_id(), 3)
        .set_type_version(Message::type_id(), 3);

    let mut snapshot_mem = vec![0u8; 1024];

    let mut f = MessageFamStructWrapper::new(0);
    f.as_mut_fam_struct().padding = 5;
    f.as_mut_fam_struct().extra_value = 6;
    f.push(10).unwrap();

    let mut f2 = MessageFamStructWrapper::new(0);
    f2.as_mut_fam_struct().padding = 7;
    f2.as_mut_fam_struct().extra_value = 8;
    f2.push(20).unwrap();

    let state = FamStructTest {
        some_u8: 1,
        messages: vec![f],
        some_string: "some_string".to_owned(),
        message_box: Box::new(f2),
        some_option: None,
    };

    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
        .unwrap();
    let mut restored_state =
        <FamStructTest as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();

    // At version 1, we expect `de_option` and `de_message` to be called.
    // `some_string` and `some_option` will take the default values.
    assert_eq!(restored_state.some_string, String::default());
    assert_eq!(restored_state.some_option, Some(S { a: 0.5, b: 0 }));
    let messages = restored_state.messages;

    // We expect to have 2 elements in the messages Vec (the one with which it was initialized and
    // the one inserted by `de_option`).
    assert_eq!(messages.len(), 2);
    for message in messages.iter() {
        assert_eq!(message.as_fam_struct_ref().extra_value, 4);
        assert_eq!(message.as_fam_struct_ref().status, Wrapping(false));
    }
    assert_eq!(messages[0].as_fam_struct_ref().padding, 5);
    assert_eq!(messages[1].as_fam_struct_ref().padding, 3);

    // Serialize as v2.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 2)
        .unwrap();
    restored_state =
        <FamStructTest as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 2).unwrap();

    assert_eq!(restored_state.some_string, String::default());
    // `some_option` is available at v2, so it will take the original value.
    assert_eq!(restored_state.some_option, None);
    let messages = restored_state.messages;
    // We expect to have only one element in `messages` as `de_option` shouldn't be called
    // this time.
    assert_eq!(messages.len(), 1);

    // Serialize as v3.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 3)
        .unwrap();
    restored_state =
        <FamStructTest as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 3).unwrap();

    // `some_string` is also available at v3.
    assert_eq!(restored_state.some_string, "some_new_string".to_owned());
    assert_eq!(restored_state.some_option, None);
    let messages = restored_state.messages;
    // `messages` field is not available anymore at v3, it will take the default value,
    // set by the corresponding `default_fn`.
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].as_fam_struct_ref().padding, 1);
}

#[derive(Clone, Versionize)]
pub struct SomeStruct {
    message: MessageFamStructWrapper,
    #[version(start = 2, ser_fn = "ser_u16")]
    some_u16: u16,
}

impl SomeStruct {
    fn ser_u16(&mut self, target_version: u16) -> VersionizeResult<()> {
        // Fail if semantic serialization is called for the latest version.
        assert!(target_version < 2);
        self.message.as_mut_fam_struct().padding += 2;
        Ok(())
    }
}

// TODO: remove this test once FamStructWrapper `Clone` implementation gets fixed.
#[test]
fn test_famstructwrapper_clone() {
    // Test that having a `FamStructWrapper<T>` in a structure that implements
    // Clone will result in keeping with their original values, only the number
    // of entries and the entries array when serializing.
    let mut vm = VersionMap::new();
    vm.new_version().set_type_version(SomeStruct::type_id(), 2);

    let mut f = MessageFamStructWrapper::new(0);
    f.as_mut_fam_struct().padding = 8;

    f.push(1).unwrap();
    f.push(2).unwrap();

    let state = SomeStruct {
        message: f,
        some_u16: 2,
    };

    let mut snapshot_mem = vec![0u8; 128];

    // Serialize as v1.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
        .unwrap();
    let mut restored_state =
        <SomeStruct as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();
    let original_values = state.message.as_slice();
    let restored_values = restored_state.message.as_slice();

    assert_ne!(
        state.message.as_fam_struct_ref().padding,
        restored_state.message.as_fam_struct_ref().padding
    );
    assert_eq!(original_values, restored_values);
    // `padding` field will take the default value (0), and then it will be incremented with 2
    // by `ser_u16`.
    assert_eq!(2, restored_state.message.as_fam_struct_ref().padding);

    // Serialize as v2.
    state
        .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 2)
        .unwrap();
    restored_state =
        <SomeStruct as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 2).unwrap();
    assert_ne!(
        state.message.as_fam_struct_ref().padding,
        restored_state.message.as_fam_struct_ref().padding
    );
    // `padding` field will take the default value (0). `ser_u16` won't be called at v2.
    assert_eq!(0, restored_state.message.as_fam_struct_ref().padding);
}
