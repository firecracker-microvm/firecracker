// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

extern crate versionize;
extern crate versionize_derive;

use std::fmt::{Debug, Formatter, Result};
use std::num::Wrapping;

use versionize::{Error, VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

#[repr(u32)]
#[derive(Versionize, PartialEq, Clone, Debug)]
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
            i => Err(Error::Serialize(format!("Unknown target version: {}", i))),
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

    #[derive(Versionize, PartialEq, Clone, Debug)]
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
        0x09, 0x0A, 0x0B, 0x0C,  0x0D, 0x0E, 0x0F, 0x00,
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
        0x09, 0x0A, 0x0B, 0x0C,  0x0D, 0x0E, 0x0F, 0x00,
    ];

    #[derive(Versionize, Copy, Clone)]
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
        versionize::Error::Deserialize(
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
        versionize::Error::Deserialize("Unknown variant_index 3".to_owned())
    );
}

#[derive(Versionize, Default, Debug, PartialEq, Clone)]
pub struct A {
    a: u32,
    #[version(start = 1, end = 2)]
    b: Option<TestState>,
    #[version(start = 2, default_fn = "default_c")]
    c: String,
}

#[derive(Versionize, Debug, PartialEq, Clone)]
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
