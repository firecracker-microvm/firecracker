// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::float_cmp)]

use self::super::{Error, Result, VersionMap, Versionize};
use vmm_sys_util::fam::{FamStruct, FamStructWrapper};

/// Implements the Versionize trait for primitive types that also implement
/// serde's Serialize/Deserialize: use serde_bincode as a backend for
/// serialization.
///
/// !TODO: Implement a backend abstraction layer so we can easily plug in different backends.
macro_rules! impl_versionize {
    ($ty:ident) => {
        impl Versionize for $ty {
            #[inline]
            fn serialize<W: std::io::Write>(
                &self,
                writer: &mut W,
                _version_map: &VersionMap,
                _version: u16,
            ) -> Result<()> {
                bincode::serialize_into(writer, &self)
                    .map_err(|ref err| Error::Serialize(format!("{:?}", err)))?;
                Ok(())
            }

            #[inline]
            fn deserialize<R: std::io::Read>(
                mut reader: &mut R,
                _version_map: &VersionMap,
                _version: u16,
            ) -> Result<Self>
            where
                Self: Sized,
            {
                Ok(bincode::deserialize_from(&mut reader)
                    .map_err(|ref err| Error::Deserialize(format!("{:?}", err)))?)
            }

            // Not used.
            fn version() -> u16 {
                1
            }
        }
    };
}

impl_versionize!(bool);
impl_versionize!(isize);
impl_versionize!(i8);
impl_versionize!(i16);
impl_versionize!(i32);
impl_versionize!(i64);
impl_versionize!(usize);
impl_versionize!(u8);
impl_versionize!(u16);
impl_versionize!(u32);
impl_versionize!(u64);
impl_versionize!(f32);
impl_versionize!(f64);
impl_versionize!(char);
impl_versionize!(String);

impl<T> Versionize for Box<T>
where
    T: Versionize,
{
    #[inline]
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        version_map: &VersionMap,
        app_version: u16,
    ) -> Result<()> {
        self.as_ref().serialize(writer, version_map, app_version)
    }

    #[inline]
    fn deserialize<R: std::io::Read>(
        reader: &mut R,
        version_map: &VersionMap,
        app_version: u16,
    ) -> Result<Self> {
        Ok(Box::new(T::deserialize(reader, version_map, app_version)?))
    }

    // Not used yet.
    fn version() -> u16 {
        1
    }
}

impl<T> Versionize for std::num::Wrapping<T>
where
    T: Versionize,
{
    #[inline]
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        version_map: &VersionMap,
        app_version: u16,
    ) -> Result<()> {
        self.0.serialize(writer, version_map, app_version)
    }

    #[inline]
    fn deserialize<R: std::io::Read>(
        reader: &mut R,
        version_map: &VersionMap,
        app_version: u16,
    ) -> Result<Self> {
        Ok(std::num::Wrapping(T::deserialize(
            reader,
            version_map,
            app_version,
        )?))
    }

    // Not used yet.
    fn version() -> u16 {
        1
    }
}

impl<T> Versionize for Option<T>
where
    T: Versionize,
{
    #[inline]
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        version_map: &VersionMap,
        app_version: u16,
    ) -> Result<()> {
        // Serialize an Option just like bincode does: u8, T.
        match &*self {
            Some(value) => {
                1u8.serialize(writer, version_map, app_version)?;
                value.serialize(writer, version_map, app_version)
            }
            None => 0u8.serialize(writer, version_map, app_version),
        }
    }

    #[inline]
    fn deserialize<R: std::io::Read>(
        reader: &mut R,
        version_map: &VersionMap,
        app_version: u16,
    ) -> Result<Self> {
        let option = u8::deserialize(reader, version_map, app_version)?;
        match option {
            0u8 => Ok(None),
            1u8 => Ok(Some(T::deserialize(reader, version_map, app_version)?)),
            value => Err(Error::Deserialize(format!(
                "Invalid option value {}",
                value
            ))),
        }
    }

    // Not used yet.
    fn version() -> u16 {
        1
    }
}

impl<T> Versionize for Vec<T>
where
    T: Versionize,
{
    #[inline]
    fn serialize<W: std::io::Write>(
        &self,
        mut writer: &mut W,
        version_map: &VersionMap,
        app_version: u16,
    ) -> Result<()> {
        // Serialize in the same fashion as bincode:
        // Write len.
        bincode::serialize_into(&mut writer, &self.len())
            .map_err(|ref err| Error::Serialize(format!("{:?}", err)))?;
        // Walk the vec and write each elemenet.
        for element in self {
            element
                .serialize(writer, version_map, app_version)
                .map_err(|ref err| Error::Serialize(format!("{:?}", err)))?;
        }
        Ok(())
    }

    #[inline]
    fn deserialize<R: std::io::Read>(
        mut reader: &mut R,
        version_map: &VersionMap,
        app_version: u16,
    ) -> Result<Self> {
        let mut v = Vec::new();
        let len: u64 = bincode::deserialize_from(&mut reader)
            .map_err(|ref err| Error::Deserialize(format!("{:?}", err)))?;
        for _ in 0..len {
            let element: T = T::deserialize(reader, version_map, app_version)
                .map_err(|ref err| Error::Deserialize(format!("{:?}", err)))?;
            v.push(element);
        }
        Ok(v)
    }

    // Not used yet.
    fn version() -> u16 {
        1
    }
}

// Implement versioning for FAM structures by using the FamStructWrapper interface.
impl<T: Default + FamStruct + Versionize> Versionize for FamStructWrapper<T>
where
    <T as FamStruct>::Entry: Versionize,
    T: std::fmt::Debug,
{
    #[inline]
    fn serialize<W: std::io::Write>(
        &self,
        mut writer: &mut W,
        version_map: &VersionMap,
        app_version: u16,
    ) -> Result<()> {
        // Write the fixed size header.
        self.as_fam_struct_ref()
            .serialize(&mut writer, version_map, app_version)?;
        // Write the array.
        self.as_slice()
            .to_vec()
            .serialize(&mut writer, version_map, app_version)?;

        Ok(())
    }

    #[inline]
    fn deserialize<R: std::io::Read>(
        reader: &mut R,
        version_map: &VersionMap,
        app_version: u16,
    ) -> Result<Self> {
        let header = T::deserialize(reader, version_map, app_version)
            .map_err(|ref err| Error::Deserialize(format!("{:?}", err)))?;
        let entries: Vec<<T as FamStruct>::Entry> =
            Vec::deserialize(reader, version_map, app_version)
                .map_err(|ref err| Error::Deserialize(format!("{:?}", err)))?;
        // Construct the object from the array items.
        // Header(T) fields will be initialized by Default trait impl.
        let mut object = FamStructWrapper::from_entries(&entries);
        // Update Default T with the deserialized header.
        std::mem::replace(object.as_mut_fam_struct(), header);
        Ok(object)
    }

    // Not used.
    fn version() -> u16 {
        1
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    use super::*;
    use super::{Result, VersionMap, Versionize};
    use vmm_sys_util::generate_fam_struct_impl;

    #[repr(C)]
    #[derive(Default, Debug, Versionize)]
    struct Message {
        pub len: u32,
        pub padding: u32,
        pub value: u32,
        #[version(start = 2, default_fn = "default_extra_value")]
        pub extra_value: u16,
        pub entries: __IncompleteArrayField<u32>,
    }

    impl Message {
        fn default_extra_value(_source_version: u16) -> u16 {
            321
        }
    }
    generate_fam_struct_impl!(Message, u32, entries, u32, len, 100);

    // Generate primitive tests using this macro.
    macro_rules! primitive_int_test {
        ($ty:ident, $fn_name:ident) => {
            #[test]
            fn $fn_name() {
                let vm = VersionMap::new();
                let mut snapshot_mem = vec![0u8; 64];

                let store: $ty = std::$ty::MAX;
                store
                    .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
                    .unwrap();
                let restore =
                    <$ty as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();

                assert_eq!(store, restore);
            }
        };
    }

    primitive_int_test!(usize, test_ser_de_usize);
    primitive_int_test!(isize, test_ser_de_isize);
    primitive_int_test!(u8, test_ser_de_u8);
    primitive_int_test!(u16, test_ser_de_u16);
    primitive_int_test!(u32, test_ser_de_u32);
    primitive_int_test!(u64, test_ser_de_u64);
    primitive_int_test!(i8, test_ser_de_i8);
    primitive_int_test!(i16, test_ser_de_i16);
    primitive_int_test!(i32, test_ser_de_i32);
    primitive_int_test!(i64, test_ser_de_i64);
    primitive_int_test!(f32, test_ser_de_f32);
    primitive_int_test!(f64, test_ser_de_f64);
    primitive_int_test!(char, test_ser_de_char);

    #[repr(u32)]
    #[derive(Debug, Versionize, PartialEq, Clone)]
    pub enum TestState {
        Zero,
        One(u32, String),
        #[version(start = 2, default_fn = "test_state_default_one")]
        Two(u32),
        #[version(start = 3, default_fn = "test_state_default_two")]
        Three(u32),
    }

    impl Default for TestState {
        fn default() -> Self {
            Self::One(1, "Default".to_owned())
        }
    }

    impl TestState {
        fn test_state_default_one(&self, target_version: u16) -> Result<TestState> {
            match target_version {
                2 => Ok(TestState::Two(2)),
                1 => Ok(TestState::Two(2)),
                i => Err(Error::Serialize(format!("Unknown target version: {}", i))),
            }
        }

        fn test_state_default_two(&self, target_version: u16) -> Result<TestState> {
            match target_version {
                3 => Ok(TestState::Three(3)),
                2 => Ok(TestState::Two(2)),
                1 => Ok(TestState::One(1, "Test".to_owned())),
                i => Err(Error::Serialize(format!("Unknown target version: {}", i))),
            }
        }
    }

    #[test]
    fn test_enum_basic() {
        let mut snapshot_mem = vec![0u8; 64];
        let mut vm = VersionMap::new();
        vm.new_version()
            .set_type_version(TestState::type_id(), 2)
            .new_version()
            .set_type_version(TestState::type_id(), 3)
            .new_version()
            .set_type_version(TestState::type_id(), 4);

        // Test trivial case.
        let state = TestState::One(1337, "a string".to_owned());
        state
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap();
        let restored_state =
            <TestState as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();
        assert_eq!(state, restored_state);
    }

    #[test]
    fn test_enum_rollback() {
        let mut snapshot_mem = vec![0u8; 64];
        let mut vm = VersionMap::new();
        vm.new_version()
            .set_type_version(TestState::type_id(), 2)
            .new_version()
            .set_type_version(TestState::type_id(), 3)
            .new_version()
            .set_type_version(TestState::type_id(), 4);

        // Test default_fn for serialization of enum variants that don't exist in previous versions.
        let state = TestState::Three(1337);
        state
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 2)
            .unwrap();
        let restored_state =
            <TestState as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();
        assert_eq!(restored_state, TestState::Two(2));

        let state = TestState::Three(1337);
        state
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap();
        let restored_state =
            <TestState as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();
        assert_eq!(restored_state, TestState::One(1, "Test".to_owned()));

        let state = TestState::Three(1337);
        state
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 3)
            .unwrap();
        let restored_state =
            <TestState as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();
        assert_eq!(restored_state, state);

        let state = TestState::Two(1234);
        state
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 2)
            .unwrap();
        let restored_state =
            <TestState as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();
        assert_eq!(restored_state, state);

        let state = TestState::Zero;
        state
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 2)
            .unwrap();
        let restored_state =
            <TestState as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();
        assert_eq!(restored_state, state);
    }

    #[test]
    fn test_ser_de_bool() {
        let vm = VersionMap::new();
        let mut snapshot_mem = vec![0u8; 64];

        let store = true;
        store
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap();
        let restore =
            <bool as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();

        assert_eq!(store, restore);
    }

    #[test]
    fn test_ser_de_string() {
        let vm = VersionMap::new();
        let mut snapshot_mem = vec![0u8; 64];

        let store = String::from("test string");
        store
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap();
        let restore =
            <String as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();

        assert_eq!(store, restore);
    }

    #[test]
    fn test_ser_de_vec() {
        let vm = VersionMap::new();
        let mut snapshot_mem = vec![0u8; 64];

        let mut store = Vec::new();
        store.push("test 1".to_owned());
        store.push("test 2".to_owned());
        store.push("test 3".to_owned());

        store
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap();
        let restore =
            <Vec<String> as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();

        assert_eq!(store, restore);
    }

    #[test]
    fn test_ser_de_option() {
        let vm = VersionMap::new();
        let mut snapshot_mem = vec![0u8; 64];
        let mut store = Some("test".to_owned());

        store
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap();
        let mut restore =
            <Option<String> as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1)
                .unwrap();
        assert_eq!(store, restore);

        // Check that ser_de also works for `None` variant.
        store = None;
        store
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap();
        restore = <Option<String> as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1)
            .unwrap();
        assert_eq!(store, restore);

        store = Some("test".to_owned());
        store
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap();
        // Corrupt `snapshot_mem` by changing the most significant bit to a value different than 0 or 1.
        snapshot_mem[0] = 2;
        let restore_err =
            <Option<String> as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1)
                .unwrap_err();
        assert_eq!(
            restore_err,
            Error::Deserialize("Invalid option value 2".to_string())
        );
        // Corrupt `snapshot_mem` by changing the most significant bit from 1 (`Some(type)`) to 0 (`None`).
        snapshot_mem[0] = 0;
        restore = <Option<String> as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1)
            .unwrap();
        assert_ne!(store, restore);
    }

    #[test]
    fn test_ser_de_box() {
        let vm = VersionMap::new();
        let mut snapshot_mem = vec![0u8; 64];

        let store = Box::new("test".to_owned());

        store
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap();
        let restore =
            <Box<String> as Versionize>::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();

        assert_eq!(store, restore);
    }

    #[test]
    fn test_ser_de_wrapping() {
        let vm = VersionMap::new();
        let mut snapshot_mem = vec![0u8; 64];

        let store = std::num::Wrapping(1337u32);

        store
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap();
        let restore = <std::num::Wrapping<u32> as Versionize>::deserialize(
            &mut snapshot_mem.as_slice(),
            &vm,
            1,
        )
        .unwrap();

        assert_eq!(store, restore);
    }

    #[test]
    fn test_ser_de_vec_version() {
        type MessageFamStructWrapper = FamStructWrapper<Message>;
        let vm = VersionMap::new();
        let mut f = MessageFamStructWrapper::new(0);
        f.as_mut_fam_struct().padding = 123;
        f.as_mut_fam_struct().extra_value = 321;

        f.push(10).unwrap();
        f.push(20).unwrap();

        let mut snapshot_mem = vec![0u8; 512];
        let mut store = Vec::new();
        store.push(f.clone());
        store.push(f.clone());

        store
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap();
        let restore = <Vec<MessageFamStructWrapper> as Versionize>::deserialize(
            &mut snapshot_mem.as_slice(),
            &vm,
            1,
        )
        .unwrap();
        let eq = store == restore;
        // This is important to test separately as we rely on the default_fn to
        // override the u16 default value.
        assert_eq!(321, restore[0].as_fam_struct_ref().extra_value);
        assert!(eq);
    }

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

    impl<T> ::std::fmt::Debug for __IncompleteArrayField<T> {
        fn fmt(&self, fmt: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
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
        ) -> Result<()> {
            Ok(())
        }

        #[inline]
        fn deserialize<R: std::io::Read>(
            _reader: &mut R,
            _version_map: &VersionMap,
            _app_version: u16,
        ) -> Result<Self> {
            Ok(Self::new())
        }

        // Not used.
        fn version() -> u16 {
            1
        }
    }

    #[test]
    fn test_famstruct() {
        type MessageFamStructWrapper = FamStructWrapper<Message>;

        let vm = VersionMap::new();
        let mut f = MessageFamStructWrapper::new(0);
        f.as_mut_fam_struct().padding = 123;
        f.as_mut_fam_struct().extra_value = 321;

        f.push(10).unwrap();
        f.push(20).unwrap();

        let mut snapshot_mem = vec![0u8; 64];
        f.serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap();
        let restored_state =
            MessageFamStructWrapper::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();

        let original_values = f.as_slice();
        let restored_values = restored_state.as_slice();

        assert_eq!(
            f.as_fam_struct_ref().padding,
            restored_state.as_fam_struct_ref().padding
        );
        assert_eq!(original_values, restored_values);
        assert_eq!(
            f.as_fam_struct_ref().extra_value,
            restored_state.as_fam_struct_ref().extra_value
        );
    }

    #[test]
    fn test_famstruct_ser_error() {
        type MessageFamStructWrapper = FamStructWrapper<Message>;

        let vm = VersionMap::new();
        let mut f = MessageFamStructWrapper::new(0);
        f.as_mut_fam_struct().padding = 123;
        f.as_mut_fam_struct().extra_value = 321;

        f.push(10).unwrap();
        f.push(20).unwrap();

        let mut snapshot_mem = vec![0u8; 16];

        assert!(f
            .serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .is_err());
    }
    #[test]
    fn test_famstruct_version() {
        type MessageFamStructWrapper = FamStructWrapper<Message>;

        let vm = VersionMap::new();
        let mut f = MessageFamStructWrapper::new(0);
        f.as_mut_fam_struct().padding = 123;
        f.push(10).unwrap();
        f.push(20).unwrap();

        let mut snapshot_mem = vec![0u8; 64];
        f.serialize(&mut snapshot_mem.as_mut_slice(), &vm, 1)
            .unwrap();
        let restored_state =
            MessageFamStructWrapper::deserialize(&mut snapshot_mem.as_slice(), &vm, 1).unwrap();

        let original_values = f.as_slice();
        let restored_values = restored_state.as_slice();

        assert_eq!(
            f.as_fam_struct_ref().padding,
            restored_state.as_fam_struct_ref().padding
        );
        assert_eq!(original_values, restored_values);
    }
}
