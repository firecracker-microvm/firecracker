// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Maps struct/enum/union versions to a sequence of root versions.
//! This is required to support the concept of a snapshot version
//! composed of individually versioned components.

use std::any::TypeId;
use std::collections::hash_map::HashMap;

const BASE_VERSION: u16 = 1;

///
/// The VersionMap API provides functionality to define the version for each serialized
/// type and attach them to specific root versions.
///
/// !TODO: Find an O(1) solution for `get_type_version()`.
///
#[derive(Clone, Debug, Default)]
pub struct VersionMap {
    versions: Vec<HashMap<TypeId, u16>>,
}

impl VersionMap {
    /// Create a new version map and set root version to 1.
    pub fn new() -> Self {
        VersionMap {
            versions: vec![HashMap::new(); 1],
        }
    }

    /// Bumps root version by 1 to create a new root version and set it as latest version.
    pub fn new_version(&mut self) -> &mut Self {
        self.versions.push(HashMap::new());
        self
    }

    /// Define a mapping between a specific type version and the latest root version.
    pub fn set_type_version(&mut self, type_id: TypeId, type_version: u16) -> &mut Self {
        // It is safe to unwrap since `self.versions` always has at least 1 element.
        self.versions
            .last_mut()
            .unwrap()
            .insert(type_id, type_version);
        self
    }

    /// Returns the version of `type_id` corresponding to the specified `root_version`.
    pub fn get_type_version(&self, root_version: u16, type_id: TypeId) -> u16 {
        let version_space = self.versions.split_at(root_version as usize).0;

        for i in (0..version_space.len()).rev() {
            if let Some(version) = version_space[i].get(&type_id) {
                return *version;
            }
        }

        BASE_VERSION
    }

    /// Returns the latest top version.
    pub fn latest_version(&self) -> u16 {
        self.versions.len() as u16
    }
}

#[cfg(test)]
mod tests {
    use super::{TypeId, VersionMap, BASE_VERSION};

    pub struct MyType;
    pub struct MySecondType;
    pub struct MyThirdType;

    #[test]
    fn test_default_version() {
        let vm = VersionMap::new();
        assert_eq!(vm.latest_version(), 1);
    }

    #[test]
    fn test_new_versions() {
        let mut vm = VersionMap::new();
        vm.new_version().new_version();
        assert_eq!(vm.latest_version(), 3);
    }

    #[test]
    fn test_1_app_version() {
        let mut vm = VersionMap::new();
        vm.set_type_version(TypeId::of::<MyType>(), 1);
        vm.set_type_version(TypeId::of::<MySecondType>(), 2);
        vm.set_type_version(TypeId::of::<MyThirdType>(), 3);

        assert_eq!(vm.get_type_version(1, TypeId::of::<MyType>()), 1);
        assert_eq!(vm.get_type_version(1, TypeId::of::<MySecondType>()), 2);
        assert_eq!(vm.get_type_version(1, TypeId::of::<MyThirdType>()), 3);
    }

    #[test]
    fn test_100_app_version_full() {
        let mut vm = VersionMap::new();

        for i in 1..=100 {
            vm.set_type_version(TypeId::of::<MyType>(), i)
                .set_type_version(TypeId::of::<MySecondType>(), i + 1)
                .set_type_version(TypeId::of::<MyThirdType>(), i + 2)
                .new_version();
        }

        for i in 1..=100 {
            assert_eq!(vm.get_type_version(i, TypeId::of::<MyType>()), i);
            assert_eq!(vm.get_type_version(i, TypeId::of::<MySecondType>()), i + 1);
            assert_eq!(vm.get_type_version(i, TypeId::of::<MyThirdType>()), i + 2);
        }
    }

    #[test]
    fn test_app_versions_with_gap() {
        let my_type_id = TypeId::of::<MyType>();
        let my_second_type_id = TypeId::of::<MySecondType>();
        let my_third_type_id = TypeId::of::<MyThirdType>();

        let mut vm = VersionMap::new();
        vm.set_type_version(my_type_id, 1);
        vm.set_type_version(my_second_type_id, 1);
        vm.set_type_version(my_third_type_id, 1);
        vm.new_version();
        vm.set_type_version(my_type_id, 2);
        vm.new_version();
        vm.set_type_version(my_third_type_id, 2);
        vm.new_version();
        vm.set_type_version(my_second_type_id, 2);

        assert_eq!(vm.get_type_version(1, my_type_id), 1);
        assert_eq!(vm.get_type_version(1, my_second_type_id), 1);
        assert_eq!(vm.get_type_version(1, my_third_type_id), 1);

        assert_eq!(vm.get_type_version(2, my_type_id), 2);
        assert_eq!(vm.get_type_version(2, my_second_type_id), 1);
        assert_eq!(vm.get_type_version(2, my_third_type_id), 1);

        assert_eq!(vm.get_type_version(3, my_type_id), 2);
        assert_eq!(vm.get_type_version(3, my_second_type_id), 1);
        assert_eq!(vm.get_type_version(3, my_third_type_id), 2);

        assert_eq!(vm.get_type_version(4, my_type_id), 2);
        assert_eq!(vm.get_type_version(4, my_second_type_id), 2);
        assert_eq!(vm.get_type_version(4, my_third_type_id), 2);
    }

    #[test]
    fn test_unset_type() {
        let vm = VersionMap::new();
        assert_eq!(vm.get_type_version(1, TypeId::of::<MyType>()), BASE_VERSION);
    }
}
