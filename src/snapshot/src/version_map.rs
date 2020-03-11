// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::hash_map::HashMap;

const BASE_VERSION: u16 = 1;

#[derive(Clone, Debug)]
pub struct VersionMap {
    versions: Vec<HashMap<String, u16>>,
}

impl VersionMap {
    pub fn new() -> Self {
        VersionMap {
            versions: vec![HashMap::new(); 1],
        }
    }

    pub fn new_version(&mut self) -> &mut Self {
        self.versions.push(HashMap::new());
        self
    }

    pub fn set_type_version(&mut self, type_name: String, type_version: u16) -> &mut Self {
        let current_version = self.versions.len();
        self.versions[current_version - 1].insert(type_name, type_version);
        self
    }

    pub fn get_type_version(&self, app_version: u16, type_name: &str) -> u16 {
        let version_space = self.versions.split_at(app_version as usize).0;

        for i in (0..version_space.len()).rev() {
            if let Some(version) = version_space[i].get(type_name) {
                // println!("Got {} @ {} for app {}", type_name, version, app_version );
                return *version;
            }
        }
        // println!("Got {} @ {} for app {}", type_name, BASE_VERSION, app_version );

        BASE_VERSION
    }

    pub fn get_latest_version(&self) -> u16 {
        return self.versions.len() as u16;
    }
}
