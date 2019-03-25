// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use json_patch::merge;
use serde_json::Value;

/// The Mmds is the Microvm Metadata Service represented as an untyped json.
#[derive(Clone)]
pub struct Mmds {
    data_store: Value,
    is_initialized: bool,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    NotFound,
    UnsupportedValueType,
}

impl Default for Mmds {
    fn default() -> Self {
        Mmds {
            data_store: Value::default(),
            is_initialized: false,
        }
    }
}

impl Mmds {
    /// This method is needed to provide the correct status code for API request.
    /// When a PATCH request is made on an uninitialized Mmds structure the status
    /// code should be 404 (Not Found) otherwise the returned status code should be
    /// 204 (No Content).
    pub fn is_initialized(&self) -> bool {
        self.is_initialized
    }

    pub fn put_data(&mut self, data: Value) {
        // TODO: we should add a data validator and only accept Strings, arrays & dictionaries
        // https://github.com/firecracker-microvm/firecracker/issues/401
        self.data_store = data;
        self.is_initialized = true;
    }

    pub fn patch_data(&mut self, patch_data: Value) {
        merge(&mut self.data_store, &patch_data);
    }

    pub fn get_data_str(&self) -> String {
        if self.data_store.is_null() {
            return String::from("{}");
        }
        self.data_store.to_string()
    }

    /// This function replicates the behavior of the Instance Metadata Service
    /// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
    /// 1. For a (key, value) pair where the value is a dictionary, it will return all the keys
    /// in the dictionary.
    /// 2. For a (key, value) pair where the value is a simple type (bool, string, number),
    /// it will return the value.
    ///
    /// When the path is not found, a NotFound error is returned.
    pub fn get_value(&self, path: String) -> Result<Vec<String>, Error> {
        // The pointer function splits the input by "/". With a trailing "/", pointer does not
        // know how to get the object.
        let value = if path.ends_with('/') {
            self.data_store.pointer(&path.as_str()[..(path.len() - 1)])
        } else {
            self.data_store.pointer(path.as_str())
        };

        match value {
            Some(val) => {
                let mut ret = Vec::new();
                // If the `dict` is Value::Null, Error::NotFound is thrown.
                // If the `dict` is not a dictionary, a Vec with the value corresponding to
                // the key is returned.
                match val.as_object() {
                    Some(map) => {
                        // When the object is a map, push all the keys in the Vec.
                        for key in map.keys() {
                            let mut key = key.clone();
                            // If the key corresponds to a dictionary, a "/" is appended
                            // to the key name.
                            if map[&key].is_object() {
                                key.push_str("/");
                            }

                            ret.push(key);
                        }
                        Ok(ret)
                    }
                    None => {
                        // When the object is not a map, return the value.
                        // The only supported Value type is String.
                        match val.as_str() {
                            Some(str_val) => {
                                ret.push(str_val.to_string());
                                Ok(ret)
                            }
                            None => Err(Error::UnsupportedValueType),
                        }
                    }
                }
            }
            None => Err(Error::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_mmds() {
        let mut mmds = Mmds::default();
        assert_eq!(mmds.is_initialized(), false);

        let mut mmds_json = "{\"meta-data\":{\"iam\":\"dummy\"},\"user-data\":\"1522850095\"}";

        mmds.put_data(serde_json::from_str(mmds_json).unwrap());
        assert_eq!(mmds.is_initialized(), true);

        assert_eq!(mmds.get_data_str(), mmds_json);

        // update the user-data field add test that patch works as expected
        let patch_json = "{\"user-data\":\"10\"}";
        mmds.patch_data(serde_json::from_str(patch_json).unwrap());
        mmds_json = "{\"meta-data\":{\"iam\":\"dummy\"},\"user-data\":\"10\"}";
        assert_eq!(mmds.get_data_str(), mmds_json);
    }

    #[test]
    fn test_get_value() {
        let mut mmds = Mmds::default();
        let data = r#"{
            "name": {
                "first": "John",
                "second": "Doe"
            },
            "age": "43",
            "phones": {
                "home": {
                    "RO": "+40 1234567",
                    "UK": "+44 1234567"
                },
                "mobile": "+44 2345678"
            }
        }"#;

        let data_store: Value = serde_json::from_str(data).unwrap();
        mmds.put_data(data_store);

        // Test invalid path.
        match mmds.get_value("/invalid_path".to_string()) {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(e, Error::NotFound),
        };
        match mmds.get_value("/invalid_path/".to_string()) {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(e, Error::NotFound),
        };

        // Test path ends with /; Value is a dictionary.
        if let Ok(ret) = mmds.get_value("/phones/".to_string()) {
            assert_eq!(ret, vec!["home/", "mobile"]);
        } else {
            assert!(false);
        }

        match mmds.get_value("/phones/home/".to_string()) {
            Ok(ret) => assert_eq!(ret, vec!["RO", "UK"]),
            Err(_) => assert!(false),
        };

        // Test path ends with /; Value is a String.
        match mmds.get_value("/phones/mobile/".to_string()) {
            Ok(ret) => assert_eq!(ret, vec!["+44 2345678"]),
            Err(_) => assert!(false),
        };

        // Test path does NOT end with /; Value is a dictionary.
        match mmds.get_value("/phones".to_string()) {
            Ok(ret) => assert_eq!(ret, vec!["home/", "mobile"]),
            Err(_) => assert!(false),
        };

        // Test path does NOT end with /; Value is a String.
        match mmds.get_value("/phones/mobile".to_string()) {
            Ok(ret) => assert_eq!(ret, vec!["+44 2345678"]),
            Err(_) => assert!(false),
        };
    }

    #[test]
    fn test_get_element_from_array() {
        let mut mmds = Mmds::default();
        let data = r#"{
            "phones": [
                "+40 1234567",
                "+44 1234567"
            ]
        }"#;

        let data_store: Value = serde_json::from_str(data).unwrap();
        mmds.put_data(data_store);

        // Test path does NOT end with /; Value is a String.
        match mmds.get_value("/phones/0".to_string()) {
            Ok(ret) => assert_eq!(ret, vec!["+40 1234567"]),
            Err(_) => assert!(false),
        };
    }

    #[test]
    fn test_invalid_types() {
        let mut mmds = Mmds::default();
        let data = r#"{
            "name": {
                "first": "John",
                "second": "Doe"
            },
            "age": 43
        }"#;

        let data_store: Value = serde_json::from_str(data).unwrap();
        // TODO: This should fail; we should only accept String types
        mmds.put_data(data_store);

        match mmds.get_value("/age".to_string()) {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(e, Error::UnsupportedValueType),
        };

        match mmds.get_value("/age/".to_string()) {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(e, Error::UnsupportedValueType),
        };
    }
}
