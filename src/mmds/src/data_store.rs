// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;

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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NotFound => write!(f, "The MMDS resource does not exist."),
            Error::UnsupportedValueType => {
                write!(f, "Cannot add non-strings values to the MMDS data-store.")
            }
        }
    }
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
    /// This method is needed to check if data store is initialized.
    /// When a PATCH request is made on an uninitialized Mmds structure this method
    /// should return a NotFound error.
    fn check_data_store_initialized(&self) -> Result<(), Error> {
        if self.is_initialized {
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    /// This method validates the data from a PATCH or PUT request and returns
    /// an UnsupportedValueType error if the data contain any value type other than
    /// Strings, arrays and dictionaries.
    pub fn check_data_valid(data: &Value) -> Result<(), Error> {
        if let Some(map) = data.as_object() {
            for key in map.keys() {
                Mmds::check_data_valid(&map[key])?;
            }
        } else if let Some(array) = data.as_array() {
            for obj in array {
                Mmds::check_data_valid(&obj)?;
            }
        } else if !data.is_string() {
            return Err(Error::UnsupportedValueType);
        }
        Ok(())
    }

    pub fn put_data(&mut self, data: Value) -> Result<(), Error> {
        Mmds::check_data_valid(&data)?;
        self.data_store = data;
        self.is_initialized = true;
        Ok(())
    }

    pub fn patch_data(&mut self, patch_data: Value) -> Result<(), Error> {
        Mmds::check_data_valid(&patch_data)?;
        self.check_data_store_initialized()?;
        super::json_patch(&mut self.data_store, &patch_data);
        Ok(())
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

        assert_eq!(
            mmds.check_data_store_initialized().unwrap_err().to_string(),
            "The MMDS resource does not exist.".to_string(),
        );

        let mut mmds_json = "{\"meta-data\":{\"iam\":\"dummy\"},\"user-data\":\"1522850095\"}";

        mmds.put_data(serde_json::from_str(mmds_json).unwrap())
            .unwrap();
        assert!(mmds.check_data_store_initialized().is_ok());

        assert_eq!(mmds.get_data_str(), mmds_json);

        // update the user-data field add test that patch works as expected
        let patch_json = "{\"user-data\":\"10\"}";
        mmds.patch_data(serde_json::from_str(patch_json).unwrap())
            .unwrap();
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
        mmds.put_data(data_store).unwrap();

        // Test invalid path.
        assert_eq!(
            mmds.get_value("/invalid_path".to_string()),
            Err(Error::NotFound)
        );
        assert_eq!(
            mmds.get_value("/invalid_path/".to_string()),
            Err(Error::NotFound)
        );

        // Test path ends with /; Value is a dictionary.
        assert_eq!(
            mmds.get_value("/phones/".to_string()).unwrap(),
            vec!["home/", "mobile"]
        );

        assert_eq!(
            mmds.get_value("/phones/home/".to_string()).unwrap(),
            vec!["RO", "UK"]
        );

        // Test path ends with /; Value is a String.
        assert_eq!(
            mmds.get_value("/phones/mobile/".to_string()).unwrap(),
            vec!["+44 2345678"]
        );

        // Test path does NOT end with /; Value is a dictionary.
        assert_eq!(
            mmds.get_value("/phones".to_string()).unwrap(),
            vec!["home/", "mobile"]
        );

        // Test path does NOT end with /; Value is a String.
        assert_eq!(
            mmds.get_value("/phones/mobile".to_string()).unwrap(),
            vec!["+44 2345678"]
        );
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
        mmds.put_data(data_store).unwrap();

        // Test path does NOT end with /; Value is a String.
        assert_eq!(
            mmds.get_value("/phones/0".to_string()).unwrap(),
            vec!["+40 1234567"]
        );
    }

    #[test]
    fn test_update_data_store() {
        let mut mmds = Mmds::default();

        let data = r#"{
            "name": {
                "first": "John",
                "second": "Doe"
            },
            "age": "43"
        }"#;
        let data_store: Value = serde_json::from_str(data).unwrap();
        assert!(mmds.put_data(data_store).is_ok());

        let data = r#"{
            "name": {
                "first": "John",
                "second": "Doe"
            },
            "age": "100"
        }"#;
        let data_store: Value = serde_json::from_str(data).unwrap();
        assert!(mmds.patch_data(data_store).is_ok());

        let data = r#"{
            "name": {
                "first": "John",
                "second": "Doe"
            },
            "age": 43
        }"#;
        let data_store: Value = serde_json::from_str(data).unwrap();
        assert_eq!(
            mmds.put_data(data_store).unwrap_err().to_string(),
            "Cannot add non-strings values to the MMDS data-store.".to_string()
        );

        let data = r#"{
            "name": {
                "first": "John",
                "second": true
            },
            "age": "43"
        }"#;
        let data_store: Value = serde_json::from_str(data).unwrap();
        assert_eq!(
            mmds.patch_data(data_store),
            Err(Error::UnsupportedValueType)
        );
    }
}
