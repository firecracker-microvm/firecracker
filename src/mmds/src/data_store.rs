// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use std::fmt;

/// The Mmds is the Microvm Metadata Service represented as an untyped json.
#[derive(Clone)]
pub struct Mmds {
    data_store: Value,
    is_initialized: bool,
}

/// MMDS possible outputs.
pub enum OutputFormat {
    Json,
    Imds,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    NotFound,
    NotInitialized,
    UnsupportedValueType,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NotFound => write!(f, "The MMDS resource does not exist."),
            Error::NotInitialized => write!(f, "The MMDS data store is not initialized."),
            Error::UnsupportedValueType => write!(
                f,
                "Cannot retrieve value. The value has an unsupported type."
            ),
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
            Err(Error::NotInitialized)
        }
    }

    pub fn put_data(&mut self, data: Value) -> Result<(), Error> {
        self.data_store = data;
        self.is_initialized = true;
        Ok(())
    }

    pub fn patch_data(&mut self, patch_data: Value) -> Result<(), Error> {
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

    /// Returns the serde::Value in IMDS format plaintext.
    /// Currently, only JSON objects and strings can be IMDS formatted.
    ///
    /// See the docs for detailed description of the IMDS format:
    /// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
    ///
    /// # Examples
    ///
    /// ```json
    /// {
    ///     "key1" : {
    ///         "key11": "value11"
    ///         "key12": "value12"
    ///     }
    ///     "key2" : "value3"
    ///     "key3" : "value3"
    /// }
    ///```
    ///
    /// IMDS formatted JSON object:
    /// ```text
    /// key1/
    /// key2
    /// key3
    /// ```
    ///
    /// JSON string:
    /// ```json
    /// "value"
    /// ```
    ///
    /// IMDS formatted string:
    /// ```text
    /// value
    /// ```
    ///
    /// If the `serde_json::Value` is not supported, an `UnsupportedValueType` error is returned.
    fn format_imds(json: &Value) -> Result<String, Error> {
        // If the `dict` is Value::Null, Error::NotFound is thrown.
        // If the `dict` is not a dictionary, a Vec with the value corresponding to
        // the key is returned.
        match json.as_object() {
            Some(map) => {
                let mut ret = Vec::new();
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
                Ok(ret.join("\n"))
            }
            None => {
                // When the object is not a map, return the value.
                // Support only `Value::String`.
                match json.as_str() {
                    Some(str_val) => Ok(str_val.to_string()),
                    None => Err(Error::UnsupportedValueType),
                }
            }
        }
    }

    /// Returns the subtree located at path. When the path corresponds to a leaf, it returns the value.
    /// Returns Error::NotFound when the path is invalid.
    pub fn get_value(&self, path: String, format: OutputFormat) -> Result<String, Error> {
        // The pointer function splits the input by "/". With a trailing "/", pointer does not
        // know how to get the object.
        let value = if path.ends_with('/') {
            self.data_store.pointer(&path.as_str()[..(path.len() - 1)])
        } else {
            self.data_store.pointer(path.as_str())
        };

        if let Some(json) = value {
            match format {
                OutputFormat::Json => Ok(json.to_string()),
                OutputFormat::Imds => Mmds::format_imds(json),
            }
        } else {
            Err(Error::NotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mmds() {
        let mut mmds = Mmds::default();

        assert_eq!(
            mmds.check_data_store_initialized().unwrap_err().to_string(),
            "The MMDS data store is not initialized.".to_string(),
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
            "age": 43,
            "phones": [
                "+401234567",
                "+441234567"
            ],
            "member": false,
            "shares_percentage": 12.12,
            "balance": -24
        }"#;
        let data_store: Value = serde_json::from_str(data).unwrap();
        mmds.put_data(data_store).unwrap();

        // Test invalid path.
        assert_eq!(
            mmds.get_value("/invalid_path".to_string(), OutputFormat::Json),
            Err(Error::NotFound)
        );
        assert_eq!(
            mmds.get_value("/invalid_path".to_string(), OutputFormat::Imds),
            Err(Error::NotFound)
        );

        // Retrieve an object.
        let mut expected_json = r#"{
                "first": "John",
                "second": "Doe"
            }"#
        .to_string();
        expected_json.retain(|c| !c.is_whitespace());
        assert_eq!(
            mmds.get_value("/name".to_string(), OutputFormat::Json)
                .unwrap(),
            expected_json
        );
        let expected_imds = "first\nsecond";
        assert_eq!(
            mmds.get_value("/name".to_string(), OutputFormat::Imds)
                .unwrap(),
            expected_imds
        );

        // Retrieve an integer.
        assert_eq!(
            mmds.get_value("/age".to_string(), OutputFormat::Json)
                .unwrap(),
            "43"
        );
        assert_eq!(
            mmds.get_value("/age".to_string(), OutputFormat::Imds)
                .err()
                .unwrap(),
            Error::UnsupportedValueType
        );

        // Test path ends with /; Value is a dictionary.
        // Retrieve an array.
        let mut expected = r#"[
                "+401234567",
                "+441234567"
            ]"#
        .to_string();
        expected.retain(|c| !c.is_whitespace());
        assert_eq!(
            mmds.get_value("/phones/".to_string(), OutputFormat::Json)
                .unwrap(),
            expected
        );
        assert_eq!(
            mmds.get_value("/phones/".to_string(), OutputFormat::Imds)
                .err()
                .unwrap(),
            Error::UnsupportedValueType
        );

        // Test path does NOT end with /; Value is a dictionary.
        assert_eq!(
            mmds.get_value("/phones".to_string(), OutputFormat::Json)
                .unwrap(),
            expected
        );
        assert_eq!(
            mmds.get_value("/phones".to_string(), OutputFormat::Imds)
                .err()
                .unwrap(),
            Error::UnsupportedValueType
        );

        // Retrieve the first element of an array.
        assert_eq!(
            mmds.get_value("/phones/0/".to_string(), OutputFormat::Json)
                .unwrap(),
            "\"+401234567\""
        );
        assert_eq!(
            mmds.get_value("/phones/0/".to_string(), OutputFormat::Imds)
                .unwrap(),
            "+401234567"
        );

        // Retrieve a boolean.
        assert_eq!(
            mmds.get_value("/member".to_string(), OutputFormat::Json)
                .unwrap(),
            "false"
        );
        assert_eq!(
            mmds.get_value("/member".to_string(), OutputFormat::Imds)
                .err()
                .unwrap(),
            Error::UnsupportedValueType
        );

        // Retrieve a float.
        assert_eq!(
            mmds.get_value("/shares_percentage".to_string(), OutputFormat::Json)
                .unwrap(),
            "12.12"
        );
        assert_eq!(
            mmds.get_value("/shares_percentage".to_string(), OutputFormat::Imds)
                .err()
                .unwrap(),
            Error::UnsupportedValueType
        );

        // Retrieve a negative integer.
        assert_eq!(
            mmds.get_value("/balance".to_string(), OutputFormat::Json)
                .unwrap(),
            "-24"
        );
        assert_eq!(
            mmds.get_value("/balance".to_string(), OutputFormat::Imds)
                .err()
                .unwrap(),
            Error::UnsupportedValueType
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
        assert!(mmds.put_data(data_store).is_ok());

        let data = r#"{
            "name": {
                "first": "John",
                "second": null
            },
            "age": "43"
        }"#;
        let data_store: Value = serde_json::from_str(data).unwrap();
        assert!(mmds.patch_data(data_store).is_ok());
    }
}
