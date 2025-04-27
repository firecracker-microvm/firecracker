// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};
use serde_json::{Value, to_vec};

use crate::mmds::token::{MmdsTokenError as TokenError, TokenAuthority};

/// The Mmds is the Microvm Metadata Service represented as an untyped json.
#[derive(Debug)]
pub struct Mmds {
    data_store: Value,
    // None when MMDS V1 is configured, Some for MMDS V2.
    token_authority: Option<TokenAuthority>,
    is_initialized: bool,
    data_store_limit: usize,
}

/// MMDS version.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum MmdsVersion {
    #[default]
    /// MMDS version 1
    V1,
    /// MMDS version 2
    V2,
}

impl Display for MmdsVersion {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            MmdsVersion::V1 => write!(f, "V1"),
            MmdsVersion::V2 => write!(f, "V2"),
        }
    }
}

/// MMDS possible outputs.
#[derive(Debug)]
pub enum OutputFormat {
    /// MMDS output format as Json
    Json,
    /// MMDS output format as Imds
    Imds,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// MMDS data store errors
pub enum MmdsDatastoreError {
    /// The MMDS patch request doesn't fit.
    DataStoreLimitExceeded,
    /// The MMDS resource does not exist.
    NotFound,
    /// The MMDS data store is not initialized.
    NotInitialized,
    /// Token Authority error: {0}
    TokenAuthority(#[from] TokenError),
    /// Cannot retrieve value. The value has an unsupported type.
    UnsupportedValueType,
}

// Used for ease of use in tests.
impl Default for Mmds {
    fn default() -> Self {
        Self::default_with_limit(51200)
    }
}

impl Mmds {
    /// MMDS default instance with limit `data_store_limit`
    pub fn default_with_limit(data_store_limit: usize) -> Self {
        Mmds {
            data_store: Value::default(),
            token_authority: None,
            is_initialized: false,
            data_store_limit,
        }
    }

    /// This method is needed to check if data store is initialized.
    /// When a PATCH request is made on an uninitialized Mmds structure this method
    /// should return a NotFound error.
    fn check_data_store_initialized(&self) -> Result<(), MmdsDatastoreError> {
        if self.is_initialized {
            Ok(())
        } else {
            Err(MmdsDatastoreError::NotInitialized)
        }
    }

    /// Set the MMDS version.
    pub fn set_version(&mut self, version: MmdsVersion) -> Result<(), MmdsDatastoreError> {
        match version {
            MmdsVersion::V1 => {
                self.token_authority = None;
                Ok(())
            }
            MmdsVersion::V2 => {
                if self.token_authority.is_none() {
                    self.token_authority = Some(TokenAuthority::new()?);
                }
                Ok(())
            }
        }
    }

    /// Return the MMDS version by checking the token authority field.
    pub fn version(&self) -> MmdsVersion {
        if self.token_authority.is_none() {
            MmdsVersion::V1
        } else {
            MmdsVersion::V2
        }
    }

    /// Sets the Additional Authenticated Data to be used for encryption and
    /// decryption of the session token when MMDS version 2 is enabled.
    pub fn set_aad(&mut self, instance_id: &str) {
        if let Some(ta) = self.token_authority.as_mut() {
            ta.set_aad(instance_id);
        }
    }

    /// Checks if the provided token has not expired.
    pub fn is_valid_token(&self, token: &str) -> Result<bool, TokenError> {
        self.token_authority
            .as_ref()
            .ok_or(TokenError::InvalidState)
            .map(|ta| ta.is_valid(token))
    }

    /// Generate a new Mmds token using the token authority.
    pub fn generate_token(&mut self, ttl_seconds: u32) -> Result<String, TokenError> {
        self.token_authority
            .as_mut()
            .ok_or(TokenError::InvalidState)
            .and_then(|ta| ta.generate_token_secret(ttl_seconds))
    }

    /// set MMDS data store limit to `data_store_limit`
    pub fn set_data_store_limit(&mut self, data_store_limit: usize) {
        self.data_store_limit = data_store_limit;
    }

    /// put `data` in MMDS data store
    pub fn put_data(&mut self, data: Value) -> Result<(), MmdsDatastoreError> {
        // It is safe to unwrap because any map keys are all strings and
        // we are using default serializer which does not return error.
        if to_vec(&data).unwrap().len() > self.data_store_limit {
            Err(MmdsDatastoreError::DataStoreLimitExceeded)
        } else {
            self.data_store = data;
            self.is_initialized = true;

            Ok(())
        }
    }

    /// patch update MMDS data store with `patch_data`
    pub fn patch_data(&mut self, patch_data: Value) -> Result<(), MmdsDatastoreError> {
        self.check_data_store_initialized()?;
        let mut data_store_clone = self.data_store.clone();

        super::json_patch(&mut data_store_clone, &patch_data);
        // It is safe to unwrap because our data store keys are all strings and
        // we are using default serializer which does not return error.
        if to_vec(&data_store_clone).unwrap().len() > self.data_store_limit {
            return Err(MmdsDatastoreError::DataStoreLimitExceeded);
        }
        self.data_store = data_store_clone;
        Ok(())
    }

    /// return MMDS data store value
    /// We do not check size of data_store before returning a result because due
    /// to limit from put/patch the data_store can not be bigger than the limit
    /// imposed by the server.
    pub fn data_store_value(&self) -> Value {
        self.data_store.clone()
    }

    /// Returns the serde::Value in IMDS format plaintext.
    /// Currently, only JSON objects and strings can be IMDS formatted.
    ///
    /// See the docs for detailed description of the IMDS format:
    /// <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html>
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
    /// ```
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
    fn format_imds(json: &Value) -> Result<String, MmdsDatastoreError> {
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
                        key.push('/');
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
                    None => Err(MmdsDatastoreError::UnsupportedValueType),
                }
            }
        }
    }

    /// Returns the subtree located at path. When the path corresponds to a leaf, it returns the
    /// value. Returns Error::NotFound when the path is invalid.
    pub fn get_value(
        &self,
        path: String,
        format: OutputFormat,
    ) -> Result<String, MmdsDatastoreError> {
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
            Err(MmdsDatastoreError::NotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Mmds {
        fn get_data_str(&self) -> String {
            if self.data_store.is_null() {
                return String::from("{}");
            }
            self.data_store.to_string()
        }
    }

    #[test]
    fn test_display_mmds_version() {
        assert_eq!(MmdsVersion::V1.to_string(), "V1");
        assert_eq!(MmdsVersion::V2.to_string(), "V2");
        assert_eq!(MmdsVersion::default().to_string(), "V1");
    }

    #[test]
    fn test_mmds_version() {
        let mut mmds = Mmds::default();

        // Test default MMDS version.
        assert_eq!(mmds.version(), MmdsVersion::V1);

        // Test setting MMDS version to v2.
        mmds.set_version(MmdsVersion::V2).unwrap();
        assert_eq!(mmds.version(), MmdsVersion::V2);

        // Test setting MMDS version back to default.
        mmds.set_version(MmdsVersion::V1).unwrap();
        assert_eq!(mmds.version(), MmdsVersion::V1);
    }

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
        mmds.check_data_store_initialized().unwrap();

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
            mmds.get_value("/invalid_path".to_string(), OutputFormat::Json)
                .unwrap_err()
                .to_string(),
            MmdsDatastoreError::NotFound.to_string()
        );
        assert_eq!(
            mmds.get_value("/invalid_path".to_string(), OutputFormat::Imds)
                .unwrap_err()
                .to_string(),
            MmdsDatastoreError::NotFound.to_string()
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
                .unwrap()
                .to_string(),
            MmdsDatastoreError::UnsupportedValueType.to_string()
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
                .unwrap()
                .to_string(),
            MmdsDatastoreError::UnsupportedValueType.to_string()
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
                .unwrap()
                .to_string(),
            MmdsDatastoreError::UnsupportedValueType.to_string()
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
                .unwrap()
                .to_string(),
            MmdsDatastoreError::UnsupportedValueType.to_string()
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
                .unwrap()
                .to_string(),
            MmdsDatastoreError::UnsupportedValueType.to_string()
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
                .unwrap()
                .to_string(),
            MmdsDatastoreError::UnsupportedValueType.to_string()
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
        mmds.put_data(data_store).unwrap();

        let data = r#"{
            "name": {
                "first": "John",
                "second": "Doe"
            },
            "age": "100"
        }"#;
        let data_store: Value = serde_json::from_str(data).unwrap();
        mmds.patch_data(data_store).unwrap();

        let data = r#"{
            "name": {
                "first": "John",
                "second": "Doe"
            },
            "age": 43
        }"#;
        let data_store: Value = serde_json::from_str(data).unwrap();
        mmds.put_data(data_store).unwrap();

        let data = r#"{
            "name": {
                "first": "John",
                "second": null
            },
            "age": "43"
        }"#;
        let data_store: Value = serde_json::from_str(data).unwrap();
        mmds.patch_data(data_store).unwrap();

        let filling = (0..51151).map(|_| "X").collect::<String>();
        let data = "{\"new_key\": \"".to_string() + &filling + "\"}";

        let data_store: Value = serde_json::from_str(&data).unwrap();
        mmds.patch_data(data_store).unwrap();

        let data = "{\"new_key2\" : \"smth\"}";
        let data_store: Value = serde_json::from_str(data).unwrap();
        assert_eq!(
            mmds.patch_data(data_store).unwrap_err().to_string(),
            MmdsDatastoreError::DataStoreLimitExceeded.to_string()
        );
        assert!(!mmds.get_data_str().contains("smth"));

        let data = "{\"new_key\" : \"smth\"}";
        let data_store: Value = serde_json::from_str(data).unwrap();
        mmds.patch_data(data_store).unwrap();
        assert!(mmds.get_data_str().contains("smth"));
        assert_eq!(mmds.get_data_str().len(), 53);

        let data = "{\"new_key2\" : \"smth2\"}";
        let data_store: Value = serde_json::from_str(data).unwrap();
        mmds.patch_data(data_store).unwrap();
        assert!(mmds.get_data_str().contains("smth2"));
        assert_eq!(mmds.get_data_str().len(), 72);
    }

    #[test]
    fn test_put_size_limit() {
        let mut mmds = Mmds::default();
        let filling = (0..51300).map(|_| "X").collect::<String>();
        let data = "{\"key\": \"".to_string() + &filling + "\"}";

        let data_store: Value = serde_json::from_str(&data).unwrap();

        assert_eq!(
            mmds.put_data(data_store).unwrap_err().to_string(),
            MmdsDatastoreError::DataStoreLimitExceeded.to_string()
        );

        assert_eq!(mmds.get_data_str().len(), 2);
    }

    #[test]
    fn test_is_valid() {
        let mut mmds = Mmds::default();
        // Set MMDS version to V2.
        mmds.set_version(MmdsVersion::V2).unwrap();
        assert_eq!(mmds.version(), MmdsVersion::V2);

        assert!(!mmds.is_valid_token("aaa").unwrap());

        mmds.token_authority = None;
        assert_eq!(
            mmds.is_valid_token("aaa").unwrap_err().to_string(),
            TokenError::InvalidState.to_string()
        )
    }

    #[test]
    fn test_generate_token() {
        let mut mmds = Mmds::default();
        // Set MMDS version to V2.
        mmds.set_version(MmdsVersion::V2).unwrap();
        assert_eq!(mmds.version(), MmdsVersion::V2);

        let token = mmds.generate_token(1).unwrap();
        assert!(mmds.is_valid_token(&token).unwrap());

        mmds.token_authority = None;
        assert_eq!(
            mmds.generate_token(1).err().unwrap().to_string(),
            TokenError::InvalidState.to_string()
        );
    }
}
