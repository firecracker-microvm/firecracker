use std::sync::{Arc, Mutex};

use json_patch::merge;
use serde_json::Value;

lazy_static! {
    // A static reference to a global MMDS instance. We currently use this for ease of access during
    // prototyping. We'll consider something like passing Arc<Mutex<MMDS>> references to the
    // appropriate threads in the future.
    pub static ref STATIC_MMDS: Arc<Mutex<MMDS>> = Arc::new(Mutex::new(MMDS::default()));
}

/// The MMDS is the Microvm Metadata Service represented as an untyped json.
#[derive(Clone)]
pub struct MMDS {
    data_store: Value,
    is_initialized: bool,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    NotFound,
    UnsupportedValueType,
}

impl Default for MMDS {
    fn default() -> Self {
        MMDS {
            data_store: Value::default(),
            is_initialized: false,
        }
    }
}

impl MMDS {
    /// This method is needed to provide the correct status code for API request.
    /// When the MMDS structure is initialized for the first time via the API, the
    /// status code should be 201 (Created) and when the structure is updated, the
    /// status code should be 204 (Updated).
    pub fn is_initialized(&self) -> bool {
        return self.is_initialized;
    }

    pub fn put_data(&mut self, data: Value) {
        // TODO: we should add a data validator and only accept Strings, arrays & dictionaries
        // https://github.com/aws/PRIVATE-firecracker/issues/401
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
        return self.data_store.to_string();
    }

    // Helper function for getting all the keys from Value::Object.
    // Returns a Vec<String> with all keys. If the key corresponds to a
    // dictionary, a "/" is appended to the key name.
    // If the `dict` is Value::Null, Error::NotFound is thrown.
    // If the `dict` is not a dictionary, a Vec with the value corresponding to
    // the key is returned.
    fn get_keys(dict: &Value) -> Result<Vec<String>, Error> {
        if dict.is_null() {
            return Err(Error::NotFound);
        }

        let mut ret = Vec::new();
        match dict.as_object() {
            Some(map) => {
                // When the object is a map, push all the keys in the Vec.
                for key in map.keys() {
                    let mut key = key.clone();
                    if dict[&key].is_object() {
                        key.push_str("/");
                    }

                    ret.push(key);
                }
                return Ok(ret);
            }
            None => {
                // When the object is not a map, return the value.
                match dict.as_str() {
                    Some(val) => {
                        ret.push(val.to_string());
                        return Ok(ret);
                    }
                    None => return Err(Error::UnsupportedValueType),
                };
            }
        };
    }

    // Helper function for converting a Value to String by following the IMDS specs.
    // The only supported Value is String. Throws UnsupportedValueType when the type of the
    // Value is not String.
    fn get_value_as_string(val: &Value) -> Result<String, Error> {
        if val.is_null() {
            return Err(Error::NotFound);
        }

        if val.is_object() {
            return Ok(String::new());
        }

        match val.as_str() {
            Some(value) => Ok(value.to_string()),
            None => Err(Error::UnsupportedValueType),
        }
    }

    /// This function replicates the behavior of the Instance Metadata Service
    /// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
    /// When the path ends with / there are two cases:
    /// 1. For a (key, value) pair where the value is a dictionary, it will return all the keys
    /// in the dictionary.
    /// 2. For a (key, value) pair where the value is a simple type (bool, string, number),
    /// it will return the value.
    ///
    /// When the path does not end with / there are also two cases to cover:
    /// 1. The value corresponding to that path is a dictionary, the function returns
    /// an empty string.
    /// 2. The value corresponding to that path is a simple type, the function returns the value.
    ///
    /// When the path is not found, a NotFound error is returned.
    pub fn get_value(&self, path: String) -> Result<Vec<String>, Error> {
        // The pointer function splits the input by "/". With a trailing "/", pointer does not
        // know how to get the object.
        let value = match path.ends_with('/') {
            true => self.data_store.pointer(&path.as_str()[..(path.len() - 1)]),
            false => self.data_store.pointer(path.as_str()),
        };

        match value {
            Some(val) => {
                // If path ends with /, return all keys in Value::Object
                if path.ends_with("/") {
                    MMDS::get_keys(val)
                } else {
                    match MMDS::get_value_as_string(val) {
                        Ok(value) => Ok(vec![value]),
                        Err(e) => Err(e),
                    }
                }
            }
            None => return Err(Error::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_mmds() {
        let mut mmds = MMDS::default();
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
        let mut mmds = MMDS::default();
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
        match mmds.get_value("/phones/".to_string()) {
            Ok(ret) => assert_eq!(ret, vec!["home/", "mobile"]),
            Err(e) => assert!(false),
        };
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
            Ok(ret) => assert_eq!(ret, vec![""]),
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
        let mut mmds = MMDS::default();
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
        let mut mmds = MMDS::default();
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
