use serde_json::Value;

/// The MMDS is the Microvm Metadata Service represented as an untyped json.
#[derive(Clone)]
pub struct MMDS {
    data_store: Value,
    is_initialized: bool,
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
        self.data_store = data;
        self.is_initialized = true;
    }

    pub fn get_data_str(&self) -> String {
        if self.data_store.is_null() {
            return String::from("{}");
        }
        return self.data_store.to_string();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json;

    #[test]
    fn test_mmds() {
        let mut mmds = MMDS::default();
        assert_eq!(mmds.is_initialized(), false);

        let mmds_json = "{\"meta-data\":{\"iam\":\"dummy\"},\"user-data\":\"1522850095\"}";

        mmds.put_data(serde_json::from_str(mmds_json).unwrap());
        assert_eq!(mmds.is_initialized(), true);

        assert_eq!(mmds.get_data_str(), mmds_json);
    }

}
