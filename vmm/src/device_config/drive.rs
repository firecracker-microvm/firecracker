use std::collections::LinkedList;
use std::path::PathBuf;
use std::result;

use data_model::device_config::{DriveConfig, DriveError};

type Result<T> = result::Result<T, DriveError>;

// Wrapper for the collection that holds all the Drive Configs.
pub struct BlockDeviceConfigs {
    pub config_list: LinkedList<DriveConfig>,
    has_root_block: bool,
    read_only_root: bool,
}

impl BlockDeviceConfigs {
    pub fn new() -> BlockDeviceConfigs {
        BlockDeviceConfigs {
            config_list: LinkedList::<DriveConfig>::new(),
            has_root_block: false,
            read_only_root: false,
        }
    }

    pub fn has_root_block_device(&self) -> bool {
        return self.has_root_block;
    }

    pub fn has_read_only_root(&self) -> bool {
        self.read_only_root
    }

    fn contains_drive_path(&self, drive_path: &PathBuf) -> bool {
        for drive_config in self.config_list.iter() {
            if drive_config.get_path_on_host() == drive_path {
                return true;
            }
        }
        return false;
    }

    pub fn contains_drive_id(&self, drive_id: &str) -> bool {
        for drive_config in self.config_list.iter() {
            if drive_config.get_id() == drive_id {
                return true;
            }
        }
        return false;
    }

    /// This function adds a Block Device Config to the list. The root block device is always
    /// added to the beginning of the list. Only one root block device can be added.
    pub fn add(&mut self, block_device_config: DriveConfig) -> Result<()> {
        // check if the path exists
        if !block_device_config.get_path_on_host().exists() {
            return Err(DriveError::InvalidBlockDevicePath);
        }

        if self.contains_drive_path(block_device_config.get_path_on_host()) {
            return Err(DriveError::BlockDevicePathAlreadyExists);
        }

        // check whether the Device Config belongs to a root device
        // we need to satisfy the condition by which a VMM can only have on root device
        if block_device_config.is_root_device() {
            if self.has_root_block {
                return Err(DriveError::RootBlockDeviceAlreadyAdded);
            } else {
                self.has_root_block = true;
                self.read_only_root = block_device_config.is_read_only();
                // Root Device should be the first in the list
                self.config_list.push_front(block_device_config);
            }
        } else {
            self.config_list.push_back(block_device_config);
        }

        Ok(())
    }

    fn get_root_id(&self) -> Option<String> {
        if !self.has_root_block {
            return None;
        } else {
            for cfg in self.config_list.iter() {
                if cfg.is_root_device() {
                    return Some(cfg.get_id().to_string());
                }
            }
        }
        None
    }

    /// This function updates a Block Device Config prior to the guest boot. The update fails if it
    /// would result in two root block devices.
    pub fn update(&mut self, block_device_config: &DriveConfig) -> Result<()> {
        // Check if the path exists
        if !block_device_config.get_path_on_host().exists() {
            return Err(DriveError::InvalidBlockDevicePath);
        }

        let root_id = self.get_root_id();
        for cfg in self.config_list.iter_mut() {
            if cfg.get_id() == block_device_config.get_id() {
                if cfg.is_root_device() {
                    // Check if the root block device is being updated
                    self.has_root_block = block_device_config.is_root_device();
                    self.read_only_root =
                        block_device_config.is_root_device() && block_device_config.is_read_only();
                } else if block_device_config.is_root_device() {
                    // Check if a second root block device is being added
                    if root_id.is_some() {
                        return Err(DriveError::RootBlockDeviceAlreadyAdded);
                    } else {
                        // One of the non-root blocks is becoming root
                        self.has_root_block = true;
                        self.read_only_root = block_device_config.is_read_only();
                    }
                }
                cfg.set_is_root_device(block_device_config.is_root_device());
                cfg.set_is_read_only(block_device_config.is_read_only());
                cfg.set_path_on_host(block_device_config.get_path_on_host());

                return Ok(());
            }
        }

        Err(DriveError::BlockDeviceUpdateFailed)
    }
}

#[cfg(test)]
mod tests {
    extern crate serde_json;

    use super::*;
    use std::fs::{self, File};
    use std::result;

    // Helper function for creating a dummy file
    // The filename has to be unique among all tests because the tests are run on many threads
    fn create_dummy_path(filename: String) -> PathBuf {
        let _file = File::create(filename.clone());
        return PathBuf::from(filename);
    }

    // Helper function for deleting a dummy file
    fn delete_dummy_path(filename: String) {
        let _rs = fs::remove_file(filename);
    }

    #[test]
    fn test_create_block_devices_configs() {
        let block_devices_configs = BlockDeviceConfigs::new();
        assert_eq!(block_devices_configs.has_root_block_device(), false);
        assert_eq!(block_devices_configs.config_list.len(), 0);
    }

    #[test]
    fn test_add_non_root_block_device() {
        let dummy_filename = String::from("test_add_non_root_block_device");

        let body = r#"{
            "drive_id": "1",
            "path_on_host": "test_add_non_root_block_device",
            "state": "Attached",
            "is_root_device": false,
            "permissions": "rw"
        }"#;

        let result: result::Result<DriveConfig, serde_json::Error> = serde_json::from_str(body);
        assert!(result.is_ok());
        let dummy_block_device = result.unwrap();

        let mut block_devices_configs = BlockDeviceConfigs::new();
        create_dummy_path(dummy_filename.clone());
        let add_result = block_devices_configs.add(dummy_block_device.clone());
        delete_dummy_path(dummy_filename);
        assert!(add_result.is_ok());

        assert_eq!(block_devices_configs.has_root_block, false);
        assert_eq!(block_devices_configs.config_list.len(), 1);
        let dev_config = block_devices_configs.config_list.iter().next().unwrap();
        assert_eq!(dev_config, &dummy_block_device);
    }

    #[test]
    fn test_root_block_device_add() {
        let mut block_devices_configs = BlockDeviceConfigs::new();

        let dummy_filename1 = String::from("test_root_block_device_add1");
        create_dummy_path(dummy_filename1.clone());

        let body = r#"{
            "drive_id": "1",
            "path_on_host": "test_root_block_device_add1",
            "state": "Attached",
            "is_root_device": true,
            "permissions": "rw"
        }"#;

        let result: result::Result<DriveConfig, serde_json::Error> = serde_json::from_str(body);
        assert!(result.is_ok());
        let root_block_device1 = result.unwrap();
        let add_result = block_devices_configs.add(root_block_device1.clone());
        delete_dummy_path(dummy_filename1);
        assert!(add_result.is_ok());

        assert_eq!(block_devices_configs.has_root_block, true);
        assert_eq!(block_devices_configs.config_list.len(), 1);

        // test adding two block devices
        let dummy_filename_2 = String::from("test_root_block_device_add2");
        create_dummy_path(dummy_filename_2.clone());

        let body = r#"{
            "drive_id": "2",
            "path_on_host": "test_root_block_device_add2",
            "state": "Attached",
            "is_root_device": true,
            "permissions": "rw"
        }"#;

        let result: result::Result<DriveConfig, serde_json::Error> = serde_json::from_str(body);
        assert!(result.is_ok());
        let root_block_device_2 = result.unwrap();

        let actual_error = format!(
            "{:?}",
            block_devices_configs.add(root_block_device_2).unwrap_err()
        );
        let expected_error = format!("{:?}", DriveError::RootBlockDeviceAlreadyAdded);

        delete_dummy_path(dummy_filename_2);
        assert_eq!(expected_error, actual_error);

        let dev_config = block_devices_configs.config_list.iter().next().unwrap();
        assert_eq!(dev_config, &root_block_device1);
    }

    #[test]
    /// Test BlockDevicesConfigs::add when you first add the root device and then the other devices
    fn test_add_ro_root_block_device_first() {
        let dummy_filename_1 = String::from("test_add_root_block_device_first_1");

        create_dummy_path(dummy_filename_1.clone());
        let body = r#"{
            "drive_id": "1",
            "path_on_host": "test_add_root_block_device_first_1",
            "state": "Attached",
            "is_root_device": true,
            "permissions": "ro"
        }"#;

        let result: result::Result<DriveConfig, serde_json::Error> = serde_json::from_str(body);
        assert!(result.is_ok());
        let root_block_device = result.unwrap();

        let dummy_filename_2 = String::from("test_add_root_block_device_first_2");
        create_dummy_path(dummy_filename_2.clone());

        let body = r#"{
            "drive_id": "2",
            "path_on_host": "test_add_root_block_device_first_2",
            "state": "Attached",
            "is_root_device": false,
            "permissions": "rw"
        }"#;

        let result: result::Result<DriveConfig, serde_json::Error> = serde_json::from_str(body);
        assert!(result.is_ok());
        let dummy_block_device_2 = result.unwrap();

        let dummy_filename_3 = String::from("test_add_root_block_device_first_3");
        create_dummy_path(dummy_filename_3.clone());

        let body = r#"{
            "drive_id": "3",
            "path_on_host": "test_add_root_block_device_first_3",
            "state": "Attached",
            "is_root_device": false,
            "permissions": "rw"
        }"#;

        let result: result::Result<DriveConfig, serde_json::Error> = serde_json::from_str(body);
        assert!(result.is_ok());
        let dummy_block_device_3 = result.unwrap();

        let mut block_devices_configs = BlockDeviceConfigs::new();
        let res_add1 = block_devices_configs.add(root_block_device.clone());
        let res_add2 = block_devices_configs.add(dummy_block_device_2.clone());
        let res_add3 = block_devices_configs.add(dummy_block_device_3.clone());

        delete_dummy_path(dummy_filename_1);
        delete_dummy_path(dummy_filename_2);
        delete_dummy_path(dummy_filename_3);

        assert!(res_add1.is_ok());
        assert!(res_add2.is_ok());
        assert!(res_add3.is_ok());

        assert_eq!(block_devices_configs.has_root_block_device(), true);
        assert_eq!(block_devices_configs.has_read_only_root(), true);
        assert_eq!(block_devices_configs.config_list.len(), 3);

        let mut block_dev_iter = block_devices_configs.config_list.iter();
        assert_eq!(block_dev_iter.next().unwrap(), &root_block_device);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_2);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_3);
    }

    #[test]
    /// Test BlockDevicesConfigs::add when you add other devices first and then the root device
    fn test_root_block_device_add_last() {
        let dummy_filename_1 = String::from("test_root_block_device_add_last_1");

        create_dummy_path(dummy_filename_1.clone());

        let body = r#"{
            "drive_id": "1",
            "path_on_host": "test_root_block_device_add_last_1",
            "state": "Attached",
            "is_root_device": true,
            "permissions": "rw"
        }"#;

        let result: result::Result<DriveConfig, serde_json::Error> = serde_json::from_str(body);
        assert!(result.is_ok());
        let root_block_device = result.unwrap();

        let dummy_filename_2 = String::from("test_root_block_device_add_last_2");
        create_dummy_path(dummy_filename_2.clone());
        let body = r#"{
            "drive_id": "2",
            "path_on_host": "test_root_block_device_add_last_2",
            "state": "Attached",
            "is_root_device": false,
            "permissions": "rw"
        }"#;

        let result: result::Result<DriveConfig, serde_json::Error> = serde_json::from_str(body);
        assert!(result.is_ok());
        let dummy_block_device_2 = result.unwrap();

        let dummy_filename_3 = String::from("test_root_block_device_add_last_3");
        create_dummy_path(dummy_filename_3.clone());

        let body = r#"{
            "drive_id": "3",
            "path_on_host": "test_root_block_device_add_last_3",
            "state": "Attached",
            "is_root_device": false,
            "permissions": "rw"
        }"#;

        let result: result::Result<DriveConfig, serde_json::Error> = serde_json::from_str(body);
        assert!(result.is_ok());
        let dummy_block_device_3 = result.unwrap();

        let mut block_devices_configs = BlockDeviceConfigs::new();

        let res_add1 = block_devices_configs.add(dummy_block_device_2.clone());
        let res_add2 = block_devices_configs.add(dummy_block_device_3.clone());
        let res_add3 = block_devices_configs.add(root_block_device.clone());

        delete_dummy_path(dummy_filename_1);
        delete_dummy_path(dummy_filename_2);
        delete_dummy_path(dummy_filename_3);

        assert!(res_add1.is_ok());
        assert!(res_add2.is_ok());
        assert!(res_add3.is_ok());

        assert_eq!(block_devices_configs.has_root_block_device(), true);
        assert_eq!(block_devices_configs.config_list.len(), 3);
        assert!(block_devices_configs.contains_drive_id("1"));
        assert!(!block_devices_configs.contains_drive_id("4"));

        let mut block_dev_iter = block_devices_configs.config_list.iter();
        // The root device should be first in the list no matter of the order in which the devices were added
        assert_eq!(block_dev_iter.next().unwrap(), &root_block_device);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_2);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_3);
    }
}
