/// Use this structure to set up the Block Device before booting the kernel
extern crate std;

use std::collections::LinkedList;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    RootBlockDeviceAlreadyAdded,
    InvalidBlockDevicePath,
}
type Result<T> = std::result::Result<T, Error>;

#[derive(PartialEq, Debug, Clone)]
pub struct BlockDeviceConfig {
    pub drive_id: String,
    pub path_on_host: PathBuf,
    pub is_root_device: bool,
}

// Wrapper for the collection that holds all the Block Devices Configs
pub struct BlockDeviceConfigs {
    pub config_list: LinkedList<BlockDeviceConfig>,
    has_root_block: bool,
}

impl BlockDeviceConfigs {
    pub fn new() -> BlockDeviceConfigs {
        BlockDeviceConfigs {
            config_list: LinkedList::<BlockDeviceConfig>::new(),
            has_root_block: false,
        }
    }

    pub fn has_root_block_device(&self) -> bool {
        return self.has_root_block;
    }

    /// only call this function as part of the API
    /// This function adds a new Block Device Config to the list. If the Block Device is the root,
    /// the Block Device will be added to the begining of the list
    pub fn add(&mut self, block_device_config: BlockDeviceConfig) -> Result<()> {
        // check if the path exists
        if !block_device_config.path_on_host.exists() {
            return Err(Error::InvalidBlockDevicePath);
        }
        // check whether the Device Config belongs to a root device
        // we need to satify the condition by which a VMM can only have on root device
        if block_device_config.is_root_device {
            if self.has_root_block {
                return Err(Error::RootBlockDeviceAlreadyAdded);
            } else {
                // Root Device should be the first in the list
                self.config_list.push_front(block_device_config);
                self.has_root_block = true;
            }
        } else {
            self.config_list.push_back(block_device_config);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    // Helper function for creating a dummy file
    // The filename has to be unique among all tests because the tests are run on many threads
    fn create_dummy_path(filename: String) -> PathBuf {
        let _file = File::create(filename.clone());
        return PathBuf::from(filename);
    }

    // Helper function for deleting a dummy file
    fn delete_dummy_path(filename: String) {
        std::fs::remove_file(filename);
    }

    #[test]
    fn test_create_block_devices_configs() {
        let block_devices_configs = BlockDeviceConfigs::new();
        assert_eq!(block_devices_configs.has_root_block_device(), false);
        assert_eq!(block_devices_configs.config_list.len(), 0);
    }

    #[test]
    fn test_add_non_root_block_device() {
        let dummy_filename = String::from("non_root_block_device");
        let dummy_path = create_dummy_path(dummy_filename.clone());

        let dummy_block_device = BlockDeviceConfig {
            path_on_host: dummy_path,
            is_root_device: false,
            drive_id: String::from("1"),
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(
            block_devices_configs
                .add(dummy_block_device.clone())
                .is_ok()
        );
        assert_eq!(block_devices_configs.has_root_block, false);
        assert_eq!(block_devices_configs.config_list.len(), 1);
        let dev_config = block_devices_configs.config_list.iter().next().unwrap();
        assert_eq!(dev_config, &dummy_block_device);

        delete_dummy_path(dummy_filename);
    }

    #[test]
    fn test_add_one_root_block_device() {
        let dummy_filename = String::from("one_root_block_device");
        let dummy_path = create_dummy_path(dummy_filename.clone());

        let dummy_block_device = BlockDeviceConfig {
            path_on_host: dummy_path,
            is_root_device: true,
            drive_id: String::from("1"),
        };
        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(
            block_devices_configs
                .add(dummy_block_device.clone())
                .is_ok()
        );
        assert_eq!(block_devices_configs.has_root_block, true);
        assert_eq!(block_devices_configs.config_list.len(), 1);
        let dev_config = block_devices_configs.config_list.iter().next().unwrap();
        assert_eq!(dev_config, &dummy_block_device);

        delete_dummy_path(dummy_filename);
    }

    #[test]
    fn test_add_two_root_block_devices_configs() {
        let dummy_filename = String::from("two_root_block_devices_configs");
        let dummy_path = create_dummy_path(dummy_filename.clone());

        let root_block_device_1 = BlockDeviceConfig {
            path_on_host: dummy_path.clone(),
            is_root_device: true,
            drive_id: String::from("1"),
        };

        let root_block_device_2 = BlockDeviceConfig {
            path_on_host: dummy_path.clone(),
            is_root_device: true,
            drive_id: String::from("2"),
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(block_devices_configs.add(root_block_device_1).is_ok());
        let actual_error = format!(
            "{:?}",
            block_devices_configs.add(root_block_device_2).unwrap_err()
        );
        let expected_error = format!("{:?}", Error::RootBlockDeviceAlreadyAdded);
        assert_eq!(expected_error, actual_error);

        delete_dummy_path(dummy_filename);
    }

    #[test]
    /// Test BlockDevicesConfigs::add when you first add the root device and then the other devices
    fn test_add_root_block_device_first() {
        let dummy_filename = String::from("root_block_device_first");
        let dummy_path = create_dummy_path(dummy_filename.clone());

        let root_block_device = BlockDeviceConfig {
            path_on_host: dummy_path.clone(),
            is_root_device: true,
            drive_id: String::from("1"),
        };

        let dummy_block_device_1 = BlockDeviceConfig {
            path_on_host: dummy_path.clone(),
            is_root_device: false,
            drive_id: String::from("2"),
        };

        let dummy_block_device_2 = BlockDeviceConfig {
            path_on_host: dummy_path.clone(),
            is_root_device: false,
            drive_id: String::from("3"),
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(block_devices_configs.add(root_block_device.clone()).is_ok());
        assert!(
            block_devices_configs
                .add(dummy_block_device_1.clone())
                .is_ok()
        );
        assert!(
            block_devices_configs
                .add(dummy_block_device_2.clone())
                .is_ok()
        );

        assert_eq!(block_devices_configs.has_root_block_device(), true);
        assert_eq!(block_devices_configs.config_list.len(), 3);

        let mut block_dev_iter = block_devices_configs.config_list.iter();
        assert_eq!(block_dev_iter.next().unwrap(), &root_block_device);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_1);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_2);

        delete_dummy_path(dummy_filename);
    }

    #[test]
    /// Test BlockDevicesConfigs::add when you add other devices first and then the root device
    fn test_root_block_device_add_last() {
        let dummy_filename = String::from("root_block_device_add_last");
        let dummy_path = create_dummy_path(dummy_filename.clone());

        let root_block_device = BlockDeviceConfig {
            path_on_host: dummy_path.clone(),
            is_root_device: true,
            drive_id: String::from("1"),
        };

        let dummy_block_device_1 = BlockDeviceConfig {
            path_on_host: dummy_path.clone(),
            is_root_device: false,
            drive_id: String::from("2"),
        };

        let dummy_block_device_2 = BlockDeviceConfig {
            path_on_host: dummy_path.clone(),
            is_root_device: false,
            drive_id: String::from("3"),
        };

        let mut block_devices_configs = BlockDeviceConfigs::new();
        assert!(
            block_devices_configs
                .add(dummy_block_device_1.clone())
                .is_ok()
        );
        assert!(
            block_devices_configs
                .add(dummy_block_device_2.clone())
                .is_ok()
        );
        assert!(block_devices_configs.add(root_block_device.clone()).is_ok());

        assert_eq!(block_devices_configs.has_root_block_device(), true);
        assert_eq!(block_devices_configs.config_list.len(), 3);

        let mut block_dev_iter = block_devices_configs.config_list.iter();
        // The root device should be first in the list no matter of the order in which the devices were added
        assert_eq!(block_dev_iter.next().unwrap(), &root_block_device);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_1);
        assert_eq!(block_dev_iter.next().unwrap(), &dummy_block_device_2);

        delete_dummy_path(dummy_filename);
    }
}
